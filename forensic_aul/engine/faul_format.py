"""The ``.faul`` portable-evidence container format.

Defines : the single source of truth for the ``.faul`` container — a **stored**
          (uncompressed) zip that bundles an acquired ``.logarchive`` together
          with its ``.acquisition.json`` sidecar so the two travel as one file.
          Owns the format constants, the writer (:func:`pack_faul`), the O(1)
          content detector (:func:`is_faul`), and the readers used by the
          extract source layer and the sidecar auto-fill.

Layout (all paths relative to the zip root)::

    faul/manifest.json                     ← marker + version + pointers
    <name>.logarchive/…                    ← the full logarchive tree
    <name>.logarchive.acquisition.json     ← the acquisition sidecar (if any)

WHY a stored zip: the entries are written with ``ZIP_STORED`` (no compression),
so unpacking is a pure sequential byte copy — no decompression CPU, friendly to
network drives, and portable as a single file. WHY a manifest at a fixed path:
a ``.faul`` shares its magic bytes (``PK\\x03\\x04``) with a full-file-system
``.zip``; the presence of ``faul/manifest.json`` in the central directory is the
cheap, unambiguous discriminator between the two.

Used by : forensic_aul.ops.acquisition.acquire (writes a ``.faul``),
          forensic_aul.ops.extraction.sources.faul (extract input handler),
          forensic_aul.ops.acquisition.report (sidecar auto-fill).
Uses    : the Python standard library only (zipfile, json).
"""

from __future__ import annotations

import json
import logging
import os
import zipfile
from pathlib import Path, PurePosixPath

log = logging.getLogger(__name__)

# ── Format constants (single source of truth) ─────────────────────────────────

FAUL_SUFFIX = ".faul"

# Fixed path of the marker/manifest inside the container. Its presence is what
# distinguishes a .faul from a plain FFS .zip (same magic bytes).
MANIFEST_ARCNAME = "faul/manifest.json"

# Bumped only on a breaking layout change; readers reject a newer major version.
FORMAT_VERSION = 1

# Magic bytes shared by every local zip file (used by is_faul as a cheap
# pre-check before opening the central directory).
_ZIP_MAGIC = b"PK\x03\x04"


# ── Writer ────────────────────────────────────────────────────────────────────

def pack_faul(
    logarchive_dir: Path,
    out_path: Path,
    *,
    sidecar: dict | None = None,
    logarchive_arcname: str | None = None,
) -> Path:
    """Pack *logarchive_dir* (and its *sidecar*) into a ``.faul`` at *out_path*.

    The logarchive tree is stored under *logarchive_arcname* (default: the
    directory's own name, e.g. ``foo.logarchive``); the *sidecar* dict, when
    given, is written as ``<logarchive_arcname>.acquisition.json``; and a
    :data:`MANIFEST_ARCNAME` marker records the format version and the two
    pointers. Every entry is written with ``ZIP_STORED`` (no compression) so
    later extraction is a plain byte copy.

    Writes atomically: the archive is built in a sibling ``*.tmp`` file and then
    ``os.replace``-d into place, so an interrupted pack never leaves a truncated
    ``.faul`` that would later be mistaken for a valid container.

    Returns the written *out_path*.

    Raises:
        FileNotFoundError: *logarchive_dir* is not a directory.
    """
    logarchive_dir = Path(logarchive_dir)
    if not logarchive_dir.is_dir():
        raise FileNotFoundError(f"logarchive directory not found: {logarchive_dir}")

    out_path = Path(out_path)
    arcname = logarchive_arcname or logarchive_dir.name
    sidecar_arcname = f"{arcname}{_ACQUISITION_SUFFIX}"

    manifest = {
        "format": "faul",
        "format_version": FORMAT_VERSION,
        "logarchive": arcname,
        "sidecar": sidecar_arcname if sidecar is not None else None,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = out_path.with_name(out_path.name + ".tmp")
    try:
        with zipfile.ZipFile(tmp_path, "w", compression=zipfile.ZIP_STORED) as zf:
            # Manifest first so it sits at the front of the central directory.
            zf.writestr(MANIFEST_ARCNAME, json.dumps(manifest, indent=2))
            if sidecar is not None:
                zf.writestr(sidecar_arcname, json.dumps(sidecar, indent=2, ensure_ascii=False))
            # Deterministic order → reproducible container bytes for identical input.
            for src_file in _iter_regular_files(logarchive_dir):
                rel = src_file.relative_to(logarchive_dir)
                zf.write(src_file, f"{arcname}/{rel.as_posix()}")
        os.replace(tmp_path, out_path)
    except BaseException:
        # Never leave a half-written container behind.
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise

    log.info(f".faul container written: {out_path}")
    return out_path


# The suffix report.py appends to a logarchive name to form the sidecar filename.
# Kept in sync with ops.acquisition.report.ACQUISITION_REPORT_SUFFIX (imported
# there); duplicated as a literal here to keep this engine module free of an
# ops-layer import (engine is a leaf the ops packages depend on, not vice-versa).
_ACQUISITION_SUFFIX = ".acquisition.json"


def _iter_regular_files(root: Path):
    """Yield every regular (non-symlink) file under *root*, sorted for determinism.

    Symlinks are skipped — a logarchive holds only regular files, and following
    one could pull in data from outside the evidence.
    """
    for dirpath, _dirs, filenames in os.walk(root):
        for name in sorted(filenames):
            p = Path(dirpath) / name
            if not p.is_symlink():
                yield p


# ── Detection (O(1)) ────────────────────────────────────────────────────────--

def is_faul(path: Path) -> bool:
    """Return True when *path* is a ``.faul`` container (content, not extension).

    A cheap magic-byte pre-check gates a central-directory lookup for
    :data:`MANIFEST_ARCNAME`; only its presence makes a zip a ``.faul``. Never
    raises — an unreadable / non-zip file is simply not a ``.faul``.
    """
    path = Path(path)
    if not path.is_file():
        return False
    try:
        with path.open("rb") as fh:
            if fh.read(len(_ZIP_MAGIC)) != _ZIP_MAGIC:
                return False
        with zipfile.ZipFile(path) as zf:
            return MANIFEST_ARCNAME in zf.namelist()
    except (OSError, zipfile.BadZipFile):
        return False


# ── Readers ─────────────────────────────────────────────────────────────────--

def read_manifest(path: Path) -> dict | None:
    """Return the parsed manifest of a ``.faul``, or None if absent/unreadable.

    Rejects (returns None on) a container whose major ``format_version`` is newer
    than this build understands, so a forward-incompatible ``.faul`` fails loudly
    at the caller rather than being half-read.
    """
    try:
        with zipfile.ZipFile(path) as zf:
            manifest = json.loads(zf.read(MANIFEST_ARCNAME))
    except (OSError, KeyError, ValueError, zipfile.BadZipFile) as exc:
        log.debug("faul manifest unreadable in %s: %s", path, exc)
        return None
    version = manifest.get("format_version")
    if isinstance(version, int) and version > FORMAT_VERSION:
        log.warning(
            f".faul {path} declares format_version {version}; this build supports "
            f"{FORMAT_VERSION} — refusing to read it."
        )
        return None
    return manifest


def read_sidecar(path: Path) -> dict | None:
    """Return the acquisition sidecar embedded in a ``.faul``, or None if absent.

    Best-effort: a container with no sidecar, or an unreadable/foreign one,
    returns None so callers (CLI case-field fallback, GUI auto-fill) simply leave
    their fields untouched.
    """
    manifest = read_manifest(path)
    if not manifest:
        return None
    sidecar_name = manifest.get("sidecar")
    if not sidecar_name:
        return None
    try:
        with zipfile.ZipFile(path) as zf:
            return json.loads(zf.read(sidecar_name))
    except (OSError, KeyError, ValueError, zipfile.BadZipFile) as exc:
        log.debug("faul sidecar unreadable in %s: %s", path, exc)
        return None


def extract_logarchive(path: Path, dest_root: Path) -> int:
    """Extract the logarchive tree from a ``.faul`` into *dest_root*.

    The container's ``<name>.logarchive/`` prefix is stripped so *dest_root*
    itself becomes the logarchive (matching the shape the parser expects). Each
    entry is copied byte-for-byte (the archive is stored, uncompressed). Returns
    the number of files written.

    Every destination is confirmed to stay under *dest_root* (zip-slip guard) —
    a ``.faul`` is still untrusted input once it leaves the acquiring host.

    Raises:
        ValueError: the container has no readable manifest, or holds no
            logarchive content.
    """
    manifest = read_manifest(path)
    if not manifest:
        raise ValueError(f"{path} is not a readable .faul container")
    arcname = manifest.get("logarchive")
    if not arcname:
        raise ValueError(f"{path} manifest names no logarchive")

    prefix = arcname.rstrip("/") + "/"
    dest_root = Path(dest_root)
    root_resolved = dest_root.resolve()
    n = 0
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            name = info.filename
            if info.is_dir() or not name.startswith(prefix):
                continue
            rel = PurePosixPath(name[len(prefix):])
            if not rel.parts:
                continue
            dest = (root_resolved / rel).resolve()
            if not dest.is_relative_to(root_resolved):
                raise ValueError(f"Unsafe .faul entry escapes work root: {name}")
            dest.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, dest.open("wb") as out:
                _copy(src, out)
            n += 1
    if n == 0:
        raise ValueError(f"{path} holds no logarchive content under {prefix!r}")
    log.info(f".faul: extracted {n} logarchive file(s) from {path.name}")
    return n


def _copy(src, out) -> None:
    """Stream *src* → *out* in fixed chunks (avoids buffering a whole tracev3)."""
    import shutil

    shutil.copyfileobj(src, out)
