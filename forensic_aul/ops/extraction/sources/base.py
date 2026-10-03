"""Shared primitives for the extract source layer.

Defines : the vocabulary every source module builds on — the :class:`SourceType`
          enum, the :class:`PreparedSource` result, the :class:`SourceHandler`
          registry-entry protocol, the integrity-mode helpers, and the low-level
          filesystem/archive helpers (quick fingerprint, safe extraction target,
          work-root allocation, tree mirroring, plist readers) reused across the
          per-source modules.
Used by : forensic_aul.ops.extraction.sources.{logarchive,sysdiagnose,filesystem,
          loose_dirs,faul} and the package ``__init__`` (registry + dispatch).
Uses    : forensic_aul.engine.integrity (compute_sha256, hash_logarchive) and the
          Python standard library.

Adding a new source: drop a module in this package that builds a
:class:`SourceHandler` (a ``matches(path)`` predicate + a ``prepare(...)`` that
returns a :class:`PreparedSource`) and register it in ``sources/__init__.py``.
Detection, preparation and the "unrecognised source" error all follow from the
registry — no other file needs to change.
"""

from __future__ import annotations

import hashlib
import logging
import os
import plistlib
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PurePosixPath

from forensic_aul.engine.integrity import hash_logarchive
from forensic_aul.engine.utils.cancellation import NEVER_CANCELLED, CancelToken
from forensic_aul.errors import SourceError

log = logging.getLogger(__name__)


# ── Source types ──────────────────────────────────────────────────────────────

class SourceType(Enum):
    """Recognised evidence container types."""

    LOGARCHIVE = "logarchive"
    SYSDIAGNOSE = "sysdiagnose"
    FILESYSTEM = "filesystem"
    LOOSE_DIRS = "loose_dirs"
    FAUL = "faul"


# LOOSE_DIRS: the two keys a mapping source must carry — the already-uncompressed
# equivalents of an FFS zip's two unified-log folders. Exposed so callers build
# the dict by name.
LOOSE_DIAGNOSTICS_KEY = "diagnostics"
LOOSE_UUIDTEXT_KEY = "uuidtext"

# Placeholder stored in case_metadata.logarchive_path when the logarchive was
# extracted into an auto-cleaned temp dir: the real path is gone after the run
# and would be a misleading dangling reference.
TEMP_DIR_PLACEHOLDER = "(temporary directory — not retained)"

# Window read from each end of an archive for the quick fingerprint.
_FINGERPRINT_WINDOW = 64 * 1024


# ── Integrity modes ───────────────────────────────────────────────────────────
# full        — per-file SHA-256 of every source file + content fingerprint.
# fingerprint — only the cheap head+size+tail archive fingerprint.
# off         — no hashing at all.
INTEGRITY_MODES = ("full", "fingerprint", "off")


# ── Prepared source ───────────────────────────────────────────────────────────

@dataclass
class PreparedSource:
    """A source normalised to a logarchive-laid-out directory, ready to parse.

    Acts as a context manager: on exit it removes any temp dir it created. For a
    LOGARCHIVE source nothing is copied and there is nothing to clean up.
    """

    source_type: SourceType
    original_path: Path           # the evidence the analyst supplied
    logarchive_root: Path         # directory laid out as a logarchive
    # hash_logarchive() fingerprint of the material; None when prepared with
    # integrity="fingerprint"/"off" (no chain-of-custody attestation taken).
    content_sha256: str | None
    file_hashes: dict[str, str]   # relative-path → sha256 ({} in non-full modes)
    # Quick tamper-evident fingerprint of the archive, captured before extraction;
    # None for a LOGARCHIVE dir / LOOSE_DIRS (no single archive file to attest).
    archive_fingerprint: str | None = None
    # Authoritative iOS version from SystemVersion.plist (FFS / sysdiagnose only);
    # None for a bare logarchive dir, where extract falls back to the build code.
    ios_product_version: str | None = None
    # Logarchive Info.plist ArchiveIdentifier (provenance / documentation), if any.
    archive_identifier: str | None = None
    # The acquisition sidecar carried inside a .faul container (case + device
    # provenance), surfaced for case-field auto-fill; None for every other source.
    sidecar: dict | None = None
    # Internal: the temp dir backing logarchive_root, if extraction was temporary.
    _tempdir: tempfile.TemporaryDirectory | None = field(default=None, repr=False)

    @property
    def is_temporary(self) -> bool:
        """True when logarchive_root is an auto-cleaned temp dir (no --work-dir)."""
        return self._tempdir is not None

    @property
    def recorded_logarchive_path(self) -> str:
        """Value to store in case_metadata.logarchive_path (placeholder if temp)."""
        if self.is_temporary:
            return TEMP_DIR_PLACEHOLDER
        return str(self.logarchive_root)

    def verify_unchanged(self) -> bool:
        """Re-check the archive fingerprint — the 'after' half of the attestation.

        Returns True when the archive is byte-identical to its pre-extraction
        snapshot (or when there is no archive, i.e. a LOGARCHIVE dir / LOOSE_DIRS).
        A False result means the evidence changed underneath us during the run,
        which the caller must surface in the forensic log.
        """
        if self.archive_fingerprint is None:
            return True
        return quick_fingerprint(self.original_path) == self.archive_fingerprint

    def cleanup(self) -> None:
        if self._tempdir is not None:
            self._tempdir.cleanup()
            self._tempdir = None

    def __enter__(self) -> "PreparedSource":
        return self

    def __exit__(self, *_exc: object) -> bool:
        self.cleanup()
        return False


# ── Extraction outcome (what an archive handler's extract step reports) ─────────

@dataclass(frozen=True)
class ExtractOutcome:
    """Side information an archive extraction surfaces beyond the files themselves.

    ``product_version`` is the iOS ``ProductVersion`` when the container carried a
    ``SystemVersion.plist``; ``sidecar`` is the acquisition report embedded in a
    ``.faul``. Both default to None for containers that carry neither.
    """

    product_version: str | None = None
    sidecar: dict | None = None


# ── Source handler (registry entry) ────────────────────────────────────────────

@dataclass(frozen=True)
class SourceHandler:
    """One pluggable evidence-container handler.

    ``matches(path)`` is the full content-first detector (a directory check, a
    magic-byte read, or a deeper content probe); ``prepare(path, work_dir=…,
    integrity=…, cancel=…)`` normalises the source into a
    :class:`PreparedSource`.
    ``priority`` orders detection — a *more specific* handler (e.g. a ``.faul``,
    which is a zip carrying a marker) must be probed **before** a broader one
    (a plain ``.zip``); lower numbers run first. ``describe`` feeds the
    "unrecognised source" error message.
    """

    source_type: SourceType
    priority: int
    matches: Callable[[Path], bool]
    prepare: Callable[..., PreparedSource]
    describe: str


# ── Quick archive fingerprint ──────────────────────────────────────────────────

def quick_fingerprint(path: Path) -> str:
    """Cheap tamper-evident fingerprint: ``sha256(head ‖ size ‖ tail)``.

    HOW: hash the first 64 KiB, then the decimal file size, then the last 64 KiB
    (skipped when the file fits in the head window, so bytes are never counted
    twice). WHY this shape: it is cheap enough to recompute before *and* after a
    long run, yet a zip's central directory lives in the tail and the embedded
    size catches truncation — so realistic modifications are detected without
    re-reading a multi-gigabyte archive end to end.
    """
    size = path.stat().st_size
    h = hashlib.sha256()
    with path.open("rb") as fh:
        head = fh.read(_FINGERPRINT_WINDOW)
        h.update(head)
        h.update(str(size).encode("ascii"))
        if size > _FINGERPRINT_WINDOW:
            tail_start = max(size - _FINGERPRINT_WINDOW, len(head))
            fh.seek(tail_start)
            h.update(fh.read(_FINGERPRINT_WINDOW))
    return h.hexdigest()


# ── Safe extraction helpers ─────────────────────────────────────────────────────

def safe_target(root: Path, rel: PurePosixPath) -> Path:
    """Resolve *rel* under *root*, refusing paths that escape it.

    WHY: archives are untrusted forensic input; a crafted ``../`` entry (zip-slip
    / tar-slip) could otherwise write outside the work dir.
    """
    root_resolved = root.resolve()
    dest = (root_resolved / rel).resolve()
    if not dest.is_relative_to(root_resolved):
        raise SourceError(f"Unsafe archive entry escapes work root: {rel}")
    return dest


def make_work_root(
    name: str, work_dir: Path | None, *, reset: bool = False
) -> tuple[Path, tempfile.TemporaryDirectory | None]:
    """Return (root, tempdir-handle). With *work_dir* the root is kept; else temp.

    *name* is the stem of the kept ``<name>.logarchive`` directory — derived from
    the evidence so a retained --work-dir is self-describing.

    A kept root that already holds files is **refused** unless *reset* is set, in
    which case it is deleted and recreated — see :func:`claim_work_root` for why.
    The temp path is always a fresh directory, so it is never affected.
    """
    if work_dir is not None:
        work_dir = Path(work_dir)
        work_dir.mkdir(parents=True, exist_ok=True)
        root = work_dir / f"{name}.logarchive"
        claim_work_root(root, reset=reset)
        return root, None
    tmp = tempfile.TemporaryDirectory(prefix="faul_source_")
    return Path(tmp.name), tmp


def claim_work_root(root: Path, *, reset: bool) -> None:
    """Take exclusive ownership of *root*, creating it empty.

    WHY this guard exists — it prevents silent evidence cross-contamination.
    Source preparation materialises the evidence into this directory and then
    hashes and parses **everything under it**. A root left behind by an earlier
    run therefore contributes its files to the next acquisition: they are hashed
    into ``content_sha256``, registered in ``source_files``, and their log entries
    are parsed into the case. Nothing downstream can tell them apart from the
    evidence actually being examined.

    That is not a hypothetical collision. The root is named after the source's
    stem, so two sysdiagnose archives from two different devices that happen to
    share a filename (``sysdiagnose_2026-08-01.tar.gz`` is not a distinctive
    name) map to the same root — and the loose-dirs handler uses a *fixed* name,
    so every loose-dirs run sharing a work dir collides regardless of source.

    So a non-empty root is refused by default. *reset* deletes it first, which is
    the deliberate "I know, start clean" path. Note it removes only the
    ``<name>.logarchive`` root FAUL created, never the operator's *work_dir*
    itself — the analyst may keep other things beside it.

    Raises:
        SourceError: *root* exists with content and *reset* is false, or *root*
            exists but is not a directory.
    """
    if root.exists() and not root.is_dir():
        raise SourceError(
            f"Work root path exists but is not a directory: {root}. "
            "Point --work-dir somewhere else."
        )
    if root.is_dir() and any(root.iterdir()):
        if not reset:
            entries = sum(1 for _ in root.rglob("*"))
            raise SourceError(
                f"Work root already exists and is not empty: {root} "
                f"({entries} entr{'y' if entries == 1 else 'ies'}). Re-using it "
                "would hash and parse those files as part of THIS acquisition — "
                "evidence from a previous run would silently enter this case. "
                "Point --work-dir at an empty directory, or pass "
                "--reset-work-dir to delete this root first."
            )
        log.warning(
            f"--reset-work-dir: deleting the existing work root {root} before "
            "extraction (its previous contents are NOT part of this acquisition)"
        )
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)


def mirror_tree(
    src_dir: Path, dest_root: Path, *, cancel: CancelToken = NEVER_CANCELLED
) -> tuple[int, int]:
    """Recreate *src_dir*'s tree under *dest_root*, hard-linking each regular file.

    Returns ``(files, copied)`` — the total files materialised and how many of them
    had to fall back to a byte copy. WHY hard links (not symlinks, not a copy):
      - zero-copy — a hard link is a second name for the same on-disk data, so
        multi-gigabyte ``tracev3`` files are not duplicated;
      - indistinguishable from a regular file — unlike a symlink, the link reports
        ``is_symlink() == False`` and ``is_file() == True``, so the forensic hasher
        (which deliberately skips symlinks) still hashes it and ``source_files`` is
        populated, and a later ``rglob`` (whose follow-symlinked-*directory*
        behaviour differs across Python 3.11–3.14) is never in play.
    The originals are only ever read. Hard links are unavailable on some
    filesystems (exFAT, certain network shares) and never span volumes, so when
    ``os.link`` fails the file is **copied** instead — same result, just more disk
    and time. If the copy also fails the error is re-raised with the path and the
    reason so the caller can surface a clear message. Source symlinks are skipped —
    a logarchive holds only regular files, and following one could pull in data
    from outside the evidence.
    """
    files = copied = 0
    src_dir = src_dir.resolve()
    # followlinks defaults False: never descend a symlinked directory.
    for dirpath, _dirnames, filenames in os.walk(src_dir):
        rel_dir = Path(dirpath).relative_to(src_dir)
        for filename in filenames:
            cancel.check()
            src_file = Path(dirpath) / filename
            if src_file.is_symlink():
                continue
            dest = dest_root / rel_dir / filename
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.link(src_file, dest)
            except OSError:
                # No hard-link support / cross-volume → copy the bytes instead.
                try:
                    shutil.copyfile(src_file, dest)
                except OSError as exc:
                    raise OSError(
                        f"Could not materialise {src_file} into the work dir "
                        f"{dest_root} — hard link and copy both failed: {exc}"
                    ) from exc
                copied += 1
            files += 1
    return files, copied


# ── iOS-version / Info.plist helpers (stdlib plistlib, no dependencies) ──────────

def product_version(data: bytes) -> str | None:
    """Return ``ProductVersion`` (e.g. "17.5.1") from a SystemVersion.plist blob."""
    try:
        parsed = plistlib.loads(data)
    except Exception as exc:  # noqa: BLE001 — a bad/foreign plist must not fail extraction
        log.debug("SystemVersion.plist parse failed: %s", exc)
        return None
    value = parsed.get("ProductVersion") if isinstance(parsed, dict) else None
    return str(value) if value else None


def read_info_plist(root: Path) -> dict | None:
    """Parse ``<root>/Info.plist`` (logarchive metadata), or None if absent/bad."""
    info_path = root / "Info.plist"
    if not info_path.is_file():
        return None
    try:
        parsed = plistlib.loads(info_path.read_bytes())
        return parsed if isinstance(parsed, dict) else None
    except Exception as exc:  # noqa: BLE001
        log.debug("Info.plist parse failed: %s", exc)
        return None


def archive_identifier(info: dict | None) -> str | None:
    """Pull the logarchive ArchiveIdentifier from a parsed Info.plist (provenance)."""
    if not info:
        return None
    value = info.get("ArchiveIdentifier")
    return str(value) if value else None


# ── Integrity-mode helpers ──────────────────────────────────────────────────────

def check_integrity_mode(integrity: str) -> None:
    # WHY a hard error: a typo like integrity="none" silently behaving as some
    # default would either waste minutes of hashing or, worse, skip an
    # attestation the operator believed they had taken.
    if integrity not in INTEGRITY_MODES:
        raise SourceError(
            f"invalid integrity mode {integrity!r}; expected one of {INTEGRITY_MODES}"
        )


def hash_for_mode(
    root: Path, integrity: str, *, cancel: CancelToken = NEVER_CANCELLED
) -> tuple[str | None, dict[str, str]]:
    """Content hash + per-file hashes for *root*, honouring the integrity mode.

    "full" runs :func:`hash_logarchive`; the other modes return ``(None, {})`` so
    every downstream consumer records NULL hashes instead of a fabricated baseline.
    """
    if integrity == "full":
        return hash_logarchive(root, cancel=cancel)
    log.info(f"Integrity mode {integrity!r}: per-file hashing skipped — no chain-of-custody attestation")
    return None, {}


# ── Shared archive-preparation flow ─────────────────────────────────────────────

def prepare_archive(
    path: Path,
    source_type: SourceType,
    extract: Callable[[Path, Path, CancelToken], ExtractOutcome | str | None],
    *,
    work_dir: Path | None,
    integrity: str,
    reset_work_dir: bool = False,
    cancel: CancelToken = NEVER_CANCELLED,
) -> PreparedSource:
    """The common single-file-archive path: snapshot → extract → hash → assemble.

    Captures the quick archive fingerprint (unless ``integrity="off"``), allocates
    a kept/temp work root, runs the format-specific *extract* into it, hashes the
    result per the integrity mode, and assembles the :class:`PreparedSource`. The
    *extract* callable materialises the logarchive files under the given root and
    returns an :class:`ExtractOutcome` (or, for convenience, a bare product-version
    string / None). Shared by the sysdiagnose, FFS and ``.faul`` handlers.

    *cancel* is handed to *extract* (which checks it per archive member) and to
    the hashing pass. A cancellation propagates as ``OperationCancelled`` after
    the temp work root has been cleaned up, exactly as any other failure does —
    so an aborted preparation leaves nothing behind.
    """
    check_integrity_mode(integrity)
    fingerprint = quick_fingerprint(path) if integrity != "off" else None
    root, tmp = make_work_root(path.stem, work_dir, reset=reset_work_dir)
    try:
        outcome = extract(path, root, cancel)
        if not isinstance(outcome, ExtractOutcome):
            outcome = ExtractOutcome(product_version=outcome)
        content_sha256, file_hashes = hash_for_mode(root, integrity, cancel=cancel)
    except BaseException:
        # Don't leak a temp dir if extraction/hashing fails partway.
        if tmp is not None:
            tmp.cleanup()
        raise

    info = read_info_plist(root)  # present for sysdiagnose's logarchive; absent for FFS
    if outcome.product_version:
        log.info(f"iOS version (SystemVersion.plist) : {outcome.product_version}")
    return PreparedSource(
        source_type=source_type,
        original_path=path,
        logarchive_root=root,
        content_sha256=content_sha256,
        file_hashes=file_hashes,
        archive_fingerprint=fingerprint,
        ios_product_version=outcome.product_version,
        archive_identifier=archive_identifier(info),
        sidecar=outcome.sidecar,
        _tempdir=tmp,
    )
