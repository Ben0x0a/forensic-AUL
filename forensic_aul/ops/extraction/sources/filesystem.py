"""FILESYSTEM source — a full-file-system ``.zip``.

Detected by the zip magic (``PK\\x03\\x04``); the unified-log material under
``private/var/db/diagnostics/`` and ``private/var/db/uuidtext/`` (optionally
beneath a root folder such as ``filesystem1/``) is folded onto a logarchive root.
The iOS ``ProductVersion`` is read from ``System/Library/CoreServices/
SystemVersion.plist`` when present.

Because a ``.faul`` is *also* a zip, this handler is registered at a lower
priority than the ``.faul`` handler, which probes the zip's content first.
"""

from __future__ import annotations

import logging
import shutil
import stat
import zipfile
from pathlib import Path, PurePosixPath

from forensic_aul.errors import SourceError
from forensic_aul.ops.extraction.sources.base import (
    ExtractOutcome,
    PreparedSource,
    SourceHandler,
    SourceType,
    prepare_archive,
    product_version,
    safe_target,
)

log = logging.getLogger(__name__)

_ZIP_MAGIC = b"PK\x03\x04"

# Unified-log material lives under these two well-known paths.
_DIAGNOSTICS_MARKER = "private/var/db/diagnostics/"
_UUIDTEXT_MARKER = "private/var/db/uuidtext/"
_SYSVERSION_FFS = "system/library/coreservices/systemversion.plist"


def matches(path: Path) -> bool:
    if not path.is_file():
        return False
    with path.open("rb") as fh:
        return fh.read(len(_ZIP_MAGIC)) == _ZIP_MAGIC


# ── FFS path mapping (pure) ─────────────────────────────────────────────────────

def _ffs_match(name: str) -> tuple[str, PurePosixPath] | None:
    """Classify one FFS zip entry path.

    Returns ``(root_prefix, relpath)`` when *name* is a unified-log file under a
    diagnostics/ or uuidtext/ tree — where ``root_prefix`` is whatever precedes
    the marker (e.g. ``"filesystem1/"`` or ``""``) and ``relpath`` is the path
    relative to the logarchive root. Returns None for unrelated entries and for
    directory entries (paths ending in ``/``).
    """
    norm = name.replace("\\", "/")
    for marker in (_DIAGNOSTICS_MARKER, _UUIDTEXT_MARKER):
        idx = norm.find(marker)
        # Require the marker at the start or on a path boundary, so a file merely
        # *named* like the marker cannot be mistaken for the real directory.
        if idx != -1 and (idx == 0 or norm[idx - 1] == "/"):
            rest = norm[idx + len(marker):]
            if rest and not rest.endswith("/"):
                return norm[:idx], PurePosixPath(rest)
    return None


def ffs_target_relpath(name: str) -> PurePosixPath | None:
    """Logarchive-relative target path for an FFS entry, or None to skip it."""
    matched = _ffs_match(name)
    return matched[1] if matched else None


def _extract(archive: Path, root: Path) -> ExtractOutcome:
    """Extract diagnostics/ + uuidtext/ from an FFS zip into a logarchive *root*."""
    version: str | None = None
    with zipfile.ZipFile(archive) as zf:
        matched: list[tuple[zipfile.ZipInfo, str, PurePosixPath]] = []
        for info in zf.infolist():
            if info.is_dir():
                continue
            if version is None and info.filename.replace("\\", "/").lower().endswith(_SYSVERSION_FFS):
                version = product_version(zf.read(info))
                continue
            # Skip symlink entries (unix mode in the high 16 bits of external_attr).
            mode = info.external_attr >> 16
            if mode and stat.S_ISLNK(mode):
                continue
            m = _ffs_match(info.filename)
            if m is None:
                continue
            prefix, rel = m
            matched.append((info, prefix, rel))

        if not matched:
            raise SourceError(
                f"FFS zip has no {_DIAGNOSTICS_MARKER} / {_UUIDTEXT_MARKER} content: {archive}"
            )

        # Pick the root folder that actually holds diagnostics; if several do
        # (multiple filesystemN roots), warn and use the first deterministically.
        diag_prefixes = sorted(
            {p for (info, p, _rel) in matched if _DIAGNOSTICS_MARKER in info.filename.replace("\\", "/")}
        )
        chosen = diag_prefixes[0] if diag_prefixes else sorted({p for (_i, p, _r) in matched})[0]
        if len(diag_prefixes) > 1:
            log.warning(f'FFS: multiple root folders contain diagnostics {diag_prefixes} — using {chosen or "(archive root)"!r}')

        n = 0
        for info, prefix, rel in matched:
            if prefix != chosen:
                continue
            dest = safe_target(root, rel)
            dest.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, dest.open("wb") as out:
                shutil.copyfileobj(src, out)
            n += 1
    log.info(f'FFS: extracted {n} file(s) from root {chosen or "(archive root)"!r}')
    return ExtractOutcome(product_version=version)


def prepare(
    path: Path,
    *,
    work_dir: Path | None = None,
    integrity: str = "full",
    reset_work_dir: bool = False,
) -> PreparedSource:
    return prepare_archive(
        Path(path), SourceType.FILESYSTEM, _extract,
        work_dir=work_dir, integrity=integrity, reset_work_dir=reset_work_dir,
    )


HANDLER = SourceHandler(
    source_type=SourceType.FILESYSTEM,
    priority=40,
    matches=matches,
    prepare=prepare,
    describe="a full-file-system .zip",
)
