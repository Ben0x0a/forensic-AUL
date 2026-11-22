"""LOGARCHIVE source — a ``.logarchive`` directory used in place.

The simplest handler: a directory that *looks like* a logarchive (see
``_LOGARCHIVE_MARKERS``) is parsed where it sits (no copy). Hashing honours the
integrity mode; there is no archive to fingerprint.
"""

from __future__ import annotations

from pathlib import Path

from forensic_aul.engine.utils.cancellation import NEVER_CANCELLED, CancelToken
from forensic_aul.ops.extraction.sources.base import (
    PreparedSource,
    SourceHandler,
    SourceType,
    archive_identifier,
    check_integrity_mode,
    hash_for_mode,
    read_info_plist,
)


# Top-level entries of which at least one is present in every logarchive layout
# (log collect, pymobiledevice3, sysdiagnose, a diagnostics/ folder): the archive
# manifest, the timesync store, the tracev3 stores, or the live buffer.
# Consumed by: matches.
_LOGARCHIVE_MARKERS: tuple[str, ...] = (
    "Info.plist", "timesync", "Persist", "Special", "Signpost", "HighVolume",
    "logdata.LiveData.tracev3",
)


def matches(path: Path) -> bool:
    """A directory holding at least one logarchive structure (used as-is).

    WHY content, not "any directory": a wrong folder would otherwise be accepted,
    parsed to zero entries and recorded as a logarchive in the case metadata.
    """
    return path.is_dir() and any((path / name).exists() for name in _LOGARCHIVE_MARKERS)


def prepare(
    path: Path,
    *,
    work_dir: Path | None = None,
    integrity: str = "full",
    reset_work_dir: bool = False,
    cancel: CancelToken = NEVER_CANCELLED,
) -> PreparedSource:
    """Use *path* in place as a logarchive; hash it per the integrity mode.

    *work_dir* / *reset_work_dir* are accepted for signature parity with the other
    handlers and ignored: nothing is materialised, so there is no work root to
    allocate or contaminate. Hashing is the only long step here, and it honours
    *cancel* per file.
    """
    check_integrity_mode(integrity)
    path = Path(path)
    content_sha256, file_hashes = hash_for_mode(path, integrity, cancel=cancel)
    info = read_info_plist(path)
    return PreparedSource(
        source_type=SourceType.LOGARCHIVE,
        original_path=path,
        logarchive_root=path,
        content_sha256=content_sha256,
        file_hashes=file_hashes,
        archive_fingerprint=None,
        ios_product_version=None,   # a bare logarchive carries only the build code
        archive_identifier=archive_identifier(info),
    )


HANDLER = SourceHandler(
    source_type=SourceType.LOGARCHIVE,
    priority=10,
    matches=matches,
    prepare=prepare,
    describe="a .logarchive directory",
)
