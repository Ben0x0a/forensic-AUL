"""LOGARCHIVE source — a ``.logarchive`` directory used in place.

The simplest handler: any directory is a logarchive, parsed where it sits (no
copy). Hashing honours the integrity mode; there is no archive to fingerprint.
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


def matches(path: Path) -> bool:
    """A directory is always a logarchive (used as-is)."""
    return path.is_dir()


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
