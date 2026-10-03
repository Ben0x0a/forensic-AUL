"""LOOSE_DIRS source — two already-uncompressed unified-log folders.

Given explicitly (not detected) as the mapping ``{"diagnostics": dir,
"uuidtext": dir}`` — the same two folders an FFS zip carries, but loose on disk.
Merged (by hard link where possible, else a byte copy) into one logarchive root.
There is no single archive to attest, so ``archive_fingerprint`` is None.

Also provides :func:`find_loose_dirs`, which locates the two folders under an
extracted full file system and returns the mapping ``prepare_source`` expects.
"""

from __future__ import annotations

import logging
from pathlib import Path

from forensic_aul.engine.utils.cancellation import NEVER_CANCELLED, CancelToken
from forensic_aul.errors import SourceError
from forensic_aul.ops.extraction.sources.base import (
    LOOSE_DIAGNOSTICS_KEY,
    LOOSE_UUIDTEXT_KEY,
    PreparedSource,
    SourceType,
    archive_identifier,
    check_integrity_mode,
    hash_for_mode,
    make_work_root,
    mirror_tree,
    read_info_plist,
)

log = logging.getLogger(__name__)


def prepare_loose_dirs(
    diagnostics: Path,
    uuidtext: Path,
    *,
    work_dir: Path | None = None,
    reset_work_dir: bool = False,
    integrity: str = "full",
    cancel: CancelToken = NEVER_CANCELLED,
) -> PreparedSource:
    """Normalise two already-uncompressed folders into a logarchive layout.

    *diagnostics* is the on-device ``private/var/db/diagnostics/`` folder
    (Persist/Special/Signpost/HighVolume/ + timesync) and *uuidtext* is
    ``private/var/db/uuidtext/`` (the 2-char dirs + dsc/). Their contents are
    merged (by hard link where possible — zero-copy — falling back to a byte
    **copy** on filesystems that do not support hard links, e.g. exFAT or some
    network shares, or when the work dir is on a different volume; see
    :func:`mirror_tree`) into one logarchive root in *work_dir* (kept) or an
    auto-cleaned temp dir. The originals are only ever read.

    Raises:
        SourceError: either path is not a directory, together they hold no files,
            or *integrity* is not a valid mode.
    """
    check_integrity_mode(integrity)
    diagnostics = Path(diagnostics)
    uuidtext = Path(uuidtext)
    for label, d in ((LOOSE_DIAGNOSTICS_KEY, diagnostics), (LOOSE_UUIDTEXT_KEY, uuidtext)):
        if not d.is_dir():
            raise SourceError(f"Loose-dirs {label} source is not a directory: {d}")

    # NOTE the fixed name: unlike the archive handlers, every loose-dirs run
    # maps to the SAME root inside a given --work-dir, so the emptiness guard
    # in claim_work_root is the only thing standing between two runs.
    root, tmp = make_work_root("EXTRACTION_LOOSE", work_dir, reset=reset_work_dir)
    try:
        files_d, copied_d = mirror_tree(diagnostics, root, cancel=cancel)
        files_u, copied_u = mirror_tree(uuidtext, root, cancel=cancel)
        n, copied = files_d + files_u, copied_d + copied_u
        if n == 0:
            raise SourceError(
                f"Loose-dirs source has no files: {diagnostics} / {uuidtext}"
            )
        if copied:
            log.warning(f"Loose dirs: hard links unavailable — copied {copied} of {n} file(s) into the work root instead (extra disk used; result is identical). To enable zero-copy, point --work-dir at the same filesystem as the source folders.")
        else:
            log.info(f"Loose dirs: hard-linked {n} file(s) into a logarchive root (zero-copy)")
        content_sha256, file_hashes = hash_for_mode(root, integrity, cancel=cancel)
    except BaseException:
        # Don't leak a temp dir if mirroring/hashing fails partway.
        if tmp is not None:
            tmp.cleanup()
        raise

    info = read_info_plist(root)  # normally absent for loose dirs; harmless if present
    return PreparedSource(
        source_type=SourceType.LOOSE_DIRS,
        original_path=diagnostics,
        logarchive_root=root,
        content_sha256=content_sha256,
        file_hashes=file_hashes,
        archive_fingerprint=None,
        ios_product_version=None,   # SystemVersion.plist lives outside these two folders
        archive_identifier=archive_identifier(info),
        _tempdir=tmp,
    )


def find_loose_dirs(fs_root: Path | str) -> dict[str, Path] | None:
    """Locate the unified-log folders under an extracted full file system.

    Searches *fs_root* for ``private/var/db/diagnostics`` and
    ``private/var/db/uuidtext`` (at the root or under one intermediate folder such
    as ``filesystem1/``) and returns the mapping ``prepare_source`` expects::

        dirs = find_loose_dirs("/evidence/ffs_extracted")
        if dirs:
            run_extract(dirs, Path("case.db"), ...)

    Returns None when no diagnostics folder is found, or when ``uuidtext`` is
    missing (both folders are required downstream). When several roots contain
    diagnostics the lexically first is chosen and a warning is logged.
    """
    root = Path(fs_root)
    if not root.is_dir():
        return None

    # The two well-known tails, checked at the root and one level down. rglob is
    # deliberately NOT used: an FFS tree holds millions of files and the folders
    # only ever sit at these two depths.
    candidates: list[Path] = []
    for base in [root, *sorted(p for p in root.iterdir() if p.is_dir())]:
        if (base / "private/var/db/diagnostics").is_dir():
            candidates.append(base)
    if not candidates:
        return None
    if len(candidates) > 1:
        log.warning(f'find_loose_dirs: multiple roots contain diagnostics {[str(c) for c in candidates]} — using {candidates[0]}')

    base = candidates[0]
    diagnostics = base / "private/var/db/diagnostics"
    uuidtext = base / "private/var/db/uuidtext"
    if not uuidtext.is_dir():
        log.warning(f"find_loose_dirs: {diagnostics} found but {uuidtext} is missing — both folders are required")
        return None
    return {LOOSE_DIAGNOSTICS_KEY: diagnostics, LOOSE_UUIDTEXT_KEY: uuidtext}
