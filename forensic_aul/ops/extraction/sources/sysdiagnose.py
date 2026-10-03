"""SYSDIAGNOSE source — a ``.tar.gz`` carrying ``system_logs.logarchive/``.

Detected by the gzip magic (``1f 8b``); the self-contained logarchive under the
tarball's wrapper folder is extracted into a work root. The iOS ``ProductVersion``
is captured opportunistically from ``logs/SystemVersion/SystemVersion.plist``.
"""

from __future__ import annotations

import logging
import shutil
import tarfile
from pathlib import Path, PurePosixPath

from forensic_aul.engine.utils.cancellation import NEVER_CANCELLED, CancelToken
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

_GZIP_MAGIC = b"\x1f\x8b"

# The self-contained logarchive sits under a wrapper folder named after the
# tarball; we key off the well-known directory name, not the wrapper.
_LOGARCHIVE_MARKER = "system_logs.logarchive/"
# SystemVersion.plist lives outside the logarchive tree (sysdiagnose logs/).
_SYSVERSION_SD = "systemversion/systemversion.plist"


def matches(path: Path) -> bool:
    if not path.is_file():
        return False
    with path.open("rb") as fh:
        return fh.read(len(_GZIP_MAGIC)) == _GZIP_MAGIC


def _extract(archive: Path, root: Path, cancel: CancelToken) -> ExtractOutcome:
    """Extract ``system_logs.logarchive/`` from a sysdiagnose tarball into *root*.

    The marker prefix (wrapper folder + ``system_logs.logarchive/``) is stripped
    so *root* itself becomes the logarchive. Captures the iOS ``ProductVersion``
    during the same pass when a ``SystemVersion.plist`` is present. *cancel* is
    checked per archive member — the finest granularity available in a
    single-pass streaming read of a gzip tarball.
    """
    n = 0
    version: str | None = None
    with tarfile.open(archive, "r:gz") as tf:
        for member in tf:
            cancel.check()
            norm = member.name.replace("\\", "/")
            if version is None and member.isfile() and norm.lower().endswith(_SYSVERSION_SD):
                src = tf.extractfile(member)
                if src is not None:
                    with src:
                        version = product_version(src.read())
                continue
            idx = norm.find(_LOGARCHIVE_MARKER)
            if idx == -1:
                continue
            # Skip links: only regular files belong in a logarchive, and links
            # could point outside the work root.
            if member.issym() or member.islnk():
                continue
            rest = norm[idx + len(_LOGARCHIVE_MARKER):]
            if not rest or rest.endswith("/") or not member.isfile():
                continue
            dest = safe_target(root, PurePosixPath(rest))
            dest.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                continue
            with src, dest.open("wb") as out:
                shutil.copyfileobj(src, out)
            n += 1
    if n == 0:
        raise SourceError(
            f"Sysdiagnose archive has no {_LOGARCHIVE_MARKER} content: {archive}"
        )
    log.info(f"Sysdiagnose: extracted {n} logarchive file(s)")
    return ExtractOutcome(product_version=version)


def prepare(
    path: Path,
    *,
    work_dir: Path | None = None,
    integrity: str = "full",
    reset_work_dir: bool = False,
    cancel: CancelToken = NEVER_CANCELLED,
) -> PreparedSource:
    return prepare_archive(
        Path(path), SourceType.SYSDIAGNOSE, _extract,
        work_dir=work_dir, integrity=integrity, reset_work_dir=reset_work_dir,
        cancel=cancel,
    )


HANDLER = SourceHandler(
    source_type=SourceType.SYSDIAGNOSE,
    priority=20,
    matches=matches,
    prepare=prepare,
    describe="a sysdiagnose .tar.gz",
)
