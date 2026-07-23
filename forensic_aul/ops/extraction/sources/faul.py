"""FAUL source — a ``.faul`` portable-evidence container.

A ``.faul`` is a stored zip bundling an acquired ``.logarchive`` with its
acquisition sidecar (see :mod:`forensic_aul.engine.faul_format`). It shares the
zip magic with a full-file-system ``.zip``, so this handler probes the zip's
*content* (the ``faul/manifest.json`` marker) and is registered ahead of the FFS
handler. Preparation extracts the logarchive tree into a work root and surfaces
the embedded sidecar on :class:`PreparedSource` for case-field auto-fill.
"""

from __future__ import annotations

import logging
from pathlib import Path

from forensic_aul.engine import faul_format
from forensic_aul.ops.extraction.sources.base import (
    ExtractOutcome,
    PreparedSource,
    SourceHandler,
    SourceType,
    prepare_archive,
)

log = logging.getLogger(__name__)


def matches(path: Path) -> bool:
    """A zip carrying the ``faul/manifest.json`` marker (content, not extension)."""
    return faul_format.is_faul(path)


def _extract(archive: Path, root: Path) -> ExtractOutcome:
    """Extract the bundled logarchive into *root*; surface the embedded sidecar.

    A ``.faul`` bundles a plain logarchive (no ``SystemVersion.plist``), so the
    iOS version is left unresolved here — extract falls back to the tracev3 build
    code exactly as it does for a bare ``.logarchive`` directory.
    """
    faul_format.extract_logarchive(archive, root)
    return ExtractOutcome(product_version=None, sidecar=faul_format.read_sidecar(archive))


def prepare(
    path: Path, *, work_dir: Path | None = None, integrity: str = "full"
) -> PreparedSource:
    return prepare_archive(
        Path(path), SourceType.FAUL, _extract,
        work_dir=work_dir, integrity=integrity,
    )


HANDLER = SourceHandler(
    source_type=SourceType.FAUL,
    priority=30,   # before FILESYSTEM (40): a .faul is a zip with a marker inside
    matches=matches,
    prepare=prepare,
    describe="a .faul portable container",
)
