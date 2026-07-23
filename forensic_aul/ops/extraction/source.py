"""Backwards-compatibility shim for the input-source layer.

The source-preparation layer was split from a single module into the pluggable
:mod:`forensic_aul.ops.extraction.sources` package (one module per evidence
container, a registry-based detector, and the ``.faul`` handler). This shim
re-exports the public surface — and the handful of internal helpers older
importers reference — so existing imports of
``forensic_aul.ops.extraction.source`` keep working.

New code should import from :mod:`forensic_aul.ops.extraction.sources` directly.
"""

from __future__ import annotations

import os  # re-exported: some tests monkeypatch ``source.os.link`` to force copies

from forensic_aul.ops.extraction.sources import (
    INTEGRITY_MODES,
    LOOSE_DIAGNOSTICS_KEY,
    LOOSE_UUIDTEXT_KEY,
    TEMP_DIR_PLACEHOLDER,
    ExtractOutcome,
    PreparedSource,
    SourceHandler,
    SourceType,
    detect_source_type,
    find_loose_dirs,
    prepare_loose_dirs,
    prepare_source,
)
from forensic_aul.ops.extraction.sources.base import (
    quick_fingerprint as _quick_fingerprint,
)
from forensic_aul.ops.extraction.sources.filesystem import (
    ffs_target_relpath as _ffs_target_relpath,
)

__all__ = [
    "INTEGRITY_MODES",
    "LOOSE_DIAGNOSTICS_KEY",
    "LOOSE_UUIDTEXT_KEY",
    "TEMP_DIR_PLACEHOLDER",
    "ExtractOutcome",
    "PreparedSource",
    "SourceHandler",
    "SourceType",
    "detect_source_type",
    "find_loose_dirs",
    "prepare_loose_dirs",
    "prepare_source",
    "_quick_fingerprint",
    "_ffs_target_relpath",
]
