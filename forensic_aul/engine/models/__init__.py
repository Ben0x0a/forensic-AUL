"""Data models for Apple Unified Log structures.

Split by domain for readability — ``chunks`` (header/catalog/process),
``firehose`` (per-entry structures + Oversize), ``strings`` (UUIDText/DSC
tables), ``timesync`` (anchors + resolution) and ``log_entry`` (the assembled
DB row). Every name is re-exported here, so callers import from the package
root regardless of which submodule defines a model:

    from forensic_aul.engine.models import Firehose, LogEntry, TimesyncBoot

All structures mirror the Rust macos-unifiedlogs library (Mandiant)
field-for-field to maximise traceability between implementations.
"""

from __future__ import annotations

from forensic_aul.engine.models.chunks import (
    CatalogChunk,
    CatalogSubchunk,
    ChunkPreamble,
    HeaderChunk,
    ProcessInfoEntry,
    ProcessInfoSubsystem,
    ProcessUUIDEntry,
)
from forensic_aul.engine.models.dumps import SimpleDump, Statedump
from forensic_aul.engine.models.firehose import (
    Firehose,
    FirehoseActivity,
    FirehoseFormatters,
    FirehoseItemData,
    FirehoseItemInfo,
    FirehoseLoss,
    FirehoseNonActivity,
    FirehosePreamble,
    FirehoseSignpost,
    FirehoseTrace,
    Oversize,
)
from forensic_aul.engine.models.log_entry import LogEntry, MessageData
from forensic_aul.engine.models.strings import (
    RangeDescriptor,
    SharedCacheStrings,
    UUIDDescriptor,
    UUIDText,
    UUIDTextEntry,
)
from forensic_aul.engine.models.timesync import (
    TimestampResolution,
    TimesyncAnchor,
    TimesyncBoot,
    TimesyncEntry,
)

__all__ = [
    "CatalogChunk",
    "CatalogSubchunk",
    "ChunkPreamble",
    "HeaderChunk",
    "ProcessInfoEntry",
    "ProcessInfoSubsystem",
    "ProcessUUIDEntry",
    "Firehose",
    "FirehoseActivity",
    "FirehoseFormatters",
    "FirehoseItemData",
    "FirehoseItemInfo",
    "FirehoseLoss",
    "FirehoseNonActivity",
    "FirehosePreamble",
    "FirehoseSignpost",
    "FirehoseTrace",
    "Oversize",
    "SimpleDump",
    "Statedump",
    "LogEntry",
    "MessageData",
    "RangeDescriptor",
    "SharedCacheStrings",
    "UUIDDescriptor",
    "UUIDText",
    "UUIDTextEntry",
    "TimestampResolution",
    "TimesyncAnchor",
    "TimesyncBoot",
    "TimesyncEntry",
]
