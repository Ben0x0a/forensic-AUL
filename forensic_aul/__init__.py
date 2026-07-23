"""forensic_aul — Forensic Apple Unified Log parser (iOS/macOS).

Defines : the public API of the installable core library. Other code (the CLI in
          launcher/, the GUI in gui/, or third-party callers) imports the
          operations from here, e.g. ``from forensic_aul import run_extract``.
Used by : launcher/* (CLI), gui/* (GUI controllers), and external consumers.
Uses    : the package's own submodules (extraction, annotation, identify, export,
          acquisition, database, models). Re-exported here so callers depend on a
          stable surface rather than internal module paths.
"""

from __future__ import annotations

__version__ = "0.1.0"

# ── Public API ────────────────────────────────────────────────────────────────
# Common exception hierarchy: every purposeful library error derives from
# ForensicAULError (operation-specific errors like AcquisitionError and
# KnowledgeBaseError included), so `except ForensicAULError` catches them all.
from forensic_aul.errors import ForensicAULError, InvalidDatabaseError, SourceError

# Core pipeline
from forensic_aul.ops.extraction.extract import open_or_extract, run_extract

# Annotation engine (load a knowledge base + annotate an extracted database)
from forensic_aul.ops.knowledge_base.loader import KnowledgeBaseError, load_kb
from forensic_aul.ops.annotation.matcher import annotate_connection, annotate_database

# Action attribution (baseline vs action diff, plus the full interactive workflow)
from forensic_aul.ops.identify.diff import run_diff
from forensic_aul.ops.identify.results import IdentifyResults, ResultCounts
from forensic_aul.ops.identify.workflow import run_identify_workflow

# Filtered export to CSV / JSON / JSONL (knowledge-base aware)
from forensic_aul.ops.export.exporter import ExportFilters, run_export

# In-memory query API — same filter vocabulary as export, but yielding rows.
# LogRow / v_logs (see engine/database/schema.py) are the stable read contract.
# count_logs/fetch_logs page for table UIs; fetch_context gives the rows around
# a line on the forensic timeline (event_order).
from forensic_aul.ops.query import (
    LogFilters,
    LogRow,
    LogStore,
    count_logs,
    fetch_context,
    fetch_logs,
    query_logs,
)

# Read-only analysis helpers (summary view + chain-of-custody verification)
from forensic_aul.ops.summary.summary import Summary, summarise
from forensic_aul.ops.verify.verify import VerifyResult, verify_database

# Device acquisition (collect a .logarchive over USB; optional pymobiledevice3)
from forensic_aul.ops.acquisition.acquire import (
    AcquisitionAborted,
    AcquisitionError,
    acquire,
)
from forensic_aul.ops.acquisition.device import DeviceInfo

# Forensic hashing / chain of custody
from forensic_aul.engine.integrity import compute_sha256, hash_logarchive

# Progress reporting: the sink protocol + ready-made sinks, so callers can type
# and build progress consumers without importing internal module paths.
from forensic_aul.engine.utils.progress import (
    ProgressEvent,
    ProgressSink,
    callback_progress_sink,
    logging_progress_sink,
    tty_bar_sink,
)

# Input-source preparation (logarchive dir / sysdiagnose .tar.gz / FFS .zip).
# The loose-dirs case goes through prepare_source / run_extract with the
# {"diagnostics": …, "uuidtext": …} mapping — no separate entry point needed.
from forensic_aul.ops.extraction.source import (
    INTEGRITY_MODES,
    PreparedSource,
    SourceType,
    find_loose_dirs,
    prepare_source,
)

# Core row model (useful for callers that type-hint or post-process log rows)
from forensic_aul.engine.models import LogEntry

# Return-value containers for the top-level operations
from forensic_aul.outcomes import (
    AcquireResult,
    AnnotateResult,
    DiffResult,
    ExportResult,
    ExtractResult,
    IdentifyResult,
)

__all__ = [
    "__version__",
    "ForensicAULError",
    "SourceError",
    "InvalidDatabaseError",
    "run_extract",
    "open_or_extract",
    "load_kb",
    "KnowledgeBaseError",
    "annotate_database",
    "annotate_connection",
    "run_diff",
    "run_identify_workflow",
    "IdentifyResult",
    "IdentifyResults",
    "ResultCounts",
    "run_export",
    "ExportFilters",
    "query_logs",
    "count_logs",
    "fetch_logs",
    "fetch_context",
    "LogFilters",
    "LogRow",
    "LogStore",
    "summarise",
    "Summary",
    "verify_database",
    "VerifyResult",
    "compute_sha256",
    "hash_logarchive",
    "ProgressEvent",
    "ProgressSink",
    "callback_progress_sink",
    "logging_progress_sink",
    "tty_bar_sink",
    "prepare_source",
    "find_loose_dirs",
    "PreparedSource",
    "SourceType",
    "INTEGRITY_MODES",
    "LogEntry",
    "ExtractResult",
    "DiffResult",
    "ExportResult",
    "AnnotateResult",
    "acquire",
    "AcquireResult",
    "AcquisitionError",
    "AcquisitionAborted",
    "DeviceInfo",
]
