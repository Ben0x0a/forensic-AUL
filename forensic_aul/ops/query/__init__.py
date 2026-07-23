"""Query subsystem — in-memory reads over an analysis database.

Defines : the public read API — ``query_logs`` (streamed filtered rows),
          ``LogStore`` (a held-open read store for paging table UIs),
          ``count_logs`` / ``fetch_logs`` (one-shot exact paging),
          ``fetch_context`` (rows around a line on the forensic timeline) —
          plus the shared vocabulary (``LogFilters``) and row model
          (``LogRow``). The implementation lives in query.py (entry points)
          and reader.py (filters → SQL → streamed rows, also consumed by the
          exporter); this package module only re-exports, matching the other
          ops packages (see ops/export/__init__.py).
Used by : forensic_aul/__init__.py (top-level re-export) and the GUI/launcher.
Uses    : forensic_aul.ops.query.query / .reader.
"""

from forensic_aul.ops.query.query import (
    LogStore,
    count_logs,
    fetch_context,
    fetch_logs,
    query_logs,
)
from forensic_aul.ops.query.reader import LogFilters, LogRow

__all__ = [
    "LogFilters", "LogRow", "LogStore", "query_logs",
    "count_logs", "fetch_logs", "fetch_context",
]
