"""Persist a computed :class:`Summary` inside the analysis database.

Defines : the ``summary_cache`` table plus ``store_summary`` /
          ``refresh_summary`` / ``load_summary`` / ``clear_summary`` — the
          statistics a database carries about itself.
Used by : forensic_aul.ops.extraction.extract (writes the cache as the final
          extract phase), forensic_aul.ops.annotation.matcher (refreshes it after
          annotations change), gui.views.screen_exploit (reads it).
Uses    : forensic_aul.ops.summary.summary (the Summary dataclasses it
          serialises), forensic_aul.engine.database.access, sqlite3, json.

WHY a cache table at all: :func:`~forensic_aul.ops.summary.summary.summarise`
makes six to seven full passes over ``logs`` (a COUNT, a MIN, a MAX, three
GROUP BY aggregations and a bucketed histogram). On a multi-million-row extract
that is tens of seconds — acceptable once, at the end of an extraction that
already took minutes, but not every time an analyst opens the database. So the
statistics are computed exactly once, by whoever last changed the data, and every
reader afterwards gets them for free.

WHY no fallback compute on the read path: a database extracted before this table
existed reports "not evaluated" (``load_summary`` returns ``None``) rather than
silently spending a minute recomputing. The absence is a fact about the database,
and the caller decides what to say about it.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from forensic_aul.engine.database.access import open_analysis_database
from forensic_aul.ops.summary.summary import (
    AnnotatedAction,
    HistogramBucket,
    Summary,
    TopEntry,
)

log = logging.getLogger(__name__)

__all__ = [
    "store_summary", "refresh_summary", "load_summary", "clear_summary",
    "init_summary_cache_schema",
]

# Single-row table: ``CHECK (id = 1)`` makes "there is at most one cached summary"
# a schema-level invariant, so a second write can only ever REPLACE the first —
# there is no way to end up with two disagreeing summaries in one database.
#
# Created with IF NOT EXISTS and probed at read time rather than versioned: this
# project has no migration hook (see engine/database/schema.py), so every optional
# table follows the same pattern as the annotation tables in ops/annotation/matcher.py.
_DDL = """
CREATE TABLE IF NOT EXISTS summary_cache (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    computed_at  TEXT NOT NULL,   -- ISO 8601 UTC
    faul_version TEXT NOT NULL,   -- the forensic-aul that computed it
    params       TEXT NOT NULL,   -- JSON: {"top": N, "buckets": N}
    payload      TEXT NOT NULL    -- JSON serialisation of Summary
);
"""


def init_summary_cache_schema(conn: sqlite3.Connection) -> None:
    """Create the ``summary_cache`` table if it is not already there."""
    with conn:
        conn.executescript(_DDL)


# ── Write ─────────────────────────────────────────────────────────────────────

def store_summary(
    conn: sqlite3.Connection, summary: Summary, *, top: int, buckets: int
) -> None:
    """Persist *summary* into *conn*'s ``summary_cache``, replacing any previous row.

    *top* and *buckets* are recorded alongside so a reader can tell which
    parameters produced the stored top-N lists and histogram resolution.
    """
    # Local import: forensic_aul/__init__.py imports this package, so a
    # module-level ``from forensic_aul import __version__`` would be circular.
    from forensic_aul import __version__

    payload = json.dumps(_summary_to_dict(summary), separators=(",", ":"))
    params = json.dumps({"top": top, "buckets": buckets}, separators=(",", ":"))
    computed_at = datetime.now(tz=timezone.utc).isoformat(timespec="seconds")
    init_summary_cache_schema(conn)
    with conn:
        conn.execute(
            "INSERT OR REPLACE INTO summary_cache "
            "(id, computed_at, faul_version, params, payload) VALUES (1, ?, ?, ?, ?)",
            (computed_at, __version__, params, payload),
        )


def refresh_summary(conn: sqlite3.Connection) -> bool:
    """Recompute the summary and store it; never raises. True when it succeeded.

    The one place the compute-then-store pair lives — extract calls it at the end
    of a run and annotate after changing the annotation counts. WHY it swallows
    failures: statistics are a convenience, and neither an extraction nor an
    annotation should be lost because summarising them went wrong. A failure
    clears the cache instead, so a stale summary is never presented as current.
    """
    # Local import: summary.py must not import this module at module scope
    # (cache.py already imports summary.py for the dataclasses).
    from forensic_aul.ops.summary.summary import (
        DEFAULT_BUCKETS,
        DEFAULT_TOP,
        summarise_connection,
    )

    try:
        summary = summarise_connection(conn, top=DEFAULT_TOP, buckets=DEFAULT_BUCKETS)
        store_summary(conn, summary, top=DEFAULT_TOP, buckets=DEFAULT_BUCKETS)
        return True
    except Exception as exc:  # noqa: BLE001 — see the docstring
        log.warning(f"Could not compute summary statistics: {exc}")
        clear_summary(conn)
        return False


def clear_summary(conn: sqlite3.Connection) -> None:
    """Drop the cached summary, so readers report "not evaluated" again.

    Used when the data changed but recomputing is not wanted here — a stale
    summary presented as current is worse than an absent one.
    """
    if not _has_cache_table(conn):
        return
    with conn:
        conn.execute("DELETE FROM summary_cache WHERE id = 1")


# ── Read ──────────────────────────────────────────────────────────────────────

def load_summary(database: Path | str | sqlite3.Connection) -> Summary | None:
    """Return the cached :class:`Summary`, or ``None`` when there is none.

    Accepts an open connection or a path (which is opened and closed here).
    Never computes and never writes: a database with no cache — extracted before
    the cache existed, or by a tool that does not write it — yields ``None``.

    Raises:
        FileNotFoundError: a path was given and does not exist.
        InvalidDatabaseError: the file is not an analysis database.
    """
    if isinstance(database, sqlite3.Connection):
        return _load(database)
    conn = open_analysis_database(database)
    try:
        return _load(conn)
    finally:
        conn.close()


def _load(conn: sqlite3.Connection) -> Summary | None:
    if not _has_cache_table(conn):
        return None
    row = conn.execute("SELECT payload FROM summary_cache WHERE id = 1").fetchone()
    if row is None:
        return None
    try:
        return _summary_from_dict(json.loads(row[0]))
    except (ValueError, TypeError, KeyError) as exc:
        # WHY tolerate a bad payload: the cache is a convenience, not evidence. A
        # payload written by an incompatible version must degrade to "not
        # evaluated", never stop the analyst opening the database.
        log.warning(f"Ignoring unreadable summary cache: {exc}")
        return None


def _has_cache_table(conn: sqlite3.Connection) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='summary_cache'"
    ).fetchone() is not None


# ── Serialisation ─────────────────────────────────────────────────────────────

def _summary_to_dict(s: Summary) -> dict:
    """Summary → JSON-ready dict (explicit, so the stored shape is reviewable)."""
    return {
        "case_number": s.case_number,
        "imei": s.imei,
        "ios_model": s.ios_model,
        "ios_build_version": s.ios_build_version,
        "ios_version": s.ios_version,
        "log_start_time": s.log_start_time,
        "log_end_time": s.log_end_time,
        "total_entries": s.total_entries,
        "range_min_ns": s.range_min_ns,
        "range_max_ns": s.range_max_ns,
        "range_seconds": s.range_seconds,
        "has_kb": s.has_kb,
        "annotated_count": s.annotated_count,
        "signature_count": s.signature_count,
        "kb_versions": list(s.kb_versions),
        "top_processes": _entries_to_list(s.top_processes),
        "top_subsystems": _entries_to_list(s.top_subsystems),
        "log_levels": _entries_to_list(s.log_levels),
        "facets": {k: _entries_to_list(v) for k, v in s.facets.items()},
        "annotated_actions": [
            [a.signature_id, a.action, a.count] for a in s.annotated_actions
        ],
        "histogram_bucket_ns": s.histogram_bucket_ns,
        # Positional triples rather than objects: the histogram is the bulkiest
        # part of the payload (one entry per bucket) and key names would repeat
        # on every one of them.
        "histogram": [[b.start_unix_ns, b.total, b.annotated] for b in s.histogram],
    }


def _summary_from_dict(d: dict) -> Summary:
    """JSON dict → Summary (the inverse of :func:`_summary_to_dict`)."""
    summary = Summary(
        case_number=d["case_number"],
        imei=d["imei"],
        ios_model=d["ios_model"],
        ios_build_version=d["ios_build_version"],
        ios_version=d["ios_version"],
        log_start_time=d["log_start_time"],
        log_end_time=d["log_end_time"],
        total_entries=d["total_entries"],
        range_min_ns=d["range_min_ns"],
        range_max_ns=d["range_max_ns"],
        range_seconds=d["range_seconds"],
        has_kb=d["has_kb"],
        annotated_count=d["annotated_count"],
        signature_count=d["signature_count"],
        kb_versions=list(d["kb_versions"]),
    )
    summary.top_processes = _entries_from_list(d["top_processes"])
    summary.top_subsystems = _entries_from_list(d["top_subsystems"])
    summary.log_levels = _entries_from_list(d["log_levels"])
    summary.facets = {
        key: _entries_from_list(value) for key, value in d.get("facets", {}).items()
    }
    summary.annotated_actions = [
        AnnotatedAction(sig_id, action, count)
        for sig_id, action, count in d["annotated_actions"]
    ]
    summary.histogram_bucket_ns = d["histogram_bucket_ns"]
    summary.histogram = [
        HistogramBucket(start, total, annotated)
        for start, total, annotated in d["histogram"]
    ]
    return summary


def _entries_to_list(entries: list[TopEntry]) -> list[list]:
    return [[e.name, e.count] for e in entries]


def _entries_from_list(raw: list[list]) -> list[TopEntry]:
    return [TopEntry(name, count) for name, count in raw]
