"""Compute a high-level summary of an analysis database.

Defines : the *data* behind the ``summary`` command — ``summarise`` runs the
          read-only queries (counts, top-N, annotation rollup, temporal
          histogram) and returns a structured :class:`Summary`. No printing /
          formatting lives here; the CLI handler (launcher/cmds/summary_cmd.py)
          and the GUI render the returned object however they like.
Used by : launcher/cmds/summary_cmd.py, forensic_aul.__init__ (public API).
Uses    : the standard library only (sqlite3).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from forensic_aul.engine.database.access import open_analysis_database


@dataclass(frozen=True)
class TopEntry:
    name: str | None
    count: int


@dataclass(frozen=True)
class AnnotatedAction:
    signature_id: str
    action: str
    count: int


@dataclass(frozen=True)
class HistogramBucket:
    start_unix_ns: int
    total: int
    annotated: int


@dataclass
class Summary:
    """Everything the ``summary`` view needs, already computed."""

    case_number: str | None
    imei: str | None
    ios_model: str | None
    ios_build_version: str | None
    ios_version: str | None
    log_start_time: str | None
    log_end_time: str | None

    total_entries: int
    range_min_ns: int | None
    range_max_ns: int | None
    range_seconds: float

    has_kb: bool
    annotated_count: int
    signature_count: int
    kb_versions: list[str] = field(default_factory=list)

    top_processes: list[TopEntry] = field(default_factory=list)
    top_subsystems: list[TopEntry] = field(default_factory=list)
    log_levels: list[TopEntry] = field(default_factory=list)
    annotated_actions: list[AnnotatedAction] = field(default_factory=list)

    histogram_bucket_ns: int = 0
    histogram: list[HistogramBucket] = field(default_factory=list)


# "Nice" histogram bucket sizes (seconds) — the smallest that is ≥ the requested
# span/buckets, so axis labels land on round durations.
_NICE_BUCKET_SECONDS = [
    1, 2, 5, 10, 15, 30,
    60, 120, 300, 600, 900, 1_800,
    3_600, 7_200, 21_600, 43_200,
    86_400, 172_800, 604_800,
]


def _round_bucket_ns(approx_ns: float) -> int:
    """Round *approx_ns* up to the next nice bucket size (in nanoseconds)."""
    approx_s = approx_ns / 1e9
    for s in _NICE_BUCKET_SECONDS:
        if s >= approx_s:
            return int(s * 1e9)
    return int(_NICE_BUCKET_SECONDS[-1] * 1e9)


def summarise(database: Path | str, *, top: int = 10, buckets: int = 40) -> Summary:
    """Compute a :class:`Summary` of the extract database at *database*.

    Raises:
        FileNotFoundError: *database* does not exist.
        InvalidDatabaseError: *database* is not an analysis database.
        ValueError: the database has no ``case_metadata`` row (not an extract DB).
    """
    conn = open_analysis_database(database)
    try:
        return _summarise(conn, top=top, buckets=buckets)
    finally:
        conn.close()


def _summarise(conn: sqlite3.Connection, *, top: int, buckets: int) -> Summary:
    md = conn.execute("""
        SELECT case_number, imei, ios_model, ios_build_version, ios_version,
               log_start_time, log_end_time
        FROM case_metadata ORDER BY id DESC LIMIT 1
    """).fetchone()
    if md is None:
        raise ValueError("case_metadata empty — not an extract database?")
    (case_number, imei, ios_model, ios_build, ios_version,
     t_start, t_end) = md

    total = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]

    has_kb = _has_table(conn, "log_annotations") and _has_table(conn, "kb_signatures")
    annotated_count = signature_count = 0
    kb_versions: list[str] = []
    if has_kb:
        annotated_count = conn.execute(
            "SELECT COUNT(DISTINCT log_id) FROM log_annotations").fetchone()[0]
        signature_count = conn.execute(
            "SELECT COUNT(*) FROM kb_signatures").fetchone()[0]
        kb_versions = [r[0] for r in conn.execute(
            "SELECT DISTINCT kb_version FROM kb_signatures")]

    base = Summary(
        case_number=case_number, imei=imei, ios_model=ios_model,
        ios_build_version=ios_build, ios_version=ios_version,
        log_start_time=t_start, log_end_time=t_end,
        total_entries=total, range_min_ns=None, range_max_ns=None,
        range_seconds=0.0, has_kb=has_kb, annotated_count=annotated_count,
        signature_count=signature_count, kb_versions=kb_versions,
    )
    if total == 0:
        return base

    # Exclude the unix_ns=0 failure sentinel from the range — otherwise one
    # unresolved entry pins range_min at 1970-01-01. Sentinel rows stay counted
    # in ``total``; they are only dropped from the wall-clock span.
    range_min, range_max = conn.execute(
        "SELECT MIN(timestamp_unix_ns), MAX(timestamp_unix_ns) FROM logs "
        "WHERE timestamp_unix_ns > 0").fetchone()
    if range_min is None:
        # Every entry was unresolved — no usable wall-clock span.
        return base
    base.range_min_ns = range_min
    base.range_max_ns = range_max
    base.range_seconds = (range_max - range_min) / 1_000_000_000

    base.top_processes = _top(conn, top,
        "SELECT p.name, COUNT(*) c FROM logs l JOIN processes p ON p.id=l.process_id "
        "GROUP BY p.id ORDER BY c DESC LIMIT ?")
    base.top_subsystems = _top(conn, top,
        "SELECT s.name, COUNT(*) c FROM logs l JOIN subsystems s ON s.id=l.subsystem_id "
        "GROUP BY s.id ORDER BY c DESC LIMIT ?")
    base.log_levels = _top(conn, 5,
        "SELECT ll.name, COUNT(*) c FROM logs l "
        "JOIN log_levels ll ON ll.id = l.log_level_id "
        "GROUP BY ll.id ORDER BY c DESC LIMIT ?")

    if has_kb and annotated_count:
        base.annotated_actions = [
            AnnotatedAction(sig_id, action, c)
            for sig_id, action, c in conn.execute("""
                SELECT kbs.signature_id, kbs.action, COUNT(*) c
                FROM log_annotations la
                JOIN kb_signatures kbs ON kbs.id = la.kb_signature_id
                GROUP BY kbs.signature_id, kbs.action
                ORDER BY c DESC LIMIT ?
            """, (top,)).fetchall()
        ]

    base.histogram_bucket_ns, base.histogram = _histogram(
        conn, range_min, range_max, buckets, has_kb=has_kb)
    return base


def _histogram(
    conn: sqlite3.Connection,
    range_min_ns: int,
    range_max_ns: int,
    target_buckets: int,
    *,
    has_kb: bool,
) -> tuple[int, list[HistogramBucket]]:
    span_ns = max(range_max_ns - range_min_ns, 1)
    bucket_ns = _round_bucket_ns(span_ns / max(target_buckets, 1))
    n_buckets = max(int(span_ns // bucket_ns) + 1, 1)

    # ``timestamp_unix_ns > 0`` drops the failure sentinel so it does not fall in
    # a spurious negative bucket below range_min.
    totals = {int(b): c for b, c in conn.execute(
        "SELECT (timestamp_unix_ns - ?) / ? AS b, COUNT(*) FROM logs "
        "WHERE timestamp_unix_ns > 0 GROUP BY b ORDER BY b",
        (range_min_ns, bucket_ns)).fetchall()}

    annot: dict[int, int] = {}
    if has_kb:
        annot = {int(b): c for b, c in conn.execute(
            "SELECT (l.timestamp_unix_ns - ?) / ? AS b, COUNT(DISTINCT la.log_id) "
            "FROM logs l JOIN log_annotations la ON la.log_id = l.id "
            "WHERE l.timestamp_unix_ns > 0 GROUP BY b ORDER BY b",
            (range_min_ns, bucket_ns)).fetchall()}

    hist = [
        HistogramBucket(
            start_unix_ns=range_min_ns + b * bucket_ns,
            total=totals.get(b, 0),
            annotated=annot.get(b, 0),
        )
        for b in range(n_buckets)
    ]
    return bucket_ns, hist


def _has_table(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def _top(conn: sqlite3.Connection, n: int, sql: str) -> list[TopEntry]:
    return [TopEntry(name, count) for name, count in conn.execute(sql, (n,)).fetchall()]
