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

    # Entries whose timestamp could not be resolved, persisted as the unix_ns=0
    # sentinel. They ARE counted in total_entries but are excluded from the
    # wall-clock range, the histogram and any time-filtered read (they cannot be
    # placed on a timeline), so without this number a reader cannot explain why
    # those figures disagree. Belongs conceptually beside range_seconds; it sits
    # here only because a defaulted field cannot precede a required one.
    unresolved_timestamps: int = 0

    top_processes: list[TopEntry] = field(default_factory=list)
    top_subsystems: list[TopEntry] = field(default_factory=list)
    log_levels: list[TopEntry] = field(default_factory=list)
    annotated_actions: list[AnnotatedAction] = field(default_factory=list)

    # Complete name→count breakdowns, keyed by facet name ("process",
    # "subsystem", "category", "level"), each ordered by descending count.
    # ``top_processes`` / ``top_subsystems`` / ``log_levels`` above are the
    # first *top* entries of the corresponding facet, kept as separate fields so
    # the CLI's summary output is unchanged. WHY the full lists too: they drive
    # the GUI's faceted filter pickers, which need every value and its count —
    # and the GROUP BY that produces the top-N already scans the whole table, so
    # dropping the LIMIT costs nothing beyond a slightly larger cached payload.
    facets: dict[str, list[TopEntry]] = field(default_factory=dict)

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


# There are only five log levels (schema.py::LOG_LEVEL_NAMES), so the "top" of
# that facet is all of it — the constant just keeps the slice self-explanatory.
_TOP_LOG_LEVELS = 5

# One un-LIMITed GROUP BY per facet, keyed by the name used in Summary.facets and
# by the GUI's filter pickers. INNER JOIN (not LEFT): a row whose process /
# subsystem / category is NULL has no name to filter on or display, and counting
# it under an empty label would invent a value the analyst cannot select.
# Consumed by: summarise_connection, and through Summary.facets by the GUI.
_FACET_SQL: dict[str, str] = {
    "process":
        "SELECT p.name, COUNT(*) c FROM logs l JOIN processes p ON p.id=l.process_id "
        "GROUP BY p.id ORDER BY c DESC",
    "subsystem":
        "SELECT s.name, COUNT(*) c FROM logs l JOIN subsystems s ON s.id=l.subsystem_id "
        "GROUP BY s.id ORDER BY c DESC",
    "category":
        "SELECT c2.name, COUNT(*) c FROM logs l JOIN categories c2 ON c2.id=l.category_id "
        "GROUP BY c2.id ORDER BY c DESC",
    "level":
        "SELECT ll.name, COUNT(*) c FROM logs l JOIN log_levels ll ON ll.id=l.log_level_id "
        "GROUP BY ll.id ORDER BY c DESC",
}


def _round_bucket_ns(approx_ns: float) -> int:
    """Round *approx_ns* up to the next nice bucket size (in nanoseconds)."""
    approx_s = approx_ns / 1e9
    for s in _NICE_BUCKET_SECONDS:
        if s >= approx_s:
            return int(s * 1e9)
    return int(_NICE_BUCKET_SECONDS[-1] * 1e9)


# Defaults for the top-N lists and the histogram resolution. Named so the extract
# -time cache write stores statistics computed with exactly the parameters every
# other caller assumes. Consumed by: summarise(), ops/extraction/extract.py,
# ops/annotation/matcher.py, launcher/cmds/summary_cmd.py.
DEFAULT_TOP = 10
DEFAULT_BUCKETS = 40


def summarise(
    database: Path | str, *, top: int = DEFAULT_TOP, buckets: int = DEFAULT_BUCKETS
) -> Summary:
    """Compute a :class:`Summary` of the extract database at *database*.

    Raises:
        FileNotFoundError: *database* does not exist.
        InvalidDatabaseError: *database* is not an analysis database.
        ValueError: the database has no ``case_metadata`` row (not an extract DB).
    """
    conn = open_analysis_database(database)
    try:
        return summarise_connection(conn, top=top, buckets=buckets)
    finally:
        conn.close()


def summarise_connection(conn: sqlite3.Connection, *, top: int, buckets: int) -> Summary:
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
    # Index-assisted equality probe on the indexed timestamp column.
    unresolved = conn.execute(
        "SELECT COUNT(*) FROM logs WHERE timestamp_unix_ns = 0"
    ).fetchone()[0]

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
        range_seconds=0.0, unresolved_timestamps=unresolved,
        has_kb=has_kb, annotated_count=annotated_count,
        signature_count=signature_count, kb_versions=kb_versions,
    )
    if total == 0:
        return base

    # Exclude the unix_ns=0 failure sentinel from the range — otherwise one
    # unresolved entry pins range_min at 1970-01-01. Sentinel rows stay counted
    # in ``total``; they are only dropped from the wall-clock span.
    #
    # WHY two statements rather than one ``SELECT MIN(...), MAX(...)``: SQLite's
    # min/max optimisation turns an aggregate over an indexed column into a
    # single index seek, but it applies to at most ONE aggregate per query — ask
    # for both together and it falls back to scanning the whole index. Two
    # queries are two O(log N) seeks; one query is O(N).
    range_min = conn.execute(
        "SELECT MIN(timestamp_unix_ns) FROM logs WHERE timestamp_unix_ns > 0"
    ).fetchone()[0]
    range_max = conn.execute(
        "SELECT MAX(timestamp_unix_ns) FROM logs WHERE timestamp_unix_ns > 0"
    ).fetchone()[0]
    if range_min is None:
        # Every entry was unresolved — no usable wall-clock span.
        return base
    base.range_min_ns = range_min
    base.range_max_ns = range_max
    base.range_seconds = (range_max - range_min) / 1_000_000_000

    # One GROUP BY per facet, un-LIMITed: the top-N lists are slices of these,
    # so the table is scanned once per facet rather than twice (see Summary.facets).
    base.facets = {
        name: _facet(conn, sql) for name, sql in _FACET_SQL.items()
    }
    base.top_processes = base.facets["process"][:top]
    base.top_subsystems = base.facets["subsystem"][:top]
    base.log_levels = base.facets["level"][:_TOP_LOG_LEVELS]

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


def _facet(conn: sqlite3.Connection, sql: str) -> list[TopEntry]:
    """Run one un-LIMITed facet GROUP BY, returning every (name, count) pair."""
    return [TopEntry(name, count) for name, count in conn.execute(sql).fetchall()]
