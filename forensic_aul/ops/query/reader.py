"""Shared read layer over an analysis database (filters → streamed log rows).

Defines : the reusable read machinery consumed by every row-level reader —
          ``LogFilters`` (the filter vocabulary), ``LogRow`` (one log entry with
          its annotations rolled up), ``build_where`` / ``resolve_time_bounds``
          (filters → SQL), ``has_kb_tables`` / ``has_fts_index`` /
          ``fts_match_query`` (capability probes + safe FTS query building),
          and ``iter_logs`` (the streaming join). The public
          ``query_logs`` entry point lives in ``forensic_aul/ops/query/__init__.py``;
          the file exporter (``ops/export/exporter.py``) consumes the same
          machinery so a filter behaves identically in both.
Used by : forensic_aul/ops/query/__init__.py (query_logs) and
          forensic_aul/ops/export/exporter.py (run_export).
Uses    : the standard library only (sqlite3, datetime), plus
          forensic_aul.engine.utils.time for timestamp formatting/parsing.

Filter semantics: list fields are OR-combined within a field and AND-combined
across fields. Annotation-based filters are expressed via EXISTS subqueries so a
matching log still exposes ALL its annotations in the output, not only the one
that triggered the filter.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterator

from forensic_aul.engine.utils.time import iso8601_from_unix_ns, parse_duration_seconds

# ── Filters ───────────────────────────────────────────────────────────────────

@dataclass
class LogFilters:
    """Row filters shared by ``query_logs`` and ``run_export``.

    Independent of argparse so the read logic can be driven programmatically
    (GUI, scripts, tests) as well as from the CLI. List fields are OR-combined
    within a field and AND-combined across fields.
    """

    time_from: str | None = None        # ISO 8601 lower bound (inclusive)
    time_to: str | None = None          # ISO 8601 upper bound (exclusive)
    last: str | None = None             # shortcut for time_from = now - DURATION (10m/1h/24h/7d)
    process: list[str] | None = None
    subsystem: list[str] | None = None
    # Resolved through categories.id, exactly like process/subsystem, and
    # index-assisted by idx_logs_category_id.
    category: list[str] | None = None
    level: list[str] | None = None
    like: str | None = None             # SQL LIKE pattern on the message column
    # Prefix match on the *composed* message — the right filter for dynamic
    # messages (format_str_id IS NULL) and generic %{public}s templates, whose
    # format string carries no usable content. %/_ in the prefix are escaped, so
    # unlike ``like`` the value is taken literally, not as a pattern.
    message_prefix: str | None = None
    # Literal substring match on the composed message (%/_ escaped, like
    # message_prefix but matching anywhere).
    message_contains: str | None = None
    # Keyword search on the composed message via the FTS5 index (logs_fts).
    # The value is free text: whitespace-separated terms are AND-combined, each
    # matched as a literal phrase (FTS query syntax in the value is inert).
    # Requires a usable full-text index — see has_fts_index; build_where raises
    # ValueError when the database has none.
    message_match: str | None = None
    # Exact match on the invariant format-string template (resolved to
    # format_strs.id — same pattern as process/subsystem).
    format_str: str | None = None
    signature: list[str] | None = None
    action: str | None = None           # case-insensitive substring of the annotation action
    tag: list[str] | None = None
    annotated_only: bool = False


# ── Filter construction ──────────────────────────────────────────────────────

def has_kb_tables(conn: sqlite3.Connection) -> bool:
    """True when the knowledge-base annotation tables exist in this database."""
    rows = conn.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type='table' AND name IN ('log_annotations', 'kb_signatures')"
    ).fetchall()
    return len(rows) == 2


def has_fts_index(conn: sqlite3.Connection) -> bool:
    """True when this database carries a *usable* full-text index over messages.

    Usable means the ``logs_fts`` virtual table exists AND is populated (or the
    ``logs`` table itself is empty). An extract interrupted before the deferred
    FTS finaliser leaves ``logs_fts`` empty while ``logs`` has rows — searching
    it would silently miss everything, so such an index is reported absent.
    """
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='logs_fts'"
    ).fetchone()
    if row is None:
        return False
    try:
        # Population is probed through the docsize shadow table (one row per
        # indexed document): logs_fts is an external-content table, so a plain
        # scan of it enumerates the CONTENT rows and reports an emptied index
        # as populated.
        fts_any = conn.execute("SELECT 1 FROM logs_fts_docsize LIMIT 1").fetchone()
    except sqlite3.Error:
        # A virtual table whose module is unavailable (SQLite built without
        # FTS5) or a corrupt/absent shadow table — either way, not usable.
        return False
    if fts_any is not None:
        return True
    logs_any = conn.execute("SELECT 1 FROM logs LIMIT 1").fetchone()
    return logs_any is None


def fts_match_query(text: str) -> str | None:
    """Turn free search text into a safe FTS5 MATCH expression, or None.

    Each whitespace-separated term becomes a double-quoted FTS string (matched
    as a phrase of its tokens), AND-combined. Quoting neutralises FTS query
    syntax (OR/NEAR/NOT, column filters, ``*``), so user input cannot change
    the query shape. Terms with no alphanumeric character tokenise to nothing
    (an FTS syntax error), so they are dropped; None means "no usable terms"
    and callers must treat it as no filter.
    """
    quoted = [
        '"' + term.replace('"', '""') + '"'
        for term in text.split()
        if any(c.isalnum() for c in term)
    ]
    return " ".join(quoted) if quoted else None


def resolve_time_bounds(f: LogFilters) -> tuple[int | None, int | None]:
    """Resolve the time filters to (from_ns, to_ns) unix-nanosecond bounds.

    ``last`` is folded into the lower bound (the tighter of the two wins).

    Raises:
        ValueError: a datetime or duration value cannot be parsed.
    """
    time_from_ns = _to_unix_ns(f.time_from) if f.time_from else None
    time_to_ns = _to_unix_ns(f.time_to) if f.time_to else None
    if f.last is not None:
        sec = parse_duration_seconds(f.last)
        if sec is None:
            raise ValueError(f"bad duration value {f.last!r}")
        cutoff = int((datetime.now(tz=timezone.utc) - timedelta(seconds=sec)).timestamp() * 1_000_000_000)
        time_from_ns = cutoff if time_from_ns is None else max(time_from_ns, cutoff)
    return time_from_ns, time_to_ns


def build_where(
    conn: sqlite3.Connection,
    f: LogFilters,
    time_from_ns: int | None,
    time_to_ns: int | None,
) -> tuple[str, list]:
    """Build the WHERE clause that restricts which `logs.id` to read.

    Annotation-based filters are expressed via EXISTS subqueries so that
    matching logs still expose ALL their annotations in the output (not
    only the one that triggered the filter).

    Raises:
        ValueError: ``message_match`` is set but the database carries no
            usable full-text index (see :func:`has_fts_index`).
    """
    clauses: list[str] = []
    params: list = []

    # Time filters exclude the unix_ns=0 failure sentinel: an unresolved row
    # cannot be proven to fall in the requested window. A ``>= positive`` bound
    # already drops 0; a to-only bound needs the explicit guard. With no time
    # bound at all, sentinel rows are included (nothing to prove them out of).
    if time_from_ns is not None:
        clauses.append("l.timestamp_unix_ns >= ?"); params.append(time_from_ns)
    if time_to_ns is not None:
        clauses.append("l.timestamp_unix_ns <  ?"); params.append(time_to_ns)
        if time_from_ns is None:
            clauses.append("l.timestamp_unix_ns > 0")

    if f.process:
        ids = _lookup_ids(conn, "processes", f.process)
        clauses.append(_in_clause("l.process_id", ids))
        params.extend(ids)
    if f.subsystem:
        ids = _lookup_ids(conn, "subsystems", f.subsystem)
        clauses.append(_in_clause("l.subsystem_id", ids))
        params.extend(ids)
    if f.category:
        ids = _lookup_ids(conn, "categories", f.category)
        clauses.append(_in_clause("l.category_id", ids))
        params.extend(ids)
    if f.level:
        # log_level is normalised: resolve the requested names to log_levels.id and
        # filter on the FK (same pattern as process/subsystem above).
        ids = _lookup_ids(conn, "log_levels", f.level)
        clauses.append(_in_clause("l.log_level_id", ids))
        params.extend(ids)
    if f.format_str:
        ids = _lookup_ids(conn, "format_strs", [f.format_str], column="value")
        clauses.append(_in_clause("l.format_str_id", ids))
        params.extend(ids)
    if f.like:
        clauses.append("l.message LIKE ?"); params.append(f.like)
    if f.message_prefix:
        # Literal prefix: escape LIKE metacharacters so %/_ in the prefix match
        # themselves (unlike ``like``, which passes the pattern through raw).
        clauses.append(r"l.message LIKE ? ESCAPE '\'")
        params.append(_escape_like(f.message_prefix) + "%")
    if f.message_contains:
        # Literal substring: same escaping, wildcards on both sides. WHY a
        # dedicated filter instead of building a ``like`` pattern at the call
        # site: ``like`` has no ESCAPE clause, so caller-side escaping silently
        # never matches — the escaping and the ESCAPE declaration must live
        # together.
        clauses.append(r"l.message LIKE ? ESCAPE '\'")
        params.append("%" + _escape_like(f.message_contains) + "%")
    if f.message_match:
        # Keyword search through the FTS5 index — an index lookup, not a table
        # scan, which is what makes an interactive search box viable on
        # multi-million-row extracts. Refuse (rather than silently fall back to
        # a LIKE scan) when no usable index exists: the caller must know the
        # capability is absent, not get a freeze that looks like a hang.
        if not has_fts_index(conn):
            raise ValueError(
                "this database has no full-text index — keyword search needs "
                "an extract with FTS enabled"
            )
        match = fts_match_query(f.message_match)
        if match is not None:
            clauses.append(
                "l.id IN (SELECT rowid FROM logs_fts WHERE logs_fts MATCH ?)"
            )
            params.append(match)

    # Annotation filters
    annot_filters: list[str] = []
    annot_params: list = []
    if f.signature:
        ph = ",".join("?" * len(f.signature))
        annot_filters.append(f"kbs.signature_id IN ({ph})")
        annot_params.extend(f.signature)
    if f.action:
        annot_filters.append("LOWER(kbs.action) LIKE ?")
        annot_params.append(f"%{f.action.lower()}%")
    if f.tag:
        # tags column stores a JSON list. json_each lets us match any element.
        ph = ",".join("?" * len(f.tag))
        annot_filters.append(
            "EXISTS (SELECT 1 FROM json_each(kbs.tags) je WHERE je.value IN (" + ph + "))"
        )
        annot_params.extend(f.tag)

    if f.annotated_only or annot_filters:
        cond = " AND ".join(annot_filters) if annot_filters else "1=1"
        clauses.append(f"""
            EXISTS (
                SELECT 1
                FROM log_annotations la
                JOIN kb_signatures kbs ON kbs.id = la.kb_signature_id
                WHERE la.log_id = l.id AND {cond}
            )
        """)
        params.extend(annot_params)

    where = (" AND ".join(clauses)) if clauses else "1=1"
    return where, params


def _escape_like(value: str) -> str:
    r"""Escape LIKE metacharacters (\, %, _) for use with ``ESCAPE '\'``."""
    return value.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")


def _lookup_ids(
    conn: sqlite3.Connection,
    table: str,
    names: list[str],
    column: str = "name",
) -> list[int]:
    out: list[int] = []
    for n in names:
        row = conn.execute(f"SELECT id FROM {table} WHERE {column} = ?", (n,)).fetchone()
        if row is not None:
            out.append(row[0])
    if not out:
        # Force a no-match. -1 is never an inserted id (PK starts at 1).
        return [-1]
    return out


def _in_clause(col: str, ids: list[int]) -> str:
    return f"{col} IN ({','.join('?' * len(ids))})"


# ── Streaming logs+annotations ────────────────────────────────────────────────

# The per-log SELECT columns (shared by both query shapes below). The KB shape
# appends the trailing annotation trio; _N_LOG_COLS names the boundary so the
# accumulation code cannot silently break when a column is added.
# ``source_order`` + ``source_file`` are appended at the end (additive, so the
# leading columns keep their positions): source_order is the physical rank
# WITHIN its tracev3 file, and source_file names that file, so together they
# answer "where in which file did this row physically sit" — the other half
# of the ordering evidence alongside event_order (the merged real timeline).
_LOG_COLS = (
    "l.id", "l.timestamp_unix_ns", "l.event_order",
    "p.name", "l.pid", "l.tid",
    "ll.name", "et.name", "s.name", "c.name", "l.message",
    "fs.value",
    "l.source_order", "sf.file_path",
)
_N_LOG_COLS = len(_LOG_COLS)
# Trailing annotation trio = (kbs.signature_id, ev.label, ev.value).
_COL_SIG_ID = _N_LOG_COLS
_COL_LABEL = _N_LOG_COLS + 1
_COL_VALUE = _N_LOG_COLS + 2

_LOG_JOINS = """
    FROM logs l
    LEFT JOIN processes    p  ON p.id  = l.process_id
    LEFT JOIN subsystems   s  ON s.id  = l.subsystem_id
    LEFT JOIN categories   c  ON c.id  = l.category_id
    LEFT JOIN log_levels   ll ON ll.id = l.log_level_id
    LEFT JOIN event_types  et ON et.id = l.event_type_id
    LEFT JOIN format_strs  fs ON fs.id = l.format_str_id
    LEFT JOIN source_files sf ON sf.id = l.tracev3_file_id
"""


class LogRow:
    """One log entry with its matched signatures and extracted values rolled up.

    The read model handed to consumers of :func:`iter_logs` /
    ``forensic_aul.query_logs``. The streaming join yields one SQL row per
    (annotation × extracted value), so a single log spans several adjacent rows
    that are accumulated here: distinct signature ids, and distinct values per
    label (joined with "; " when a label legitimately holds several values
    across annotations).

    ``source_order`` (physical rank within ``source_file``) plus ``source_file``
    (the tracev3 file's path, from ``source_files.file_path``) locate a row's
    exact position in the raw acquisition, complementing ``event_order`` (the
    merged real timeline across all files) — together they are the ordering
    evidence the tamper signal relies on. Either is ``None`` when the ordering
    pass never ran or the source file's provenance was not resolved.
    """

    __slots__ = (
        "log_id", "timestamp_unix_ns", "event_order",
        "process", "pid", "tid",
        "log_level", "event_type", "subsystem", "category", "message",
        "format_string",
        "source_order", "source_file",
        "signature_ids", "_values_by_label",
    )

    def __init__(self, row: tuple) -> None:
        (self.log_id, self.timestamp_unix_ns, self.event_order,
         self.process, self.pid, self.tid,
         self.log_level, self.event_type, self.subsystem, self.category,
         self.message, self.format_string,
         self.source_order, self.source_file) = row[:_N_LOG_COLS]
        self.signature_ids: list[str] = []
        self._values_by_label: dict[str, list[str]] = {}
        self.absorb(row[_COL_SIG_ID], row[_COL_LABEL], row[_COL_VALUE])

    @property
    def timestamp_iso(self) -> str:
        """ISO 8601 (ns-precise) timestamp, formatted from the stored unix_ns.

        The ISO string is not persisted on ``logs`` (see schema.py); it is
        formatted on read so consumers keep a human-readable ``timestamp``.
        A failed resolution is stored as the sentinel ``unix_ns == 0``; emit an
        empty string for it rather than a misleading 1970-01-01 date.
        """
        if self.timestamp_unix_ns == 0:
            return ""
        return iso8601_from_unix_ns(self.timestamp_unix_ns)

    def absorb(self, sig_id: str | None, label: str | None, value: str | None) -> None:
        if sig_id and sig_id not in self.signature_ids:
            self.signature_ids.append(sig_id)
        if label is not None and value is not None:
            vals = self._values_by_label.setdefault(label, [])
            if value not in vals:
                vals.append(value)

    def value_for(self, label: str) -> str:
        """Cell value for *label* — distinct values joined, or empty string."""
        vals = self._values_by_label.get(label)
        return "; ".join(vals) if vals else ""

    def values_dict(self) -> dict[str, str]:
        """Mapping of label → joined value (only labels present on this log)."""
        return {label: "; ".join(vals) for label, vals in self._values_by_label.items()}


def iter_logs(
    conn: sqlite3.Connection,
    where: str,
    params: list,
    *,
    has_kb: bool,
    limit: int | None = None,
) -> Iterator[LogRow]:
    """Stream logs joined with annotations + extracted values, collapsing duplicates.

    With KB tables present the LEFT JOINs produce one row per
    (log × annotation × extracted value); we order by (timestamp, log_id) so all
    rows for a log land contiguously and are accumulated in Python. *limit*
    bounds the number of **logs** yielded (not joined SQL rows).
    """
    cols = ", ".join(_LOG_COLS)
    if has_kb:
        sql = f"""
            SELECT {cols}, kbs.signature_id, ev.label, ev.value
            {_LOG_JOINS}
            LEFT JOIN log_annotations  la  ON la.log_id = l.id
            LEFT JOIN kb_signatures    kbs ON kbs.id = la.kb_signature_id
            LEFT JOIN extracted_values ev  ON ev.log_annotation_id = la.id
            WHERE {where}
            ORDER BY l.timestamp_unix_ns ASC, l.id ASC, kbs.signature_id ASC
        """
    else:
        sql = f"""
            SELECT {cols}, NULL, NULL, NULL
            {_LOG_JOINS}
            WHERE {where}
            ORDER BY l.timestamp_unix_ns ASC, l.id ASC
        """
    cur = conn.execute(sql, params)
    yielded = 0
    pending: LogRow | None = None
    for row in cur:
        if limit is not None and yielded >= limit:
            return
        log_id = row[0]
        if pending is None:
            pending = LogRow(row)
            continue
        if log_id == pending.log_id:
            pending.absorb(row[_COL_SIG_ID], row[_COL_LABEL], row[_COL_VALUE])
            continue
        yield pending
        yielded += 1
        pending = LogRow(row)
    if pending is not None and (limit is None or yielded < limit):
        yield pending


def count_rows(conn: sqlite3.Connection, where: str, params: list) -> int:
    """Total logs matching *where* — the paging counterpart of :func:`fetch_page`.

    The WHERE clause only references ``l`` columns and EXISTS subqueries (see
    :func:`build_where`), so no lookup JOINs are needed for counting.
    """
    return conn.execute(
        f"SELECT COUNT(*) FROM logs l WHERE {where}", params
    ).fetchone()[0]


def fetch_page(
    conn: sqlite3.Connection,
    where: str,
    params: list,
    *,
    has_kb: bool,
    offset: int,
    limit: int,
) -> list[LogRow]:
    """One page of logs (offset/limit in LOGS, not joined rows), annotations rolled up.

    WHY an id-subquery instead of LIMIT/OFFSET on the joined query: with KB
    tables the LEFT JOINs yield one row per (log × annotation × value), so a
    row-level LIMIT would cut a log's annotations in half and make page sizes
    unpredictable. Paging the ids first keeps pages exact and the rollup whole.
    """
    page_where = f"""l.id IN (
        SELECT l.id FROM logs l WHERE {where}
        ORDER BY l.timestamp_unix_ns ASC, l.id ASC LIMIT ? OFFSET ?
    )"""
    return list(iter_logs(conn, page_where, [*params, limit, offset], has_kb=has_kb))


def fetch_event_window(
    conn: sqlite3.Connection,
    eo_low: int,
    eo_high: int,
    *,
    has_kb: bool,
) -> list[LogRow]:
    """Rows whose ``event_order`` lies in [eo_low, eo_high], in event order.

    Used for the "context around a line" view: event_order is the deterministic
    forensic timeline (never wall-clock, which can be shifted), so neighbours by
    event_order show what actually surrounded the entry.
    """
    rows = list(iter_logs(
        conn, "l.event_order BETWEEN ? AND ?", [eo_low, eo_high], has_kb=has_kb,
    ))
    # iter_logs orders by (timestamp, id) for rollup contiguity; the context
    # view wants the forensic sequence, so re-sort the small window here.
    rows.sort(key=lambda r: r.event_order if r.event_order is not None else 0)
    return rows


def discover_labels(
    conn: sqlite3.Connection,
    where: str,
    params: list,
) -> list[str]:
    """Return the sorted distinct extracted-value labels among matching logs.

    Used by tabular consumers (CSV export) that need the universe of labels up
    front to emit one column each. Sorted for a stable, reproducible order.
    """
    sql = f"""
        SELECT DISTINCT ev.label
        FROM logs l
        JOIN log_annotations la  ON la.log_id = l.id
        JOIN extracted_values ev ON ev.log_annotation_id = la.id
        WHERE {where}
        ORDER BY ev.label
    """
    return [row[0] for row in conn.execute(sql, params)]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _to_unix_ns(value: str) -> int:
    """Parse an ISO 8601 datetime to nanoseconds since epoch (UTC)."""
    # Strip a trailing Z that fromisoformat doesn't accept on older Pythons.
    v = value.rstrip("Z")
    try:
        dt = datetime.fromisoformat(v)
    except ValueError as exc:
        raise ValueError(f"cannot parse datetime {value!r}: {exc}") from None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1_000_000_000)
