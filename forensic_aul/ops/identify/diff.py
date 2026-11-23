"""Diff logic for the ``identify`` subcommand.

Defines : ``run_diff`` (= ``classify_rows`` → the SQLite and CSV outputs) — given
          two extracted SQLite databases (baseline +
          post-action), produces an optional CSV of *retained* lines (entries
          attributable to the action) and a SQLite ``identified_logs`` table
          containing every entry from the action DB whose timestamp is after
          the baseline cutoff, with an ``excluded`` flag column and a
          ``matched_signatures`` column (populated when the action DB carries
          knowledge-base annotations). Also creates ``hidden_keys`` +
          ``v_identified_visible`` — a reversible, analyst-driven prune layer
          on top of the engine's mechanical ``excluded`` classification.
Used by : forensic_aul.ops.workflows.identify (run_identify_workflow),
          forensic_aul.ops.identify.results (IdentifyResults — reopens the
          same hidden_keys/view objects and the source_order/source_file
          backfill), launcher/cmds/identify_cmd.py.
Uses    : forensic_aul.engine.database.reader (has_kb_tables), forensic_aul.outcomes
          (DiffResult), forensic_aul.engine.utils.time (iso8601_from_unix_ns).

Noise definition and tiers
--------------------------
Only action rows newer than the baseline cutoff are considered (the cutoff is
``MAX(timestamp_unix_ns)`` of the baseline — the last line collected before the
operator performed the action). Each one gets a ``tier``:

  ``repeat``        its ``(message, process)`` already appears in the baseline —
                    background noise, ``excluded = 1``;
  ``new_values``    its ``(format string, process)`` appears in the baseline but
                    not with this message — a known event with new values;
  ``new_template``  neither — an event the baseline never produced: the
                    strongest sign the line belongs to the action.

Retained rows are ``new_values`` + ``new_template``. WHY tiers and not a
tighter key: a stricter "same template = noise" rule would drop the action's own
lines whose template also fires idly (a camera opened twice); a looser one keeps
70 % of lines (I2). Ranking keeps everything and says which lines to read first.

A *generic* format string — no literal text once its ``%`` specifiers are
removed, e.g. ``%{public}s`` — is not a template: two lines sharing it may have
nothing in common, so it never makes a row ``new_values``. Dynamic messages
(no format string) are compared by message only.

The classification is SQL over the action database with the baseline attached:
the baseline keys are copied into two indexed temporary tables, and every action
row is LEFT JOINed against them.

The CSV holds the retained rows only; the SQLite output holds every
post-cutoff row with its tier and ``excluded`` flag.
"""

from __future__ import annotations

import contextlib
import csv
import logging
import re
import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from forensic_aul.engine.utils.time import iso8601_from_unix_ns
from forensic_aul.engine.database.reader import has_kb_tables
from forensic_aul.outcomes import DiffResult

log = logging.getLogger(__name__)


# Columns selected per row, in display order. Joined against the lookup tables
# (processes, subsystems, categories, log_levels, event_types, source_files) for
# human readability. The ISO timestamp is not stored — it is formatted on read
# from timestamp_unix_ns (the first SELECT column), so it is omitted from the
# SQL. Rows newer than the cutoff OR with the unix_ns=0 failure sentinel: a
# sentinel row cannot be proven to predate the action, so it is surfaced
# (excluded=0) with a note rather than silently dropped. event_order and
# source_order (+ source_file, the tracev3 file it ranks within) are carried
# through so the tamper signal stays visible in the diff output too (L10):
# event_order shows the merged timeline stays monotonic while wall-clock moves
# backwards; source_order + source_file pin down exactly where in which file
# each entry physically sat.
#
# matched_signatures is a scalar subquery (not a JOIN) specifically to avoid row
# multiplication: a log matched by several signatures must still appear once —
# GROUP_CONCAT collapses them into one comma-joined cell. The {matched_signatures}
# placeholder is filled in by _build_csv_sql: only present when the action DB
# carries the KB annotation tables (has_kb_tables), otherwise it selects ''.
_CSV_SQL_TEMPLATE = """
SELECT
    l.timestamp_unix_ns   AS timestamp_unix_ns,
    o.event_order         AS event_order,
    o.source_order        AS source_order,
    sf.file_path          AS source_file,
    p.name                AS process,
    l.pid                 AS pid,
    l.tid                 AS tid,
    ll.name               AS log_level,
    et.name               AS event_type,
    s.name                AS subsystem,
    c.name                AS category,
    l.message             AS message,
    fs.value              AS format_string,
    {matched_signatures}  AS matched_signatures,
    CASE
        WHEN bm.message IS NOT NULL THEN 'repeat'
        WHEN bt.template IS NOT NULL THEN 'new_values'
        ELSE 'new_template'
    END                   AS tier
FROM logs l
LEFT JOIN logs_order   o  ON o.id  = l.id
LEFT JOIN processes    p  ON p.id  = l.process_id
LEFT JOIN subsystems   s  ON s.id  = l.subsystem_id
LEFT JOIN categories   c  ON c.id  = l.category_id
LEFT JOIN log_levels   ll ON ll.id = l.log_level_id
LEFT JOIN event_types  et ON et.id = l.event_type_id
LEFT JOIN source_files sf ON sf.id = l.tracev3_file_id
LEFT JOIN format_strs  fs ON fs.id = l.format_str_id
LEFT JOIN temp.base_messages  bm
       ON bm.message = l.message AND bm.process = COALESCE(p.name, '')
LEFT JOIN temp.base_templates bt
       ON bt.template = fs.value AND bt.process = COALESCE(p.name, '')
WHERE l.timestamp_unix_ns > ? OR l.timestamp_unix_ns = 0
ORDER BY l.timestamp_unix_ns ASC, l.id ASC
"""

# The baseline keys, copied from the attached baseline into indexed temporary
# tables so the classification above is two index lookups per row.
_BASELINE_KEY_SQL = (
    """CREATE TEMP TABLE base_messages AS
        SELECT DISTINCT bl.message AS message, COALESCE(bp.name, '') AS process
        FROM base.logs bl LEFT JOIN base.processes bp ON bp.id = bl.process_id
        WHERE bl.message IS NOT NULL""",
    "CREATE UNIQUE INDEX temp.base_messages_key ON base_messages(message, process)",
    """CREATE TEMP TABLE base_templates AS
        SELECT DISTINCT bf.value AS template, COALESCE(bp.name, '') AS process
        FROM base.logs bl
        JOIN base.format_strs bf ON bf.id = bl.format_str_id
        LEFT JOIN base.processes bp ON bp.id = bl.process_id
        WHERE faul_has_literal_text(bf.value)""",
    "CREATE UNIQUE INDEX temp.base_templates_key ON base_templates(template, process)",
)

# A printf / os_log conversion: %, optional {privacy,…} annotation, flags,
# width, precision, length modifier, conversion character (or %% / %@).
# Consumed by: has_literal_text.
_FORMAT_SPEC_RE = re.compile(r"%(?:\{[^}]*\})?[-+ #0'0-9.*]*(?:hh|h|ll|l|j|z|t|L|q)?[A-Za-z@%]")


def has_literal_text(template: str | None) -> bool:
    """True when *template* says something beyond its ``%`` specifiers."""
    if not template:
        return False
    return any(ch.isalnum() for ch in _FORMAT_SPEC_RE.sub("", template))

_MATCHED_SIGNATURES_SUBQUERY = """(
    SELECT GROUP_CONCAT(kbs.signature_id)
    FROM log_annotations la
    JOIN kb_signatures kbs ON kbs.id = la.kb_signature_id
    WHERE la.log_id = l.id
)"""


def _build_csv_sql(conn: sqlite3.Connection) -> str:
    """Fill in the matched_signatures column — subquery only when KB tables exist."""
    expr = _MATCHED_SIGNATURES_SUBQUERY if has_kb_tables(conn) else "''"
    return _CSV_SQL_TEMPLATE.format(matched_signatures=expr)


_CSV_HEADER = [
    "timestamp", "timestamp_unix_ns", "event_order", "source_order", "source_file",
    "process", "pid", "tid",
    "log_level", "event_type", "subsystem", "category", "message",
    "matched_signatures", "tier", "format_string", "note",
]

# The tier values, strongest signal first. Consumed by: classify_rows, run_diff,
# ops/identify/results.py, the frontends.
TIER_NEW_TEMPLATE = "new_template"
TIER_NEW_VALUES = "new_values"
TIER_REPEAT = "repeat"
# A row whose timestamp could not be resolved: kept (it cannot be proven to
# predate the action) but not compared — its own tier, so a retained row never
# reads "repeat" and the tier counts add up to the retained count.
TIER_UNRESOLVED = "unresolved"


def _baseline_cutoff_ns(baseline_db: Path) -> int:
    """Return the upper-bound timestamp of the baseline DB (nanoseconds).

    Excludes the unix_ns=0 failure sentinel so an all-unresolved baseline raises
    the no-entries error rather than yielding a cutoff of 0 (which would let
    every action row through).
    """
    # contextlib.closing, not the bare connection context manager: the latter
    # only manages the transaction and leaves the connection open until GC.
    with contextlib.closing(sqlite3.connect(str(baseline_db))) as conn:
        row = conn.execute(
            "SELECT MAX(timestamp_unix_ns) FROM logs WHERE timestamp_unix_ns > 0"
        ).fetchone()
    if row is None or row[0] is None:
        raise ValueError(f"baseline DB {baseline_db} contains no log entries")
    return int(row[0])


def run_diff(
    baseline_db: Path,
    action_db: Path,
    csv_out: Path | None,
    sqlite_out: Path,
) -> DiffResult:
    """Diff a post-action database against a baseline and write both outputs.

    Computes the baseline cutoff (``MAX(timestamp_unix_ns)`` over *baseline_db*),
    then streams every entry from *action_db* newer than the cutoff with its tier
    (``new_template`` / ``new_values`` / ``repeat``); ``repeat`` rows are the
    *excluded* baseline noise. See the module docstring for the definitions.

    Args:
        baseline_db: SQLite database extracted *before* the action was performed.
        action_db: SQLite database extracted *after* the action was performed.
        csv_out: Destination CSV — receives the retained rows only (UTF-8 with BOM
            so Excel auto-detects the encoding). Parent dirs are created. ``None``
            skips writing a CSV entirely; the retained/excluded counts are
            computed identically either way.
        sqlite_out: Destination SQLite — receives every post-cutoff row with an
            ``excluded`` flag column, so excluded lines remain re-inspectable. An
            existing file at this path is overwritten.

    Returns:
        A :class:`~forensic_aul.outcomes.DiffResult` with the two output paths and
        the ``retained`` / ``excluded`` counts (*retained* = rows in the CSV,
        *excluded* = rows flagged as baseline noise).

    Raises:
        ValueError: *baseline_db* contains no log entries (no cutoff derivable).
    """
    cutoff_ns = _baseline_cutoff_ns(baseline_db)
    log.info(f"Baseline cutoff (unix_ns): {cutoff_ns}")

    n_retained = n_excluded = n_unresolved = n_new_templates = n_new_values = 0
    with contextlib.ExitStack() as stack:
        db_out = stack.enter_context(_SqliteOut(sqlite_out))
        csv_writer = stack.enter_context(_CsvOut(csv_out)) if csv_out is not None else None
        for row in classify_rows(action_db, baseline_db, cutoff_ns):
            db_out.add(row)
            if row.excluded:
                n_excluded += 1
                continue
            n_retained += 1
            n_unresolved += row.timestamp_unix_ns == 0
            n_new_templates += row.tier == TIER_NEW_TEMPLATE
            n_new_values += row.tier == TIER_NEW_VALUES
            if csv_writer is not None:
                csv_writer.add(row)

    if n_unresolved:
        log.warning(f"Diff: {n_unresolved} action row(s) had an unresolved timestamp (timestamp_unix_ns=0) — kept as retained with excluded=0 and a note (cannot be proven pre-cutoff)")
    log.info(f"Diff complete: {n_retained} retained ({n_new_templates} new template, "
             f"{n_new_values} new values), {n_excluded} excluded")
    return DiffResult(
        csv_path=csv_out,
        sqlite_path=sqlite_out,
        retained=n_retained,
        excluded=n_excluded,
        new_templates=n_new_templates,
        new_values=n_new_values,
        unresolved=n_unresolved,
    )


# ── Compute ──────────────────────────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class DiffRow:
    """One action-database row after the cutoff, classified."""

    timestamp: str              # ISO 8601 UTC; "" when unresolved
    timestamp_unix_ns: int
    event_order: int | None
    source_order: int | None
    source_file: str | None
    process: str | None
    pid: int | None
    tid: int | None
    log_level: str | None
    event_type: str | None
    subsystem: str | None
    category: str | None
    message: str | None
    format_string: str | None   # the invariant template; None for a dynamic message
    matched_signatures: str
    tier: str                   # TIER_NEW_TEMPLATE / _NEW_VALUES / _REPEAT / _UNRESOLVED
    excluded: bool              # baseline noise: tier == repeat (see the module docstring)
    note: str


def classify_rows(action_db: Path, baseline_db: Path, cutoff_ns: int) -> Iterator[DiffRow]:
    """Stream every *action_db* row after *cutoff_ns* with its tier against
    *baseline_db*. Pure computation: both databases are only read (the baseline
    keys live in temporary tables of this connection)."""
    # Both read-only: they are this diff's inputs and must not change. The keys
    # go to the connection's TEMP schema, which stays writable.
    with contextlib.closing(sqlite3.connect(read_only_uri(action_db), uri=True)) as src:
        src.create_function("faul_has_literal_text", 1, has_literal_text, deterministic=True)
        src.execute("ATTACH DATABASE ? AS base", (read_only_uri(baseline_db),))
        for statement in _BASELINE_KEY_SQL:
            src.execute(statement)
        for row in src.execute(_build_csv_sql(src), (cutoff_ns,)):
            (ts_ns, event_order, source_order, source_file, proc, pid, tid,
             lvl, et, sub, cat, msg, fmt, matched_sigs, tier) = row
            if ts_ns == 0:
                # Unresolved timestamp: an empty ISO (not the 1970 sentinel), and
                # retained — it cannot be proven to predate the action.
                ts, note, excluded = "", "unresolved timestamp (timestamp_unix_ns=0)", False
                tier = TIER_UNRESOLVED
            else:
                ts, note = iso8601_from_unix_ns(ts_ns), ""
                excluded = tier == TIER_REPEAT
            yield DiffRow(ts, ts_ns, event_order, source_order, source_file, proc, pid,
                          tid, lvl, et, sub, cat, msg, fmt, matched_sigs or "", tier,
                          excluded, note)


def read_only_uri(db: Path) -> str:
    """An SQLite URI opening *db* read-only (percent-encoded: any path is safe)."""
    return Path(db).resolve().as_uri() + "?mode=ro"


# ── Outputs ──────────────────────────────────────────────────────────────────

class _SqliteOut:
    """The ``identified_logs`` database: every classified row, with its flag."""

    _BATCH = 1_000
    _INSERT = """
        INSERT INTO identified_logs
            (timestamp, timestamp_unix_ns, event_order, source_order, source_file,
             process, pid, tid,
             log_level, event_type, subsystem, category, message, format_string,
             matched_signatures, tier, excluded, note)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            path.unlink()
        self._conn = sqlite3.connect(str(path))
        self._batch: list[tuple] = []
        # Output SQLite schema: identical columns to the CSV plus the flag.
        self._conn.execute("""
            CREATE TABLE identified_logs (
                id                  INTEGER PRIMARY KEY,
                timestamp           TEXT,
                timestamp_unix_ns   INTEGER,
                event_order         INTEGER,
                source_order        INTEGER,
                source_file         TEXT,
                process             TEXT,
                pid                 INTEGER,
                tid                 INTEGER,
                log_level           TEXT,
                event_type          TEXT,
                subsystem           TEXT,
                category            TEXT,
                message             TEXT,
                format_string       TEXT,
                matched_signatures  TEXT NOT NULL DEFAULT '',
                tier                TEXT NOT NULL,
                excluded            INTEGER NOT NULL,
                note                TEXT
            )
        """)
        self._conn.execute("CREATE INDEX idx_identified_logs_excluded ON identified_logs(excluded)")
        self._conn.execute("CREATE INDEX idx_identified_logs_ts ON identified_logs(timestamp_unix_ns)")
        self._conn.execute("CREATE INDEX idx_identified_logs_tier ON identified_logs(tier)")
        # hidden_keys / v_identified_visible: analyst judgment, kept separate from
        # `excluded`. `excluded` is the engine's mechanical classification and is
        # never rewritten after the diff runs; hidden_keys is reversible (the
        # viewer's "hide identical lines"), persisted so a reopened session keeps
        # the pruning across runs.
        create_hidden_keys_objects(self._conn)

    def add(self, r: DiffRow) -> None:
        self._batch.append((r.timestamp, r.timestamp_unix_ns, r.event_order, r.source_order,
                            r.source_file, r.process, r.pid, r.tid, r.log_level, r.event_type,
                            r.subsystem, r.category, r.message, r.format_string,
                            r.matched_signatures, r.tier, int(r.excluded), r.note))
        if len(self._batch) >= self._BATCH:
            self._flush()

    def _flush(self) -> None:
        self._conn.executemany(self._INSERT, self._batch)
        self._batch.clear()

    def __enter__(self) -> _SqliteOut:
        return self

    def __exit__(self, exc_type, *_rest) -> None:  # type: ignore[no-untyped-def]
        try:
            if exc_type is None:
                if self._batch:
                    self._flush()
                self._conn.commit()
        finally:
            self._conn.close()


class _CsvOut:
    """The retained rows as CSV (UTF-8 with BOM, so Excel detects the encoding)."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = path.open("w", newline="", encoding="utf-8-sig")
        self._writer = csv.writer(self._fh)
        self._writer.writerow(_CSV_HEADER)

    def add(self, r: DiffRow) -> None:
        self._writer.writerow([r.timestamp, r.timestamp_unix_ns, r.event_order, r.source_order,
                               r.source_file, r.process, r.pid, r.tid, r.log_level,
                               r.event_type, r.subsystem, r.category, r.message,
                               r.matched_signatures, r.tier, r.format_string, r.note])

    def __enter__(self) -> _CsvOut:
        return self

    def __exit__(self, *_exc) -> None:  # type: ignore[no-untyped-def]
        self._fh.close()


def create_hidden_keys_objects(conn: sqlite3.Connection) -> None:
    """Create hidden_keys + v_identified_visible (idempotent — CREATE ... IF NOT EXISTS).

    Shared with :mod:`forensic_aul.ops.identify.results` so an older diff DB
    (produced before this feature) can gain the same objects on open.
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS hidden_keys (
            message TEXT NOT NULL,
            process TEXT NOT NULL,
            UNIQUE (message, process)
        )
    """)
    conn.execute("""
        CREATE VIEW IF NOT EXISTS v_identified_visible AS
            SELECT il.* FROM identified_logs il
            LEFT JOIN hidden_keys hk
                ON hk.message = il.message AND hk.process = COALESCE(il.process, '')
            WHERE hk.message IS NULL
    """)


def ensure_source_columns(conn: sqlite3.Connection) -> None:
    """Add ``source_order``/``source_file``/``format_string``/``tier`` to
    ``identified_logs`` if absent.

    Shared with :mod:`forensic_aul.ops.identify.results` so a pre-L10 diff DB
    (produced before these two columns existed) can gain them on open. Unlike
    the hidden_keys/v_identified_visible objects above, a column addition has
    no ``IF NOT EXISTS`` form — ``ALTER TABLE ... ADD COLUMN`` raises if the
    column is already there — so presence is checked via ``PRAGMA table_info``
    first, keeping this idempotent across repeated calls (e.g. on every
    ``IdentifyResults`` open).
    """
    cols = {row[1] for row in conn.execute("PRAGMA table_info(identified_logs)")}
    if "source_order" not in cols:
        conn.execute("ALTER TABLE identified_logs ADD COLUMN source_order INTEGER")
    if "source_file" not in cols:
        conn.execute("ALTER TABLE identified_logs ADD COLUMN source_file TEXT")
    # Tiers (2026-11): NULL on a database diffed before they existed.
    if "format_string" not in cols:
        conn.execute("ALTER TABLE identified_logs ADD COLUMN format_string TEXT")
    if "tier" not in cols:
        conn.execute("ALTER TABLE identified_logs ADD COLUMN tier TEXT")
