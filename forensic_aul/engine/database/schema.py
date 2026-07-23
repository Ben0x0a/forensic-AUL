"""SQLite schema for the AUL Parser normalised database.

Tables
------
case_metadata     — one row per extraction session
source_files      — one row per parsed file (sha256, path, type)
processes         — lookup: process name
libraries         — lookup: (name, uuid)
subsystems        — lookup: subsystem string
categories        — lookup: category string
format_strs       — lookup: raw format string
log_levels        — seeded lookup: Default/Info/Debug/Error/Fault
event_types       — seeded lookup: Log/Activity/Trace/Signpost/Loss
process_uuids     — lookup: process image UUID (one row per distinct image)
boots             — lookup: boot_uuid + physical first-appearance ``rank`` (drives event_order)
logs              — main log table (tens of millions of rows)
logs_fts          — FTS5 virtual table over logs.message (created only if FTS5 available)

All FKs use INTEGER (SQLite rowid alias) for maximum compactness. The four
high-repetition string columns that used to live inline on ``logs`` —
``log_level``, ``event_type``, ``process_uuid`` and ``boot_uuid`` — are
normalised into the lookup tables above: at tens of millions of rows a 1–36 byte
string per row is far more expensive than an INTEGER FK, and ``boot_id`` makes
the event_order sort an integer comparison instead of a TEXT one.
"""

from __future__ import annotations

import sqlite3
import logging

from forensic_aul.config import WAL_AUTOCHECKPOINT_PAGES

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Seeded vocabularies + ordering sentinel
# ---------------------------------------------------------------------------

# Canonical low-cardinality vocabularies. They are seeded into ``log_levels`` /
# ``event_types`` at schema creation with stable ids (1-based, in list order) so
# the writer maps a value→id with a cached lookup and consumers JOIN for the
# human-readable name. The membership mirrors the parser's mappings in
# ops/extraction/extract.py (_LOG_LEVELS / _EVENT_TYPES). Consumed by:
# database/writer.py (value→id) and the export/summary/diff/matcher readers.
LOG_LEVEL_NAMES: tuple[str, ...] = ("Default", "Info", "Debug", "Error", "Fault")
# Statedump/Simpledump are non-Firehose log records (tags 0x6003/0x6004) emitted
# as ordinary lines by `log show`; appended after the firehose vocabulary to keep
# the original ids stable.
EVENT_TYPE_NAMES: tuple[str, ...] = (
    "Log", "Activity", "Trace", "Signpost", "Loss", "Statedump", "Simpledump",
)

# Rank given to a boot seen in the logs but absent from the timesync layout (so it
# has no physical first-appearance position). It is larger than any real rank, so
# such boots sort *after* every known boot in event_order. Consumed by:
# database/writer.py (rank for an unknown boot) and database/ordering.py (the
# COALESCE fallback when a logs row has no boot_id at all). WHY a shared constant:
# the writer stores it and the ordering reads it back — they must agree.
UNKNOWN_BOOT_RANK: int = 1 << 30

# ---------------------------------------------------------------------------
# DDL statements
# ---------------------------------------------------------------------------

_DDL_CASE_METADATA = """
CREATE TABLE IF NOT EXISTS case_metadata (
    id                    INTEGER PRIMARY KEY,
    case_number           TEXT,
    imei                  TEXT,
    exhibit_number        TEXT,
    analyst_name          TEXT,
    ios_model             TEXT,
    ios_build_version     TEXT,        -- build code from the tracev3 header (e.g. 21F90)
    ios_version           TEXT,        -- marketing iOS version (SystemVersion.plist, or build-table fallback)
    log_start_time        TEXT,        -- ISO 8601 UTC
    log_end_time          TEXT,        -- ISO 8601 UTC
    notes                 TEXT,
    source_path           TEXT,        -- the evidence supplied (dir / .tar.gz / .zip)
    source_type           TEXT,        -- logarchive | sysdiagnose | filesystem
    source_fingerprint    TEXT,        -- quick head+tail+size archive fingerprint (NULL for a dir)
    logarchive_path       TEXT,        -- logarchive root parsed (placeholder if a temp dir)
    logarchive_sha256     TEXT,
    log_file_path         TEXT,        -- path to the operational log file
    log_file_sha256       TEXT,        -- SHA-256 of the log file (sealed at end of run)
    acquisition_timestamp TEXT NOT NULL,
    tool_version          TEXT NOT NULL
);
"""

_DDL_SOURCE_FILES = """
CREATE TABLE IF NOT EXISTS source_files (
    id           INTEGER PRIMARY KEY,
    file_path    TEXT NOT NULL UNIQUE,  -- relative to logarchive root
    file_type    TEXT NOT NULL,         -- tracev3 | uuidtext | dsc | timesync
    sha256       TEXT,                  -- "before" digest, captured at registration
    sha256_after TEXT,                  -- re-hash at end of run (per-file integrity)
    -- 1 = unchanged during the run, 0 = CHANGED (data suspect), NULL = no baseline
    -- or file unreadable at verification time. A 0/NULL on one file does not
    -- invalidate the others — their rows stay independently usable.
    integrity_ok INTEGER,
    file_size    INTEGER,
    parsed_at    TEXT NOT NULL
);
"""

_DDL_PROCESSES = """
CREATE TABLE IF NOT EXISTS processes (
    id   INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);
"""

_DDL_LIBRARIES = """
CREATE TABLE IF NOT EXISTS libraries (
    id   INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    uuid TEXT NOT NULL,
    UNIQUE(name, uuid)
);
"""

_DDL_SUBSYSTEMS = """
CREATE TABLE IF NOT EXISTS subsystems (
    id   INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);
"""

_DDL_CATEGORIES = """
CREATE TABLE IF NOT EXISTS categories (
    id   INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);
"""

_DDL_FORMAT_STRS = """
CREATE TABLE IF NOT EXISTS format_strs (
    id    INTEGER PRIMARY KEY,
    value TEXT NOT NULL UNIQUE
);
"""

# Seeded enums (populated in init_schema from LOG_LEVEL_NAMES / EVENT_TYPE_NAMES).
_DDL_LOG_LEVELS = """
CREATE TABLE IF NOT EXISTS log_levels (
    id   INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);
"""

_DDL_EVENT_TYPES = """
CREATE TABLE IF NOT EXISTS event_types (
    id   INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);
"""

# One row per distinct process-image UUID (cardinality: hundreds–thousands), so
# the 32-hex-char string is stored once instead of on every log row.
_DDL_PROCESS_UUIDS = """
CREATE TABLE IF NOT EXISTS process_uuids (
    id   INTEGER PRIMARY KEY,
    uuid TEXT NOT NULL UNIQUE
);
"""

# One row per boot. ``rank`` is the physical first-appearance order across the
# name-sorted timesync files (see ops/extraction/extract.py step 4); it is the
# primary key of the event_order sort. A boot present in the logs but absent from
# the timesync layout is inserted with rank = UNKNOWN_BOOT_RANK so it sorts last.
_DDL_BOOTS = """
CREATE TABLE IF NOT EXISTS boots (
    id        INTEGER PRIMARY KEY,
    boot_uuid TEXT NOT NULL UNIQUE,
    rank      INTEGER NOT NULL
);
"""

# One row per *unique* timesync anchor used during conversion. A single anchor
# is shared by many log entries (a boot anchor by an entire boot's worth of
# entries; a record anchor by every entry within its kernel-time window). The
# UNIQUE(file_id, file_offset) tuple makes the byte-level provenance the
# natural deduplication key.
_DDL_TIMESYNC_ANCHORS = """
CREATE TABLE IF NOT EXISTS timesync_anchors (
    id                       INTEGER PRIMARY KEY,
    timesync_file_id         INTEGER NOT NULL REFERENCES source_files(id),
    file_offset              INTEGER NOT NULL,
    boot_uuid                TEXT    NOT NULL,
    kernel_continuous_time   INTEGER NOT NULL,
    walltime_unix_ns         INTEGER NOT NULL,
    timebase_numerator       INTEGER NOT NULL,
    timebase_denominator     INTEGER NOT NULL,
    timezone_offset_mins     INTEGER,
    UNIQUE (timesync_file_id, file_offset)
);
"""

# Shutdown / reboot events parsed from the logarchive's ``shutdown.log`` (Extra/
# for a logarchive or sysdiagnose, diagnostics root for an FFS). These are
# WALL-CLOCK anchored (a Unix epoch from the ``SIGTERM: [<epoch>]`` line) and have
# NO mach continuous time or boot, so they live OUTSIDE the logs/event_order
# timeline and are correlated to logs by wall-clock time. One event has many
# clients (processes still alive at power-off), hence the second table.
_DDL_SHUTDOWN_EVENTS = """
CREATE TABLE IF NOT EXISTS shutdown_events (
    id               INTEGER PRIMARY KEY,
    source_file_id   INTEGER REFERENCES source_files(id),  -- the shutdown.log
    shutdown_unix_ns INTEGER NOT NULL,   -- power-off time (SIGTERM epoch × 1e9)
    shutdown_iso     TEXT    NOT NULL,   -- ISO 8601 UTC
    delay_seconds    REAL,               -- longest still-alive check = total shutdown delay
    client_count     INTEGER NOT NULL    -- distinct processes that lingered at any check
);
"""

_DDL_SHUTDOWN_CLIENTS = """
CREATE TABLE IF NOT EXISTS shutdown_clients (
    id                INTEGER PRIMARY KEY,
    shutdown_event_id INTEGER NOT NULL REFERENCES shutdown_events(id),
    pid               INTEGER,
    process_path      TEXT,
    lingered_seconds  REAL    -- last 'After Xs' check the process was still alive at
);
"""

_DDL_SHUTDOWN_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_shutdown_events_time    ON shutdown_events(shutdown_unix_ns);",
    "CREATE INDEX IF NOT EXISTS idx_shutdown_clients_event  ON shutdown_clients(shutdown_event_id);",
    "CREATE INDEX IF NOT EXISTS idx_shutdown_clients_path   ON shutdown_clients(process_path);",
]

_DDL_LOGS = """
CREATE TABLE IF NOT EXISTS logs (
    -- ``INTEGER PRIMARY KEY`` is the rowid alias; ``AUTOINCREMENT`` would
    -- add a sqlite_sequence row update on every INSERT for no benefit here
    -- (we never reuse deleted ids, and the rowid is sufficient for FKs).
    id                  INTEGER PRIMARY KEY,

    -- Deterministic forensic ordering (assigned post-load by database/ordering.py;
    -- both are NULL until that pass runs). Never order by wall-clock for sequence —
    -- that would hide time-shifting.
    source_order        INTEGER,  -- physical position WITHIN its tracev3 file (1-based, byte order)
    event_order         INTEGER,  -- merged real timeline: (boot physical rank, monotonic timestamp_mach)

    -- Source traceability: which file contributed each piece of information
    tracev3_file_id     INTEGER REFERENCES source_files(id),  -- raw Firehose entry source
    format_src_file_id  INTEGER REFERENCES source_files(id),  -- UUIDText or DSC file (format string)
    timesync_file_id    INTEGER REFERENCES source_files(id),  -- .timesync file (timestamp conversion)

    -- Byte-level offsets back into the source files. Together with the file
    -- ids above they let an investigator open the raw bytes and re-derive
    -- every piece of resolved data.
    tracev3_chunkset_file_offset    INTEGER,  -- offset of the chunkset within the tracev3 file
    tracev3_firehose_inner_offset   INTEGER,  -- offset of the firehose preamble in the decompressed chunkset
    tracev3_entry_inner_offset      INTEGER,  -- offset of this entry within the firehose preamble
    format_string_file_offset       INTEGER,  -- offset of the format string in the UUIDText/DSC file (NULL for dynamic)

    -- Timing. The human-readable ISO 8601 string is NOT stored: it is fully
    -- derivable from timestamp_unix_ns (engine/utils/time.iso8601_from_unix_ns)
    -- and formatted on read by the export/diff layers, saving ~30 bytes/row.
    timestamp_unix_ns    INTEGER NOT NULL,   -- nanoseconds since 1970-01-01 UTC
    timestamp_mach       INTEGER NOT NULL,   -- raw mach continuous time (kernel ticks)
    timesync_anchor_id   INTEGER REFERENCES timesync_anchors(id),  -- anchor used to derive unix_ns

    -- Process
    process_id          INTEGER REFERENCES processes(id),
    pid                 INTEGER,
    tid                 INTEGER,
    euid                INTEGER,

    -- Classification (normalised — see the lookup tables above)
    log_level_id        INTEGER REFERENCES log_levels(id),   -- Debug/Info/Default/Error/Fault
    event_type_id       INTEGER REFERENCES event_types(id),  -- Log/Activity/Trace/Signpost/Loss
    subsystem_id        INTEGER REFERENCES subsystems(id),
    category_id         INTEGER REFERENCES categories(id),

    -- Message
    message             TEXT,
    format_str_id       INTEGER REFERENCES format_strs(id),

    -- Library / UUID
    library_id          INTEGER REFERENCES libraries(id),
    process_uuid_id     INTEGER REFERENCES process_uuids(id),

    -- Activity
    activity_id         INTEGER,
    parent_activity_id  INTEGER,
    boot_id             INTEGER REFERENCES boots(id),  -- normalised boot_uuid; rank drives event_order

    -- Raw forensic data
    raw_data            TEXT               -- JSON: list[FirehoseItemInfo] for traceability
);
"""

# Deliberately lean. Each index on a tens-of-millions-row table costs storage and
# a full sorted build in the finalisation tail, so only the columns that analyst
# queries actually seek/sort on are indexed:
#   - timestamp_unix_ns : export/diff order + time-range bounds
#   - subsystem_id / category_id / process_id : common analyst facet filters
#   - format_str_id : the lead pre-filter of the KB annotation hot path
#   - event_order   : the deterministic forensic timeline (ORDER BY event_order)
# Everything else is intentionally NOT indexed (measured as pure cost here):
#   * log_level_id / event_type_id — 5-value columns, never selective;
#   * boot_id — only ever sorted (and event_order already leads with its rank);
#   * pid, timestamp_mach — rare residual filters, scan is acceptable;
#   * format_src_file_id / timesync_file_id / tracev3_file_id — provenance columns,
#     not query keys.
_DDL_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_logs_timestamp_unix_ns  ON logs(timestamp_unix_ns);",
    "CREATE INDEX IF NOT EXISTS idx_logs_subsystem_id       ON logs(subsystem_id);",
    "CREATE INDEX IF NOT EXISTS idx_logs_category_id        ON logs(category_id);",
    "CREATE INDEX IF NOT EXISTS idx_logs_process_id         ON logs(process_id);",
    "CREATE INDEX IF NOT EXISTS idx_logs_format_str_id      ON logs(format_str_id);",
    "CREATE INDEX IF NOT EXISTS idx_logs_event_order        ON logs(event_order);",
]

# Stable read view — the ONLY schema surface external consumers may rely on
# (together with the query_logs API). It denormalises the lookup tables back
# into readable columns so a consumer never touches the *_id FKs; the underlying
# tables remain an internal implementation detail and may change. Keep this
# column list backward-compatible: only ever APPEND columns.
_DDL_V_LOGS = """
CREATE VIEW IF NOT EXISTS v_logs AS
SELECT
    l.id                  AS id,
    l.timestamp_unix_ns   AS timestamp_unix_ns,
    l.source_order        AS source_order,
    l.event_order         AS event_order,
    p.name                AS process,
    l.pid                 AS pid,
    l.tid                 AS tid,
    ll.name               AS log_level,
    et.name               AS event_type,
    s.name                AS subsystem,
    c.name                AS category,
    l.message             AS message,
    fs.value              AS format_string,
    b.boot_uuid           AS boot_uuid
FROM logs l
LEFT JOIN processes   p  ON p.id  = l.process_id
LEFT JOIN subsystems  s  ON s.id  = l.subsystem_id
LEFT JOIN categories  c  ON c.id  = l.category_id
LEFT JOIN log_levels  ll ON ll.id = l.log_level_id
LEFT JOIN event_types et ON et.id = l.event_type_id
LEFT JOIN format_strs fs ON fs.id = l.format_str_id
LEFT JOIN boots       b  ON b.id  = l.boot_id;
"""

_DDL_FTS5 = """
CREATE VIRTUAL TABLE IF NOT EXISTS logs_fts
    USING fts5(message, content='logs', content_rowid='id');
"""

_DDL_FTS5_TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS logs_ai AFTER INSERT ON logs BEGIN
    INSERT INTO logs_fts(rowid, message) VALUES (new.id, new.message);
END;
CREATE TRIGGER IF NOT EXISTS logs_ad AFTER DELETE ON logs BEGIN
    INSERT INTO logs_fts(logs_fts, rowid, message) VALUES ('delete', old.id, old.message);
END;
CREATE TRIGGER IF NOT EXISTS logs_au AFTER UPDATE ON logs BEGIN
    INSERT INTO logs_fts(logs_fts, rowid, message) VALUES ('delete', old.id, old.message);
    INSERT INTO logs_fts(rowid, message) VALUES (new.id, new.message);
END;
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def has_fts5(conn: sqlite3.Connection) -> bool:
    """Return True if the SQLite build supports FTS5.

    Delegates to _fts5_available which probes by actually creating a
    virtual table — more reliable than parsing error messages.
    """
    return _fts5_available(conn)


def _fts5_available(conn: sqlite3.Connection) -> bool:
    """Return True if the SQLite build supports FTS5.

    Probes ``PRAGMA compile_options`` rather than mutating the schema; the
    older approach of CREATE/DROP'ing a probe table left transient DDL on
    the connection and could surprise concurrent readers.
    """
    rows = conn.execute("PRAGMA compile_options").fetchall()
    options = {row[0] for row in rows}
    return "ENABLE_FTS5" in options


def init_schema(
    conn: sqlite3.Connection,
    enable_fts5: bool = True,
    *,
    defer_fts_triggers: bool = False,
    create_indexes: bool = True,
) -> bool:
    """Create all tables, indexes, and (optionally) FTS5 virtual table.

    Returns True if FTS5 was successfully created, False otherwise.
    Caller is responsible for the transaction or autocommit mode.

    When *create_indexes* is False the secondary indexes on ``logs`` are NOT
    created here; the caller builds them once after the bulk load via
    ``finalize_indexes``. Building indexes after the data is loaded avoids
    maintaining ~14 B-trees on every INSERT (the dominant write cost / WAL churn
    on a large extract). This is safe to default-on for the extract pipeline: an
    interrupted run simply has unindexed (but complete and correct) data — unlike
    deferred FTS, which would return silently empty results.

    When *defer_fts_triggers* is True the FTS5 virtual table is created but its
    INSERT/UPDATE/DELETE maintenance triggers are NOT — so a bulk load does not
    pay per-row index churn. The caller must later call ``finalize_deferred_fts``
    to populate the index once and install the triggers. WHY this is opt-in: a
    run interrupted before the finaliser leaves ``logs_fts`` empty, so full-text
    search would silently miss everything until a manual rebuild.
    """
    # Wrap the schema-setup DDL in a single transaction. ``executescript``
    # otherwise commits at every statement boundary, which slows the cold
    # start of every extract by an order of magnitude.
    with conn:
        cur = conn.cursor()

        # Core tables — order matters: timesync_anchors and logs depend on
        # source_files; logs also references the lookup tables below, so every
        # lookup must exist before _DDL_LOGS.
        for ddl in (
            _DDL_CASE_METADATA,
            _DDL_SOURCE_FILES,
            _DDL_PROCESSES,
            _DDL_LIBRARIES,
            _DDL_SUBSYSTEMS,
            _DDL_CATEGORIES,
            _DDL_FORMAT_STRS,
            _DDL_LOG_LEVELS,
            _DDL_EVENT_TYPES,
            _DDL_PROCESS_UUIDS,
            _DDL_BOOTS,
            _DDL_TIMESYNC_ANCHORS,
            _DDL_LOGS,
            _DDL_SHUTDOWN_EVENTS,
            _DDL_SHUTDOWN_CLIENTS,
        ):
            cur.executescript(ddl)

        # Seed the two fixed enums with stable 1-based ids (in list order) so the
        # writer can resolve a name→id from a cached lookup against a pre-populated
        # table. INSERT OR IGNORE keeps init_schema idempotent.
        cur.executemany(
            "INSERT OR IGNORE INTO log_levels(id, name) VALUES (?, ?)",
            list(enumerate(LOG_LEVEL_NAMES, start=1)),
        )
        cur.executemany(
            "INSERT OR IGNORE INTO event_types(id, name) VALUES (?, ?)",
            list(enumerate(EVENT_TYPE_NAMES, start=1)),
        )

        # Stable read view for external consumers (see _DDL_V_LOGS).
        cur.executescript(_DDL_V_LOGS)

        # Shutdown tables are tiny (a handful of rows) — index them inline rather
        # than via the deferred bulk-load path used for `logs`.
        for ddl in _DDL_SHUTDOWN_INDEXES:
            cur.execute(ddl)

        # Indexes (optionally deferred to finalize_indexes for bulk loads)
        if create_indexes:
            for ddl in _DDL_INDEXES:
                cur.execute(ddl)

        # FTS5 (optional)
        fts5_ok = False
        if enable_fts5:
            if _fts5_available(conn):
                cur.executescript(_DDL_FTS5)
                if defer_fts_triggers:
                    log.debug(
                        "schema: FTS5 virtual table created (triggers deferred — "
                        "index will be rebuilt at end of run)"
                    )
                else:
                    cur.executescript(_DDL_FTS5_TRIGGERS)
                    log.debug("schema: FTS5 virtual table + triggers created")
                fts5_ok = True
            else:
                log.warning(
                    "schema: FTS5 not available in this SQLite build — "
                    "full-text search will fall back to LIKE"
                )
    return fts5_ok


def ensure_views(conn: sqlite3.Connection) -> None:
    """Create the stable read views on a database that predates them.

    Idempotent (CREATE VIEW IF NOT EXISTS). Called opportunistically by
    ``query_logs`` so an old analysis database gains ``v_logs`` on first read;
    raises ``sqlite3.Error`` on a read-only database — the caller decides
    whether that matters (query_logs ignores it and reads the tables directly).
    """
    with conn:
        conn.executescript(_DDL_V_LOGS)


def finalize_deferred_fts(conn: sqlite3.Connection) -> None:
    """Populate logs_fts in one pass and install its maintenance triggers.

    Counterpart to ``init_schema(..., defer_fts_triggers=True)``: builds the
    full-text index over all rows loaded so far (a single sequential pass, far
    cheaper than per-row trigger maintenance during a bulk load), then creates
    the INSERT/UPDATE/DELETE triggers so subsequent mutations stay consistent.
    """
    with conn:
        # 'rebuild' repopulates the external-content FTS index from `logs`.
        conn.execute("INSERT INTO logs_fts(logs_fts) VALUES('rebuild')")
        conn.executescript(_DDL_FTS5_TRIGGERS)


def finalize_indexes(conn: sqlite3.Connection) -> None:
    """Build the secondary ``logs`` indexes after a bulk load.

    Counterpart to ``init_schema(..., create_indexes=False)``. Each index is one
    sequential sorted build over the finished table — far cheaper than updating
    every index on every INSERT during the load. The sort spills to a temp FILE
    (not RAM) so a multi-million-row build cannot exhaust memory; the setting is
    restored afterwards.
    """
    # Force on-disk temp storage just for the (potentially large) index sorts,
    # then restore whatever the connection had (apply_pragmas sets MEMORY).
    prev = conn.execute("PRAGMA temp_store").fetchone()[0]
    conn.execute("PRAGMA temp_store=FILE;")
    try:
        for ddl in _DDL_INDEXES:
            conn.execute(ddl)
    finally:
        conn.execute(f"PRAGMA temp_store={int(prev)};")


def apply_pragmas(
    conn: sqlite3.Connection,
    *,
    synchronous: str = "NORMAL",
    sort_threads: int = 0,
) -> None:
    """Apply performance pragmas for bulk insertion.

    Must be called before any writes. WAL mode + ``synchronous=NORMAL`` (the
    default) is durable and **never corrupts** the database — at worst a power
    loss costs the last few uncommitted transactions. ``synchronous=OFF`` is
    faster but can corrupt the database on an OS crash / power loss, so it is
    opt-in only (extract's ``--fast-write``).

    *sort_threads* sets ``PRAGMA threads`` — the max auxiliary threads SQLite may
    use for large sorts. This parallelises the two sort-heavy finaliser steps
    (``CREATE INDEX`` builds and the ``ROW_NUMBER`` ordering passes) across cores;
    0 (default) keeps SQLite's single-threaded sorter.
    """
    sync = synchronous.upper()
    if sync not in ("OFF", "NORMAL", "FULL", "EXTRA"):
        raise ValueError(f"invalid synchronous mode: {synchronous!r}")
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute(f"PRAGMA synchronous={sync};")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA cache_size=-65536;")   # 64 MB page cache
    conn.execute("PRAGMA temp_store=MEMORY;")
    if sort_threads > 0:
        conn.execute(f"PRAGMA threads={sort_threads};")
    # Checkpoint the WAL far less often than SQLite's 1 000-page default: over a
    # multi-GB extract the default rewrites WAL pages into the main DB constantly,
    # inflating total bytes written several-fold (see WAL_AUTOCHECKPOINT_PAGES).
    conn.execute(f"PRAGMA wal_autocheckpoint={WAL_AUTOCHECKPOINT_PAGES};")
