"""Batch SQLite writer for AUL log entries.

BatchWriter manages lookup tables (processes, subsystems, etc.) via
INSERT OR IGNORE + SELECT id, then inserts log entries in batches using
executemany() for throughput.

Design for future parallelisation
-----------------------------------
- `add_batch(entries)` accepts list[LogEntry] so a queue-consumer thread
  can call it without changing the interface.
- All lookup-table state is encapsulated; the main parsing workers are
  stateless and only produce LogEntry objects.
- No singletons or module-level state.
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from forensic_aul.config import BATCH_SIZE as _DEFAULT_BATCH_SIZE
from forensic_aul.engine.database.schema import UNKNOWN_BOOT_RANK
from forensic_aul.engine.models import LogEntry, TimesyncAnchor

log = logging.getLogger(__name__)

# SQLite's INTEGER is a *signed* 64-bit value (−2**63 … 2**63−1). A few Apple
# fields are genuinely **u64** and routinely have bit 63 set — most notably a
# statedump ``activity_id`` such as ``0x80000000000015C5`` (bit 63 is one of
# Apple's activity-id flags; the macos-unifiedlogs reference also types these and
# the thread id as u64). Binding the raw value raises ``OverflowError: Python int
# too large to convert to SQLite INTEGER``. We store it as its two's-complement
# signed i64 — bit-for-bit identical, recovered on read with
# ``value & 0xFFFFFFFFFFFFFFFF``.
#
# WHY only these columns: an activity id / thread id is an opaque correlation
# token (compared by equality, never ordered or arithmetic), so a 2's-complement
# representation is harmless. Ordered magnitudes such as ``timestamp_mach`` are
# deliberately *not* folded — a top-bit-set mach time would be a misparse to
# surface, not silently reinterpret (the writer's per-row fallback accounts for
# any such genuinely-unstorable value instead).
_U64_SIGN_BIT = 1 << 63
_U64_MODULO = 1 << 64


def _u64_to_i64(value: int) -> int:
    """Map a u64 (0 … 2**64−1) to its two's-complement signed i64 for SQLite.

    Values already in signed range (< 2**63) pass through unchanged, so the
    common small activity id / thread id / 0 is stored exactly as before.
    """
    return value - _U64_MODULO if value >= _U64_SIGN_BIT else value


# Single source of truth for the logs INSERT, shared by the batch (executemany)
# path and the per-row fallback so they stay in lock-step.
_INSERT_LOGS_SQL = """
    INSERT INTO logs(
        tracev3_file_id, format_src_file_id, timesync_file_id,
        tracev3_chunkset_file_offset, tracev3_firehose_inner_offset,
        tracev3_entry_inner_offset, format_string_file_offset,
        timestamp_unix_ns, timestamp_mach,
        timesync_anchor_id,
        process_id, pid, tid, euid,
        log_level_id, event_type_id,
        subsystem_id, category_id,
        message, format_str_id, library_id,
        process_uuid_id, activity_id, parent_activity_id,
        boot_id, raw_data
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
"""


class BatchWriter:
    """Write LogEntry objects to an open SQLite connection in batches.

    Usage::

        writer = BatchWriter(conn, batch_size=1000)
        for entry in entries:
            writer.add(entry)
        writer.flush()
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        batch_size: int = _DEFAULT_BATCH_SIZE,
    ) -> None:
        self._conn = conn
        self._batch_size = batch_size
        self._pending: list[tuple] = []
        # Count of log rows the database refused to store even one-by-one. A
        # forensic store must account for every entry, so these are never dropped
        # silently: each is logged with provenance and totalled here, then
        # surfaced by the extract pipeline. Normally 0.
        self._write_errors = 0

        # In-memory caches: name → rowid
        # These are populated lazily via _get_or_insert().
        self._processes: dict[str, int] = {}
        self._subsystems: dict[str, int] = {}
        self._categories: dict[str, int] = {}
        self._format_strs: dict[str, int] = {}
        self._log_levels: dict[str, int] = {}
        self._event_types: dict[str, int] = {}
        self._process_uuids: dict[str, int] = {}
        # boot_uuid → boots.id. Pre-populated in rank order via register_boot();
        # any boot_uuid seen during parsing but never registered is an "unknown"
        # boot inserted lazily with rank = UNKNOWN_BOOT_RANK (sorts last).
        self._boots: dict[str, int] = {}
        self._libraries: dict[tuple[str, str], int] = {}  # (name, uuid) → id
        # (timesync_file_id, file_offset) → timesync_anchors.id
        self._timesync_anchors: dict[tuple[int, int], int] = {}

    # ------------------------------------------------------------------ #
    # Public interface                                                     #
    # ------------------------------------------------------------------ #

    def add(self, entry: LogEntry) -> None:
        """Queue a single log entry for insertion."""
        self._pending.append(self._to_row(entry))
        if len(self._pending) >= self._batch_size:
            self._flush_batch()

    def add_batch(self, entries: Sequence[LogEntry]) -> None:
        """Queue multiple log entries (parallel-worker friendly interface)."""
        for entry in entries:
            self.add(entry)

    def flush(self) -> None:
        """Flush any remaining pending entries to the database."""
        if self._pending:
            self._flush_batch()

    @property
    def write_errors(self) -> int:
        """Number of log rows the database refused to store (normally 0).

        Each was logged with its source provenance. The extract pipeline surfaces
        this so an incomplete store is always visible, never silent.
        """
        return self._write_errors

    # ------------------------------------------------------------------ #
    # Lookup-table helpers                                                #
    # ------------------------------------------------------------------ #

    def get_or_insert_process(self, name: str) -> int:
        """Return the rowid for *name* in `processes`, inserting if absent."""
        return self._get_or_insert(
            self._processes, name,
            "INSERT OR IGNORE INTO processes(name) VALUES (?)",
            "SELECT id FROM processes WHERE name = ?",
            (name,),
        )

    def get_or_insert_subsystem(self, name: str) -> int:
        return self._get_or_insert(
            self._subsystems, name,
            "INSERT OR IGNORE INTO subsystems(name) VALUES (?)",
            "SELECT id FROM subsystems WHERE name = ?",
            (name,),
        )

    def get_or_insert_category(self, name: str) -> int:
        return self._get_or_insert(
            self._categories, name,
            "INSERT OR IGNORE INTO categories(name) VALUES (?)",
            "SELECT id FROM categories WHERE name = ?",
            (name,),
        )

    def get_or_insert_format_str(self, value: str) -> int:
        return self._get_or_insert(
            self._format_strs, value,
            "INSERT OR IGNORE INTO format_strs(value) VALUES (?)",
            "SELECT id FROM format_strs WHERE value = ?",
            (value,),
        )

    def get_or_insert_log_level(self, name: str) -> int:
        """Return the rowid for *name* in the seeded ``log_levels`` table.

        ``log_levels`` is pre-seeded at schema creation, so this resolves to a
        cached lookup against an existing row (the INSERT OR IGNORE is a defensive
        no-op should the parser ever emit an unforeseen level).
        """
        return self._get_or_insert(
            self._log_levels, name,
            "INSERT OR IGNORE INTO log_levels(name) VALUES (?)",
            "SELECT id FROM log_levels WHERE name = ?",
            (name,),
        )

    def get_or_insert_event_type(self, name: str) -> int:
        """Return the rowid for *name* in the seeded ``event_types`` table."""
        return self._get_or_insert(
            self._event_types, name,
            "INSERT OR IGNORE INTO event_types(name) VALUES (?)",
            "SELECT id FROM event_types WHERE name = ?",
            (name,),
        )

    def get_or_insert_process_uuid(self, uuid: str) -> int:
        """Return the rowid for *uuid* in ``process_uuids``, inserting if absent."""
        return self._get_or_insert(
            self._process_uuids, uuid,
            "INSERT OR IGNORE INTO process_uuids(uuid) VALUES (?)",
            "SELECT id FROM process_uuids WHERE uuid = ?",
            (uuid,),
        )

    def register_boot(self, boot_uuid: str, rank: int) -> int:
        """Insert a *known* boot with its physical first-appearance *rank*.

        Called once per timesync boot before parsing so event_order has a real
        rank for every boot the timesync layout describes. Returns the boots.id.
        WHY upfront: a boot's rank comes from the deterministic timesync layout,
        not from parse order (which is non-deterministic under multiprocessing).
        """
        cached = self._boots.get(boot_uuid)
        if cached is not None:
            return cached
        self._conn.execute(
            "INSERT OR IGNORE INTO boots(boot_uuid, rank) VALUES (?, ?)",
            (boot_uuid, rank),
        )
        row = self._conn.execute(
            "SELECT id FROM boots WHERE boot_uuid = ?", (boot_uuid,)
        ).fetchone()
        rowid: int = row[0]
        self._boots[boot_uuid] = rowid
        return rowid

    def get_or_insert_boot(self, boot_uuid: str) -> int:
        """Return the boots.id for *boot_uuid*, inserting an unknown boot if absent.

        A hit is the common case (boots are pre-registered via register_boot). A
        miss means a boot present in the logs but absent from the timesync layout;
        it is inserted with rank = UNKNOWN_BOOT_RANK so it sorts after every known
        boot in event_order.
        """
        cached = self._boots.get(boot_uuid)
        if cached is not None:
            return cached
        return self.register_boot(boot_uuid, UNKNOWN_BOOT_RANK)

    def get_or_insert_library(self, name: str, uuid: str) -> int:
        key = (name, uuid)
        if key in self._libraries:
            return self._libraries[key]
        self._conn.execute(
            "INSERT OR IGNORE INTO libraries(name, uuid) VALUES (?, ?)",
            (name, uuid),
        )
        row = self._conn.execute(
            "SELECT id FROM libraries WHERE name = ? AND uuid = ?",
            (name, uuid),
        ).fetchone()
        rowid: int = row[0]
        self._libraries[key] = rowid
        return rowid

    def get_or_insert_timesync_anchor(
        self,
        anchor: TimesyncAnchor,
        timesync_file_id: int,
    ) -> int:
        """Return the rowid for *anchor* in ``timesync_anchors``, inserting if absent.

        Anchors are deduplicated by ``(timesync_file_id, file_offset)`` — the
        byte-level provenance is the natural identity. The cache lives for the
        lifetime of the writer so a single anchor record is inserted once per
        extract run, even if shared by millions of log entries.
        """
        cache_key = (timesync_file_id, anchor.file_offset)
        cached = self._timesync_anchors.get(cache_key)
        if cached is not None:
            return cached

        self._conn.execute(
            """
            INSERT OR IGNORE INTO timesync_anchors(
                timesync_file_id, file_offset, boot_uuid,
                kernel_continuous_time, walltime_unix_ns,
                timebase_numerator, timebase_denominator,
                timezone_offset_mins
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timesync_file_id,
                anchor.file_offset,
                anchor.boot_uuid,
                anchor.kernel_continuous_time,
                anchor.walltime_unix_ns,
                anchor.timebase_numerator,
                anchor.timebase_denominator,
                anchor.timezone_offset_mins,
            ),
        )
        row = self._conn.execute(
            "SELECT id FROM timesync_anchors WHERE timesync_file_id = ? AND file_offset = ?",
            (timesync_file_id, anchor.file_offset),
        ).fetchone()
        rowid: int = row[0]
        self._timesync_anchors[cache_key] = rowid
        return rowid

    def insert_source_file(
        self,
        file_path: str,
        file_type: str,
        sha256: str | None,
        file_size: int | None,
    ) -> int:
        """Insert a source file record and return its rowid."""
        parsed_at = _now_iso()
        self._conn.execute(
            """
            INSERT OR IGNORE INTO source_files(file_path, file_type, sha256, file_size, parsed_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (file_path, file_type, sha256, file_size, parsed_at),
        )
        row = self._conn.execute(
            "SELECT id FROM source_files WHERE file_path = ?",
            (file_path,),
        ).fetchone()
        return row[0]

    def insert_shutdown_event(
        self,
        source_file_id: int | None,
        shutdown_unix_ns: int,
        shutdown_iso: str,
        delay_seconds: float | None,
        client_count: int,
    ) -> int:
        """Insert one shutdown_events row and return its rowid."""
        cur = self._conn.execute(
            """
            INSERT INTO shutdown_events(
                source_file_id, shutdown_unix_ns, shutdown_iso, delay_seconds, client_count
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (source_file_id, shutdown_unix_ns, shutdown_iso, delay_seconds, client_count),
        )
        rowid = cur.lastrowid
        if rowid is None:
            raise RuntimeError("insert_shutdown_event: lastrowid was None")
        return rowid

    def insert_shutdown_clients(
        self,
        shutdown_event_id: int,
        clients: Sequence[tuple[int | None, str, float | None]],
    ) -> None:
        """Insert shutdown_clients rows: each *client* is (pid, process_path, lingered_seconds)."""
        self._conn.executemany(
            """
            INSERT INTO shutdown_clients(shutdown_event_id, pid, process_path, lingered_seconds)
            VALUES (?, ?, ?, ?)
            """,
            [(shutdown_event_id, pid, proc, secs) for (pid, proc, secs) in clients],
        )

    def insert_case_metadata(
        self,
        *,
        case_number: str | None = None,
        imei: str | None = None,
        exhibit_number: str | None = None,
        analyst_name: str | None = None,
        ios_model: str | None = None,
        ios_build_version: str | None = None,
        log_start_time: str | None = None,
        log_end_time: str | None = None,
        notes: str | None = None,
        source_path: str | None = None,
        source_type: str | None = None,
        archive_fingerprint: str | None = None,
        logarchive_path: str | None = None,
        logarchive_sha256: str | None = None,
        tool_version: str = "0.1.0",
    ) -> int:
        """Insert a case_metadata row and return its rowid."""
        acquisition_timestamp = _now_iso()
        cur = self._conn.execute(
            """
            INSERT INTO case_metadata(
                case_number, imei, exhibit_number, analyst_name,
                ios_model, ios_build_version,
                log_start_time, log_end_time,
                notes, source_path, source_type, source_fingerprint,
                logarchive_path, logarchive_sha256,
                acquisition_timestamp, tool_version
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                case_number, imei, exhibit_number, analyst_name,
                ios_model, ios_build_version,
                log_start_time, log_end_time,
                notes, source_path, source_type, archive_fingerprint,
                logarchive_path, logarchive_sha256,
                acquisition_timestamp, tool_version,
            ),
        )
        rowid = cur.lastrowid
        if rowid is None:
            # Defensive: ``lastrowid`` is documented to be set after a successful
            # INSERT on a rowid table, but we never want to silently return None
            # to a caller that types it as ``int``.
            raise RuntimeError("insert_case_metadata: lastrowid was None")
        return rowid

    def update_case_metadata(
        self,
        rowid: int,
        *,
        ios_model: str | None = None,
        ios_build_version: str | None = None,
        ios_version: str | None = None,
        log_start_time: str | None = None,
        log_end_time: str | None = None,
        log_file_path: str | None = None,
        log_file_sha256: str | None = None,
    ) -> None:
        """Update mutable fields of an existing case_metadata row."""
        fields: list[tuple[str, object]] = []
        if ios_model is not None:
            fields.append(("ios_model", ios_model))
        if ios_build_version is not None:
            fields.append(("ios_build_version", ios_build_version))
        if ios_version is not None:
            fields.append(("ios_version", ios_version))
        if log_start_time is not None:
            fields.append(("log_start_time", log_start_time))
        if log_end_time is not None:
            fields.append(("log_end_time", log_end_time))
        if log_file_path is not None:
            fields.append(("log_file_path", log_file_path))
        if log_file_sha256 is not None:
            fields.append(("log_file_sha256", log_file_sha256))
        if not fields:
            return
        set_clause = ", ".join(f"{col} = ?" for col, _ in fields)
        values = [v for _, v in fields] + [rowid]
        self._conn.execute(
            f"UPDATE case_metadata SET {set_clause} WHERE id = ?",
            values,
        )

    # ------------------------------------------------------------------ #
    # Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    def _to_row(self, entry: LogEntry) -> tuple:
        """Convert a LogEntry to a tuple for the logs INSERT."""
        process_id = self.get_or_insert_process(entry.process) if entry.process else None
        subsystem_id = self.get_or_insert_subsystem(entry.subsystem) if entry.subsystem else None
        category_id = self.get_or_insert_category(entry.category) if entry.category else None
        format_str_id = (
            self.get_or_insert_format_str(entry.message_format_string)
            if entry.message_format_string else None
        )
        library_id = (
            self.get_or_insert_library(entry.library, entry.library_uuid)
            if entry.library else None
        )
        # Normalised classification / identity columns: map the repeated strings to
        # their lookup ids (None when the source value is empty/falsy).
        log_level_id = (
            self.get_or_insert_log_level(entry.log_level) if entry.log_level else None
        )
        event_type_id = (
            self.get_or_insert_event_type(entry.event_type) if entry.event_type else None
        )
        process_uuid_id = (
            self.get_or_insert_process_uuid(entry.process_uuid) if entry.process_uuid else None
        )
        boot_id = self.get_or_insert_boot(entry.boot_uuid) if entry.boot_uuid else None
        # raw_data is already a JSON string (or None) in LogEntry — the extract
        # pipeline only builds it when --keep-raw is set, so it is normally None.
        raw_data_json = entry.raw_data

        return (
            entry.tracev3_file_id,
            entry.format_src_file_id,
            entry.timesync_file_id,
            entry.tracev3_chunkset_file_offset,
            entry.tracev3_firehose_inner_offset,
            entry.tracev3_entry_inner_offset,
            entry.format_string_file_offset,
            entry.timestamp_unix_ns,
            entry.timestamp_mach,
            entry.timesync_anchor_id,
            process_id,
            entry.pid,
            _u64_to_i64(entry.tid),
            entry.euid,
            log_level_id,
            event_type_id,
            subsystem_id,
            category_id,
            entry.message,
            format_str_id,
            library_id,
            process_uuid_id,
            _u64_to_i64(entry.activity_id),
            _u64_to_i64(entry.parent_activity_id),
            boot_id,
            raw_data_json,
        )

    def _flush_batch(self) -> None:
        if not self._pending:
            return
        # Fast path: insert the whole batch in one executemany. WHY the savepoint:
        # executemany is all-or-nothing and may apply some rows before a bad one
        # raises. On failure we ROLLBACK TO the savepoint to undo *only* this
        # batch's partial log rows (the lookup-table inserts made earlier in the
        # transaction are before the savepoint, so they survive and the cached ids
        # stay valid), then re-insert row by row. This guarantees one rejected row
        # cannot discard the whole batch and is never double-inserted.
        try:
            self._conn.execute("SAVEPOINT _flush")
            try:
                self._conn.executemany(_INSERT_LOGS_SQL, self._pending)
            except Exception as exc:  # noqa: BLE001 — fall back, never lose the batch
                self._conn.execute("ROLLBACK TO _flush")
                log.warning(f"BatchWriter: batch insert failed ({exc}) — retrying {len(self._pending)} row(s) individually so good rows are kept and bad rows are reported")
                self._insert_individually(self._pending)
            self._conn.execute("RELEASE _flush")
            self._conn.commit()
            log.debug("BatchWriter: committed %d rows", len(self._pending))
        finally:
            self._pending.clear()

    def _insert_individually(self, rows: list[tuple]) -> None:
        """Insert *rows* one at a time, accounting for any the database rejects.

        Used only after a batch ``executemany`` failed. A row that still cannot be
        stored is logged at ERROR with its source provenance and counted in
        ``write_errors`` — a forensic store must never drop an entry silently.
        """
        for row in rows:
            try:
                self._conn.execute(_INSERT_LOGS_SQL, row)
            except Exception as exc:  # noqa: BLE001 — isolate and report the one row
                self._write_errors += 1
                # Row layout mirrors _to_row(): [0]=tracev3_file_id and
                # [3..5]=the byte offsets that locate the record in its source.
                log.error(f"BatchWriter: DROPPED an unstorable log row — tracev3_file_id={row[0]!r} chunkset_off={row[3]!r} firehose_off={row[4]!r} entry_off={row[5]!r} : {exc}")

    def _get_or_insert(
        self,
        cache: dict[str, int],
        key: str,
        insert_sql: str,
        select_sql: str,
        params: tuple,
    ) -> int:
        if key in cache:
            return cache[key]
        self._conn.execute(insert_sql, params)
        row = self._conn.execute(select_sql, params).fetchone()
        rowid: int = row[0]
        cache[key] = rowid
        return rowid


def register_source_file(
    writer: "BatchWriter",
    logarchive_root: Path,
    file_path: Path,
    file_type: str,
    file_hashes: dict[str, str] | None = None,
) -> int:
    """Insert a source_files row for *file_path* and return its id.

    *file_hashes* is the ``{relative_path: sha256}`` dict from
    :func:`forensic_aul.engine.integrity.hash_logarchive`. If ``None``, the SHA-256
    is computed on demand (slower, for single-file use such as shutdown.log).
    """
    from forensic_aul.engine.integrity import compute_sha256

    rel = file_path.relative_to(logarchive_root).as_posix()

    if file_hashes is not None:
        sha256 = file_hashes.get(rel)
    else:
        try:
            sha256 = compute_sha256(file_path)
        except OSError:
            sha256 = None

    try:
        file_size = file_path.stat().st_size
    except OSError:
        file_size = None

    return writer.insert_source_file(rel, file_type, sha256, file_size)


def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string with microsecond precision.

    Microseconds match the precision of the per-log entry ``timestamp`` column,
    so ``case_metadata.acquisition_timestamp`` and ``source_files.parsed_at``
    line up with the log timestamps when sorting.
    """
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
