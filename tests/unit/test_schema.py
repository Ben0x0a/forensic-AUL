"""Tests for forensic_aul.engine.database.schema — DDL, pragmas, FTS5 probe."""

import sqlite3
import pytest
from forensic_aul.config import WAL_AUTOCHECKPOINT_PAGES
from forensic_aul.engine.database.schema import (
    apply_pragmas,
    finalize_deferred_fts,
    has_fts5,
    init_schema,
)


def _insert_log(c: sqlite3.Connection, rowid: int, message: str) -> None:
    """Insert a minimal logs row (only the NOT NULL columns + message)."""
    c.execute(
        "INSERT INTO logs (id, timestamp_unix_ns, timestamp_mach, message) "
        "VALUES (?,?,?,?)",
        (rowid, 0, 0, message),
    )


def _trigger_names(c: sqlite3.Connection) -> set[str]:
    return {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}


EXPECTED_TABLES = {
    "case_metadata",
    "source_files",
    "processes",
    "libraries",
    "subsystems",
    "categories",
    "format_strs",
    "log_levels",
    "event_types",
    "process_uuids",
    "boots",
    "logs",
}


def _table_names(c: sqlite3.Connection) -> set[str]:
    rows = c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return {r[0] for r in rows}


def _index_names(c: sqlite3.Connection) -> set[str]:
    rows = c.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()
    return {r[0] for r in rows}


class TestInitSchema:
    def test_all_tables_created(self, conn):
        assert EXPECTED_TABLES.issubset(_table_names(conn))

    def test_idempotent(self, conn):
        # Running twice must not raise
        init_schema(conn)
        assert EXPECTED_TABLES.issubset(_table_names(conn))

    def test_logs_columns(self, conn):
        cols = {r[1] for r in conn.execute("PRAGMA table_info(logs)")}
        for expected in ("id", "timestamp_unix_ns", "timestamp_mach",
                         "timesync_anchor_id",
                         "pid", "tid", "euid",
                         "log_level_id", "event_type_id", "message",
                         "tracev3_file_id", "format_src_file_id", "timesync_file_id",
                         "tracev3_chunkset_file_offset", "tracev3_firehose_inner_offset",
                         "tracev3_entry_inner_offset", "format_string_file_offset",
                         "process_uuid_id", "boot_id", "raw_data"):
            assert expected in cols, f"Missing column: {expected}"
        # The normalised-away string columns and the derived ISO must be gone.
        for gone in ("timestamp_iso", "log_level", "event_type", "boot_uuid",
                     "process_uuid"):
            assert gone not in cols, f"Column should have been removed: {gone}"

    def test_seeded_enums(self, conn):
        levels = {r[0] for r in conn.execute("SELECT name FROM log_levels")}
        events = {r[0] for r in conn.execute("SELECT name FROM event_types")}
        assert {"Default", "Info", "Debug", "Error", "Fault"} <= levels
        assert {"Log", "Activity", "Trace", "Signpost", "Loss"} <= events

    def test_timesync_anchors_table(self, conn):
        tables = _table_names(conn)
        assert "timesync_anchors" in tables
        cols = {r[1] for r in conn.execute("PRAGMA table_info(timesync_anchors)")}
        for expected in ("id", "timesync_file_id", "file_offset", "boot_uuid",
                         "kernel_continuous_time", "walltime_unix_ns",
                         "timebase_numerator", "timebase_denominator"):
            assert expected in cols, f"Missing timesync_anchors column: {expected}"

    def test_case_metadata_columns(self, conn):
        cols = {r[1] for r in conn.execute("PRAGMA table_info(case_metadata)")}
        for expected in ("case_number", "imei", "logarchive_sha256",
                         "log_file_path", "log_file_sha256",
                         "acquisition_timestamp", "tool_version"):
            assert expected in cols, f"Missing column: {expected}"

    def test_indexes_on_logs(self, conn):
        indexes = _index_names(conn)
        # The lean kept set (see schema._DDL_INDEXES).
        assert "idx_logs_timestamp_unix_ns" in indexes
        assert "idx_logs_subsystem_id"      in indexes
        assert "idx_logs_category_id"       in indexes
        assert "idx_logs_process_id"        in indexes
        assert "idx_logs_format_str_id"     in indexes
        assert "idx_logs_event_order"       in indexes
        # Deliberately dropped: low-selectivity / provenance / redundant indexes.
        for gone in ("idx_logs_timestamp_mach", "idx_logs_log_level",
                     "idx_logs_event_type", "idx_logs_boot_uuid", "idx_logs_boot_id",
                     "idx_logs_pid", "idx_logs_timestamp_iso",
                     "idx_logs_format_src_file_id", "idx_logs_timesync_file_id",
                     "idx_logs_source_order"):
            assert gone not in indexes, f"index should have been dropped: {gone}"

    def test_fts5_virtual_table_if_available(self, conn):
        tables = _table_names(conn)
        if has_fts5(conn):
            assert "logs_fts" in tables
        # If FTS5 unavailable, absence of logs_fts is acceptable

    def test_no_fts_skips_logs_fts_table(self):
        """--no-fts (enable_fts5=False) must not create logs_fts even when FTS5 is available."""
        c = sqlite3.connect(":memory:")
        apply_pragmas(c)
        init_schema(c, enable_fts5=False)
        try:
            assert "logs_fts" not in _table_names(c)
        finally:
            c.close()

    def test_no_fts_like_still_works(self):
        """Without FTS5, LIKE on the message column must still work (it uses a table scan)."""
        c = sqlite3.connect(":memory:")
        apply_pragmas(c)
        init_schema(c, enable_fts5=False)
        try:
            _insert_log(c, 1, "hello world")
            _insert_log(c, 2, "unrelated")
            c.commit()
            rows = c.execute("SELECT id FROM logs WHERE message LIKE '%hello%'").fetchall()
            assert len(rows) == 1 and rows[0][0] == 1
        finally:
            c.close()


class TestApplyPragmas:
    def test_wal_mode(self):
        c = sqlite3.connect(":memory:")
        apply_pragmas(c)
        mode = c.execute("PRAGMA journal_mode").fetchone()[0]
        # In-memory DBs may report "memory" even after WAL pragma — both are acceptable
        assert mode in ("wal", "memory")
        c.close()

    def test_foreign_keys_on(self):
        c = sqlite3.connect(":memory:")
        apply_pragmas(c)
        fk = c.execute("PRAGMA foreign_keys").fetchone()[0]
        assert fk == 1
        c.close()

    def test_wal_autocheckpoint_raised(self):
        # On-memory DBs accept the pragma; the value must match our config so the
        # WAL is checkpointed far less often than SQLite's 1000-page default.
        c = sqlite3.connect(":memory:")
        apply_pragmas(c)
        assert c.execute("PRAGMA wal_autocheckpoint").fetchone()[0] == WAL_AUTOCHECKPOINT_PAGES

    def test_synchronous_default_safe_vs_fast(self):
        # 0=OFF, 1=NORMAL, 2=FULL. Default must be safe (NORMAL); OFF is opt-in.
        c = sqlite3.connect(":memory:")
        apply_pragmas(c)
        assert c.execute("PRAGMA synchronous").fetchone()[0] == 1  # NORMAL
        apply_pragmas(c, synchronous="OFF")
        assert c.execute("PRAGMA synchronous").fetchone()[0] == 0  # OFF
        c.close()

    def test_invalid_synchronous_rejected(self):
        c = sqlite3.connect(":memory:")
        with pytest.raises(ValueError):
            apply_pragmas(c, synchronous="SOMETIMES")
        c.close()


class TestDeferredIndexes:
    def test_create_indexes_false_defers_then_finalize_builds(self):
        c = sqlite3.connect(":memory:")
        apply_pragmas(c)
        init_schema(c, create_indexes=False)
        idx = {r[0] for r in c.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_logs_%'"
        )}
        assert idx == set(), "indexes should be deferred"

        from forensic_aul.engine.database.schema import finalize_indexes
        finalize_indexes(c)
        idx = {r[0] for r in c.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_logs_%'"
        )}
        assert "idx_logs_event_order" in idx and "idx_logs_process_id" in idx
        # temp_store restored to MEMORY (2) after the build.
        assert c.execute("PRAGMA temp_store").fetchone()[0] == 2
        c.close()
        c.close()


class TestHasFts5:
    def test_returns_bool(self, conn):
        result = has_fts5(conn)
        assert isinstance(result, bool)


class TestDeferredFts:
    """The --fast-fts path: bulk-load without triggers, then rebuild once."""

    def _fresh(self, *, defer: bool):
        c = sqlite3.connect(":memory:")
        apply_pragmas(c)
        ok = init_schema(c, defer_fts_triggers=defer)
        if not ok:
            c.close()
            pytest.skip("FTS5 unavailable in this SQLite build")
        return c

    def test_default_creates_triggers(self):
        c = self._fresh(defer=False)
        assert "logs_ai" in _trigger_names(c)
        c.close()

    def test_deferred_skips_triggers_until_finalize(self):
        c = self._fresh(defer=True)
        assert "logs_ai" not in _trigger_names(c)

        _insert_log(c, 1, "hello world")
        c.commit()
        # Without triggers and before the rebuild, the index is empty.
        n = c.execute("SELECT count(*) FROM logs_fts WHERE logs_fts MATCH 'hello'").fetchone()[0]
        assert n == 0

        finalize_deferred_fts(c)
        # Rebuild populates the index and installs the triggers.
        n = c.execute("SELECT count(*) FROM logs_fts WHERE logs_fts MATCH 'hello'").fetchone()[0]
        assert n == 1
        assert "logs_ai" in _trigger_names(c)

        # Triggers now keep the index live for subsequent inserts.
        _insert_log(c, 2, "second message")
        c.commit()
        n = c.execute("SELECT count(*) FROM logs_fts WHERE logs_fts MATCH 'second'").fetchone()[0]
        assert n == 1
        c.close()
