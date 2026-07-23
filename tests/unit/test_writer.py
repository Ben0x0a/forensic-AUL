"""Tests for forensic_aul.engine.database.writer — BatchWriter."""

import json
import sqlite3
import pytest
from forensic_aul.engine.database.writer import BatchWriter
from forensic_aul.engine.database.schema import apply_pragmas, init_schema


def _row_count(conn: sqlite3.Connection, table: str) -> int:
    return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


class TestLookupTables:
    def test_get_or_insert_process_deduplication(self, writer):
        id1 = writer.get_or_insert_process("syslogd")
        id2 = writer.get_or_insert_process("syslogd")
        assert id1 == id2

    def test_get_or_insert_process_two_different(self, writer):
        id1 = writer.get_or_insert_process("proc_a")
        id2 = writer.get_or_insert_process("proc_b")
        assert id1 != id2

    def test_get_or_insert_subsystem(self, writer):
        sid = writer.get_or_insert_subsystem("com.apple.system")
        assert isinstance(sid, int)
        assert writer.get_or_insert_subsystem("com.apple.system") == sid

    def test_get_or_insert_category(self, writer):
        cid = writer.get_or_insert_category("syslog")
        assert writer.get_or_insert_category("syslog") == cid

    def test_get_or_insert_format_str(self, writer):
        fid = writer.get_or_insert_format_str("Hello %s!")
        assert writer.get_or_insert_format_str("Hello %s!") == fid

    def test_get_or_insert_library(self, writer):
        lid = writer.get_or_insert_library("/usr/lib/libSystem.B.dylib", "DEADBEEF" * 4)
        lid2 = writer.get_or_insert_library("/usr/lib/libSystem.B.dylib", "DEADBEEF" * 4)
        assert lid == lid2

    def test_library_different_uuid_different_id(self, writer):
        lid1 = writer.get_or_insert_library("/usr/lib/libFoo.dylib", "AAAA" * 8)
        lid2 = writer.get_or_insert_library("/usr/lib/libFoo.dylib", "BBBB" * 8)
        assert lid1 != lid2


class TestInsertSourceFile:
    def test_returns_int(self, writer):
        fid = writer.insert_source_file("Persist/log.tracev3", "tracev3", "abc123", 1024)
        assert isinstance(fid, int)
        assert fid > 0

    def test_idempotent(self, writer):
        # INSERT OR IGNORE — second call returns same id
        fid1 = writer.insert_source_file("x.tracev3", "tracev3", "hash1", 100)
        fid2 = writer.insert_source_file("x.tracev3", "tracev3", "hash1", 100)
        assert fid1 == fid2


class TestBatchWrite:
    def test_add_single_entry_commits_on_flush(self, conn, sample_log_entry):
        w = BatchWriter(conn, batch_size=10)
        w.add(sample_log_entry)
        assert _row_count(conn, "logs") == 0  # not yet flushed
        w.flush()
        assert _row_count(conn, "logs") == 1

    def test_batch_flush_on_threshold(self, conn, sample_log_entry):
        w = BatchWriter(conn, batch_size=3)
        for _ in range(3):
            w.add(sample_log_entry)
        # Should have auto-flushed at batch_size=3
        assert _row_count(conn, "logs") == 3

    def test_add_batch(self, conn, sample_log_entry):
        w = BatchWriter(conn, batch_size=100)
        w.add_batch([sample_log_entry] * 5)
        w.flush()
        assert _row_count(conn, "logs") == 5

    def test_to_row_length(self, writer, sample_log_entry):
        # 26 positional parameters: the four normalised columns (log_level_id,
        # event_type_id, process_uuid_id, boot_id) plus all the rest, with the
        # derived timestamp_iso column no longer stored.
        row = writer._to_row(sample_log_entry)
        assert len(row) == 26

    def test_to_row_normalises_lookups(self, writer, sample_log_entry):
        # The repeated strings map to lookup ids; the seeded enums resolve to a
        # stable id, and boot/process_uuid are inserted on demand.
        row = writer._to_row(sample_log_entry)
        level_id = writer.get_or_insert_log_level("Default")
        event_id = writer.get_or_insert_event_type("Log")
        assert level_id in row and event_id in row

    def test_raw_data_none_stored_as_null(self, conn, sample_log_entry):
        sample_log_entry.raw_data = None
        w = BatchWriter(conn, batch_size=1)
        w.add(sample_log_entry)
        row = conn.execute("SELECT raw_data FROM logs LIMIT 1").fetchone()
        assert row[0] is None

    def test_raw_data_json_stored_as_string(self, conn, sample_log_entry):
        sample_log_entry.raw_data = json.dumps([{"type": "0x22", "size": 4, "value": "test"}])
        w = BatchWriter(conn, batch_size=1)
        w.add(sample_log_entry)
        row = conn.execute("SELECT raw_data FROM logs LIMIT 1").fetchone()
        assert row[0] is not None
        parsed = json.loads(row[0])
        assert parsed[0]["value"] == "test"

    def test_u64_activity_id_does_not_overflow_and_round_trips(self, conn, sample_log_entry):
        # A statedump activity_id is a genuine u64 and may have bit 63 set (an
        # Apple flag), e.g. 0x80000000000015C5 — larger than SQLite's signed
        # INTEGER max. It must store without OverflowError (the bug that crashed
        # the parallel path and silently dropped batches in the serial path) and
        # recover bit-for-bit with ``value & 0xFFFFFFFFFFFFFFFF``.
        u64 = 0x80000000000015C5
        assert u64 > 2**63 - 1                      # outside signed int64 range
        sample_log_entry.activity_id = u64
        sample_log_entry.parent_activity_id = 0xFFFFFFFFFFFFFFFF
        w = BatchWriter(conn, batch_size=1)
        w.add(sample_log_entry)                     # must not raise OverflowError
        row = conn.execute(
            "SELECT activity_id, parent_activity_id FROM logs LIMIT 1"
        ).fetchone()
        assert row[0] & 0xFFFFFFFFFFFFFFFF == u64
        assert row[1] & 0xFFFFFFFFFFFFFFFF == 0xFFFFFFFFFFFFFFFF

    def test_small_activity_id_is_unchanged(self, conn, sample_log_entry):
        # Common case (u32 / 0) is in signed range → stored verbatim, not folded.
        sample_log_entry.activity_id = 0x15C5
        w = BatchWriter(conn, batch_size=1)
        w.add(sample_log_entry)
        row = conn.execute("SELECT activity_id FROM logs LIMIT 1").fetchone()
        assert row[0] == 0x15C5


class TestWriteResilience:
    """A single unstorable row must never discard the batch or be lost silently."""

    def _rows(self, base, n):
        import dataclasses
        return [dataclasses.replace(base, message=f"row{i}") for i in range(n)]

    def test_one_bad_row_keeps_the_rest_and_counts_it(self, conn, sample_log_entry):
        # timestamp_mach is u64 but NOT folded (it is an ordered magnitude), so a
        # top-bit-set value is genuinely unstorable — the exact "unforeseen value"
        # the safety net exists for.
        import dataclasses
        entries = self._rows(sample_log_entry, 5)
        entries[2] = dataclasses.replace(entries[2], timestamp_mach=2**63)
        w = BatchWriter(conn, batch_size=100)
        w.add_batch(entries)
        w.flush()                                   # must not raise
        msgs = [r[0] for r in conn.execute("SELECT message FROM logs ORDER BY message")]
        # All four good rows present exactly once (no whole-batch loss, and the
        # rows executemany applied before failing are not double-inserted) …
        assert msgs == ["row0", "row1", "row3", "row4"]
        # … and the one bad row is accounted for, not silently dropped.
        assert w.write_errors == 1

    def test_bad_first_row_still_inserts_the_rest(self, conn, sample_log_entry):
        import dataclasses
        entries = self._rows(sample_log_entry, 3)
        entries[0] = dataclasses.replace(entries[0], timestamp_mach=2**63)
        w = BatchWriter(conn, batch_size=100)
        w.add_batch(entries)
        w.flush()
        msgs = [r[0] for r in conn.execute("SELECT message FROM logs ORDER BY message")]
        assert msgs == ["row1", "row2"]
        assert w.write_errors == 1

    def test_clean_batch_has_no_write_errors(self, conn, sample_log_entry):
        w = BatchWriter(conn, batch_size=100)
        w.add_batch(self._rows(sample_log_entry, 4))
        w.flush()
        assert w.write_errors == 0
        assert conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0] == 4

    def test_lookup_rows_survive_the_fallback(self, conn, sample_log_entry):
        # The savepoint must roll back only the partial log rows, not the
        # lookup-table inserts made earlier in the same transaction — otherwise the
        # surviving rows would reference processes/subsystems that no longer exist.
        import dataclasses
        entries = self._rows(sample_log_entry, 3)
        entries[1] = dataclasses.replace(entries[1], timestamp_mach=2**63)
        w = BatchWriter(conn, batch_size=100)
        w.add_batch(entries)
        w.flush()
        # The good rows resolve their process via a real processes row (join works).
        n = conn.execute(
            "SELECT COUNT(*) FROM logs l JOIN processes p ON l.process_id = p.id"
        ).fetchone()[0]
        assert n == 2


class TestCaseMetadata:
    def test_insert_returns_rowid(self, writer):
        mid = writer.insert_case_metadata(case_number="CASE-001", imei="123456789012345")
        assert isinstance(mid, int)
        assert mid > 0

    def test_update_log_hash(self, conn, writer):
        mid = writer.insert_case_metadata(case_number="TEST")
        conn.commit()
        writer.update_case_metadata(mid, log_file_path="/tmp/test.log", log_file_sha256="deadbeef")
        conn.commit()
        row = conn.execute(
            "SELECT log_file_path, log_file_sha256 FROM case_metadata WHERE id = ?", (mid,)
        ).fetchone()
        assert row[0] == "/tmp/test.log"
        assert row[1] == "deadbeef"

    def test_update_with_no_fields_is_noop(self, conn, writer):
        mid = writer.insert_case_metadata(case_number="TEST")
        conn.commit()
        # Should not raise, should not modify anything
        writer.update_case_metadata(mid)


class TestRegisterBoot:
    def test_register_boot_known_rank(self, conn, writer):
        bid = writer.register_boot("AABBCCDD", rank=0)
        assert isinstance(bid, int) and bid > 0
        row = conn.execute("SELECT rank FROM boots WHERE boot_uuid = ?", ("AABBCCDD",)).fetchone()
        assert row[0] == 0

    def test_register_boot_idempotent(self, writer):
        bid1 = writer.register_boot("UUID1111", rank=5)
        bid2 = writer.register_boot("UUID1111", rank=5)
        assert bid1 == bid2

    def test_get_or_insert_boot_unknown_uses_unknown_rank(self, conn, writer):
        from forensic_aul.engine.database.schema import UNKNOWN_BOOT_RANK

        # UUID never registered via register_boot — should be inserted with UNKNOWN_BOOT_RANK.
        bid = writer.get_or_insert_boot("NEVERKNOWN")
        assert isinstance(bid, int) and bid > 0
        row = conn.execute("SELECT rank FROM boots WHERE boot_uuid = ?", ("NEVERKNOWN",)).fetchone()
        assert row[0] == UNKNOWN_BOOT_RANK

    def test_get_or_insert_boot_hit_returns_cached(self, writer):
        # Pre-register with rank 3, then get_or_insert_boot should return the same id.
        bid_reg = writer.register_boot("PREKNOWN", rank=3)
        bid_get = writer.get_or_insert_boot("PREKNOWN")
        assert bid_reg == bid_get

    def test_unknown_rank_sorts_after_known(self, conn, writer):
        from forensic_aul.engine.database.schema import UNKNOWN_BOOT_RANK

        writer.register_boot("FIRST", rank=0)
        writer.register_boot("SECOND", rank=1)
        writer.get_or_insert_boot("ORPHAN")
        rows = {
            r[0]: r[1]
            for r in conn.execute("SELECT boot_uuid, rank FROM boots")
        }
        assert rows["ORPHAN"] == UNKNOWN_BOOT_RANK
        assert rows["ORPHAN"] > rows["FIRST"]
        assert rows["ORPHAN"] > rows["SECOND"]
