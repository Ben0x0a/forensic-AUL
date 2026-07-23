"""Unit tests for the core summary + verify logic (moved out of the CLI handlers)."""

from __future__ import annotations

import sqlite3

import pytest

from forensic_aul.engine.integrity import compute_sha256, seal_log_file
from forensic_aul.engine.database.schema import apply_pragmas, init_schema
from forensic_aul.ops.summary.summary import Summary, summarise
from forensic_aul.engine.utils.time import parse_duration_seconds
from forensic_aul.ops.verify.verify import verify_database

_BASE_NS = 1_705_320_001_000_000_000


def _extract_db(path, *, logarchive_sha=None, logarchive_path=None) -> None:
    conn = sqlite3.connect(str(path))
    apply_pragmas(conn)
    init_schema(conn)
    conn.execute("INSERT INTO processes(id, name) VALUES (1, 'syslogd'), (2, 'locationd')")
    conn.execute(
        "INSERT INTO case_metadata(case_number, imei, ios_model, log_start_time, "
        "log_end_time, logarchive_path, logarchive_sha256, acquisition_timestamp, tool_version) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        ("C1", "0", "iPhone", "2024-01-15T12:00:01Z", "2024-01-15T12:00:03Z",
         logarchive_path, logarchive_sha, "2024-01-15T00:00:00Z", "0.1.0"),
    )
    for i, proc in ((1, 1), (2, 2), (3, 1)):
        conn.execute(
            "INSERT INTO logs(id, timestamp_unix_ns, timestamp_mach, "
            "log_level_id, message, process_id) "
            "VALUES (?,?,?,(SELECT id FROM log_levels WHERE name=?),?,?)",
            (i, _BASE_NS + i * 1_000_000_000, i * 1000,
             "Default", f"m{i}", proc),
        )
    conn.commit()
    conn.close()


# ── parse_duration_seconds (now a single shared core util) ────────────────────

@pytest.mark.parametrize("value,seconds", [
    ("30s", 30), ("10m", 600), ("1h", 3600), ("2d", 172800), ("1.5h", 5400),
])
def test_parse_duration(value, seconds):
    assert parse_duration_seconds(value) == seconds


@pytest.mark.parametrize("value", ["", "10x", "abc", "10"])
def test_parse_duration_bad(value):
    assert parse_duration_seconds(value) is None


# ── summary ───────────────────────────────────────────────────────────────────

def test_summarise_basic(tmp_path):
    db = tmp_path / "a.db"
    _extract_db(db)
    s = summarise(db, top=5, buckets=10)
    assert isinstance(s, Summary)
    assert s.case_number == "C1"
    assert s.total_entries == 3
    # syslogd (2 rows) ranks above locationd (1 row).
    assert [t.name for t in s.top_processes] == ["syslogd", "locationd"]
    assert s.top_processes[0].count == 2
    assert s.histogram and sum(b.total for b in s.histogram) == 3


def test_summarise_not_extract_db(tmp_path):
    db = tmp_path / "empty.db"
    sqlite3.connect(str(db)).close()  # no case_metadata table at all
    with pytest.raises(Exception):
        summarise(db)


# ── verify ────────────────────────────────────────────────────────────────────

def test_verify_logarchive_match(tmp_path):
    # Build a tiny logarchive dir and store its real hash, then verify.
    arch = tmp_path / "x.logarchive"
    arch.mkdir()
    (arch / "Info.plist").write_bytes(b"hello")
    from forensic_aul.engine.integrity import hash_logarchive
    global_sha, _ = hash_logarchive(arch)

    db = tmp_path / "a.db"
    _extract_db(db, logarchive_sha=global_sha, logarchive_path=str(arch))
    res = verify_database(db, skip_files=True)
    assert res.ok
    assert any(c.label.startswith("logarchive global") and c.status == "ok" for c in res.checks)


def test_verify_logarchive_mismatch(tmp_path):
    arch = tmp_path / "x.logarchive"
    arch.mkdir()
    (arch / "Info.plist").write_bytes(b"hello")
    db = tmp_path / "a.db"
    _extract_db(db, logarchive_sha="deadbeef" * 8, logarchive_path=str(arch))
    res = verify_database(db, skip_files=True)
    assert not res.ok and res.failed >= 1


# ── seal_log_file ─────────────────────────────────────────────────────────────

def test_seal_log_file_stores_digest(tmp_path):
    db = tmp_path / "a.db"
    _extract_db(db)
    mid = sqlite3.connect(str(db)).execute("SELECT id FROM case_metadata").fetchone()[0]
    logf = tmp_path / "session.log"
    logf.write_text("audit trail\n")

    digest = seal_log_file(db, logf, mid)
    assert digest == compute_sha256(logf)
    stored = sqlite3.connect(str(db)).execute(
        "SELECT log_file_sha256 FROM case_metadata WHERE id=?", (mid,)).fetchone()[0]
    assert stored == digest


def test_seal_log_file_no_metadata_id(tmp_path):
    db = tmp_path / "a.db"
    _extract_db(db)
    logf = tmp_path / "session.log"
    logf.write_text("x")
    # metadata_id None → returns digest but does not write.
    assert seal_log_file(db, logf, None) == compute_sha256(logf)
