"""Unit tests for the core summary + verify logic (moved out of the CLI handlers)."""

from __future__ import annotations

import sqlite3

import pytest

from forensic_aul.engine.integrity import compute_sha256, seal_log_file
from forensic_aul.engine.database.schema import apply_pragmas, init_schema
from forensic_aul.ops.summary.cache import clear_summary, load_summary, store_summary
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


def test_summarise_full_facets(tmp_path):
    """facets carry every value; the top-N lists are slices of them."""
    db = tmp_path / "facets.db"
    _extract_db(db)
    s = summarise(db, top=1, buckets=10)
    # top=1 truncates the visible list but never the facet behind it.
    assert [t.name for t in s.top_processes] == ["syslogd"]
    assert [t.name for t in s.facets["process"]] == ["syslogd", "locationd"]
    assert dict((t.name, t.count) for t in s.facets["process"]) == {
        "syslogd": 2, "locationd": 1,
    }
    assert set(s.facets) == {"process", "subsystem", "category", "level"}
    # Every row has a level and none has a subsystem/category in this fixture.
    assert [t.name for t in s.facets["level"]] == ["Default"]
    assert s.facets["subsystem"] == []


# ── summary cache ─────────────────────────────────────────────────────────────

def test_summary_cache_round_trip(tmp_path):
    db = tmp_path / "cached.db"
    _extract_db(db)
    original = summarise(db, top=5, buckets=10)

    conn = sqlite3.connect(str(db))
    store_summary(conn, original, top=5, buckets=10)
    conn.commit()
    conn.close()

    restored = load_summary(db)
    assert restored is not None
    assert restored.case_number == original.case_number
    assert restored.total_entries == original.total_entries
    assert restored.range_min_ns == original.range_min_ns
    assert restored.range_seconds == original.range_seconds
    assert [(t.name, t.count) for t in restored.top_processes] == \
           [(t.name, t.count) for t in original.top_processes]
    assert {k: [(t.name, t.count) for t in v] for k, v in restored.facets.items()} == \
           {k: [(t.name, t.count) for t in v] for k, v in original.facets.items()}
    assert restored.histogram_bucket_ns == original.histogram_bucket_ns
    assert [(b.start_unix_ns, b.total, b.annotated) for b in restored.histogram] == \
           [(b.start_unix_ns, b.total, b.annotated) for b in original.histogram]


def test_load_summary_absent_returns_none(tmp_path):
    """A database extracted before the cache existed reports "not evaluated"."""
    db = tmp_path / "uncached.db"
    _extract_db(db)
    assert load_summary(db) is None


def test_load_summary_ignores_unreadable_payload(tmp_path):
    """A payload from an incompatible version degrades to None, never raises."""
    db = tmp_path / "corrupt.db"
    _extract_db(db)
    conn = sqlite3.connect(str(db))
    store_summary(conn, summarise(db), top=5, buckets=10)
    conn.execute("UPDATE summary_cache SET payload = '{\"nope\": 1}' WHERE id = 1")
    conn.commit()
    conn.close()
    assert load_summary(db) is None


def test_clear_summary(tmp_path):
    db = tmp_path / "cleared.db"
    _extract_db(db)
    conn = sqlite3.connect(str(db))
    store_summary(conn, summarise(db), top=5, buckets=10)
    conn.commit()
    assert load_summary(conn) is not None
    clear_summary(conn)
    assert load_summary(conn) is None
    # Clearing a database that never had the table is a no-op, not an error.
    conn.close()


def test_summary_cache_is_single_row(tmp_path):
    """A second store REPLACEs the first — two disagreeing summaries cannot exist."""
    db = tmp_path / "single.db"
    _extract_db(db)
    conn = sqlite3.connect(str(db))
    summary = summarise(db)
    store_summary(conn, summary, top=5, buckets=10)
    store_summary(conn, summary, top=9, buckets=99)
    conn.commit()
    assert conn.execute("SELECT COUNT(*) FROM summary_cache").fetchone()[0] == 1
    assert conn.execute("SELECT params FROM summary_cache").fetchone()[0] == \
           '{"top":9,"buckets":99}'
    conn.close()


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


# ── Unresolved timestamps in the summary (review item L8) ─────────────────────

def _db_with_unresolved(path, n: int = 2):
    """The standard fixture plus *n* entries whose timestamp never resolved."""
    _extract_db(path)
    conn = sqlite3.connect(str(path))
    for i in range(n):
        conn.execute(
            "INSERT INTO logs(id, timestamp_unix_ns, timestamp_mach, message, process_id) "
            "VALUES (?, 0, 0, ?, 1)",
            (100 + i, f"unresolved {i}"),
        )
    conn.commit()
    conn.close()


def test_summary_counts_unresolved_timestamps(tmp_path):
    db = tmp_path / "unresolved.db"
    _db_with_unresolved(db, n=2)
    s = summarise(db)
    assert s.unresolved_timestamps == 2
    # They are part of the corpus…
    assert s.total_entries == 5
    # …but cannot be placed on a timeline, so they are absent from both the
    # wall-clock range and the histogram. Without unresolved_timestamps a reader
    # could not explain why those two figures disagree with the total.
    assert sum(b.total for b in s.histogram) == 3
    assert s.range_min_ns > 0


def test_summary_range_is_not_dragged_to_1970(tmp_path):
    db = tmp_path / "unresolved.db"
    _db_with_unresolved(db, n=1)
    s = summarise(db)
    assert s.log_start_time == "2024-01-15T12:00:01Z"   # from case_metadata
    assert s.range_seconds == 2.0                        # 3 resolved rows, 1s apart


def test_unresolved_count_is_zero_on_a_clean_database(tmp_path):
    db = tmp_path / "clean.db"
    _extract_db(db)
    assert summarise(db).unresolved_timestamps == 0


def test_unresolved_count_round_trips_through_the_cache(tmp_path):
    db = tmp_path / "cached.db"
    _db_with_unresolved(db, n=3)
    conn = sqlite3.connect(str(db))
    store_summary(conn, summarise(db), top=5, buckets=10)
    conn.commit()
    conn.close()
    assert load_summary(db).unresolved_timestamps == 3


def test_report_states_the_unresolved_count(tmp_path):
    """It has to be said in the report, not left for the analyst to infer."""
    from forensic_aul.ops.summary.report import format_summary

    db = tmp_path / "unresolved.db"
    _db_with_unresolved(db, n=1)
    text = format_summary(summarise(db))
    assert "Unresolved" in text
    assert "1 entry" in text            # inflected
    # And says what the consequence is.
    assert "time-filtered export" in text

    clean = tmp_path / "clean.db"
    _extract_db(clean)
    assert "Unresolved" not in format_summary(summarise(clean))


# ── A global-hash mismatch says WHICH kind of change it is ────────────────────
#
# The global hash covers each file's relative path AND its content digest, so a
# mismatch means one of the two moved. On the check most likely to be read as
# tampering, "mismatch" alone leaves that distinction to the reader.

def _archive_and_db(tmp_path, *, stored_sha, name="x"):
    """A real logarchive plus a database whose source_files hashes match it."""
    from forensic_aul.engine.integrity import compute_sha256

    arch = tmp_path / f"{name}.logarchive"
    (arch / "Persist").mkdir(parents=True, exist_ok=True)
    payload = arch / "Persist" / "0.tracev3"
    payload.write_bytes(b"payload")

    db = tmp_path / f"{name}.db"
    _extract_db(db, logarchive_sha=stored_sha, logarchive_path=str(arch))
    conn = sqlite3.connect(str(db))
    conn.execute(
        "INSERT INTO source_files(file_path, file_type, sha256, parsed_at) "
        "VALUES (?,?,?,?)",
        ("Persist/0.tracev3", "tracev3", compute_sha256(payload),
         "2024-01-15T00:00:00Z"),
    )
    conn.commit()
    conn.close()
    return db, arch


def _global_check(result):
    return next(c for c in result.checks if c.label == "logarchive global SHA-256")


def test_content_change_is_named_as_a_content_change(tmp_path):
    db, arch = _archive_and_db(tmp_path, stored_sha="deadbeef" * 8, name="t")
    (arch / "Persist" / "0.tracev3").write_bytes(b"tampered")
    detail = _global_check(verify_database(db)).detail
    assert "changed content" in detail


def test_rename_is_named_as_a_path_change_not_a_content_change(tmp_path):
    """A renamed file: content intact, no longer where the database says."""
    db, arch = _archive_and_db(tmp_path, stored_sha="deadbeef" * 8, name="r")
    (arch / "Persist" / "0.tracev3").rename(arch / "Persist" / "renamed.tracev3")
    detail = _global_check(verify_database(db)).detail
    assert "content is intact" in detail
    assert "no longer at their recorded path" in detail
    assert "changed content" not in detail


def test_unrecorded_file_change_says_the_shape_differs(tmp_path):
    """Every recorded digest matches, so the difference is a path or an extra file.

    hash_logarchive covers every file in the tree; source_files records only the
    ones that were parsed, so an unparsed file can move the global hash while
    every per-file check still passes.
    """
    db, arch = _archive_and_db(tmp_path, stored_sha="deadbeef" * 8, name="u")
    (arch / "Info.plist").write_bytes(b"not parsed, but hashed")
    detail = _global_check(verify_database(db)).detail
    assert "every recorded file's content matches" in detail
    assert "did not record" in detail


def test_skip_files_says_it_cannot_tell(tmp_path):
    """Without the per-file evidence, verify must not guess either way."""
    db, _ = _archive_and_db(tmp_path, stored_sha="deadbeef" * 8, name="s")
    detail = _global_check(verify_database(db, skip_files=True)).detail
    assert "--skip-files" in detail
    assert "renamed or moved" in detail


def test_matching_global_hash_still_passes(tmp_path):
    from forensic_aul.engine.integrity import hash_logarchive

    db, arch = _archive_and_db(tmp_path, stored_sha="placeholder", name="m")
    real_sha, _ = hash_logarchive(arch)
    db, _ = _archive_and_db(tmp_path, stored_sha=real_sha, name="m2")
    assert _global_check(verify_database(db)).status == "ok"


def test_moving_the_archive_does_not_change_its_hash(tmp_path):
    """Paths are relative to the root, so relocating a whole case is safe."""
    import shutil

    from forensic_aul.engine.integrity import hash_logarchive

    _, arch = _archive_and_db(tmp_path, stored_sha="placeholder", name="mv")
    before, _ = hash_logarchive(arch)
    moved = tmp_path / "elsewhere" / "deep" / "mv.logarchive"
    moved.parent.mkdir(parents=True)
    shutil.move(str(arch), str(moved))
    assert hash_logarchive(moved)[0] == before


def test_a_moved_archive_verifies_via_the_override(tmp_path):
    """After a move the stored absolute path is stale; --logarchive still works."""
    import shutil

    from forensic_aul.engine.integrity import hash_logarchive

    _, probe = _archive_and_db(tmp_path, stored_sha="placeholder", name="p")
    real_sha, _ = hash_logarchive(probe)
    db, arch = _archive_and_db(tmp_path, stored_sha=real_sha, name="q")
    moved = tmp_path / "moved" / "q.logarchive"
    moved.parent.mkdir()
    shutil.move(str(arch), str(moved))

    # Without the override the archive cannot be located at all — a distinct
    # check from a hash mismatch, and it must not be reported as one.
    stale = verify_database(db)
    missing = next(c for c in stale.checks if c.label == "logarchive hash")
    assert missing.status == "fail" and "directory missing" in missing.detail
    assert not any(c.label == "logarchive global SHA-256" for c in stale.checks)

    # Pointed at the new location, the hash still matches: the move changed
    # nothing inside the archive.
    assert _global_check(verify_database(db, logarchive=moved)).status == "ok"
