"""Integration tests — full extract pipeline on the real logarchive.

These tests are skipped automatically if the logarchive is not present in
tests/data/. They exercise the complete stack end-to-end and serve as the
primary regression guard when changing parser or writer code.

Run only integration tests:
    pytest tests/integration/ -v

Skip integration tests (fast mode):
    pytest tests/ -v -m "not integration"
"""

import sqlite3
from pathlib import Path

import pytest

from forensic_aul.engine.database.schema import EVENT_TYPE_NAMES, LOG_LEVEL_NAMES
from forensic_aul.ops.extraction.extract import run_extract
from forensic_aul.ops.summary.cache import load_summary

# ── Test data paths ────────────────────────────────────────────────────────────

_TESTS       = Path(__file__).parent.parent
_LOGARCHIVE  = _TESTS / "data"  / "iphoneSE_afterbackup.logarchive"
_NDJSON      = _TESTS / "results" / "expected" / "iphoneSE_afterbackup.ndjson"

pytestmark = pytest.mark.integration


# ── Skip guard ─────────────────────────────────────────────────────────────────

def _require_logarchive():
    if not _LOGARCHIVE.is_dir():
        pytest.skip(f"Logarchive not found: {_LOGARCHIVE}")


# ── Fixture: run extract once per session ─────────────────────────────────────

@pytest.fixture(scope="module")
def extracted_db(tmp_path_factory):
    """Run extract once and return the path to the resulting SQLite database."""
    _require_logarchive()
    db_path = tmp_path_factory.mktemp("extract") / "test_extract.db"
    run_extract(
        logarchive=_LOGARCHIVE,
        db_path=db_path,
        case_number="TEST-INTEGRATION",
        imei="000000000000000",
        notes="pytest integration run",
        batch_size=500,
    )
    return db_path


@pytest.fixture(scope="module")
def db_conn(extracted_db):
    c = sqlite3.connect(str(extracted_db))
    c.row_factory = sqlite3.Row
    yield c
    c.close()


# ── Schema sanity ──────────────────────────────────────────────────────────────

class TestSchema:
    def test_logs_table_exists(self, db_conn):
        tables = {r[0] for r in db_conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        assert "logs" in tables

    def test_all_lookup_tables_exist(self, db_conn):
        tables = {r[0] for r in db_conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        for t in ("processes", "subsystems", "categories", "libraries",
                  "format_strs", "source_files", "case_metadata"):
            assert t in tables, f"Missing table: {t}"


# ── Summary statistics cached at extract time ──────────────────────────────────

class TestSummaryCache:
    """Extract computes the summary once and stores it; readers never recompute."""

    def test_summary_cache_written(self, extracted_db):
        summary = load_summary(extracted_db)
        assert summary is not None, "extract did not cache a summary"
        assert summary.total_entries > 0

    def test_cached_totals_match_the_database(self, db_conn, extracted_db):
        summary = load_summary(extracted_db)
        real = db_conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        assert summary.total_entries == real

    def test_facets_are_complete_not_truncated(self, extracted_db, db_conn):
        """facets hold every distinct value, unlike the top-N display lists."""
        summary = load_summary(extracted_db)
        distinct_processes = db_conn.execute(
            "SELECT COUNT(*) FROM (SELECT DISTINCT process_id FROM logs "
            "WHERE process_id IS NOT NULL)"
        ).fetchone()[0]
        assert len(summary.facets["process"]) == distinct_processes
        assert len(summary.top_processes) <= len(summary.facets["process"])


# ── Entry counts ───────────────────────────────────────────────────────────────

class TestEntryCounts:
    def test_has_log_entries(self, db_conn):
        count = db_conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        assert count > 0, "No log entries written"

    def test_entry_count_in_expected_range(self, db_conn):
        """Rough sanity check — a real iOS logarchive has hundreds of thousands of entries."""
        count = db_conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        assert count > 1_000, f"Suspiciously low entry count: {count}"

    def test_source_files_registered(self, db_conn):
        count = db_conn.execute("SELECT COUNT(*) FROM source_files").fetchone()[0]
        assert count > 0

    def test_tracev3_source_files_present(self, db_conn):
        count = db_conn.execute(
            "SELECT COUNT(*) FROM source_files WHERE file_type = 'tracev3'"
        ).fetchone()[0]
        assert count > 0


# ── Field completeness ─────────────────────────────────────────────────────────

class TestFieldCompleteness:
    def test_timestamps_not_null(self, db_conn):
        null_count = db_conn.execute(
            "SELECT COUNT(*) FROM logs WHERE timestamp_unix_ns IS NULL"
        ).fetchone()[0]
        assert null_count == 0, f"{null_count} rows with NULL timestamp_unix_ns"

    def test_timestamp_iso_derivable(self, db_conn):
        # The ISO string is no longer stored — it is formatted on read from
        # timestamp_unix_ns; verify the helper produces a well-formed value.
        from forensic_aul.engine.utils.time import iso8601_from_unix_ns
        row = db_conn.execute(
            "SELECT timestamp_unix_ns FROM logs ORDER BY RANDOM() LIMIT 1"
        ).fetchone()
        if row:
            ts = iso8601_from_unix_ns(row[0])
            assert "T" in ts and "Z" in ts, f"Unexpected timestamp format: {ts!r}"

    def test_boot_id_present(self, db_conn):
        null_count = db_conn.execute(
            "SELECT COUNT(*) FROM logs WHERE boot_id IS NULL"
        ).fetchone()[0]
        total = db_conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        # Allow up to 1% missing boot (parse errors)
        assert null_count / total < 0.01, f"{null_count}/{total} rows missing boot_id"

    def test_event_types_are_valid(self, db_conn):
        # The schema's seeded vocabulary is the single source of truth (it grew
        # Statedump/Simpledump when those records moved into `logs`).
        valid = set(EVENT_TYPE_NAMES)
        rows = db_conn.execute(
            "SELECT DISTINCT et.name FROM logs l "
            "JOIN event_types et ON et.id = l.event_type_id"
        ).fetchall()
        for row in rows:
            assert row[0] in valid, f"Unknown event_type: {row[0]!r}"

    def test_log_levels_are_valid(self, db_conn):
        valid = set(LOG_LEVEL_NAMES)
        rows = db_conn.execute(
            "SELECT DISTINCT ll.name FROM logs l "
            "JOIN log_levels ll ON ll.id = l.log_level_id"
        ).fetchall()
        for row in rows:
            assert row[0] in valid, f"Unknown log_level: {row[0]!r}"

    def test_traceability_columns_set(self, db_conn):
        """At least 95% of rows should have tracev3_file_id set."""
        total = db_conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        with_id = db_conn.execute(
            "SELECT COUNT(*) FROM logs WHERE tracev3_file_id IS NOT NULL"
        ).fetchone()[0]
        assert with_id / total >= 0.95, \
            f"Only {with_id}/{total} rows have tracev3_file_id"


# ── Case metadata ──────────────────────────────────────────────────────────────

class TestCaseMetadata:
    def test_case_metadata_row_exists(self, db_conn):
        count = db_conn.execute("SELECT COUNT(*) FROM case_metadata").fetchone()[0]
        assert count == 1

    def test_case_number_stored(self, db_conn):
        row = db_conn.execute("SELECT case_number FROM case_metadata LIMIT 1").fetchone()
        assert row[0] == "TEST-INTEGRATION"

    def test_logarchive_sha256_stored(self, db_conn):
        row = db_conn.execute("SELECT logarchive_sha256 FROM case_metadata LIMIT 1").fetchone()
        assert row[0] is not None and len(row[0]) == 64

    def test_ios_model_populated(self, db_conn):
        row = db_conn.execute("SELECT ios_model FROM case_metadata LIMIT 1").fetchone()
        assert row[0] is not None and row[0] != ""

    def test_log_time_range_populated(self, db_conn):
        row = db_conn.execute(
            "SELECT log_start_time, log_end_time FROM case_metadata LIMIT 1"
        ).fetchone()
        assert row[0] is not None
        assert row[1] is not None
        assert row[0] <= row[1]


# ── Comparison against ndjson (if reference available) ────────────────────────

class TestComparisonAgainstReference:
    @pytest.fixture(autouse=True)
    def _require_ndjson(self):
        if not _NDJSON.is_file():
            pytest.skip(f"Reference ndjson not found: {_NDJSON}")

    @pytest.mark.xfail(
        reason="Reference ndjson was generated by 'log show' which applies default "
               "level filters (Default/Error/Fault only) and excludes Info/Debug. "
               "Our parser captures all entries (~2M vs ~258K reference), so the "
               "count intentionally diverges. This test needs a filtered reference "
               "or a pre-filtered DB query to be meaningful.",
        strict=False,
    )
    def test_entry_count_within_5_percent(self, db_conn):
        from forensic_aul.validation.ndjson_loader import load_ndjson
        ref = load_ndjson(_NDJSON)
        db_count = db_conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        delta = abs(db_count - ref.count) / max(ref.count, 1)
        assert delta < 0.05, (
            f"Entry count delta {delta:.1%} > 5%  "
            f"(ref={ref.count}, db={db_count})"
        )

    def test_timestamp_match_rate_above_90_percent(self, extracted_db):
        from forensic_aul.validation.ndjson_loader import load_ndjson
        from forensic_aul.validation.comparator import compare, load_db_records
        ref = load_ndjson(_NDJSON)
        db_records = load_db_records(extracted_db)
        report = compare(ref, db_records, max_samples=5)
        match_rate = report.matched / ref.count if ref.count else 0
        assert match_rate >= 0.90, (
            f"Timestamp match rate {match_rate:.1%} < 90%  "
            f"(matched={report.matched}, ref={ref.count})"
        )
