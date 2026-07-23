"""Unit tests for forensic_aul.ops.query — the in-memory query API.

Builds a tiny on-disk analysis database (same shape as test_export.py, plus
format strings and prefix-hostile messages) and exercises ``query_logs`` filter
by filter, the LIKE-escaping of ``message_prefix``, ``limit`` semantics, the
stable ``v_logs`` view (including its on-demand creation on a database that
predates it), and the eager/lazy error split.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from forensic_aul import LogRow, query_logs
from forensic_aul.engine.database.schema import apply_pragmas, ensure_views, init_schema
from forensic_aul.ops.annotation.matcher import init_annotation_schema

# Wall-clock base: 2024-01-15T12:00:01Z, in nanoseconds since the Unix epoch.
_BASE_NS = 1_705_320_001_000_000_000


def _make_db(path: Path, *, with_kb: bool = False, annotate: bool = False) -> None:
    """Create a populated analysis DB at *path* (4 logs, 2 processes).

    Row 4 carries a message containing LIKE metacharacters so the
    ``message_prefix`` escaping can be asserted; rows 1/3 share a format string.
    """
    conn = sqlite3.connect(str(path))
    apply_pragmas(conn)
    init_schema(conn)

    conn.executemany("INSERT INTO processes(id, name) VALUES (?, ?)",
                     [(1, "syslogd"), (2, "locationd")])
    conn.executemany("INSERT INTO subsystems(id, name) VALUES (?, ?)",
                     [(1, "com.apple.system"), (2, "com.apple.locationd")])
    conn.executemany("INSERT INTO categories(id, name) VALUES (?, ?)",
                     [(1, "syslog"), (2, "loc")])
    conn.execute("INSERT INTO format_strs(id, value) VALUES (1, 'Hello %@')")
    # Minimal case_metadata row so summary/overview consumers of this fixture
    # (e.g. the Exploit screen tests) can call summarise() on it.
    conn.execute(
        "INSERT INTO case_metadata(case_number, imei, acquisition_timestamp, tool_version) "
        "VALUES ('CASE-T', '35600', '2024-01-15T00:00:00Z', 'test')"
    )

    # (id, unix_ns, mach, pid, tid, level, event_type, message, proc, subsys, cat, fmt)
    rows = [
        (1, _BASE_NS + 0,             1000, 42, 101,
         "Default", "Log", "Hello world",          1, 1, 1, 1),
        (2, _BASE_NS + 1_000_000_000, 2000, 55, 102,
         "Error",   "Log", "Location updated",     2, 2, 2, None),
        (3, _BASE_NS + 2_000_000_000, 3000, 42, 103,
         "Info",    "Log", "Hello again",          1, 1, 1, 1),
        # LIKE metacharacters in the message: a literal "100%" and "_x".
        (4, _BASE_NS + 3_000_000_000, 4000, 42, 104,
         "Default", "Log", "progress 100%_x done", 1, 1, 1, None),
    ]
    conn.executemany(
        "INSERT INTO logs(id, timestamp_unix_ns, timestamp_mach, "
        "pid, tid, log_level_id, event_type_id, message, process_id, subsystem_id, "
        "category_id, format_str_id) "
        "VALUES (?, ?, ?, ?, ?, "
        "(SELECT id FROM log_levels WHERE name=?), "
        "(SELECT id FROM event_types WHERE name=?), ?, ?, ?, ?, ?)",
        rows,
    )

    if with_kb:
        init_annotation_schema(conn)
        conn.execute(
            "INSERT INTO kb_signatures(id, signature_id, action, description, confidence, "
            "tags, source_file, kb_version, kb_sha256, applied_at, match_count) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (1, "loc.update", "Location was updated", "desc", "high",
             json.dumps(["location", "privacy"]), "loc.yaml", "1.0.0", "deadbeef",
             "2024-01-15T00:00:00+00:00", 1),
        )
        if annotate:
            conn.execute(
                "INSERT INTO log_annotations(id, log_id, kb_signature_id) VALUES (1, 2, 1)",
            )
            conn.executemany(
                "INSERT INTO extracted_values(log_annotation_id, label, value) VALUES (?, ?, ?)",
                [(1, "lat", "48.8"), (1, "lon", "2.3")],
            )
    conn.commit()
    conn.close()


@pytest.fixture()
def db(tmp_path) -> Path:
    path = tmp_path / "case.db"
    _make_db(path)
    return path


@pytest.fixture()
def kb_db(tmp_path) -> Path:
    path = tmp_path / "annotated.db"
    _make_db(path, with_kb=True, annotate=True)
    return path


# ── Basic reads ───────────────────────────────────────────────────────────────

class TestQueryBasics:
    def test_all_rows_in_order(self, db):
        rows = list(query_logs(db))
        assert [r.message for r in rows] == [
            "Hello world", "Location updated", "Hello again", "progress 100%_x done",
        ]
        assert all(isinstance(r, LogRow) for r in rows)

    def test_row_fields(self, db):
        row = next(iter(query_logs(db, process="locationd")))
        assert row.process == "locationd"
        assert row.pid == 55 and row.tid == 102
        assert row.log_level == "Error" and row.event_type == "Log"
        assert row.subsystem == "com.apple.locationd" and row.category == "loc"
        assert row.timestamp_unix_ns == _BASE_NS + 1_000_000_000
        assert row.timestamp_iso.startswith("2024-01-15T12:00:02")
        assert row.format_string is None  # dynamic message
        assert row.signature_ids == [] and row.values_dict() == {}

    def test_format_string_exposed(self, db):
        rows = list(query_logs(db, process="syslogd", level="Default"))
        assert rows[0].format_string == "Hello %@"

    def test_limit_counts_logs(self, db):
        assert len(list(query_logs(db, limit=2))) == 2
        assert len(list(query_logs(db, limit=0))) == 0
        assert len(list(query_logs(db, limit=99))) == 4

    def test_abandoning_iterator_is_safe(self, db):
        it = query_logs(db)
        next(it)
        it.close()  # must close the underlying connection without raising


# ── Filters ───────────────────────────────────────────────────────────────────

class TestQueryFilters:
    def test_single_string_accepted_for_list_filters(self, db):
        assert len(list(query_logs(db, process="syslogd"))) == 3
        assert len(list(query_logs(db, subsystem="com.apple.locationd"))) == 1
        assert len(list(query_logs(db, level=["Error", "Info"]))) == 2

    def test_message_prefix(self, db):
        assert [r.message for r in query_logs(db, message_prefix="Hello")] == [
            "Hello world", "Hello again",
        ]

    def test_message_prefix_escapes_like_metacharacters(self, db):
        # The literal "%"/"_" in the prefix must match themselves, not act as
        # wildcards: "progress 100%" may only match row 4, and a wildcard-style
        # prefix must not suddenly match everything.
        assert len(list(query_logs(db, message_prefix="progress 100%_x"))) == 1
        assert len(list(query_logs(db, message_prefix="%"))) == 0
        assert len(list(query_logs(db, message_prefix="progress 100%Z"))) == 0

    def test_format_str_exact(self, db):
        rows = list(query_logs(db, format_str="Hello %@"))
        assert [r.message for r in rows] == ["Hello world", "Hello again"]
        assert list(query_logs(db, format_str="no such template")) == []

    def test_message_contains_is_literal(self, db):
        # Substring anywhere, with %/_ matching themselves (unlike grep).
        assert len(list(query_logs(db, message_contains="100%_x"))) == 1
        assert len(list(query_logs(db, message_contains="%"))) == 1  # the literal % row
        assert [r.message for r in query_logs(db, message_contains="again")] == ["Hello again"]

    def test_grep_stays_raw_like(self, db):
        assert len(list(query_logs(db, grep="%Location%"))) == 1

    def test_time_window(self, db):
        rows = list(query_logs(db, time_from="2024-01-15T12:00:02",
                               time_to="2024-01-15T12:00:03"))
        assert [r.message for r in rows] == ["Location updated"]


# ── Knowledge-base rollup ─────────────────────────────────────────────────────

class TestQueryKb:
    def test_annotations_rolled_up(self, kb_db):
        row = next(iter(query_logs(kb_db, annotated_only=True)))
        assert row.message == "Location updated"
        assert row.signature_ids == ["loc.update"]
        assert row.values_dict() == {"lat": "48.8", "lon": "2.3"}
        assert row.value_for("lat") == "48.8" and row.value_for("absent") == ""

    def test_signature_and_tag_filters(self, kb_db):
        assert len(list(query_logs(kb_db, signature="loc.update"))) == 1
        assert len(list(query_logs(kb_db, tag="privacy"))) == 1
        assert len(list(query_logs(kb_db, tag="nonexistent"))) == 0


# ── Errors ────────────────────────────────────────────────────────────────────

class TestQueryErrors:
    def test_missing_database_raises_eagerly(self, tmp_path):
        # Raised at call time, before the generator is iterated.
        with pytest.raises(FileNotFoundError):
            query_logs(tmp_path / "absent.db")

    def test_bad_duration_raises_eagerly(self, db):
        with pytest.raises(ValueError):
            query_logs(db, last="10x")

    def test_kb_filter_without_kb_raises_on_iteration(self, db):
        it = query_logs(db, annotated_only=True)
        with pytest.raises(ValueError):
            next(it)


# ── Stable view ───────────────────────────────────────────────────────────────

class TestVLogsView:
    def test_view_created_by_init_schema(self, db):
        conn = sqlite3.connect(str(db))
        try:
            rows = conn.execute(
                "SELECT process, log_level, message, format_string FROM v_logs "
                "ORDER BY timestamp_unix_ns",
            ).fetchall()
        finally:
            conn.close()
        assert rows[0] == ("syslogd", "Default", "Hello world", "Hello %@")
        assert rows[1][:2] == ("locationd", "Error")

    def test_view_added_to_predating_database(self, db):
        # Simulate a database created before v_logs existed.
        conn = sqlite3.connect(str(db))
        conn.execute("DROP VIEW v_logs")
        conn.commit()
        conn.close()

        # query_logs opportunistically recreates it…
        list(query_logs(db, limit=1))

        conn = sqlite3.connect(str(db))
        try:
            assert conn.execute(
                "SELECT name FROM sqlite_master WHERE type='view' AND name='v_logs'"
            ).fetchone() is not None
        finally:
            conn.close()

    def test_ensure_views_idempotent(self, db):
        conn = sqlite3.connect(str(db))
        try:
            ensure_views(conn)
            ensure_views(conn)
        finally:
            conn.close()


# ── Paged access (count_logs / fetch_logs / fetch_context) ───────────────────

class TestPagedAccess:
    def test_count_matches_query(self, db):
        from forensic_aul import LogFilters, count_logs

        assert count_logs(db) == 4
        assert count_logs(db, LogFilters(process=["syslogd"])) == 3
        assert count_logs(db, LogFilters(process=["absent"])) == 0

    def test_fetch_logs_pages_are_exact_and_ordered(self, db):
        from forensic_aul import fetch_logs

        page1 = fetch_logs(db, offset=0, limit=2)
        page2 = fetch_logs(db, offset=2, limit=2)
        assert [r.message for r in page1] == ["Hello world", "Location updated"]
        assert [r.message for r in page2] == ["Hello again", "progress 100%_x done"]
        assert fetch_logs(db, offset=4, limit=2) == []

    def test_fetch_logs_page_counts_logs_not_joined_rows(self, kb_db):
        from forensic_aul import fetch_logs

        # The annotated log carries 2 extracted values (2 joined rows) but must
        # count as ONE log in the page window.
        page = fetch_logs(kb_db, offset=0, limit=2)
        assert len(page) == 2
        annotated = [r for r in page if r.signature_ids]
        assert annotated and annotated[0].values_dict() == {"lat": "48.8", "lon": "2.3"}

    def test_fetch_context_window(self, db):
        import sqlite3

        from forensic_aul import fetch_context, query_logs

        # Assign a simple event_order (the fixture has none by default).
        conn = sqlite3.connect(str(db))
        conn.execute("UPDATE logs SET event_order = id * 10")
        conn.commit(); conn.close()

        anchor = next(iter(query_logs(db, message_prefix="Hello again")))
        ctx = fetch_context(db, anchor.log_id, before=10, after=10)
        assert [r.message for r in ctx] == ["Location updated", "Hello again", "progress 100%_x done"]
        assert any(r.log_id == anchor.log_id for r in ctx)

    def test_fetch_context_errors(self, db):
        from forensic_aul import fetch_context

        with pytest.raises(ValueError, match="does not exist"):
            fetch_context(db, 999)
        # event_order not assigned in the raw fixture → explicit error.
        with pytest.raises(ValueError, match="event_order"):
            fetch_context(db, 1)


# ── Keyword search (message_match / FTS) ──────────────────────────────────────

class TestMessageMatch:
    def test_keyword_match_is_case_insensitive_and_anywhere(self, db):
        rows = list(query_logs(db, message_match="hello"))
        assert [r.log_id for r in rows] == [1, 3]

    def test_terms_are_and_combined(self, db):
        rows = list(query_logs(db, message_match="hello world"))
        assert [r.log_id for r in rows] == [1]

    def test_fts_query_syntax_is_inert(self, db):
        # OR must be a literal term (no message contains it), never an operator;
        # quotes / NEAR / stars must not raise an FTS syntax error either.
        assert list(query_logs(db, message_match="hello OR world")) == []
        assert list(query_logs(db, message_match='NEAR("hello" "world")')) == []
        # A dangling quote / star must not raise an FTS syntax error; the star
        # is a separator to the tokeniser, so this is the keyword "hello".
        rows = list(query_logs(db, message_match='"hello*'))
        assert [r.log_id for r in rows] == [1, 3]

    def test_punctuation_only_terms_mean_no_filter(self, db):
        assert len(list(query_logs(db, message_match="%%% ..."))) == 4

    def test_no_fts_index_raises(self, db):
        conn = sqlite3.connect(str(db))
        for trigger in ("logs_ai", "logs_ad", "logs_au"):
            conn.execute(f"DROP TRIGGER IF EXISTS {trigger}")
        conn.execute("DROP TABLE IF EXISTS logs_fts")
        conn.commit(); conn.close()
        with pytest.raises(ValueError, match="full-text index"):
            list(query_logs(db, message_match="hello"))

    def test_empty_fts_index_with_rows_counts_as_absent(self, db):
        # An interrupted --fast-fts extract leaves logs_fts empty while logs has
        # rows; searching it would silently miss everything, so it must raise.
        conn = sqlite3.connect(str(db))
        conn.execute("INSERT INTO logs_fts(logs_fts) VALUES('delete-all')")
        conn.commit(); conn.close()
        with pytest.raises(ValueError, match="full-text index"):
            list(query_logs(db, message_match="hello"))

    def test_fts_match_query_quoting(self):
        from forensic_aul.ops.query.reader import fts_match_query

        assert fts_match_query('foo "bar"') == '"foo" """bar"""'
        assert fts_match_query("%%% ...") is None


# ── LogStore (held-open read store) ───────────────────────────────────────────

class TestLogStore:
    def test_capabilities_count_and_paging(self, kb_db):
        from forensic_aul import LogFilters, LogStore

        with LogStore(kb_db) as store:
            assert store.has_kb is True
            assert store.has_fts is True
            assert store.count() == 4
            assert store.count(LogFilters(process=["syslogd"])) == 3
            page = store.fetch(offset=2, limit=2)
            assert [r.message for r in page] == ["Hello again", "progress 100%_x done"]

    def test_context_through_store(self, db):
        from forensic_aul import LogStore

        conn = sqlite3.connect(str(db))
        conn.execute("UPDATE logs SET event_order = id * 10")
        conn.commit(); conn.close()
        with LogStore(db) as store:
            ctx = store.context(3, before=10, after=10)
            assert [r.log_id for r in ctx] == [2, 3, 4]

    def test_annotation_filter_without_kb_raises(self, db):
        from forensic_aul import LogFilters, LogStore

        with LogStore(db) as store:
            assert store.has_kb is False
            with pytest.raises(ValueError, match="no KB annotations"):
                store.count(LogFilters(annotated_only=True))
