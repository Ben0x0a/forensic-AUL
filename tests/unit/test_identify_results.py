"""Unit tests for forensic_aul.ops.identify.results — the diff-DB read/annotate layer.

Builds the diff DB via the real ``run_diff`` over the same synthetic extract DBs
``test_diff.py`` constructs, so ``IdentifyResults`` is exercised against a
genuine diff output rather than a hand-rolled fixture.
"""

from __future__ import annotations

import sqlite3

import pytest

from forensic_aul.engine.database.schema import apply_pragmas, init_schema
from forensic_aul.errors import InvalidDatabaseError
from forensic_aul.ops.annotation.matcher import init_annotation_schema
from forensic_aul.ops.identify.diff import run_diff
from forensic_aul.ops.identify.results import IdentifyResults, ResultCounts


def _db(path, rows) -> None:
    """rows: list of (unix_ns, message, process_name)."""
    conn = sqlite3.connect(str(path))
    apply_pragmas(conn)
    init_schema(conn)
    procs = {name for _, _, name in rows}
    pid_of = {name: i + 1 for i, name in enumerate(sorted(procs))}
    for name, pid in pid_of.items():
        conn.execute("INSERT INTO processes(id, name) VALUES (?, ?)", (pid, name))
    for i, (ns, msg, proc) in enumerate(rows, 1):
        conn.execute(
            "INSERT INTO logs(id, timestamp_unix_ns, timestamp_mach, "
            "message, process_id) VALUES (?,?,?,?,?)",
            (i, ns, ns, msg, pid_of[proc]),
        )
    conn.commit()
    conn.close()


def _build_diff_db(tmp_path, *, with_kb=False):
    """Baseline noise = {(boot, p1)}; action has retained + excluded + KB-known rows."""
    _db(tmp_path / "base.db", [(100, "boot", "p1")])
    action_path = tmp_path / "act.db"
    _db(action_path, [
        (300, "boot", "p1"),                  # baseline noise -> excluded
        (300, "user tapped Camera", "p2"),    # retained, kb-known (if with_kb)
        (400, "background chatter", "p2"),    # retained, not kb-known
    ])
    if with_kb:
        conn = sqlite3.connect(str(action_path))
        init_annotation_schema(conn)
        conn.execute(
            "INSERT INTO kb_signatures (id, signature_id, action, kb_version, "
            "kb_sha256, applied_at) VALUES (1, 'sig.tap', 'tapped', '1.0.0', "
            "'deadbeef', '2026-01-01T00:00:00Z')"
        )
        log_id = conn.execute(
            "SELECT id FROM logs WHERE message = 'user tapped Camera'"
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO log_annotations (log_id, kb_signature_id) VALUES (?, 1)", (log_id,)
        )
        conn.commit()
        conn.close()

    sqlite_out = tmp_path / "identified.db"
    run_diff(tmp_path / "base.db", action_path, tmp_path / "identified.csv", sqlite_out)
    return sqlite_out


class TestConstruction:
    def test_missing_file_raises_file_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            IdentifyResults(tmp_path / "nope.db")

    def test_text_file_raises_invalid_database_error(self, tmp_path):
        path = tmp_path / "not_a_db.txt"
        path.write_text("hello world", encoding="utf-8")
        with pytest.raises(InvalidDatabaseError):
            IdentifyResults(path)

    def test_analysis_db_without_identified_logs_raises(self, tmp_path):
        # A DB built with init_schema (a run_extract-style analysis DB) has a
        # `logs` table but no `identified_logs` — the wrong shape entirely.
        path = tmp_path / "analysis.db"
        conn = sqlite3.connect(str(path))
        apply_pragmas(conn)
        init_schema(conn)
        conn.close()
        with pytest.raises(InvalidDatabaseError, match="identified_logs"):
            IdentifyResults(path)

    def test_older_diff_db_without_hidden_keys_gains_them_on_open(self, tmp_path):
        # Simulate a diff DB produced before hidden_keys/v_identified_visible
        # existed: identified_logs present, but neither of the newer objects.
        path = tmp_path / "old_identified.db"
        conn = sqlite3.connect(str(path))
        conn.execute("""
            CREATE TABLE identified_logs (
                id INTEGER PRIMARY KEY, timestamp TEXT, timestamp_unix_ns INTEGER,
                event_order INTEGER, process TEXT, pid INTEGER, tid INTEGER,
                log_level TEXT, event_type TEXT, subsystem TEXT, category TEXT,
                message TEXT, matched_signatures TEXT NOT NULL DEFAULT '',
                excluded INTEGER NOT NULL, note TEXT
            )
        """)
        conn.execute(
            "INSERT INTO identified_logs (timestamp, timestamp_unix_ns, message, "
            "matched_signatures, excluded, note) VALUES ('', 100, 'x', '', 0, '')"
        )
        conn.commit()
        conn.close()

        with IdentifyResults(path) as res:
            tables = {row[0] for row in res._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
            views = {row[0] for row in res._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='view'"
            )}
            assert "hidden_keys" in tables
            assert "v_identified_visible" in views
            # Reads still work on the upgraded DB.
            assert len(res.rows(include_kb_known=True)) == 1


class TestCounts:
    def test_counts_per_category(self, tmp_path):
        db = _build_diff_db(tmp_path, with_kb=True)
        with IdentifyResults(db) as res:
            counts = res.counts()
        assert isinstance(counts, ResultCounts)
        assert counts.noise == 1        # "boot"(p1)
        assert counts.kb_known == 1     # "user tapped Camera"
        assert counts.retained == 1     # "background chatter" only (kb_known excluded)
        assert counts.hidden == 0

    def test_counts_reflect_hidden_rows(self, tmp_path):
        db = _build_diff_db(tmp_path, with_kb=False)
        with IdentifyResults(db) as res:
            before = res.counts().retained
            res.hide("background chatter", "p2")
            after = res.counts()
        assert after.hidden == 1
        assert after.retained == before - 1  # hiding one retained row removes it from the count


class TestRows:
    def test_default_rows_excludes_noise_kb_known_and_hidden(self, tmp_path):
        db = _build_diff_db(tmp_path, with_kb=True)
        with IdentifyResults(db) as res:
            rows = res.rows()
        msgs = {r["message"] for r in rows}
        assert msgs == {"background chatter"}

    def test_include_flags_widen_the_result(self, tmp_path):
        db = _build_diff_db(tmp_path, with_kb=True)
        with IdentifyResults(db) as res:
            all_rows = res.rows(include_noise=True, include_kb_known=True, include_hidden=True)
        msgs = {r["message"] for r in all_rows}
        assert msgs == {"boot", "user tapped Camera", "background chatter"}

    def test_rows_ordered_by_timestamp_then_id(self, tmp_path):
        db = _build_diff_db(tmp_path, with_kb=True)
        with IdentifyResults(db) as res:
            rows = res.rows(include_noise=True, include_kb_known=True)
        timestamps = [r["timestamp_unix_ns"] for r in rows]
        assert timestamps == sorted(timestamps)

    def test_search_literal_percent_and_underscore(self, tmp_path):
        _db(tmp_path / "base.db", [(100, "boot", "p1")])
        _db(tmp_path / "act.db", [
            (300, "100% done_now", "p2"),
            (300, "unrelated line", "p2"),
        ])
        sqlite_out = tmp_path / "identified.db"
        run_diff(tmp_path / "base.db", tmp_path / "act.db", tmp_path / "o.csv", sqlite_out)

        with IdentifyResults(sqlite_out) as res:
            hits = res.rows(search="100% done_now")
            assert {r["message"] for r in hits} == {"100% done_now"}
            # A pattern-looking search string must not match unrelated text via
            # LIKE wildcarding — the % and _ are literal.
            no_hits = res.rows(search="100X done_now")
            assert no_hits == []
            wildcard_attempt = res.rows(search="100_done_now")
            assert wildcard_attempt == []

    def test_limit_and_offset(self, tmp_path):
        _db(tmp_path / "base.db", [(50, "boot", "p1")])
        _db(tmp_path / "act.db", [
            (100, "line-a", "p2"), (200, "line-b", "p2"), (300, "line-c", "p2"),
        ])
        sqlite_out = tmp_path / "identified.db"
        run_diff(tmp_path / "base.db", tmp_path / "act.db", tmp_path / "o.csv", sqlite_out)

        with IdentifyResults(sqlite_out) as res:
            page1 = res.rows(limit=2, offset=0)
            page2 = res.rows(limit=2, offset=2)
        assert [r["message"] for r in page1] == ["line-a", "line-b"]
        assert [r["message"] for r in page2] == ["line-c"]


class TestHiding:
    def test_hide_then_unhide_round_trip(self, tmp_path):
        db = _build_diff_db(tmp_path, with_kb=False)
        with IdentifyResults(db) as res:
            assert any(r["message"] == "background chatter" for r in res.rows())
            res.hide("background chatter", "p2")
            assert not any(r["message"] == "background chatter" for r in res.rows())
            res.unhide("background chatter", "p2")
            assert any(r["message"] == "background chatter" for r in res.rows())

    def test_none_process_key_round_trips_as_empty_string(self, tmp_path):
        _db(tmp_path / "base.db", [(50, "boot", "p1")])
        _db(tmp_path / "act.db", [(300, "orphan message", "p1")])
        sqlite_out = tmp_path / "identified.db"
        run_diff(tmp_path / "base.db", tmp_path / "act.db", tmp_path / "o.csv", sqlite_out)

        # Force a NULL process on the identified_logs row to simulate a log
        # with no resolved process name.
        conn = sqlite3.connect(str(sqlite_out))
        conn.execute("UPDATE identified_logs SET process = NULL WHERE message = 'orphan message'")
        conn.commit()
        conn.close()

        with IdentifyResults(sqlite_out) as res:
            res.hide("orphan message", None)
            assert res.hidden_keys() == [("orphan message", "")]
            assert not any(r["message"] == "orphan message" for r in res.rows())
            res.unhide("orphan message", None)
            assert any(r["message"] == "orphan message" for r in res.rows())

    def test_hidden_keys_persist_across_close_reopen(self, tmp_path):
        db = _build_diff_db(tmp_path, with_kb=False)
        with IdentifyResults(db) as res:
            res.hide("background chatter", "p2")

        with IdentifyResults(db) as res2:
            assert res2.hidden_keys() == [("background chatter", "p2")]
            assert not any(r["message"] == "background chatter" for r in res2.rows())


class TestExportCsv:
    def test_export_csv_content_and_count(self, tmp_path):
        db = _build_diff_db(tmp_path, with_kb=True)
        out = tmp_path / "export.csv"
        with IdentifyResults(db) as res:
            count = res.export_csv(out)
        assert count == 2  # default include_kb_known=True, include_noise=False

        import csv
        with out.open(encoding="utf-8-sig") as fp:
            rows = list(csv.DictReader(fp))
        assert rows[0].keys() == {
            "timestamp", "timestamp_unix_ns", "event_order", "source_order",
            "source_file", "process", "pid",
            "tid", "log_level", "event_type", "subsystem", "category",
            "message", "matched_signatures", "note",
        }
        msgs = {r["message"] for r in rows}
        assert msgs == {"user tapped Camera", "background chatter"}

    def test_export_csv_respects_include_noise_false_default(self, tmp_path):
        db = _build_diff_db(tmp_path, with_kb=False)
        out = tmp_path / "export.csv"
        with IdentifyResults(db) as res:
            res.export_csv(out, include_noise=False)

        import csv
        with out.open(encoding="utf-8-sig") as fp:
            msgs = {r["message"] for r in csv.DictReader(fp)}
        assert "boot" not in msgs


class TestCountMethod:
    def test_count_matches_rows_under_every_flag_combination(self, tmp_path):
        db = _build_diff_db(tmp_path, with_kb=True)
        with IdentifyResults(db) as res:
            for noise in (False, True):
                for kb in (False, True):
                    for search in (None, "chatter"):
                        flags = dict(
                            include_noise=noise, include_kb_known=kb, search=search,
                        )
                        assert res.count(**flags) == len(res.rows(**flags)), flags

    def test_count_reflects_hidden_rows(self, tmp_path):
        db = _build_diff_db(tmp_path, with_kb=False)
        with IdentifyResults(db) as res:
            before = res.count()
            res.hide("background chatter", "p2")
            assert res.count() == before - 1
            assert res.count(include_hidden=True) == before


class TestHideGuards:
    def test_hide_none_message_raises_value_error(self, tmp_path):
        db = _build_diff_db(tmp_path, with_kb=False)
        with IdentifyResults(db) as res:
            with pytest.raises(ValueError, match="no message"):
                res.hide(None, "p2")
