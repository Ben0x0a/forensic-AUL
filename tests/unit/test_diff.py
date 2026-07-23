"""Unit tests for the baseline-vs-action diff (forensic_aul/ops/identify/diff.py)."""

from __future__ import annotations

import csv
import sqlite3

import pytest

from forensic_aul.engine.database.schema import apply_pragmas, init_schema
from forensic_aul.ops.annotation.matcher import init_annotation_schema
from forensic_aul.ops.identify.diff import run_diff


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


def test_diff_retained_and_excluded(tmp_path):
    # Baseline: noise = {(boot, p1), (idle, p1)}, cutoff = 200.
    _db(tmp_path / "base.db", [(100, "boot", "p1"), (200, "idle", "p1")])
    # Action (all > cutoff except the 150 one which must be ignored):
    _db(tmp_path / "act.db", [
        (150, "pre-cutoff", "p1"),     # ≤ cutoff → not considered at all
        (300, "idle", "p1"),           # baseline noise → excluded
        (300, "user tapped Camera", "p2"),  # new → retained
        (400, "boot", "p2"),           # same msg as baseline but DIFFERENT process → retained
    ])

    csv_out = tmp_path / "out.csv"
    sqlite_out = tmp_path / "out.db"
    res = run_diff(tmp_path / "base.db", tmp_path / "act.db", csv_out, sqlite_out)

    assert res.retained == 2      # "user tapped" + "boot"(p2)
    assert res.excluded == 1      # "idle"(p1)

    # CSV holds only retained rows.
    with csv_out.open(encoding="utf-8-sig") as fp:
        msgs = {row["message"] for row in csv.DictReader(fp)}
    assert msgs == {"user tapped Camera", "boot"}

    # The SQLite output keeps every post-cutoff row with an excluded flag.
    c = sqlite3.connect(str(sqlite_out))
    total = c.execute("SELECT COUNT(*) FROM identified_logs").fetchone()[0]
    excl = c.execute("SELECT COUNT(*) FROM identified_logs WHERE excluded=1").fetchone()[0]
    c.close()
    assert total == 3 and excl == 1


def test_diff_empty_baseline_raises(tmp_path):
    _db(tmp_path / "base.db", [])
    _db(tmp_path / "act.db", [(100, "x", "p1")])
    with pytest.raises(ValueError):
        run_diff(tmp_path / "base.db", tmp_path / "act.db",
                 tmp_path / "o.csv", tmp_path / "o.db")


def test_diff_csv_out_none_skips_csv_but_counts_match(tmp_path):
    _db(tmp_path / "base.db", [(100, "boot", "p1"), (200, "idle", "p1")])
    _db(tmp_path / "act.db", [
        (300, "idle", "p1"),
        (300, "user tapped Camera", "p2"),
        (400, "boot", "p2"),
    ])
    sqlite_out = tmp_path / "out.db"
    res = run_diff(tmp_path / "base.db", tmp_path / "act.db", None, sqlite_out)

    assert res.csv_path is None
    assert not (tmp_path / "out.csv").exists()
    assert res.retained == 2
    assert res.excluded == 1


def test_diff_matched_signatures_populated_from_kb_tables(tmp_path):
    _db(tmp_path / "base.db", [(100, "boot", "p1")])
    action_path = tmp_path / "act.db"
    _db(action_path, [
        (300, "user tapped Camera", "p2"),
        (300, "another retained line", "p2"),
    ])
    conn = sqlite3.connect(str(action_path))
    init_annotation_schema(conn)
    conn.execute(
        "INSERT INTO kb_signatures (id, signature_id, action, kb_version, kb_sha256, applied_at) "
        "VALUES (1, 'sig.tap', 'tapped', '1.0.0', 'deadbeef', '2026-01-01T00:00:00Z')"
    )
    log_id = conn.execute(
        "SELECT id FROM logs WHERE message = 'user tapped Camera'"
    ).fetchone()[0]
    conn.execute(
        "INSERT INTO log_annotations (log_id, kb_signature_id) VALUES (?, 1)", (log_id,)
    )
    conn.commit()
    conn.close()

    csv_out = tmp_path / "out.csv"
    sqlite_out = tmp_path / "out.db"
    run_diff(tmp_path / "base.db", action_path, csv_out, sqlite_out)

    c = sqlite3.connect(str(sqlite_out))
    rows = dict(c.execute(
        "SELECT message, matched_signatures FROM identified_logs"
    ).fetchall())
    c.close()
    assert rows["user tapped Camera"] == "sig.tap"
    assert rows["another retained line"] == ""

    with csv_out.open(encoding="utf-8-sig") as fp:
        by_msg = {row["message"]: row["matched_signatures"] for row in csv.DictReader(fp)}
    assert by_msg["user tapped Camera"] == "sig.tap"
    assert by_msg["another retained line"] == ""


def test_diff_matched_signatures_empty_without_kb_tables(tmp_path):
    _db(tmp_path / "base.db", [(100, "boot", "p1")])
    _db(tmp_path / "act.db", [(300, "user tapped Camera", "p2")])
    sqlite_out = tmp_path / "out.db"
    run_diff(tmp_path / "base.db", tmp_path / "act.db", tmp_path / "out.csv", sqlite_out)

    c = sqlite3.connect(str(sqlite_out))
    values = [row[0] for row in c.execute("SELECT matched_signatures FROM identified_logs")]
    c.close()
    assert values and all(v == "" for v in values)


def test_diff_hidden_keys_and_view_created_and_hiding_works(tmp_path):
    _db(tmp_path / "base.db", [(100, "boot", "p1")])
    _db(tmp_path / "act.db", [
        (300, "user tapped Camera", "p2"),
        (400, "another line", "p2"),
    ])
    sqlite_out = tmp_path / "out.db"
    run_diff(tmp_path / "base.db", tmp_path / "act.db", tmp_path / "out.csv", sqlite_out)

    conn = sqlite3.connect(str(sqlite_out))
    tables = {row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )}
    views = {row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='view'"
    )}
    assert "hidden_keys" in tables
    assert "v_identified_visible" in views

    visible_before = {row[0] for row in conn.execute(
        "SELECT message FROM v_identified_visible"
    )}
    assert visible_before == {"user tapped Camera", "another line"}

    # Hiding a key removes it from the view but leaves identified_logs intact.
    conn.execute("INSERT INTO hidden_keys (message, process) VALUES (?, ?)",
                ("user tapped Camera", "p2"))
    conn.commit()

    visible_after = {row[0] for row in conn.execute(
        "SELECT message FROM v_identified_visible"
    )}
    assert visible_after == {"another line"}

    still_in_table = {row[0] for row in conn.execute(
        "SELECT message FROM identified_logs"
    )}
    assert still_in_table == {"user tapped Camera", "another line"}
    conn.close()
