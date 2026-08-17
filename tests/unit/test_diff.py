"""Unit tests for the baseline-vs-action diff (forensic_aul/ops/identify/diff.py)."""

from __future__ import annotations

import csv
import sqlite3

import pytest

from forensic_aul.engine.database.ordering import assign_ordering
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


def _action_db_multi_source(path) -> None:
    """Action DB with 2 tracev3 files (2 rows each), ordering assigned by the
    real production pass (``assign_ordering``, not hand-computed) — for testing
    that source_order/source_file survive the diff (L10). All timestamps are
    well past any baseline cutoff used by the tests below, so every row is
    retained. Mirrors the fixture pattern in tests/unit/test_ordering.py.
    """
    conn = sqlite3.connect(str(path))
    apply_pragmas(conn)
    init_schema(conn)
    conn.execute("INSERT INTO processes(id, name) VALUES (1, 'p2')")
    conn.executemany(
        "INSERT INTO source_files (id, file_path, file_type, parsed_at) VALUES (?, ?, ?, ?)",
        [
            (1, "logdata/a.tracev3", "tracev3", "2024-01-15T00:00:00Z"),
            (2, "logdata/b.tracev3", "tracev3", "2024-01-15T00:00:00Z"),
        ],
    )
    conn.execute("INSERT INTO boots (id, boot_uuid, rank) VALUES (1, 'BOOT-A', 0)")
    # (id, tracev3_file_id, chunkset_offset, mach, message) — source_order is
    # per-file rank by chunkset offset; event_order is the merged rank by mach.
    rows = [
        (1, 1, 100, 10, "row 1"),
        (2, 1, 200, 30, "row 2"),
        (3, 2, 50, 20, "row 3"),
        (4, 2, 150, 40, "row 4"),
    ]
    for rid, file_id, chunk, mach, msg in rows:
        conn.execute(
            "INSERT INTO logs (id, tracev3_file_id, tracev3_chunkset_file_offset, "
            "tracev3_firehose_inner_offset, tracev3_entry_inner_offset, boot_id, "
            "timestamp_unix_ns, timestamp_mach, message, process_id) "
            "VALUES (?, ?, ?, 0, 0, 1, ?, ?, ?, 1)",
            (rid, file_id, chunk, 300_000_000_000 + mach, mach, msg),
        )
    conn.commit()
    assign_ordering(conn)
    conn.commit()
    conn.close()


def test_diff_carries_source_order_and_source_file(tmp_path):
    _db(tmp_path / "base.db", [(100, "boot", "p1")])  # cutoff = 100
    action_path = tmp_path / "act.db"
    _action_db_multi_source(action_path)

    csv_out = tmp_path / "out.csv"
    sqlite_out = tmp_path / "out.db"
    res = run_diff(tmp_path / "base.db", action_path, csv_out, sqlite_out)
    assert res.retained == 4

    c = sqlite3.connect(str(sqlite_out))
    rows = c.execute(
        "SELECT message, source_order, source_file, event_order FROM identified_logs"
    ).fetchall()
    c.close()
    by_msg = {msg: (so, sf, eo) for msg, so, sf, eo in rows}

    # source_order restarts per file: rows 1/2 are file a, rows 3/4 are file b.
    assert by_msg["row 1"][:2] == (1, "logdata/a.tracev3")
    assert by_msg["row 2"][:2] == (2, "logdata/a.tracev3")
    assert by_msg["row 3"][:2] == (1, "logdata/b.tracev3")
    assert by_msg["row 4"][:2] == (2, "logdata/b.tracev3")

    # event_order is one merged, ever-increasing sequence — unlike source_order
    # it never restarts, even though the two files interleave by mach time.
    event_orders = [by_msg[f"row {i}"][2] for i in range(1, 5)]
    assert sorted(event_orders) == [1, 2, 3, 4]
    assert event_orders[0] < event_orders[2] < event_orders[1] < event_orders[3]

    with csv_out.open(encoding="utf-8-sig") as fp:
        reader = csv.DictReader(fp)
        assert "source_order" in reader.fieldnames
        assert "source_file" in reader.fieldnames
        by_msg_csv = {row["message"]: row for row in reader}
    assert by_msg_csv["row 1"]["source_order"] == "1"
    assert by_msg_csv["row 1"]["source_file"] == "logdata/a.tracev3"
    assert by_msg_csv["row 3"]["source_order"] == "1"
    assert by_msg_csv["row 3"]["source_file"] == "logdata/b.tracev3"


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


# ── The unix_ns=0 sentinel in identify (review item L8) ───────────────────────
#
# The cutoff is MAX(timestamp_unix_ns) over the baseline. A row whose timestamp
# never resolved has unix_ns=0, which is *below* any real cutoff — so a naive
# "newer than the cutoff" test would silently drop it from both outputs. It
# cannot be proven to predate the action either, so the contract is: keep it,
# mark it retained (excluded=0), and say why in the note column.

def test_baseline_cutoff_ignores_unresolved_rows(tmp_path):
    """An unresolved row in the BASELINE must not drag the cutoff down to 0.

    MAX() over a column containing 0 is unaffected, but MIN()-style or
    ordering-based cutoffs would be — and a cutoff of 0 would retain the entire
    action database as "new".
    """
    base, action = tmp_path / "b.db", tmp_path / "a.db"
    _db(base, [(0, "unresolved baseline", "p1"), (1_000, "baseline", "p1")])
    _db(action, [(2_000, "after the action", "p1")])
    out = tmp_path / "out.db"
    result = run_diff(base, action, tmp_path / "out.csv", out)
    assert result.retained == 1


def test_unresolved_action_row_is_retained_with_a_note(tmp_path):
    base, action = tmp_path / "b.db", tmp_path / "a.db"
    _db(base, [(1_000, "baseline", "p1")])
    _db(action, [(0, "UNRESOLVED", "p1"), (2_000, "after the action", "p1")])
    out = tmp_path / "out.db"
    run_diff(base, action, tmp_path / "out.csv", out)

    conn = sqlite3.connect(str(out))
    row = conn.execute(
        "SELECT timestamp, timestamp_unix_ns, excluded, note FROM identified_logs "
        "WHERE message = 'UNRESOLVED'"
    ).fetchone()
    conn.close()
    assert row is not None, "an unresolved row must not be silently dropped"
    timestamp, unix_ns, excluded, note = row
    assert unix_ns == 0                  # the sentinel stays visible
    assert timestamp in ("", None)       # never rendered as 1970
    assert excluded == 0                 # retained: cannot be proven pre-cutoff
    assert "unresolved" in (note or "").lower()


def test_unresolved_action_row_reaches_the_csv(tmp_path):
    base, action = tmp_path / "b.db", tmp_path / "a.db"
    _db(base, [(1_000, "baseline", "p1")])
    _db(action, [(0, "UNRESOLVED", "p1"), (2_000, "after", "p1")])
    csv_out = tmp_path / "out.csv"
    run_diff(base, action, csv_out, tmp_path / "out.db")

    rows = list(csv.DictReader(csv_out.read_text(encoding="utf-8-sig").splitlines()))
    hit = [r for r in rows if r["message"] == "UNRESOLVED"]
    assert len(hit) == 1
    assert hit[0]["timestamp"] == ""
    assert "unresolved" in hit[0]["note"].lower()


def test_unresolved_rows_are_counted_and_warned_about(tmp_path, caplog):
    """The analyst must be told, not left to notice — these rows are unplaceable."""
    import logging

    base, action = tmp_path / "b.db", tmp_path / "a.db"
    _db(base, [(1_000, "baseline", "p1")])
    _db(action, [(0, "U1", "p1"), (0, "U2", "p1"), (2_000, "after", "p1")])
    with caplog.at_level(logging.WARNING):
        run_diff(base, action, tmp_path / "out.csv", tmp_path / "out.db")
    warnings = " ".join(r.message for r in caplog.records if r.levelno >= logging.WARNING)
    assert "2" in warnings and "unresolved" in warnings.lower()
