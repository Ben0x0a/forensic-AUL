"""The cross-repetition ranking (forensic_aul/ops/identify/repeat.py)."""

from __future__ import annotations

import sqlite3

from forensic_aul import ranked_templates
from forensic_aul.ops.identify.diff import create_identified_schema, write_identified_csv
from forensic_aul.ops.identify.repeat import merge_repetitions, rank_repeated
from forensic_aul.reports import format_ranking


def _identified(path, rows):
    """rows: (process, format_string, message, tier) — a real identified schema."""
    conn = sqlite3.connect(path)
    create_identified_schema(conn)
    conn.executemany(
        "INSERT INTO identified_logs (timestamp_unix_ns, process, format_string, message, "
        "tier, excluded) VALUES (?, ?, ?, ?, ?, ?)",
        [(i, p, f, m, t, int(t == "repeat")) for i, (p, f, m, t) in enumerate(rows, 1)])
    conn.commit()
    conn.close()
    return path


def test_templates_new_in_every_repetition_rank_first(tmp_path):
    shot = ("screenshotd", "saved screenshot %{public}s")
    dbs = [
        _identified(tmp_path / "1.db", [
            (*shot, "saved screenshot A", "new_template"),
            ("wifid", "scan %d", "scan 1", "new_template"),             # once only
            ("kernel", "tick", "tick", "repeat"),                       # noise: not ranked
        ]),
        _identified(tmp_path / "2.db", [
            (*shot, "saved screenshot B", "new_template"),
            ("app", "%{public}s", "generic one", "new_template"),       # generic: keyed by message
        ]),
        _identified(tmp_path / "3.db", [
            (*shot, "saved screenshot C", "new_template"),
            ("app", "%{public}s", "generic two", "new_template"),
        ]),
    ]
    merged = tmp_path / "identified.db"
    merge_repetitions(dbs, merged)
    result = rank_repeated(merged, tmp_path / "repeat.csv")
    assert (result.cycles, result.templates, result.in_every_cycle) == (3, 4, 1)

    top = ranked_templates(result.path)
    assert top[0][1:5] == (3, 3, 3, "screenshotd")
    assert {row[4] for row in top} == {"screenshotd", "wifid", "app"}
    assert "kernel" not in format_ranking(result, top)

    import csv

    with result.csv_path.open(encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert [r["rank"] for r in rows] == ["1", "2", "3", "4"]
    assert rows[0]["process"] == "screenshotd" and rows[0]["new_template_cycles"] == "3"
    assert rows[0]["template"] == "saved screenshot %{public}s"


def test_merged_lines_csv_carries_the_repetition_and_the_flags(tmp_path):
    """One CSV for every repetition: the export columns, the 1/0 flags, and the
    repetition each line came from; noise rows are left out."""
    import csv

    dbs = [
        _identified(tmp_path / "1.db", [("camera", "opened %d", "opened 1", "new_template"),
                                        ("kernel", "tick", "tick", "repeat")]),
        _identified(tmp_path / "2.db", [("camera", "opened %d", "opened 2", "new_values")]),
    ]
    merged = tmp_path / "identified.db"
    merge_repetitions(dbs, merged)
    out = tmp_path / "identified.csv"
    assert write_identified_csv(merged, out) == 2
    with out.open(encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert [(r["message"], r["new_template"], r["new_message"], r["repetition"]) for r in rows] == [
        ("opened 1", "1", "1", "1"), ("opened 2", "0", "1", "2")]
