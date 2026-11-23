"""The cross-repetition ranking (forensic_aul/ops/identify/repeat.py)."""

from __future__ import annotations

import sqlite3

from forensic_aul import ranked_templates
from forensic_aul.ops.identify.repeat import rank_repeated
from forensic_aul.reports import format_ranking


def _identified(path, rows):
    """rows: (process, format_string, message, tier)."""
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE identified_logs (process TEXT, format_string TEXT, "
                 "message TEXT, tier TEXT, excluded INTEGER)")
    conn.executemany("INSERT INTO identified_logs VALUES (?, ?, ?, ?, ?)",
                     [(p, f, m, t, int(t == "repeat")) for p, f, m, t in rows])
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
    result = rank_repeated(dbs, tmp_path / "repeat.db")
    assert (result.cycles, result.templates, result.in_every_cycle) == (3, 4, 1)

    top = ranked_templates(result.path)
    assert top[0][1:5] == (3, 3, 3, "screenshotd")
    assert {row[4] for row in top} == {"screenshotd", "wifid", "app"}
    assert "kernel" not in format_ranking(result, top)
