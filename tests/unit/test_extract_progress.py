"""Parse-phase progress (forensic_aul/ops/extraction/extract.py: _ByteProgress)
and the per-index callback of finalize_indexes.

Guards the L8 fix: an extract used to report a handful of events, so a consumer
could not draw a moving bar. No archive is parsed here.
"""

from __future__ import annotations

import sqlite3

from forensic_aul.engine.database.schema import finalize_indexes, init_schema
from forensic_aul.engine.utils.progress import ProgressReporter
from forensic_aul.ops.extraction.extract import _ByteProgress


def _bar():
    events: list = []
    reporter = ProgressReporter(events.append, [("parse", 1.0)])
    reporter.phase("parse")
    events.clear()
    return reporter, events


def test_fraction_is_the_mean_of_parsed_and_written_bytes():
    reporter, events = _bar()
    progress = _ByteProgress(reporter, total_bytes=1000)
    progress.set_parsed(1000, "")          # workers done, nothing written yet
    progress.advance(0, 500, "")
    assert [round(e.phase_fraction, 3) for e in events] == [0.5, 0.75]


def test_tiny_steps_are_dropped_but_the_end_is_always_reported():
    reporter, events = _bar()
    progress = _ByteProgress(reporter, total_bytes=100_000)
    for _ in range(1000):                  # 1000 steps of 0.1 % each
        progress.advance(100, 100, "")
    assert 190 <= len(events) <= 201       # one per 0.5 %, not one per step
    assert events[-1].phase_fraction == 1.0


def test_finalize_indexes_reports_each_index(tmp_path):
    conn = sqlite3.connect(tmp_path / "t.db")
    init_schema(conn, create_indexes=False)
    calls: list = []
    finalize_indexes(conn, on_index=lambda done, total: calls.append((done, total)))
    assert calls and calls[-1][0] == calls[-1][1]
    assert [done for done, _ in calls] == list(range(1, len(calls) + 1))
