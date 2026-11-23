"""Unit tests for the format watch — forensic_aul/ops/extraction/format_watch.py.

Covers : counting per (kind, detail), the cap on distinct details per kind, and
         that only the alert kinds are logged as WARNING.
Uses    : caplog.
"""

from __future__ import annotations

import logging

from forensic_aul.engine.parser.firehose import FLAG_HAS_PERSONA, KNOWN_FLAG_BITS
from forensic_aul.ops.extraction import format_watch
from forensic_aul.ops.extraction.format_watch import FormatWatch


def test_counts_per_kind_and_detail():
    w = FormatWatch()
    w.note("codec", "lz4")
    w.note("codec", "lz4")
    w.note("firehose_flag", "0x2000")
    assert w.rows() == (("codec", "lz4", 2), ("firehose_flag", "0x2000", 1))


def test_a_freely_varying_detail_cannot_grow_without_bound():
    w = FormatWatch()
    for i in range(500):
        w.note("catalog_drift", f"note {i}")
    rows = w.rows()
    assert len(rows) == 51 and ("catalog_drift", "(other values)", 450) in rows


def test_alert_kinds_warn_and_codecs_inform(caplog):
    with caplog.at_level(logging.INFO, logger="forensic_aul.ops.extraction.format_watch"):
        format_watch.log_summary([("codec", "lzbitmap", 3), ("firehose_flag", "0x2000", 2),
                                  ("firehose_flag", "0x2000", 1)])
    levels = {r.getMessage().split(" (")[0]: r.levelname for r in caplog.records}
    assert levels == {"Format watch: codec lzbitmap": "INFO",
                      "Format watch: firehose_flag 0x2000": "WARNING"}
    assert "(×3)" in caplog.records[-1].getMessage()


def test_persona_is_a_known_flag_now():
    assert FLAG_HAS_PERSONA & KNOWN_FLAG_BITS
