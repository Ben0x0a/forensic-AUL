"""Unit tests for the extract verdict — forensic_aul/outcomes.py (ExtractStatus).

Covers : the one status policy behind ``ExtractResult.status``: FAILED when nothing
         could be decoded (the iOS 27 case: chunksets present, none decoded),
         DEGRADED for losses a reader must know about, OK otherwise.
Uses    : ExtractResult built directly — the policy is pure.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from forensic_aul import ExtractResult, ExtractStatus

_CLEAN = ExtractResult(
    db_path=Path("case.db"), metadata_id=1, entry_count=1000, parse_errors=0,
    write_errors=0, source_type="logarchive", source_sha256=None,
    chunksets=10, chunksets_decoded=10,
)


def test_clean_run_is_ok():
    assert (_CLEAN.status, _CLEAN.status_reasons) == (ExtractStatus.OK, ())


def test_nothing_decoded_is_failed():
    """B4: 0 entries and only parse errors used to be reported as complete."""
    r = replace(_CLEAN, entry_count=0, parse_errors=59, chunksets_decoded=0,
                undecodable_files=("Persist/0.tracev3",))
    assert r.status is ExtractStatus.FAILED
    assert "not supported" in r.status_reasons[0]


def test_decoded_but_no_entry_is_failed():
    assert replace(_CLEAN, entry_count=0).status is ExtractStatus.FAILED


@pytest.mark.parametrize("change, words", [
    ({"parse_errors": 3}, "3 parse error"),
    ({"write_errors": 2}, "refused by the database"),
    ({"source_files_changed": 1}, "changed during the run"),
    ({"chunksets_decoded": 7, "undecodable_files": ("a",)}, "3 of 10 chunksets"),
    ({"chunksets": 0, "chunksets_decoded": 0, "entry_count": 0}, "no log data"),
])
def test_losses_are_degraded_and_named(change, words):
    r = replace(_CLEAN, **change)
    assert r.status is ExtractStatus.DEGRADED
    assert any(words in reason for reason in r.status_reasons)
