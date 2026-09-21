"""Unit tests for Firehose item collection and private-string application.

Covers the two data-loss defects recorded as L11 residue in
tasks/open_items_2026-08.md:

* ``collect_items`` phase 4 conflated "this item is an empty string" with "the
  string pool is exhausted", so one empty argument abandoned every later item in
  the entry — the values were parsed and then discarded.
* ``_apply_private_data`` read the private-strings offset/size from
  ``firehose_non_activity`` for every entry, so a **signpost** entry (which keeps
  them on ``firehose_signpost``) never had its private items resolved and kept
  ``<private>`` placeholders for ever.

Item buffers are built by hand here: they are small, and a synthetic buffer
states the layout under test far more clearly than a captured blob would.
"""

from __future__ import annotations

import struct

import pytest

from forensic_aul.engine.models import Firehose, FirehoseItemInfo
from forensic_aul.engine.parser.firehose import (
    ACTIVITY_TYPE_ACTIVITY,
    ACTIVITY_TYPE_NON_ACTIVITY,
    ACTIVITY_TYPE_SIGNPOST,
    _apply_private_data,
    _private_strings_ref,
    collect_items,
)

# A public string item: type 0x20, header size 4, then (offset, size) as <HH.
_PUBLIC_STRING = 0x20


def _string_item(size: int) -> bytes:
    """The 6-byte header of one public-string item declaring *size* pool bytes."""
    return bytes([_PUBLIC_STRING, 0x04]) + struct.pack("<HH", 0, size)


def _values(*sizes: int, pool: bytes) -> list[str]:
    """Collect items declaring *sizes* against *pool*; return their resolved values."""
    data = b"".join(_string_item(s) for s in sizes) + pool
    items = collect_items(data, len(sizes), 0)
    return [info.message_strings for info in items.item_info]


# ── Empty string items must not truncate the entry ────────────────────────────

def test_empty_first_item_does_not_swallow_the_second():
    """The regression: "%s = %s" with an empty first argument lost the second."""
    assert _values(0, 6, pool=b"world\x00") == ["", "world"]


def test_empty_item_in_the_middle_is_transparent():
    assert _values(3, 0, 6, pool=b"ab\x00world\x00") == ["ab", "", "world"]


def test_several_empty_items_in_a_row():
    assert _values(0, 0, 3, pool=b"ab\x00") == ["", "", "ab"]


def test_all_items_empty():
    assert _values(0, 0, pool=b"") == ["", ""]


def test_trailing_empty_item():
    assert _values(3, 0, pool=b"ab\x00") == ["ab", ""]


def test_no_empty_items_is_unaffected():
    """The common path must be untouched by the fix."""
    assert _values(3, 6, pool=b"ab\x00world\x00") == ["ab", "world"]


# ── A genuinely exhausted pool is still a stop, and is reported ───────────────

def test_truncated_pool_leaves_later_items_empty():
    """Real truncation: the second item's bytes are simply not there."""
    assert _values(3, 6, pool=b"ab\x00") == ["ab", ""]


def test_truncated_pool_is_logged(caplog):
    """Data loss must be diagnosable — the old code stopped silently."""
    import logging

    with caplog.at_level(logging.DEBUG, logger="forensic_aul.engine.parser.firehose"):
        _values(3, 6, pool=b"ab\x00")
    assert any("exhausted" in r.message.lower() for r in caplog.records)


def test_partially_available_item_takes_what_is_there():
    """A short pool truncates that item's value rather than dropping it."""
    assert _values(10, pool=b"abc") == ["abc"]


# ── Private strings resolve for signpost entries too ──────────────────────────

def _entry(activity_type: int) -> Firehose:
    return Firehose(
        unknown_log_activity_type=activity_type, unknown_log_type=0, flags=0,
        format_string_location=0, thread_id=0, continuous_time_delta=0,
        continuous_time_delta_upper=0, data_size=0,
    )


def test_signpost_private_strings_are_found():
    """The regression: these were parsed off disk and then never read back."""
    entry = _entry(ACTIVITY_TYPE_SIGNPOST)
    entry.firehose_signpost.private_strings_offset = 4096
    entry.firehose_signpost.private_strings_size = 32
    assert _private_strings_ref(entry) == (4096, 32)


def test_non_activity_private_strings_still_found():
    entry = _entry(ACTIVITY_TYPE_NON_ACTIVITY)
    entry.firehose_non_activity.private_strings_offset = 2048
    entry.firehose_non_activity.private_strings_size = 16
    assert _private_strings_ref(entry) == (2048, 16)


def test_signpost_does_not_read_the_non_activity_record():
    """A signpost's zeroed non-activity sub-record must not mask its real values."""
    entry = _entry(ACTIVITY_TYPE_SIGNPOST)
    entry.firehose_signpost.private_strings_offset = 100
    entry.firehose_signpost.private_strings_size = 8
    entry.firehose_non_activity.private_strings_offset = 999   # must be ignored
    entry.firehose_non_activity.private_strings_size = 999
    assert _private_strings_ref(entry) == (100, 8)


@pytest.mark.parametrize("activity_type", [ACTIVITY_TYPE_ACTIVITY])
def test_types_without_private_strings_report_none(activity_type):
    """Activity entries carry no private-strings pair; (0, 0) means "skip"."""
    assert _private_strings_ref(_entry(activity_type)) == (0, 0)


# The tests above pin the lookup helper. These drive _apply_private_data itself,
# so a change that reverted it to reading firehose_non_activity directly would
# fail here even though the helper still worked.

_PRIVATE_STRING = 0x21   # a private string item; starts life as "<private>"


def _entry_with_private_item(activity_type: int, *, offset: int, size: int) -> Firehose:
    entry = _entry(activity_type)
    if activity_type == ACTIVITY_TYPE_SIGNPOST:
        entry.firehose_signpost.private_strings_offset = offset
        entry.firehose_signpost.private_strings_size = size
    else:
        entry.firehose_non_activity.private_strings_offset = offset
        entry.firehose_non_activity.private_strings_size = size
    entry.message.item_info.append(
        FirehoseItemInfo(message_strings="<private>", item_type=_PRIVATE_STRING, item_size=6)
    )
    return entry


@pytest.mark.parametrize("activity_type", [ACTIVITY_TYPE_SIGNPOST, ACTIVITY_TYPE_NON_ACTIVITY])
def test_apply_private_data_resolves_the_item(activity_type):
    """A signpost's private item must stop reading "<private>" like any other."""
    entry = _entry_with_private_item(activity_type, offset=16, size=6)
    _apply_private_data(b"secret\x00", [entry], 16)
    assert entry.message.item_info[0].message_strings == "secret"


def test_apply_private_data_skips_an_entry_with_no_private_strings():
    entry = _entry_with_private_item(ACTIVITY_TYPE_SIGNPOST, offset=0, size=0)
    _apply_private_data(b"secret\x00", [entry], 0)
    assert entry.message.item_info[0].message_strings == "<private>"


def test_apply_private_data_ignores_an_out_of_range_offset():
    """A corrupt offset must leave the placeholder, never read the wrong bytes."""
    entry = _entry_with_private_item(ACTIVITY_TYPE_SIGNPOST, offset=9999, size=6)
    _apply_private_data(b"secret\x00", [entry], 16)
    assert entry.message.item_info[0].message_strings == "<private>"
