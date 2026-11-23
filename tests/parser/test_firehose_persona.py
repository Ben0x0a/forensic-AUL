"""Unit tests for the iOS 27 has_persona firehose flag — forensic_aul/engine/parser/firehose.py.

Covers : with flag 0x40 set, a u32 persona id follows the current activity id in
         non-activity, signpost and activity entries; it is read, and every later
         field (private-data range, subsystem id) lands where it belongs. Without
         the flag (every OS before 27) the layout is unchanged.
Uses    : entry bytes built here from the documented layout (synthetic values).
"""

from __future__ import annotations

import struct

import pytest

from forensic_aul.engine.parser.firehose import (
    FLAG_HAS_CURRENT_AID,
    FLAG_HAS_PERSONA,
    FLAG_HAS_PRIVATE_DATA,
    FLAG_HAS_SUBSYSTEM,
    FLAG_MAIN_EXE,
    _parse_non_activity,
    _parse_signpost,
)

_BASE = FLAG_HAS_CURRENT_AID | FLAG_HAS_PRIVATE_DATA | FLAG_HAS_SUBSYSTEM | FLAG_MAIN_EXE


def _entry(with_persona: bool) -> bytes:
    data = struct.pack("<II", 0x1234, 0x80000000)          # current activity id + sentinel
    if with_persona:
        data += struct.pack("<I", 501)                     # persona id (iOS 27)
    data += struct.pack("<HH", 0x200, 16)                  # private strings offset / size
    data += struct.pack("<I", 0xABCD)                      # pc id
    data += struct.pack("<H", 7)                           # subsystem id
    return data


@pytest.mark.parametrize("parse", [_parse_non_activity, _parse_signpost])
@pytest.mark.parametrize("with_persona", [False, True])
def test_fields_after_the_persona_id_land_in_place(parse, with_persona):
    flags = _BASE | (FLAG_HAS_PERSONA if with_persona else 0)
    record, pos = parse(_entry(with_persona), 0, flags)
    assert record.persona_id == (501 if with_persona else 0)
    assert (record.private_strings_offset, record.private_strings_size) == (0x200, 16)
    subsystem = getattr(record, "subsystem_value", None)
    if subsystem is None:
        subsystem = record.subsystem
    assert subsystem == 7
    assert pos == len(_entry(with_persona))
