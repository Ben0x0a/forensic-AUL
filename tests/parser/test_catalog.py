"""Unit tests for the catalog parser — forensic_aul/engine/parser/catalog.py.

Covers : the pre-iOS-27 layout, the iOS 27 persona block, that every section is
         read from its DECLARED offset (an unknown block between sections is
         skipped and reported as format drift, not misread), and that impossible
         offsets are refused.
Uses    : catalog bytes built here from the documented layout (synthetic values).
"""

from __future__ import annotations

import struct

import pytest

from forensic_aul.engine.parser.catalog import parse_catalog_chunk
from forensic_aul.engine.parser.format import CHUNK_TAG_CATALOG
from forensic_aul.errors import CorruptRecord

_UUID = bytes(range(16))
_STRINGS = b"com.example.sub\x00default\x00"


def _pad8(b: bytes) -> bytes:
    return b + b"\x00" * (-len(b) % 8)


def _process_entry(persona_id: int = 0) -> bytes:
    head = struct.pack("<HHHHQIIIIII", 0, 0, 0, 0, 7, 9, 123, 501, persona_id, 0, 0)
    subsystems = struct.pack("<II", 1, 0) + struct.pack("<HHH", 5, 0, 16)
    return _pad8(head + subsystems)


def _descriptor(compression: int = 0x100) -> bytes:
    return _pad8(struct.pack("<QQIIIH", 1, 2, 4096, compression, 1, 0) + struct.pack("<I", 0))


def _personas() -> bytes:
    headers = _pad8(struct.pack("<III", 501, 2, 0))
    text = _pad8(b"FEEDEEEE-DDDD-CCCC-BBBB-5555000001F5\x00")
    return headers + text


def _catalog(*, personas: bytes = b"", n_persona: int = 0, extra: bytes = b"",
             compression: int = 0x100, persona_id: int = 0) -> bytes:
    uuids, proc = _UUID, _process_entry(persona_id)
    strings_off = len(uuids)
    proc_off = strings_off + len(_STRINGS)
    persona_off = proc_off + len(proc) + len(extra)
    sub_off = persona_off + len(personas)
    body = uuids + _STRINGS + proc + extra + personas + _descriptor(compression)
    header = struct.pack("<HHHHHHHHQ", strings_off, proc_off, 1, sub_off, 1,
                         persona_off if n_persona else 0, n_persona, 0, 1000)
    payload = header + body
    return struct.pack("<IIQ", CHUNK_TAG_CATALOG, 0x11, len(payload)) + payload


def test_pre_ios_27_layout():
    c = parse_catalog_chunk(_catalog())
    assert c.catalog_uuids == [_UUID.hex().upper()]
    assert c.catalog_subsystem_strings == _STRINGS
    entry = c.get_process_info(7, 9)
    assert entry is not None and entry.pid == 123 and entry.effective_user_id == 501
    assert c.catalog_subchunks[0].uncompressed_size == 4096
    assert (c.personas, c.observations) == ([], [])


def test_ios_27_persona_block_is_parsed():
    c = parse_catalog_chunk(_catalog(personas=_personas(), n_persona=1, persona_id=501))
    assert c.persona_count == 1
    assert c.personas[0].persona_id == 501
    assert c.personas[0].uuid == "FEEDEEEE-DDDD-CCCC-BBBB-5555000001F5"
    assert c.get_process_info(7, 9).persona_id == 501
    assert c.catalog_subchunks[0].uncompressed_size == 4096, "descriptors read after the personas"
    assert c.observations == []


def test_an_unknown_block_is_skipped_and_reported_not_misread():
    """The iOS 27 failure mode: a block the parser does not know sits between two
    sections. Read from declared offsets, the sections after it are still right."""
    c = parse_catalog_chunk(_catalog(extra=b"\x01" * 24))
    assert c.catalog_subchunks[0].uncompressed_size == 4096
    assert any("process entries: 24 byte(s)" in note for note in c.observations)


def test_an_undeclared_compression_value_is_an_observation():
    c = parse_catalog_chunk(_catalog(compression=0x999))
    assert any("unknown compression 0x999" in note for note in c.observations)
    assert parse_catalog_chunk(_catalog(compression=0x700)).observations == []


def test_offsets_out_of_order_are_refused():
    raw = bytearray(_catalog())
    struct.pack_into("<H", raw, 16 + 2, 1)            # proc_off before strings_off
    with pytest.raises(CorruptRecord, match="out of order"):
        parse_catalog_chunk(bytes(raw))
