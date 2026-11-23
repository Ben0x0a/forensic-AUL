"""Parse Apple Unified Log Catalog chunk (tag 0x600b).

The Catalog contains process metadata, subsystem/category strings, the persona
block (iOS 27 / macOS 27) and descriptors for the compressed chunksets that
follow it.

Defines : ``parse_catalog_chunk``.
Used by : forensic_aul.ops.extraction.tracev3_parse and .oversize_pass.
Uses    : forensic_aul.engine.models (the catalog dataclasses),
          forensic_aul.engine.parser.reader, .format, forensic_aul.errors.

WHY each section is read from its DECLARED offset (not one after the other): the
header gives every section's start. Reading them in sequence instead meant that
the first new block Apple added — the iOS 27 persona block — shifted every later
read and broke every catalog. Each section is now parsed inside its own slice;
the sequential layout is only a cross-check, and a mismatch (records that do not
exactly fill their section) is recorded in ``CatalogChunk.observations`` as
format drift while parsing goes on.

Layout (all section offsets are relative to the end of the fixed header):

    preamble(16)  strings_off u16  proc_off u16  n_proc u16  subchunks_off u16
                  n_subchunks u16  persona_off u16  n_persona u16  unknown u16
                  earliest_firehose_timestamp u64
    [0, strings_off)             catalog UUIDs (16 bytes each, big-endian)
    [strings_off, proc_off)      subsystem / category string pool
    [proc_off, persona_off|subchunks_off)  process entries
    [persona_off, subchunks_off) personas (iOS 27; only when n_persona > 0)
    [subchunks_off, end)         chunkset descriptors

Binary layout reference: macos-UnifiedLogs/src/catalog.rs (v0.7.0)
Padding formula from:    macos-UnifiedLogs/src/util.rs :: padding_size()
"""

from __future__ import annotations

import logging

from forensic_aul.engine.models import (
    CatalogChunk,
    CatalogPersona,
    CatalogSubchunk,
    ProcessInfoEntry,
    ProcessInfoSubsystem,
    ProcessUUIDEntry,
)
from forensic_aul.engine.parser.format import (
    CATALOG_COMPRESSION_LZ4,
    CATALOG_COMPRESSION_LZBITMAP,
    CHUNK_PREAMBLE_SIZE,
)
from forensic_aul.engine.parser.reader import BinaryReader, reader_from_bytes
from forensic_aul.errors import CorruptRecord, TruncatedRecord

log = logging.getLogger(__name__)

_FIXED_HEADER = 8 * 2 + 8            # eight u16 + the u64 timestamp
_UUID_SIZE = 16
_PERSONA_HEADER = 12                 # persona_id, persona_type, uuid_offset (3 × u32)
_PERSONA_UUID_TEXT = 37              # 36-character UUID + NUL
_KNOWN_COMPRESSION = frozenset({CATALOG_COMPRESSION_LZ4}) | CATALOG_COMPRESSION_LZBITMAP


def parse_catalog_chunk(data: bytes) -> CatalogChunk:
    """Parse a CatalogChunk from raw chunk bytes (*data* starts at the preamble).

    Raises:
        CorruptRecord: a section offset outside the chunk or out of order.
        TruncatedRecord: the chunk ends inside its fixed header, or a section's
            records run past the space the header gives it.
    """
    r = reader_from_bytes(data)
    chunk_tag = r.u32()
    chunk_sub_tag = r.u32()
    chunk_data_size = r.u64()
    strings_off = r.u16()
    proc_off = r.u16()
    n_proc = r.u16()
    subchunks_off = r.u16()
    n_subchunks = r.u16()
    persona_off = r.u16()
    n_persona = r.u16()
    unknown = r.u16()
    earliest_firehose_timestamp = r.u64()

    body = data[CHUNK_PREAMBLE_SIZE + _FIXED_HEADER:CHUNK_PREAMBLE_SIZE + chunk_data_size]
    observations: list[str] = []
    has_personas = n_persona > 0 and proc_off <= persona_off <= subchunks_off
    if n_persona > 0 and not has_personas:
        observations.append(f"persona block declared ({n_persona} at {persona_off}) outside "
                            f"[{proc_off}, {subchunks_off}] — ignored")
    proc_end = persona_off if has_personas else subchunks_off
    # WHY: every section must start inside the chunk and after the previous one,
    # or the slices below would overlap or read past the end.
    if not strings_off <= proc_off <= proc_end <= subchunks_off <= len(body):
        raise CorruptRecord(f"catalog section offsets out of order or past the chunk: "
                            f"{strings_off}/{proc_off}/{proc_end}/{subchunks_off} in {len(body)}")

    if strings_off % _UUID_SIZE:
        observations.append(f"UUID section of {strings_off} bytes is not a multiple of {_UUID_SIZE}")
    uuids_r = reader_from_bytes(body[:strings_off])
    catalog_uuids = [uuids_r.uuid_be() for _ in range(strings_off // _UUID_SIZE)]
    catalog_subsystem_strings = body[strings_off:proc_off]

    proc_r = reader_from_bytes(body[proc_off:proc_end])
    catalog_process_info_entries: dict[str, ProcessInfoEntry] = {}
    for _ in range(n_proc):
        entry = _in_section("process entries", lambda: _parse_process_info_entry(proc_r, catalog_uuids))
        catalog_process_info_entries[f"{entry.first_number_proc_id}_{entry.second_number_proc_id}"] = entry
    _left_over("process entries", proc_r, observations)

    personas: list[CatalogPersona] = []
    if has_personas:
        persona_r = reader_from_bytes(body[persona_off:subchunks_off])
        personas = _in_section("personas", lambda: _parse_personas(persona_r, n_persona))
        _left_over("personas", persona_r, observations)

    sub_r = reader_from_bytes(body[subchunks_off:])
    catalog_subchunks = [
        _in_section("chunkset descriptors", lambda: _parse_catalog_subchunk(sub_r, observations))
        for _ in range(n_subchunks)
    ]
    _left_over("chunkset descriptors", sub_r, observations)

    for note in observations:
        log.debug("catalog format drift: %s", note)
    return CatalogChunk(
        chunk_tag=chunk_tag,
        chunk_sub_tag=chunk_sub_tag,
        chunk_data_size=chunk_data_size,
        catalog_subsystem_strings_offset=strings_off,
        catalog_process_info_entries_offset=proc_off,
        number_process_information_entries=n_proc,
        catalog_offset_sub_chunks=subchunks_off,
        number_sub_chunks=n_subchunks,
        persona_offset=persona_off,
        persona_count=n_persona,
        unknown=unknown,
        earliest_firehose_timestamp=earliest_firehose_timestamp,
        catalog_uuids=catalog_uuids,
        catalog_subsystem_strings=catalog_subsystem_strings,
        catalog_process_info_entries=catalog_process_info_entries,
        catalog_subchunks=catalog_subchunks,
        personas=personas,
        observations=observations,
    )


def _in_section(name, parse):  # type: ignore[no-untyped-def]
    """Run *parse*; a read past the section's end names the section."""
    try:
        return parse()
    except TruncatedRecord as exc:
        raise TruncatedRecord(f"catalog {name} run past their section: {exc}") from exc


def _left_over(name: str, r: BinaryReader, observations: list[str]) -> None:
    """Bytes a section's records did not use: alignment padding (up to 7 zero
    bytes) is expected; anything else is format drift — new or longer records."""
    rest = r.read(r.remaining())
    if len(rest) > 7 or any(rest):
        observations.append(f"{name}: {len(rest)} byte(s) after the declared records")


def _parse_personas(r: BinaryReader, count: int) -> list[CatalogPersona]:
    """The persona block: *count* fixed headers, padding to 8, then *count*
    37-byte UUID strings, padding to 8 (macos-UnifiedLogs catalog.rs)."""
    headers = [(r.u32(), r.u32(), r.u32()) for _ in range(count)]
    r.skip(_anticipated_padding_size_8(count, _PERSONA_HEADER))
    personas = [
        CatalogPersona(persona_id=pid, persona_type=ptype, uuid_offset=off,
                       uuid=r.cstr_fixed(_PERSONA_UUID_TEXT))
        for pid, ptype, off in headers
    ]
    r.skip(_anticipated_padding_size_8(count, _PERSONA_UUID_TEXT))
    return personas


# ── Internal parsers ──────────────────────────────────────────────────────────

def _parse_process_info_entry(r: BinaryReader, uuids: list[str]) -> ProcessInfoEntry:
    index = r.u16()
    unknown = r.u16()
    catalog_main_uuid_index = r.u16()
    catalog_dsc_uuid_index = r.u16()
    first_number_proc_id = r.u64()
    second_number_proc_id = r.u32()
    pid = r.u32()
    effective_user_id = r.u32()
    persona_id = r.u32()
    number_uuids_entries = r.u32()
    unknown3 = r.u32()

    uuid_info_entries: list[ProcessUUIDEntry] = []
    for _ in range(number_uuids_entries):
        uuid_entry = _parse_process_uuid_entry(r, uuids)
        uuid_info_entries.append(uuid_entry)

    number_subsystems = r.u32()
    unknown4 = r.u32()

    subsystem_entries: list[ProcessInfoSubsystem] = []
    for _ in range(number_subsystems):
        sub = ProcessInfoSubsystem(
            identifier=r.u16(),
            subsystem_offset=r.u16(),
            category_offset=r.u16(),
        )
        subsystem_entries.append(sub)

    # 8-byte alignment padding after subsystem entries
    # Formula: padding_size(items_count * items_size, 8)
    # where items_size for ProcessInfoSubsystem = 6 bytes (3 × u16)
    padding = _anticipated_padding_size_8(number_subsystems, 6)
    if padding:
        r.skip(padding)

    main_uuid = uuids[catalog_main_uuid_index] if catalog_main_uuid_index < len(uuids) else ""
    dsc_uuid = uuids[catalog_dsc_uuid_index] if catalog_dsc_uuid_index < len(uuids) else ""

    return ProcessInfoEntry(
        index=index,
        unknown=unknown,
        catalog_main_uuid_index=catalog_main_uuid_index,
        catalog_dsc_uuid_index=catalog_dsc_uuid_index,
        first_number_proc_id=first_number_proc_id,
        second_number_proc_id=second_number_proc_id,
        pid=pid,
        effective_user_id=effective_user_id,
        persona_id=persona_id,
        number_uuids_entries=number_uuids_entries,
        unknown3=unknown3,
        uuid_info_entries=uuid_info_entries,
        number_subsystems=number_subsystems,
        unknown4=unknown4,
        subsystem_entries=subsystem_entries,
        main_uuid=main_uuid,
        dsc_uuid=dsc_uuid,
    )


def _parse_process_uuid_entry(r: BinaryReader, uuids: list[str]) -> ProcessUUIDEntry:
    size = r.u32()
    unknown = r.u32()
    catalog_uuid_index = r.u16()

    # Load address is stored as 6 bytes LE (48-bit address)
    raw6 = r.read(6)
    load_address = int.from_bytes(raw6, "little")

    uuid = uuids[catalog_uuid_index] if catalog_uuid_index < len(uuids) else ""

    return ProcessUUIDEntry(
        size=size,
        unknown=unknown,
        catalog_uuid_index=catalog_uuid_index,
        load_address=load_address,
        uuid=uuid,
    )


def _parse_catalog_subchunk(r: BinaryReader, observations: list[str]) -> CatalogSubchunk:
    start = r.u64()
    end = r.u64()
    uncompressed_size = r.u32()
    compression_algorithm = r.u32()

    if compression_algorithm not in _KNOWN_COMPRESSION:
        # Only declared: the chunkset's own magic decides how it is decoded.
        observations.append(f"chunkset descriptor declares unknown compression 0x{compression_algorithm:x}")

    number_index = r.u32()
    indexes: list[int] = [r.u16() for _ in range(number_index)]

    number_string_offsets = r.u32()
    string_offsets: list[int] = [r.u16() for _ in range(number_string_offsets)]

    # 8-byte alignment padding after the variable-length arrays
    # Each element is 2 bytes (u16); total payload = (number_index + number_string_offsets) * 2
    padding = _anticipated_padding_size_8(number_index + number_string_offsets, 2)
    if padding:
        r.skip(padding)

    return CatalogSubchunk(
        start=start,
        end=end,
        uncompressed_size=uncompressed_size,
        compression_algorithm=compression_algorithm,
        number_index=number_index,
        indexes=indexes,
        number_string_offsets=number_string_offsets,
        string_offsets=string_offsets,
    )


def _anticipated_padding_size_8(items_count: int, items_size: int) -> int:
    """Return bytes of padding needed to align items_count*items_size to 8 bytes.

    Formula from macos-UnifiedLogs/src/util.rs :: padding_size():
        (alignment - (total_size & (alignment - 1))) & (alignment - 1)
    """
    total_size = items_count * items_size
    alignment = 8
    return (alignment - (total_size & (alignment - 1))) & (alignment - 1)
