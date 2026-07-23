"""Parse Apple Unified Log Catalog chunk (tag 0x600b).

The Catalog contains process metadata, subsystem/category strings, and
descriptors for the LZ4-compressed chunkset sub-chunks that follow it.

Binary layout reference: macos-UnifiedLogs/src/catalog.rs
Padding formula from:    macos-UnifiedLogs/src/util.rs :: padding_size()
"""

from __future__ import annotations

import logging

from forensic_aul.engine.models import (
    CatalogChunk,
    CatalogSubchunk,
    ProcessInfoEntry,
    ProcessInfoSubsystem,
    ProcessUUIDEntry,
)
from forensic_aul.engine.parser.reader import BinaryReader, reader_from_bytes

log = logging.getLogger(__name__)

CHUNK_TAG_CATALOG: int = 0x600B
LZ4_COMPRESSION: int = 0x100  # 256


def parse_catalog_chunk(data: bytes) -> CatalogChunk:
    """Parse a CatalogChunk from raw chunk payload bytes.

    The *data* slice must start at the outer preamble (chunk_tag u32).

    Raises:
        EOFError, ValueError on parse failure.
    """
    r = reader_from_bytes(data)

    chunk_tag = r.u32()
    chunk_sub_tag = r.u32()
    chunk_data_size = r.u64()

    catalog_subsystem_strings_offset = r.u16()
    catalog_process_info_entries_offset = r.u16()
    number_process_information_entries = r.u16()
    catalog_offset_sub_chunks = r.u16()
    number_sub_chunks = r.u16()
    unknown = r.read(6)  # alignment padding
    earliest_firehose_timestamp = r.u64()

    # UUID array: each UUID is 16 bytes big-endian.
    # Count = catalog_subsystem_strings_offset / 16
    number_catalog_uuids = catalog_subsystem_strings_offset // 16
    catalog_uuids: list[str] = []
    for _ in range(number_catalog_uuids):
        catalog_uuids.append(r.uuid_be())

    # Subsystem strings blob
    subsystem_strings_length = (
        catalog_process_info_entries_offset - catalog_subsystem_strings_offset
    )
    catalog_subsystem_strings = r.read(subsystem_strings_length)

    # Process info entries
    catalog_process_info_entries: dict[str, ProcessInfoEntry] = {}
    for _ in range(number_process_information_entries):
        entry = _parse_process_info_entry(r, catalog_uuids)
        key = f"{entry.first_number_proc_id}_{entry.second_number_proc_id}"
        catalog_process_info_entries[key] = entry

    # Catalog sub-chunks
    catalog_subchunks: list[CatalogSubchunk] = []
    for _ in range(number_sub_chunks):
        subchunk = _parse_catalog_subchunk(r)
        catalog_subchunks.append(subchunk)

    return CatalogChunk(
        chunk_tag=chunk_tag,
        chunk_sub_tag=chunk_sub_tag,
        chunk_data_size=chunk_data_size,
        catalog_subsystem_strings_offset=catalog_subsystem_strings_offset,
        catalog_process_info_entries_offset=catalog_process_info_entries_offset,
        number_process_information_entries=number_process_information_entries,
        catalog_offset_sub_chunks=catalog_offset_sub_chunks,
        number_sub_chunks=number_sub_chunks,
        unknown=unknown,
        earliest_firehose_timestamp=earliest_firehose_timestamp,
        catalog_uuids=catalog_uuids,
        catalog_subsystem_strings=catalog_subsystem_strings,
        catalog_process_info_entries=catalog_process_info_entries,
        catalog_subchunks=catalog_subchunks,
    )


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
    unknown2 = r.u32()
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
        unknown2=unknown2,
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


def _parse_catalog_subchunk(r: BinaryReader) -> CatalogSubchunk:
    start = r.u64()
    end = r.u64()
    uncompressed_size = r.u32()
    compression_algorithm = r.u32()

    if compression_algorithm != LZ4_COMPRESSION:
        log.warning(f"Catalog subchunk has unexpected compression algorithm 0x{compression_algorithm:x} (expected LZ4 0x{LZ4_COMPRESSION:x})")

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
