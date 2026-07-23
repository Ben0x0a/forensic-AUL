"""tracev3 chunk-level data models — header, catalog, and process metadata.

All structures mirror the Rust macos-unifiedlogs library (Mandiant)
field-for-field to maximise traceability between implementations.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


# ── Chunk-level structures ────────────────────────────────────────────────────

@dataclass
class ChunkPreamble:
    """16-byte preamble that precedes every chunk in a tracev3 file."""
    chunk_tag: int        # u32 LE — 0x1000=Header, 0x600b=Catalog, 0x600d=Chunkset
    chunk_sub_tag: int    # u32 LE
    chunk_data_size: int  # u64 LE — payload size (not including this preamble)
    file_offset: int      # byte offset of this preamble in the source file


@dataclass
class HeaderChunk:
    """Parsed tracev3 file header (chunk tag 0x1000)."""
    chunk_tag: int
    chunk_sub_tag: int
    chunk_data_size: int
    mach_time_numerator: int        # u32 — timebase ratio numerator (1 on Intel, 125 on ARM)
    mach_time_denominator: int      # u32 — timebase ratio denominator (1 on Intel, 3 on ARM)
    continuous_time: int            # u64 — mach continuous time at capture
    unknown_time: int               # u64 — possibly wall-clock boot time (unix seconds)
    unknown: int                    # u32
    bias_min: int                   # u32 — timezone offset in minutes
    daylight_savings: int           # u32 — 0=no DST, 1=DST
    unknown_flags: int              # u32
    sub_chunk_tag: int              # u32 — 0x6100
    sub_chunk_data_size: int        # u32
    sub_chunk_continuous_time: int  # u64
    sub_chunk_tag_2: int            # u32 — 0x6101
    sub_chunk_tag_data_size_2: int  # u32
    unknown_2: int                  # u32
    unknown_3: int                  # u32
    build_version_string: str       # 16 bytes, null-padded
    hardware_model_string: str      # 32 bytes, null-padded
    sub_chunk_tag_3: int            # u32 — 0x6102
    sub_chunk_tag_data_size_3: int  # u32
    boot_uuid: str                  # 16 bytes big-endian UUID, hex string uppercase no dashes
    logd_pid: int                   # u32
    logd_exit_status: int           # u32
    sub_chunk_tag_4: int            # u32 — 0x6103
    sub_chunk_tag_data_size_4: int  # u32
    timezone_path: str              # 48 bytes, null-padded


# ── Catalog structures ────────────────────────────────────────────────────────

@dataclass
class ProcessUUIDEntry:
    """UUID entry within a ProcessInfoEntry — maps a UUID index to a load address."""
    size: int              # u32
    unknown: int           # u32
    catalog_uuid_index: int  # u16 — index into CatalogChunk.catalog_uuids
    load_address: int      # u64
    uuid: str              # resolved from catalog_uuids[catalog_uuid_index]


@dataclass
class ProcessInfoSubsystem:
    """Subsystem/category pair offsets within a ProcessInfoEntry."""
    identifier: int        # u16
    subsystem_offset: int  # u16 — byte offset into catalog_subsystem_strings
    category_offset: int   # u16 — byte offset into catalog_subsystem_strings


@dataclass
class ProcessInfoEntry:
    """Per-process metadata stored in the Catalog chunk."""
    index: int
    unknown: int                       # u16
    catalog_main_uuid_index: int       # u16 — index into catalog_uuids (UUIDText file)
    catalog_dsc_uuid_index: int        # u16 — index into catalog_uuids (DSC file)
    first_number_proc_id: int          # u64 — part of composite process key
    second_number_proc_id: int         # u32 — part of composite process key
    pid: int                           # u32
    effective_user_id: int             # u32 (euid)
    unknown2: int                      # u32
    number_uuids_entries: int          # u32
    unknown3: int                      # u32
    uuid_info_entries: list[ProcessUUIDEntry]
    number_subsystems: int             # u32
    unknown4: int                      # u32
    subsystem_entries: list[ProcessInfoSubsystem]
    main_uuid: str                     # resolved UUID string
    dsc_uuid: str                      # resolved UUID string


@dataclass
class CatalogSubchunk:
    """Compressed sub-chunk descriptor within the Catalog."""
    start: int                # u64 — mach continuous time start
    end: int                  # u64 — mach continuous time end
    uncompressed_size: int    # u32
    compression_algorithm: int  # u32 — 0x100 = LZ4 block
    number_index: int         # u32
    indexes: list[int]        # u16 each — indices into catalog_uuids
    number_string_offsets: int  # u32
    string_offsets: list[int]  # u16 each


@dataclass
class CatalogChunk:
    """Parsed Catalog chunk (tag 0x600b) containing process/subsystem metadata."""
    chunk_tag: int
    chunk_sub_tag: int
    chunk_data_size: int
    catalog_subsystem_strings_offset: int   # u16 — relative to start of UUID array
    catalog_process_info_entries_offset: int  # u16
    number_process_information_entries: int  # u16
    catalog_offset_sub_chunks: int          # u16
    number_sub_chunks: int                  # u16
    unknown: bytes                          # 6 bytes padding
    earliest_firehose_timestamp: int        # u64
    catalog_uuids: list[str]               # big-endian 128-bit UUIDs as hex strings
    catalog_subsystem_strings: bytes        # raw null-terminated string pool
    catalog_process_info_entries: dict[str, ProcessInfoEntry]  # key: "first:second"
    catalog_subchunks: list[CatalogSubchunk]

    def get_process_info(
        self, first_proc_id: int, second_proc_id: int
    ) -> Optional[ProcessInfoEntry]:
        # Key format mirrors the Rust implementation: "{first}_{second}"
        return self.catalog_process_info_entries.get(f"{first_proc_id}_{second_proc_id}")

    def get_pid(self, first_proc_id: int, second_proc_id: int) -> int:
        entry = self.get_process_info(first_proc_id, second_proc_id)
        return entry.pid if entry else 0

    def get_euid(self, first_proc_id: int, second_proc_id: int) -> int:
        entry = self.get_process_info(first_proc_id, second_proc_id)
        return entry.effective_user_id if entry else 0

    def get_subsystem(
        self, subsystem_value: int, first_proc_id: int, second_proc_id: int
    ) -> tuple[str, str]:
        """Return (subsystem, category) strings for a log entry."""
        entry = self.get_process_info(first_proc_id, second_proc_id)
        if not entry:
            return ("", "")
        for sub in entry.subsystem_entries:
            if sub.identifier == subsystem_value:
                subsystem = _extract_cstr(self.catalog_subsystem_strings, sub.subsystem_offset)
                category = _extract_cstr(self.catalog_subsystem_strings, sub.category_offset)
                return (subsystem, category)
        return ("", "")

    def get_catalog_dsc(
        self, first_proc_id: int, second_proc_id: int
    ) -> tuple[str, str]:
        """Return (dsc_uuid, main_uuid) for the process."""
        entry = self.get_process_info(first_proc_id, second_proc_id)
        if not entry:
            return ("", "")
        return (entry.dsc_uuid, entry.main_uuid)


def _extract_cstr(data: bytes, offset: int) -> str:
    """Extract a null-terminated UTF-8 string from a byte pool at the given offset."""
    if offset >= len(data):
        return ""
    end = data.find(b"\x00", offset)
    if end == -1:
        end = len(data)
    try:
        return data[offset:end].decode("utf-8", errors="replace")
    except Exception:
        return ""
