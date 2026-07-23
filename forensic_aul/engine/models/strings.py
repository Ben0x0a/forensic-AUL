"""Format-string table data models — UUIDText and DSC (shared cache) files.

All structures mirror the Rust macos-unifiedlogs library field-for-field.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class UUIDTextEntry:
    """Descriptor for a format-string range within a UUIDText file."""
    range_start_offset: int  # u32 — base offset for this range
    entry_size: int          # u32 — number of bytes in this range


@dataclass
class UUIDText:
    """Parsed UUIDText file — maps a UUID to format strings."""
    uuid: str                           # derived from filename, e.g. "AA/BBBBB..." → "AABBBBB..."
    signature: int                      # u32 — must be 0x66778899
    major_version: int                  # u32
    minor_version: int                  # u32
    entry_descriptors: list[UUIDTextEntry]
    footer_data: bytes                  # raw null-terminated string pool


@dataclass
class RangeDescriptor:
    """A string range within a DSC file."""
    range_offset: int      # u64 (v2) or u32 (v1) — base offset in the string file
    data_offset: int       # u32 — offset to string data within this file
    range_size: int        # u32
    unknown_uuid_index: int  # u32 (v1) or u64 (v2)
    strings: bytes         # raw string data for this range


@dataclass
class UUIDDescriptor:
    """UUID entry within a DSC file — maps UUID to a library path."""
    text_offset: int   # u32
    text_size: int     # u32
    uuid: str          # 16-byte big-endian UUID
    path_offset: int   # u32
    path_string: str   # null-terminated library path


@dataclass
class SharedCacheStrings:
    """Parsed DSC shared string cache file."""
    signature: int         # u32 — must be 0x64736368 ("dsch")
    major_version: int     # u16 — 1=Big Sur, 2=Monterey+
    minor_version: int     # u16
    number_ranges: int     # u32
    number_uuids: int      # u32
    ranges: list[RangeDescriptor]
    uuids: list[UUIDDescriptor]
    dsc_uuid: str          # derived from filename
