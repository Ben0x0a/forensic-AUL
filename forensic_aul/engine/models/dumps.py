"""Statedump / Simpledump chunk models.

Defines : Statedump, SimpleDump
Used by  : forensic_aul.engine.parser.statedump (parsers),
           forensic_aul.ops.extraction.entry_builder (→ LogEntry)

Both are non-Firehose log sub-chunks (tags 0x6003 / 0x6004) that ``log show``
emits as ordinary log lines. They mirror the Rust macos-unifiedlogs structs
(``chunks/statedump.rs`` / ``chunks/simpledump.rs``) field-for-field so the port
stays auditable.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Statedump:
    """A Statedump log entry (tag 0x6003) — a plist, custom object or protobuf."""
    chunk_tag: int
    chunk_subtag: int
    chunk_data_size: int
    first_proc_id: int           # u64
    second_proc_id: int          # u32
    ttl: int                     # u8
    continuous_time: int         # u64 — mach continuous time
    activity_id: int             # u64
    uuid: str                    # sender UUID (uppercase hex, no dashes)
    unknown_data_type: int       # u32 — 1=plist, 2=protobuf, 3=custom object
    unknown_data_size: int       # u32 — size of statedump_data
    decoder_library: str         # only set for custom-object (type 3)
    decoder_type: str            # only set for custom-object (type 3)
    title_name: str
    statedump_data: bytes = b""


@dataclass
class SimpleDump:
    """A Simpledump log entry (tag 0x6004) — a single message string (macOS 12+)."""
    chunk_tag: int
    chunk_subtag: int
    chunk_data_size: int
    first_proc_id: int               # u64
    second_proc_id: int              # u64
    continuous_time: int             # u64 — mach continuous time
    thread_id: int                   # u64
    unknown_offset: int              # u32
    unknown_ttl: int                 # u16
    unknown_type: int                # u16
    sender_uuid: str                 # uppercase hex, no dashes
    dsc_uuid: str                    # uppercase hex, no dashes
    unknown_number_message_strings: int = 0  # u32
    subsystem: str = ""
    message_string: str = ""
