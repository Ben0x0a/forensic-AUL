"""Firehose entry data models — the per-process log-entry structures.

Includes Oversize, whose payload is a ``FirehoseItemData`` block (strings too
large for a normal Firehose entry). All structures mirror the Rust
macos-unifiedlogs library field-for-field.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FirehoseFormatters:
    """Formatter flags that determine which file holds the format string."""
    main_exe: bool = False           # flag 0x2 — format string in UUIDText file
    shared_cache: bool = False       # flag 0x4 — format string in DSC file
    has_large_offset: int = 0        # flag 0x20 — extra u16 large offset
    large_shared_cache: int = 0      # flag 0xc  — extra u16 large shared cache offset
    absolute: bool = False           # flag 0x8  — absolute UUID index
    uuid_relative: str = ""          # flag 0xa  — 16-byte UUID in data
    main_plugin: bool = False
    pc_style: bool = False
    main_exe_alt_index: int = 0      # extra u16 when absolute and not main_exe


@dataclass
class FirehoseItemInfo:
    """A single formatted item within a Firehose log message."""
    message_strings: str  # resolved string value (or number as string)
    item_type: int        # u8 — 0x20/0x22/0x40/0x42/0x30-0x32/0xf2=string, 0x1=private num, etc.
    item_size: int        # u16 — size in bytes of the raw value


@dataclass
class FirehoseItemData:
    """Collection of items and optional backtrace for a Firehose entry."""
    item_info: list[FirehoseItemInfo] = field(default_factory=list)
    backtrace_strings: list[str] = field(default_factory=list)


@dataclass
class FirehoseNonActivity:
    """Non-activity type Firehose log entry (log_activity_type == 0x4)."""
    unknown_activity_id: int = 0          # u32, present if flag 0x0001
    unknown_sentinel: int = 0             # u32, always 0x80000000?
    private_strings_offset: int = 0       # u16, present if flag 0x0100
    private_strings_size: int = 0         # u16, present if flag 0x0100
    unknown_message_string_ref: int = 0   # u32, present if flag 0x0008
    subsystem_value: int = 0              # u16, present if flag 0x0200 (has_subsystem)
    ttl_value: int = 0                    # u8,  present if flag 0x0400 (has_rules)
    data_ref_value: int = 0               # u32, present if flag 0x0800 (has_oversize)
    unknown_pc_id: int = 0               # u32, for absolute offset calculation
    firehose_formatters: FirehoseFormatters = field(default_factory=FirehoseFormatters)


@dataclass
class FirehoseActivity:
    """Activity type Firehose log entry (log_activity_type == 0x2)."""
    unknown_activity_id: int = 0    # u32
    unknown_sentinel: int = 0       # u32, always 0x80000000?
    pid: int = 0                    # u64, present if flag 0x0010 (has_unique_pid)
    unknown_activity_id_2: int = 0  # u32, present if flag 0x0001 (has_current_aid)
    unknown_sentinel_2: int = 0     # u32
    unknown_activity_id_3: int = 0  # u32, present if flag 0x0200 (has_other_aid)
    unknown_sentinel_3: int = 0     # u32
    unknown_message_string_ref: int = 0  # u32
    unknown_pc_id: int = 0          # u32
    firehose_formatters: FirehoseFormatters = field(default_factory=FirehoseFormatters)


@dataclass
class FirehoseSignpost:
    """Signpost type Firehose log entry (log_activity_type == 0x6)."""
    unknown_pc_id: int = 0            # u32
    unknown_activity_id: int = 0      # u32, present if flag 0x0001
    unknown_sentinel: int = 0         # u32
    subsystem: int = 0                # u16
    signpost_id: int = 0              # u64
    signpost_name: int = 0            # u32
    private_strings_offset: int = 0   # u16, present if flag 0x0100
    private_strings_size: int = 0     # u16, present if flag 0x0100
    ttl_value: int = 0                # u8,  present if flag 0x0400
    data_ref_value: int = 0           # u32, present if flag 0x0800
    firehose_formatters: FirehoseFormatters = field(default_factory=FirehoseFormatters)


@dataclass
class FirehoseTrace:
    """Trace type Firehose log entry (log_activity_type == 0x3)."""
    unknown_pc_id: int = 0
    message_data: FirehoseItemData = field(default_factory=FirehoseItemData)


@dataclass
class FirehoseLoss:
    """Loss type Firehose log entry (log_activity_type == 0x7)."""
    start_time: int = 0  # u64
    end_time: int = 0    # u64
    count: int = 0       # u32


@dataclass
class Firehose:
    """A single parsed Firehose log entry."""
    unknown_log_activity_type: int  # u8 — 0x2=Activity, 0x3=Trace, 0x4=NonActivity, 0x6=Signpost, 0x7=Loss
    unknown_log_type: int           # u8 — maps to log level
    flags: int                      # u16 — bit flags controlling optional fields
    format_string_location: int     # u32 — offset into UUID/DSC for format string
    thread_id: int                  # u64
    continuous_time_delta: int      # u32 — low 32 bits of delta
    continuous_time_delta_upper: int  # u16 — high 16 bits of delta
    data_size: int                  # u16
    firehose_activity: FirehoseActivity = field(default_factory=FirehoseActivity)
    firehose_non_activity: FirehoseNonActivity = field(default_factory=FirehoseNonActivity)
    firehose_loss: FirehoseLoss = field(default_factory=FirehoseLoss)
    firehose_signpost: FirehoseSignpost = field(default_factory=FirehoseSignpost)
    firehose_trace: FirehoseTrace = field(default_factory=FirehoseTrace)
    unknown_item: int = 0           # u8
    number_items: int = 0           # u8
    message: FirehoseItemData = field(default_factory=FirehoseItemData)
    # Byte offset of this entry's first byte (its activity-type) within the
    # FirehosePreamble bytes. Used to surface forensic provenance back to the
    # source tracev3 file.
    entry_inner_offset: int = 0


@dataclass
class FirehosePreamble:
    """Header preceding a block of Firehose entries in a decompressed chunkset."""
    chunk_tag: int
    chunk_sub_tag: int
    chunk_data_size: int
    first_number_proc_id: int       # u64 — composite process ID part 1
    second_number_proc_id: int      # u32 — composite process ID part 2
    ttl: int                        # u8
    collapsed: int                  # u8 — 1 if private data is collapsed
    unknown: bytes                  # 2 bytes
    public_data_size: int           # u16 — includes 16 bytes of preamble fields
    private_data_virtual_offset: int  # u16 — 0x1000 means no private data
    unknown2: int                   # u16
    unknown3: int                   # u16
    base_continuous_time: int       # u64 — base mach time for all entries in this block
    public_data: list[Firehose] = field(default_factory=list)


# ── Oversize ──────────────────────────────────────────────────────────────────

@dataclass
class Oversize:
    """Oversize log entry — contains strings too large for normal Firehose entries."""
    chunk_tag: int
    chunk_sub_tag: int
    chunk_data_size: int
    first_proc_id: int        # u64
    second_proc_id: int       # u32
    ttl: int                  # u8
    continuous_time: int      # u64
    data_ref_index: int       # u32 — matches data_ref_value in FirehoseNonActivity/Signpost
    public_data_size: int     # u16
    private_data_size: int    # u16
    message_items: FirehoseItemData = field(default_factory=FirehoseItemData)
