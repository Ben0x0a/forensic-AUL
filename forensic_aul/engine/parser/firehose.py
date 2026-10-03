"""Parse Apple Unified Log Firehose entries.

FirehosePreamble contains a block of log entries for a single process.
Each entry (Firehose) has a type-specific sub-structure and a list of
formatted message items.

Binary layout reference:
  macos-UnifiedLogs/src/chunks/firehose/firehose_log.rs
  macos-UnifiedLogs/src/chunks/firehose/flags.rs
  macos-UnifiedLogs/src/chunks/firehose/nonactivity.rs
  macos-UnifiedLogs/src/chunks/firehose/activity.rs
  macos-UnifiedLogs/src/chunks/firehose/signpost.rs
  macos-UnifiedLogs/src/chunks/firehose/trace.rs
  macos-UnifiedLogs/src/chunks/firehose/loss.rs
"""

from __future__ import annotations

import base64
import logging
import struct

from forensic_aul.engine.models import (
    Firehose,
    FirehoseActivity,
    FirehoseFormatters,
    FirehoseItemData,
    FirehoseItemInfo,
    FirehoseLoss,
    FirehoseNonActivity,
    FirehosePreamble,
    FirehoseSignpost,
    FirehoseTrace,
)

log = logging.getLogger(__name__)

# ── Activity type codes ───────────────────────────────────────────────────────
ACTIVITY_TYPE_ACTIVITY: int = 0x2
ACTIVITY_TYPE_TRACE: int = 0x3
ACTIVITY_TYPE_NON_ACTIVITY: int = 0x4
ACTIVITY_TYPE_SIGNPOST: int = 0x6
ACTIVITY_TYPE_LOSS: int = 0x7
ACTIVITY_TYPE_REMNANT: int = 0x0

VALID_LOG_TYPES: frozenset[int] = frozenset([
    ACTIVITY_TYPE_ACTIVITY,
    ACTIVITY_TYPE_TRACE,
    ACTIVITY_TYPE_NON_ACTIVITY,
    ACTIVITY_TYPE_SIGNPOST,
    ACTIVITY_TYPE_LOSS,
])

# ── Flags for formatter source ────────────────────────────────────────────────
FLAG_MAIN_EXE: int = 0x2          # format string in UUIDText
FLAG_SHARED_CACHE: int = 0x4      # format string in DSC
FLAG_ABSOLUTE: int = 0x8          # absolute UUID index
FLAG_UUID_RELATIVE: int = 0xA     # UUID embedded in data
FLAG_LARGE_OFFSET: int = 0x20     # extra u16 large offset
FLAG_LARGE_SHARED_CACHE: int = 0xC  # extra u16 large shared cache

FLAG_MASK_FORMAT: int = 0xE       # mask to extract formatter flag

# Other flags
FLAG_HAS_CURRENT_AID: int = 0x0001
FLAG_HAS_UNIQUE_PID: int = 0x0010
FLAG_HAS_PRIVATE_DATA: int = 0x0100
FLAG_HAS_SUBSYSTEM: int = 0x0200
FLAG_HAS_RULES: int = 0x0400
FLAG_HAS_OVERSIZE: int = 0x0800
FLAG_HAS_CONTEXT_DATA: int = 0x1000
FLAG_HAS_OTHER_AID: int = 0x0200  # same bit as HAS_SUBSYSTEM but in Activity context
FLAG_HAS_MESSAGE_STRING_REF: int = 0x0008  # declared in Rust struct, not parsed
FLAG_HAS_NAME: int = 0x8000           # signpost-only — has_name flag (signpost.rs:111)

# Item type constants
NUMBER_ITEM_TYPES: frozenset[int] = frozenset([0x0, 0x2])
STRING_ITEMS_GET_PHASE: frozenset[int] = frozenset([
    0x20, 0x21, 0x22, 0x25, 0x40, 0x41, 0x42,
    0x30, 0x31, 0x32, 0xF2, 0x35, 0x81, 0xF1,
])
STRING_ITEMS_COLLECT_PHASE: frozenset[int] = frozenset([0x20, 0x22, 0x40, 0x42, 0x30, 0x31, 0x32, 0xF2])
PRIVATE_NUMBER: int = 0x1
PRIVATE_STRINGS: frozenset[int] = frozenset([0x21, 0x25, 0x35, 0x31, 0x41, 0x81, 0xF1])
PRECISION_ITEMS: frozenset[int] = frozenset([0x10, 0x12])
SENSITIVE_ITEMS: frozenset[int] = frozenset([0x5, 0x45, 0x85])
OBJECT_ITEMS: frozenset[int] = frozenset([0x40, 0x42])
ARBITRARY_ITEMS: frozenset[int] = frozenset([0x30, 0x31, 0x32])
BASE64_RAW_BYTES: int = 0xF2

# Sentinel returned by _parse_item_number for a number item whose size is not one
# the AUL uses (1/2/4/8 bytes) — the item could not be decoded, so this is "no
# value", NOT the number −9999. It reaches the formatter as the string "-9999"
# (message_strings is a str), so consumers that reinterpret the stored integer
# must exclude it — see engine/parser/message.py::_reinterpret_double.
UNPARSEABLE_NUMBER: int = -9999

CHUNK_PREAMBLE_SIZE: int = 16
NO_PRIVATE_DATA: int = 0x1000  # private_data_virtual_offset value = no private data


def parse_firehose_preamble(data: bytes) -> FirehosePreamble | None:
    """Parse a FirehosePreamble from sub-chunk data (including the 16-byte preamble).

    Args:
        data: Raw bytes starting at chunk_tag (full sub-chunk including preamble).

    Returns:
        FirehosePreamble or None on parse error.
    """
    pos = 0

    def read(n: int) -> bytes:
        nonlocal pos
        if pos + n > len(data):
            raise EOFError(f"Firehose preamble truncated at pos={pos}, need {n} bytes")
        chunk = data[pos:pos+n]
        pos += n
        return chunk

    def u8() -> int:
        return struct.unpack_from("<B", read(1))[0]

    def u16() -> int:
        return struct.unpack_from("<H", read(2))[0]

    def u32() -> int:
        return struct.unpack_from("<I", read(4))[0]

    def u64() -> int:
        return struct.unpack_from("<Q", read(8))[0]

    try:
        # Outer preamble (16 bytes)
        chunk_tag = u32()
        chunk_sub_tag = u32()
        chunk_data_size = u64()

        # Inner header
        first_number_proc_id = u64()
        second_number_proc_id = u32()
        ttl = u8()
        collapsed = u8()
        unknown = read(2)
        public_data_size = u16()
        private_data_virtual_offset = u16()
        unknown2 = u16()
        unknown3 = u16()
        base_continuous_time = u64()

        # public_data_size includes the 16 bytes of preamble fields above
        public_data_size_offset = 16
        public_data_bytes_count = public_data_size - public_data_size_offset
        if public_data_bytes_count < 0:
            log.warning(f"FirehosePreamble: public_data_size={public_data_size} < {public_data_size_offset}, empty public data")
            public_data_bytes_count = 0

        public_data_start = pos
        public_data_end = pos + public_data_bytes_count

        # Slice of remaining data (may include private data after public data)
        remaining_after_header = data[pos:]
        public_data_bytes = data[pos:public_data_end]
        after_public = data[public_data_end:]

        # Parse firehose entries from the public data slice. We pass
        # ``public_data_start`` so each entry can record its byte offset
        # relative to the beginning of the FirehosePreamble (and therefore,
        # together with the chunkset offsets, back to the .tracev3 file).
        public_data_list = _parse_firehose_entries(
            public_data_bytes,
            private_data_virtual_offset,
            public_data_offset_in_preamble=public_data_start,
        )

        # Handle private data strings if present
        if private_data_virtual_offset != NO_PRIVATE_DATA:
            private_input = _locate_private_data(
                after_public, public_data_bytes, public_data_size,
                public_data_size_offset, private_data_virtual_offset,
                collapsed, data, pos,
            )
            if private_input:
                _apply_private_data(private_input, public_data_list,
                                    private_data_virtual_offset)

        return FirehosePreamble(
            chunk_tag=chunk_tag,
            chunk_sub_tag=chunk_sub_tag,
            chunk_data_size=chunk_data_size,
            first_number_proc_id=first_number_proc_id,
            second_number_proc_id=second_number_proc_id,
            ttl=ttl,
            collapsed=collapsed,
            unknown=unknown,
            public_data_size=public_data_size,
            private_data_virtual_offset=private_data_virtual_offset,
            unknown2=unknown2,
            unknown3=unknown3,
            base_continuous_time=base_continuous_time,
            public_data=public_data_list,
        )

    except EOFError as exc:
        log.error(f"Failed to parse FirehosePreamble: {exc}")
        return None


# ── Private data location ─────────────────────────────────────────────────────

def _locate_private_data(
    after_public: bytes,
    public_data_bytes: bytes,
    public_data_size: int,
    public_data_size_offset: int,
    private_data_virtual_offset: int,
    collapsed: int,
    full_data: bytes,
    header_end_pos: int,
) -> bytes | None:
    """Locate the private data section following the public data.

    The logic mirrors the Rust parser's private data offset calculations.
    """
    # Skip zero padding from after_public
    stripped = after_public.lstrip(b"\x00")

    # If stripping consumed everything but collapsed flag is set, use raw after_public
    if not stripped or collapsed == 1:
        stripped = after_public

    if not stripped:
        return None

    return stripped


def _private_strings_ref(entry: Firehose) -> tuple[int, int]:
    """Return ``(offset, size)`` of *entry*'s private strings, or ``(0, 0)``.

    The pair lives on the activity-type-specific sub-record: only non-activity
    and signpost entries carry one (both parse it under flag 0x0100 — see
    _parse_single_firehose). WHY a dispatch rather than reading
    ``firehose_non_activity`` directly: a signpost entry leaves that sub-record
    at its zero defaults, so a direct read reported "no private strings" for
    every signpost — its offset and size were parsed off disk and then never
    used, leaving the entry's private items as ``<private>`` placeholders for
    ever. Same per-activity-type dispatch as ``_get_unknown_pc_id`` in
    engine/parser/format_string.py.
    """
    if entry.unknown_log_activity_type == ACTIVITY_TYPE_SIGNPOST:
        sp = entry.firehose_signpost
        return sp.private_strings_offset, sp.private_strings_size
    na = entry.firehose_non_activity
    return na.private_strings_offset, na.private_strings_size


def _apply_private_data(
    private_data: bytes,
    entries: list[Firehose],
    private_data_virtual_offset: int,
) -> None:
    """Update entries' private item values from the private data section."""
    for entry in entries:
        strings_offset, strings_size = _private_strings_ref(entry)
        if strings_size == 0:
            continue
        str_offset = strings_offset - private_data_virtual_offset
        if str_offset < 0 or str_offset >= len(private_data):
            continue
        private_slice = private_data[str_offset:]
        parse_private_items(private_slice, entry.message)


# ── Firehose entry list parser ────────────────────────────────────────────────

def _parse_firehose_entries(
    public_data: bytes,
    private_data_virtual_offset: int,
    *,
    public_data_offset_in_preamble: int = 0,
) -> list[Firehose]:
    """Parse all Firehose entries from the public data bytes.

    *public_data_offset_in_preamble* is the byte offset at which *public_data*
    starts inside the enclosing FirehosePreamble bytes. It is added to each
    entry's local position so :attr:`Firehose.entry_inner_offset` is reported
    relative to the preamble (i.e. the same coordinate system the caller
    persists).
    """
    entries: list[Firehose] = []
    pos = 0
    min_entry_size = 24  # fixed header size

    while pos < len(public_data):
        if pos + min_entry_size > len(public_data):
            break

        # Skip zero padding between entries
        if public_data[pos] == 0:
            pos += 1
            continue

        entry_start_pos = pos
        entry, consumed = _parse_single_firehose(public_data, pos)
        if entry is None:
            break
        entry.entry_inner_offset = public_data_offset_in_preamble + entry_start_pos

        if entry.unknown_log_activity_type == ACTIVITY_TYPE_REMNANT:
            entries.append(entry)
            break

        if entry.unknown_log_activity_type not in VALID_LOG_TYPES:
            log.warning(f"Unknown log activity type 0x{entry.unknown_log_activity_type:x}, stopping public_data parse")
            if entry.unknown_log_activity_type != 0:
                entries.append(entry)
            break

        entries.append(entry)
        pos += consumed

        if len(public_data) - pos < min_entry_size:
            break

    return entries


# The fixed 24-byte header every firehose entry starts with, precompiled because
# it is unpacked once per log entry:
#   B  unknown_log_activity_type   B  unknown_log_type
#   H  flags                       I  format_string_location
#   Q  thread_id                   I  continuous_time_delta
#   H  continuous_time_delta_upper H  data_size
# "<" keeps it byte-exact (little-endian, no alignment padding) — with a native
# prefix the compiler would insert padding before the Q and shift every field
# after it.
_ENTRY_HEADER = struct.Struct("<BBHIQIHH")


def _parse_single_firehose(data: bytes, base_pos: int) -> tuple[Firehose | None, int]:
    """Parse one Firehose entry at *base_pos* within *data*.

    Returns (Firehose, bytes_consumed) or (None, 0).
    """
    pos = base_pos

    def read(n: int) -> bytes:
        nonlocal pos
        if pos + n > len(data):
            raise EOFError(f"Truncated at pos={pos}, need {n}")
        chunk = data[pos:pos+n]
        pos += n
        return chunk

    try:
        # One unpack for the whole 24-byte header instead of eight read+unpack
        # pairs. This runs once per log entry — tens of millions of times on a
        # large archive — so the eight slices, eight format-string parses and
        # eight one-element tuples were pure per-entry overhead. Same bytes, same
        # order, same little-endian layout; see _ENTRY_HEADER.
        if pos + _ENTRY_HEADER.size > len(data):
            raise EOFError(f"Truncated at pos={pos}, need {_ENTRY_HEADER.size}")
        (act_type, log_type, flags, fmt_loc, thread_id,
         ct_delta, ct_delta_upper, data_size) = _ENTRY_HEADER.unpack_from(data, pos)
        pos += _ENTRY_HEADER.size

        entry_data_start = pos
        entry_data = read(data_size)
        entry_data_end = pos

        fhose = Firehose(
            unknown_log_activity_type=act_type,
            unknown_log_type=log_type,
            flags=flags,
            format_string_location=fmt_loc,
            thread_id=thread_id,
            continuous_time_delta=ct_delta,
            continuous_time_delta_upper=ct_delta_upper,
            data_size=data_size,
        )

        ep = 0  # position within entry_data

        if act_type == ACTIVITY_TYPE_ACTIVITY:
            non_act, ep = _parse_activity(entry_data, ep, flags, log_type)
            fhose.firehose_activity = non_act

        elif act_type == ACTIVITY_TYPE_NON_ACTIVITY:
            non_act, ep = _parse_non_activity(entry_data, ep, flags)
            fhose.firehose_non_activity = non_act

        elif act_type == ACTIVITY_TYPE_SIGNPOST:
            sp, ep = _parse_signpost(entry_data, ep, flags)
            fhose.firehose_signpost = sp

        elif act_type == ACTIVITY_TYPE_LOSS:
            loss, ep = _parse_loss(entry_data, ep)
            fhose.firehose_loss = loss

        elif act_type == ACTIVITY_TYPE_TRACE:
            trace, ep = _parse_trace(entry_data, ep)
            fhose.firehose_trace = trace
            fhose.message = trace.message_data

        elif act_type == ACTIVITY_TYPE_REMNANT:
            pass

        else:
            # Mirror the Rust reference (firehose_log.rs:504): on an unknown
            # activity type we stop parsing and return the entry as-is, rather
            # than running the item collector against an unknown layout —
            # which previously produced random "items" that polluted the DB.
            log.warning(f"Unknown log activity type 0x{act_type:x} — stopping at this entry")
            padding = _padding_size_8(data_size)
            return fhose, (pos + padding) - base_pos

        # Parse items if enough data remains (skip for trace/remnant which handle differently)
        if act_type not in (ACTIVITY_TYPE_TRACE, ACTIVITY_TYPE_REMNANT):
            remaining_entry = entry_data[ep:]
            if len(remaining_entry) >= 6:
                fhose.unknown_item = remaining_entry[0]
                fhose.number_items = remaining_entry[1]
                item_data = collect_items(remaining_entry[2:], fhose.number_items, flags)
                fhose.message = item_data

        # Calculate 8-byte alignment padding
        padding = _padding_size_8(data_size)
        pos_after_padding = pos + padding

        consumed = pos_after_padding - base_pos
        return fhose, consumed

    except EOFError as exc:
        log.debug("EOFError parsing firehose entry at 0x%x: %s", base_pos, exc)
        return None, 0


# ── Formatter flags parser ────────────────────────────────────────────────────

def _parse_formatter_flags(data: bytes, pos: int, flags: int) -> tuple[FirehoseFormatters, int]:
    """Parse formatter flags from *data* starting at *pos*.

    Returns (FirehoseFormatters, new_pos).
    """
    fmt = FirehoseFormatters()
    flag_key = flags & FLAG_MASK_FORMAT

    # NOTE: flag_key is ``flags & 0xE``, so it can never equal 0x20 — this first
    # branch is unreachable, exactly as in the Rust reference (flags.rs keeps the
    # same dead 0x20 arm for documentation). The has_large_offset u16 is actually
    # read by the bit-check ``flags & FLAG_LARGE_OFFSET`` inside the 0xC and 0x4
    # arms below, which is the reachable path. Kept for line-by-line parity with
    # flags.rs so the port stays auditable.
    if flag_key == FLAG_LARGE_OFFSET:  # 0x20 (unreachable — see note above)
        if pos + 2 > len(data):
            return fmt, pos
        fmt.has_large_offset = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        if flags & FLAG_LARGE_SHARED_CACHE:
            if pos + 2 <= len(data):
                fmt.large_shared_cache = struct.unpack_from("<H", data, pos)[0]
                pos += 2

    elif flag_key == FLAG_LARGE_SHARED_CACHE:  # 0xc
        if flags & FLAG_LARGE_OFFSET:
            if pos + 2 <= len(data):
                fmt.has_large_offset = struct.unpack_from("<H", data, pos)[0]
                pos += 2
        if pos + 2 <= len(data):
            fmt.large_shared_cache = struct.unpack_from("<H", data, pos)[0]
            pos += 2

    elif flag_key == FLAG_ABSOLUTE:  # 0x8
        fmt.absolute = True
        if not (flags & 0x2):  # not main_exe flag
            if pos + 2 <= len(data):
                fmt.main_exe_alt_index = struct.unpack_from("<H", data, pos)[0]
                pos += 2

    elif flag_key == FLAG_MAIN_EXE:  # 0x2
        fmt.main_exe = True

    elif flag_key == FLAG_SHARED_CACHE:  # 0x4
        fmt.shared_cache = True
        if flags & FLAG_LARGE_OFFSET:
            if pos + 2 <= len(data):
                fmt.has_large_offset = struct.unpack_from("<H", data, pos)[0]
                pos += 2

    elif flag_key == FLAG_UUID_RELATIVE:  # 0xa
        if pos + 16 <= len(data):
            uuid_int = int.from_bytes(data[pos:pos+16], "big")
            fmt.uuid_relative = format(uuid_int, "032X")
            pos += 16

    else:
        log.warning(f"Unknown firehose formatter flag 0x{flag_key:x} (flags=0x{flags:x})")

    return fmt, pos


# ── Type-specific parsers ─────────────────────────────────────────────────────

def _parse_non_activity(
    data: bytes, pos: int, flags: int
) -> tuple[FirehoseNonActivity, int]:
    na = FirehoseNonActivity()

    if flags & FLAG_HAS_CURRENT_AID:
        if pos + 8 <= len(data):
            na.unknown_activity_id = struct.unpack_from("<I", data, pos)[0]
            na.unknown_sentinel = struct.unpack_from("<I", data, pos+4)[0]
            pos += 8

    if flags & FLAG_HAS_PRIVATE_DATA:
        if pos + 4 <= len(data):
            na.private_strings_offset = struct.unpack_from("<H", data, pos)[0]
            na.private_strings_size = struct.unpack_from("<H", data, pos+2)[0]
            pos += 4

    if pos + 4 <= len(data):
        na.unknown_pc_id = struct.unpack_from("<I", data, pos)[0]
        pos += 4

    fmt, pos = _parse_formatter_flags(data, pos, flags)
    na.firehose_formatters = fmt

    if flags & FLAG_HAS_SUBSYSTEM:
        if pos + 2 <= len(data):
            na.subsystem_value = struct.unpack_from("<H", data, pos)[0]
            pos += 2

    if flags & FLAG_HAS_RULES:
        if pos + 1 <= len(data):
            na.ttl_value = data[pos]
            pos += 1

    if flags & FLAG_HAS_OVERSIZE:
        if pos + 4 <= len(data):
            na.data_ref_value = struct.unpack_from("<I", data, pos)[0]
            pos += 4

    # NOTE: the Rust reference declares ``unknown_message_string_ref`` on the
    # struct but never reads it from the stream — the field is always 0 in
    # practice. A previous revision of this file consumed 4 bytes here when
    # ``flags & 0x0008`` was set, which silently desynchronised every later
    # offset. Do not reintroduce that read.
    return na, pos


def _parse_activity(
    data: bytes, pos: int, flags: int, log_type: int
) -> tuple[FirehoseActivity, int]:
    act = FirehoseActivity()
    USERACTION: int = 0x3

    if log_type != USERACTION:
        if pos + 8 <= len(data):
            act.unknown_activity_id = struct.unpack_from("<I", data, pos)[0]
            act.unknown_sentinel = struct.unpack_from("<I", data, pos+4)[0]
            pos += 8

    if flags & FLAG_HAS_UNIQUE_PID:
        if pos + 8 <= len(data):
            act.pid = struct.unpack_from("<Q", data, pos)[0]
            pos += 8

    if flags & FLAG_HAS_CURRENT_AID:
        if pos + 8 <= len(data):
            act.unknown_activity_id_2 = struct.unpack_from("<I", data, pos)[0]
            act.unknown_sentinel_2 = struct.unpack_from("<I", data, pos+4)[0]
            pos += 8

    if flags & FLAG_HAS_OTHER_AID:
        if pos + 8 <= len(data):
            act.unknown_activity_id_3 = struct.unpack_from("<I", data, pos)[0]
            act.unknown_sentinel_3 = struct.unpack_from("<I", data, pos+4)[0]
            pos += 8

    # NOTE: like NonActivity, the Rust reference declares but never parses
    # ``unknown_message_string_ref``. Reading 4 bytes here when 0x0008 is set
    # would shift unknown_pc_id and the formatter flags by 4 bytes.

    if pos + 4 <= len(data):
        act.unknown_pc_id = struct.unpack_from("<I", data, pos)[0]
        pos += 4

    fmt, pos = _parse_formatter_flags(data, pos, flags)
    act.firehose_formatters = fmt

    return act, pos


def _parse_signpost(
    data: bytes, pos: int, flags: int
) -> tuple[FirehoseSignpost, int]:
    sp = FirehoseSignpost()

    if flags & FLAG_HAS_CURRENT_AID:
        if pos + 8 <= len(data):
            sp.unknown_activity_id = struct.unpack_from("<I", data, pos)[0]
            sp.unknown_sentinel = struct.unpack_from("<I", data, pos+4)[0]
            pos += 8

    if flags & FLAG_HAS_PRIVATE_DATA:
        if pos + 4 <= len(data):
            sp.private_strings_offset = struct.unpack_from("<H", data, pos)[0]
            sp.private_strings_size = struct.unpack_from("<H", data, pos+2)[0]
            pos += 4

    if pos + 4 <= len(data):
        sp.unknown_pc_id = struct.unpack_from("<I", data, pos)[0]
        pos += 4

    fmt, pos = _parse_formatter_flags(data, pos, flags)
    sp.firehose_formatters = fmt

    if flags & FLAG_HAS_SUBSYSTEM:
        if pos + 2 <= len(data):
            sp.subsystem = struct.unpack_from("<H", data, pos)[0]
            pos += 2

    # signpost_id: u64
    if pos + 8 <= len(data):
        sp.signpost_id = struct.unpack_from("<Q", data, pos)[0]
        pos += 8

    # Order below mirrors signpost.rs: has_rules → has_oversize → has_name.
    # has_name is bit 0x8000 (NOT 0x0800 — the latter is has_oversize and
    # was being mis-applied as has_name in a previous revision, causing the
    # ``signpost_name`` field to be read at the wrong offset).
    if flags & FLAG_HAS_RULES:
        if pos + 1 <= len(data):
            sp.ttl_value = data[pos]
            pos += 1

    if flags & FLAG_HAS_OVERSIZE:
        if pos + 4 <= len(data):
            sp.data_ref_value = struct.unpack_from("<I", data, pos)[0]
            pos += 4

    if flags & FLAG_HAS_NAME:
        if pos + 4 <= len(data):
            sp.signpost_name = struct.unpack_from("<I", data, pos)[0]
            pos += 4
        # If large_shared_cache is also set, two bytes of padding follow the
        # signpost_name (signpost.rs:120-123).
        if sp.firehose_formatters.large_shared_cache != 0:
            if pos + 2 <= len(data):
                pos += 2

    return sp, pos


def _parse_loss(data: bytes, pos: int) -> tuple[FirehoseLoss, int]:
    loss = FirehoseLoss()
    if pos + 8 <= len(data):
        loss.start_time = struct.unpack_from("<Q", data, pos)[0]
        pos += 8
    if pos + 8 <= len(data):
        loss.end_time = struct.unpack_from("<Q", data, pos)[0]
        pos += 8
    # ``count`` is a u64 in the Rust reference (loss.rs). A previous revision
    # of this parser read it as u32, which both truncated the value and
    # advanced the position by only 4 bytes.
    if pos + 8 <= len(data):
        loss.count = struct.unpack_from("<Q", data, pos)[0]
        pos += 8
    return loss, pos


def _parse_trace(data: bytes, pos: int) -> tuple[FirehoseTrace, int]:
    trace = FirehoseTrace()

    if pos + 4 <= len(data):
        trace.unknown_pc_id = struct.unpack_from("<I", data, pos)[0]
        pos += 4

    remaining = data[pos:]
    if len(remaining) >= 4:
        # Trace message data is stored reversed
        rev = bytearray(remaining)
        rev.reverse()
        trace.message_data = _parse_trace_message(bytes(rev))

    return trace, len(data)  # consume all entry data


def _parse_trace_message(data: bytes) -> FirehoseItemData:
    """Parse the reversed trace message data."""
    item_data = FirehoseItemData()
    if len(data) < 4:
        return item_data

    pos = 0
    if pos >= len(data):
        return item_data

    num_entries = data[pos]
    pos += 1

    sizes: list[int] = []
    for _ in range(num_entries):
        if pos >= len(data):
            break
        sizes.append(data[pos])
        pos += 1

    for sz in sizes:
        if pos + sz > len(data):
            break
        raw = data[pos:pos+sz]
        pos += sz
        if sz == 1:
            val = raw[0]
        elif sz == 2:
            val = struct.unpack_from(">H", raw)[0]
        elif sz == 4:
            val = struct.unpack_from(">I", raw)[0]
        elif sz == 8:
            val = struct.unpack_from(">Q", raw)[0]
        else:
            val = raw[0] if raw else 0
        item_data.item_info.append(FirehoseItemInfo(
            message_strings=str(val),
            item_type=0x0,
            item_size=sz,
        ))

    item_data.item_info.reverse()
    return item_data


# ── Item collection ───────────────────────────────────────────────────────────

def collect_items(data: bytes, num_items: int, flags: int) -> FirehoseItemData:
    """Collect and resolve all message items from a Firehose entry's item data.

    This mirrors FirehosePreamble::collect_items() in the Rust source.
    """
    item_data = FirehoseItemData()
    if num_items == 0 or not data:
        return item_data

    # Phase 1: Read item metadata (types/sizes/offsets) AND inline number values.
    # The Rust reference (collect_items in firehose_log.rs) reads each number's
    # value immediately after its 2-byte header — so a stream that interleaves
    # number and string items is not equivalent to "all headers, then all
    # numbers in declaration order". Doing it in two phases shifted the
    # subsequent string pool by N bytes whenever any number item appeared
    # after a string item header.
    pos = 0
    raw_items: list[dict] = []

    for _ in range(num_items):
        if pos + 2 > len(data):
            break

        item_type = data[pos]
        item_size = data[pos + 1]
        pos += 2

        item: dict = {
            "item_type": item_type,
            "item_size": item_size,
            "offset": 0,
            "message_string_size": 0,
            "message_strings": "",
        }

        if (item_type in STRING_ITEMS_GET_PHASE or item_type == PRIVATE_NUMBER
                or item_type in SENSITIVE_ITEMS):
            if pos + 4 <= len(data):
                item["offset"] = struct.unpack_from("<H", data, pos)[0]
                item["message_string_size"] = struct.unpack_from("<H", data, pos + 2)[0]
                pos += 4

        elif item_type in PRECISION_ITEMS:
            # Precision items carry only a length (consumed inline).
            pos += item_size

        elif item_type in NUMBER_ITEM_TYPES:
            # Number values immediately follow the 2-byte header.
            if pos + item_size <= len(data):
                raw = data[pos:pos + item_size]
                item["message_strings"] = str(_parse_item_number(raw))
                pos += item_size

        raw_items.append(item)

    # Phase 2 — backtrace + string pool starts where phase 1 left off.
    pool_start = pos
    has_context_data = bool(flags & FLAG_HAS_CONTEXT_DATA)
    backtrace_sig = b"\x01\x00\x12"

    if has_context_data:
        btrace_strings, pool_start = _get_backtrace_data(data, pool_start)
        item_data.backtrace_strings = btrace_strings
    elif pool_start + 3 <= len(data) and data[pool_start:pool_start+3] == backtrace_sig:
        btrace_strings, pool_start = _get_backtrace_data(data, pool_start)
        item_data.backtrace_strings = btrace_strings

    # Phase 4: Resolve string items from pool
    string_pool = data[pool_start:]
    sp = 0
    for item in raw_items:
        itype = item["item_type"]

        if itype in NUMBER_ITEM_TYPES:
            continue

        if itype in PRIVATE_STRINGS or itype in SENSITIVE_ITEMS:
            item["message_strings"] = "<private>"
            continue

        if itype == PRIVATE_NUMBER:
            continue

        if itype in PRECISION_ITEMS:
            continue

        if item["message_string_size"] == 0 and item["message_strings"]:
            continue

        if itype in OBJECT_ITEMS and item["message_string_size"] == 0:
            item["message_strings"] = "(null)"
            continue

        if itype in STRING_ITEMS_COLLECT_PHASE:
            msg_size = item["message_string_size"]

            # An item that declares zero bytes IS an empty string — it consumes
            # nothing from the pool and says nothing about the items after it.
            # WHY this is its own branch: the two conditions below used to be
            # collapsed into one ``msg_size <= 0: break``, so a legitimately
            # empty argument aborted resolution for every LATER item in the
            # entry. A message like "%s = %s" whose first argument was empty
            # silently lost its second one — the value was in the pool, parsed,
            # and then discarded.
            if msg_size == 0:
                item["message_strings"] = ""
                continue

            # A non-empty item with nothing left in the pool means the item data
            # was truncated. Later items cannot resolve either, so stop — but log
            # it, because this is data loss and the previous code was silent
            # about it.
            available = len(string_pool) - sp
            if available <= 0:
                log.debug(
                    "String pool exhausted with %d byte(s) still requested — "
                    "remaining items left empty (truncated item data?)", msg_size,
                )
                break
            msg_size = min(msg_size, available)

            raw = string_pool[sp:sp+msg_size]
            sp += msg_size
            if itype in ARBITRARY_ITEMS or itype == BASE64_RAW_BYTES:
                item["message_strings"] = base64.b64encode(raw).decode("ascii")
            else:
                item["message_strings"] = _extract_string(raw)

    # Finalise into FirehoseItemInfo list
    for item in raw_items:
        item_data.item_info.append(FirehoseItemInfo(
            message_strings=item["message_strings"],
            item_type=item["item_type"],
            item_size=item["message_string_size"],
        ))

    return item_data


def _get_backtrace_data(data: bytes, pos: int) -> tuple[list[str], int]:
    """Parse backtrace data from the item buffer. Returns (strings, new_pos)."""
    strings: list[str] = []
    if pos >= len(data):
        return strings, pos

    # Skip signature [1, 0, 18]
    if data[pos:pos+3] == b"\x01\x00\x12":
        pos += 3
    else:
        if pos >= len(data):
            return strings, pos
        # Try reading backtrace header directly
        pass

    if pos >= len(data):
        return strings, pos

    uuid_count = data[pos]
    pos += 1
    if pos + 2 > len(data):
        return strings, pos

    offset_count = struct.unpack_from("<H", data, pos)[0]
    pos += 2

    uuids: list[int] = []
    for _ in range(uuid_count):
        if pos + 16 > len(data):
            break
        uuid_int = int.from_bytes(data[pos:pos+16], "big")
        uuids.append(uuid_int)
        pos += 16

    offsets: list[int] = []
    for _ in range(offset_count):
        if pos + 4 > len(data):
            break
        offsets.append(struct.unpack_from("<I", data, pos)[0])
        pos += 4

    indexes: list[int] = []
    for _ in range(offset_count):
        if pos >= len(data):
            break
        indexes.append(data[pos])
        pos += 1

    for i, idx in enumerate(indexes):
        uuid = uuids[idx] if idx < len(uuids) else 0
        offset = offsets[i] if i < len(offsets) else 0
        strings.append(f'"{uuid:X}" +0x{offset:x}')

    # 4-byte alignment padding for offset_count
    padding = _padding_size_4(offset_count)
    pos += padding

    return strings, pos


def parse_private_items(private_data: bytes, item_data: FirehoseItemData) -> None:
    """Resolve private item values in-place from private data section."""
    pos = 0
    private_strings_set = {0x21, 0x25, 0x41, 0x35, 0x31, 0x81, 0xF1}
    base64_private = {0x35, 0x31}
    private_number = 0x1
    private_number_private = 0x8000

    for info in item_data.item_info:
        if info.item_type in private_strings_set:
            if info.item_type in base64_private:
                sz = min(info.item_size, len(private_data) - pos)
                if sz > 0:
                    info.message_strings = base64.b64encode(private_data[pos:pos+sz]).decode()
                    pos += sz
            else:
                if info.item_size == 0:
                    info.message_strings = "<private>"
                else:
                    end = private_data.find(b"\x00", pos)
                    if end == -1 or end - pos > info.item_size:
                        end = pos + info.item_size
                    info.message_strings = private_data[pos:end].decode("utf-8", errors="replace")
                    pos += info.item_size

        elif info.item_type == private_number:
            if info.item_size == private_number_private:
                info.message_strings = "<private>"
            else:
                sz = info.item_size
                if pos + sz <= len(private_data):
                    raw = private_data[pos:pos+sz]
                    val = _parse_item_number(raw)
                    info.message_strings = str(val)
                    pos += sz


# ── Utility functions ─────────────────────────────────────────────────────────

def _parse_item_number(raw: bytes) -> int:
    """Signed little-endian integer value of a number item's raw bytes.

    Returns :data:`UNPARSEABLE_NUMBER` when the item size is not one the AUL uses
    (1/2/4/8), i.e. the item could not be decoded at all — consumers must treat
    that as "no value", not as the number −9999.
    """
    sz = len(raw)
    if sz == 1:
        return struct.unpack_from("<b", raw)[0]
    elif sz == 2:
        return struct.unpack_from("<h", raw)[0]
    elif sz == 4:
        return struct.unpack_from("<i", raw)[0]
    elif sz == 8:
        return struct.unpack_from("<q", raw)[0]
    return UNPARSEABLE_NUMBER


def _extract_string(raw: bytes) -> str:
    end = raw.find(b"\x00")
    if end != -1:
        raw = raw[:end]
    return raw.decode("utf-8", errors="replace")


def _padding_size_8(size: int) -> int:
    """Bytes of 8-byte alignment padding after *size* bytes of data."""
    return (8 - (size & 7)) & 7


def _padding_size_4(count: int) -> int:
    """Bytes of 4-byte alignment padding for *count* items."""
    return (4 - (count & 3)) & 3
