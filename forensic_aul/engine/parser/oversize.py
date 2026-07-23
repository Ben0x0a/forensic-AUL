"""Parse Oversize sub-chunks (tag 0x6002) from decompressed chunksets.

Oversize sub-chunks carry message items that are too large to fit in a
normal Firehose entry.  A Firehose NonActivity or Signpost entry references
them via `data_ref_value`; the pipeline joins them before message assembly.

Binary layout (after the 16-byte outer chunk preamble):
    first_proc_id       u64
    second_proc_id      u32
    ttl                 u8
    _unknown            u8  (3 bytes padding / flags)
    _unknown2           u8
    _unknown3           u8
    continuous_time     u64
    data_ref_index      u32
    public_data_size    u16
    private_data_size   u16
    -- item data follows --
    unknown_item        u8
    number_items        u8
    <items>

Reference: macos-UnifiedLogs/src/chunks/oversize.rs
"""

from __future__ import annotations

import logging
import struct

from forensic_aul.engine.models import FirehoseItemData, Oversize
from forensic_aul.engine.parser.firehose import collect_items  # reuse item parsing logic

log = logging.getLogger(__name__)

_PREAMBLE_SIZE: int = 16  # outer tag(4)+sub_tag(4)+data_size(8)

# Size of the fixed header that follows the 16-byte outer preamble
# u64(8) + u32(4) + u8+u8+u8+u8(4) + u64(8) + u32(4) + u16(2) + u16(2) = 32
_HEADER_SIZE: int = 32


def parse_oversize_chunk(data: bytes) -> Oversize | None:
    """Parse an Oversize sub-chunk from raw sub-chunk bytes (preamble included).

    Args:
        data: Raw bytes beginning at the 16-byte chunk preamble.

    Returns:
        Oversize or None on parse error.
    """
    if len(data) < _PREAMBLE_SIZE + _HEADER_SIZE:
        log.debug("Oversize: data too short (%d bytes)", len(data))
        return None

    pos = 0

    def read(n: int) -> bytes:
        nonlocal pos
        chunk = data[pos : pos + n]
        if len(chunk) != n:
            raise EOFError(f"Oversize truncated at pos={pos}, need {n}")
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
        # Outer 16-byte preamble
        chunk_tag = u32()
        chunk_sub_tag = u32()
        chunk_data_size = u64()

        # Fixed header
        first_proc_id = u64()
        second_proc_id = u32()
        ttl = u8()
        _unk1 = u8()   # unknown / padding
        _unk2 = u8()
        _unk3 = u8()
        continuous_time = u64()
        data_ref_index = u32()
        public_data_size = u16()
        private_data_size = u16()

        # Item data: the first two bytes are unknown_item + number_items
        item_region = data[pos : pos + public_data_size]
        if len(item_region) < 2:
            return Oversize(
                chunk_tag=chunk_tag,
                chunk_sub_tag=chunk_sub_tag,
                chunk_data_size=chunk_data_size,
                first_proc_id=first_proc_id,
                second_proc_id=second_proc_id,
                ttl=ttl,
                continuous_time=continuous_time,
                data_ref_index=data_ref_index,
                public_data_size=public_data_size,
                private_data_size=private_data_size,
                message_items=FirehoseItemData(),
            )

        _unknown_item = item_region[0]
        number_items = item_region[1]
        items_data = item_region[2:]

        # Flags = 0 for oversize (no formatter flags affect item collection here)
        message_items = collect_items(items_data, number_items, flags=0)

        # If private data is present it follows the public data. Clamp the
        # slice to the actual buffer size — Rust does the same in oversize.rs
        # to keep parsing the surviving bytes when the file claims more data
        # than what physically remains.
        private_start = pos + public_data_size
        if private_data_size > 0 and private_start < len(data):
            from forensic_aul.engine.parser.firehose import parse_private_items
            available = len(data) - private_start
            private_end = private_start + min(private_data_size, available)
            private_data = data[private_start:private_end]
            parse_private_items(private_data, message_items)

        return Oversize(
            chunk_tag=chunk_tag,
            chunk_sub_tag=chunk_sub_tag,
            chunk_data_size=chunk_data_size,
            first_proc_id=first_proc_id,
            second_proc_id=second_proc_id,
            ttl=ttl,
            continuous_time=continuous_time,
            data_ref_index=data_ref_index,
            public_data_size=public_data_size,
            private_data_size=private_data_size,
            message_items=message_items,
        )

    except EOFError as exc:
        log.debug("Oversize: parse error: %s", exc)
        return None
