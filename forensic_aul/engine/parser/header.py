"""Parse Apple Unified Log tracev3 header chunk (tag 0x1000).

Binary layout reference: macos-UnifiedLogs/src/header.rs
"""

from __future__ import annotations

import logging

from forensic_aul.engine.models import HeaderChunk
from forensic_aul.engine.parser.reader import BinaryReader

log = logging.getLogger(__name__)

CHUNK_TAG_HEADER: int = 0x1000

# Sub-chunk tags within the header
SUB_CHUNK_TAG_0: int = 0x6100  # mach continuous time
SUB_CHUNK_TAG_1: int = 0x6101  # build version + hardware model
SUB_CHUNK_TAG_2: int = 0x6102  # boot UUID + logd info
SUB_CHUNK_TAG_3: int = 0x6103  # timezone path


def _validate_sub_chunk_tag(actual: int, expected: int) -> None:
    """Warn if a header sub-chunk tag does not match the expected constant.

    A mismatch usually means the file is truncated or follows a different
    header layout than the one this parser was written against — silently
    continuing would yield meaningless ``boot_uuid`` / ``hardware_model``
    strings, so we surface it via the logger. We do not raise: real-world
    captures occasionally include benign deviations and a hard failure here
    would discard the rest of the file.
    """
    if actual != expected:
        log.warning(f"header: unexpected sub-chunk tag 0x{actual:04x} (expected 0x{expected:04x})")


def parse_header_chunk(r: BinaryReader) -> HeaderChunk:
    """Parse a HeaderChunk from *r*.

    The reader must be positioned at the start of the chunk tag (i.e. after the
    outer preamble has already been read by the tracev3 iterator).

    Raises:
        EOFError: if the stream is truncated.
    """
    chunk_tag = r.u32()
    chunk_sub_tag = r.u32()
    chunk_data_size = r.u64()

    mach_time_numerator = r.u32()
    mach_time_denominator = r.u32()
    continuous_time = r.u64()
    unknown_time = r.u64()
    unknown = r.u32()
    bias_min = r.u32()
    daylight_savings = r.u32()
    unknown_flags = r.u32()

    # Sub-chunk 0x6100
    sub_chunk_tag = r.u32()
    _validate_sub_chunk_tag(sub_chunk_tag, SUB_CHUNK_TAG_0)
    sub_chunk_data_size = r.u32()
    sub_chunk_continuous_time = r.u64()

    # Sub-chunk 0x6101 — build version (16 bytes) + hardware model (32 bytes)
    sub_chunk_tag_2 = r.u32()
    _validate_sub_chunk_tag(sub_chunk_tag_2, SUB_CHUNK_TAG_1)
    sub_chunk_tag_data_size_2 = r.u32()
    unknown_2 = r.u32()
    unknown_3 = r.u32()
    build_version_string = r.cstr_fixed(16)
    hardware_model_string = r.cstr_fixed(32)

    # Sub-chunk 0x6102 — boot UUID (16 bytes BE) + logd info
    sub_chunk_tag_3 = r.u32()
    _validate_sub_chunk_tag(sub_chunk_tag_3, SUB_CHUNK_TAG_2)
    sub_chunk_tag_data_size_3 = r.u32()
    boot_uuid = r.uuid_be()
    logd_pid = r.u32()
    logd_exit_status = r.u32()

    # Sub-chunk 0x6103 — timezone path (48 bytes)
    sub_chunk_tag_4 = r.u32()
    _validate_sub_chunk_tag(sub_chunk_tag_4, SUB_CHUNK_TAG_3)
    sub_chunk_tag_data_size_4 = r.u32()
    timezone_path = r.cstr_fixed(48)

    return HeaderChunk(
        chunk_tag=chunk_tag,
        chunk_sub_tag=chunk_sub_tag,
        chunk_data_size=chunk_data_size,
        mach_time_numerator=mach_time_numerator,
        mach_time_denominator=mach_time_denominator,
        continuous_time=continuous_time,
        unknown_time=unknown_time,
        unknown=unknown,
        bias_min=bias_min,
        daylight_savings=daylight_savings,
        unknown_flags=unknown_flags,
        sub_chunk_tag=sub_chunk_tag,
        sub_chunk_data_size=sub_chunk_data_size,
        sub_chunk_continuous_time=sub_chunk_continuous_time,
        sub_chunk_tag_2=sub_chunk_tag_2,
        sub_chunk_tag_data_size_2=sub_chunk_tag_data_size_2,
        unknown_2=unknown_2,
        unknown_3=unknown_3,
        build_version_string=build_version_string,
        hardware_model_string=hardware_model_string,
        sub_chunk_tag_3=sub_chunk_tag_3,
        sub_chunk_tag_data_size_3=sub_chunk_tag_data_size_3,
        boot_uuid=boot_uuid,
        logd_pid=logd_pid,
        logd_exit_status=logd_exit_status,
        sub_chunk_tag_4=sub_chunk_tag_4,
        sub_chunk_tag_data_size_4=sub_chunk_tag_data_size_4,
        timezone_path=timezone_path,
    )
