"""Statedump / Simpledump sub-chunk parsers (tags 0x6003 / 0x6004).

Defines : parse_statedump, parse_simpledump, decode_statedump_data
Used by  : forensic_aul.ops.extraction.tracev3_parse (chunkset sub-chunk loop)
Uses     : forensic_aul.engine.models.dumps (Statedump, SimpleDump)

These are non-Firehose log records that ``log show`` prints as ordinary lines.
The byte layout mirrors the Rust reference (``chunks/statedump.rs`` and
``chunks/simpledump.rs``) field-for-field so the port stays auditable.

Note on Statedump payload decoding: the Rust reference can decode custom Apple
objects (location/config trackers) and protobuf payloads via dedicated binary
decoders. Those are not ported here; for type 2 (protobuf) and type 3 (custom
object) the raw payload is surfaced base64-encoded with an explicit
"unsupported"/"failed" marker — exactly the fallback ``log show`` /
macos-unifiedlogs use for objects they cannot decode. Binary **plist** payloads
(type 1) ARE decoded, via the stdlib ``plistlib``.
"""

from __future__ import annotations

import base64
import datetime
import json
import logging
import plistlib
import struct

from forensic_aul.engine.models.dumps import SimpleDump, Statedump

log = logging.getLogger(__name__)

_CUSTOM_OBJECT_TYPE: int = 3
_PLIST_TYPE: int = 1
_PROTOBUF_TYPE: int = 2
_FIXED_STRING_SIZE: int = 64

# Statedump fixed-header layout up to (and including) unknown_data_size, parsed in
# one shot. <  : little-endian; see chunks/statedump.rs::parse_statedump.
#   I  chunk_tag (u32)            I  chunk_sub_tag (u32)
#   Q  chunk_data_size (u64)      Q  first_proc_id (u64)
#   I  second_proc_id (u32)       B  ttl (u8)        3x reserved (3 bytes)
#   Q  continuous_time (u64)      Q  activity_id (u64)
#   16s uuid (u128)               I  unknown_data_type (u32)
#   I  unknown_data_size (u32)
_STATEDUMP_HEADER = struct.Struct("<IIQQIB3xQQ16sII")

# Simpledump fixed-header layout up to (and including) the three trailing sizes.
#   I chunk_tag  I chunk_sub_tag  Q chunk_data_size
#   Q first_proc_id  Q second_proc_id  Q continuous_time  Q thread_id
#   I unknown_offset  H unknown_ttl  H unknown_type
#   16s sender_uuid  16s dsc_uuid
#   I number_message_strings  I size_subsystem_string  I size_message_string
_SIMPLEDUMP_HEADER = struct.Struct("<IIQQQQQIHH16s16sIII")


def _cstr(data: bytes) -> str:
    """Decode a null-terminated (or null-padded) UTF-8 string, lossily."""
    end = data.find(b"\x00")
    if end != -1:
        data = data[:end]
    return data.decode("utf-8", errors="replace")


def parse_statedump(data: bytes) -> Statedump | None:
    """Parse a Statedump sub-chunk (full bytes, including the 16-byte preamble)."""
    if len(data) < _STATEDUMP_HEADER.size:
        log.debug("statedump: truncated header (%d bytes)", len(data))
        return None
    (
        chunk_tag, chunk_sub_tag, chunk_data_size, first_proc_id, second_proc_id,
        ttl, continuous_time, activity_id, uuid_bytes, unknown_data_type,
        unknown_data_size,
    ) = _STATEDUMP_HEADER.unpack_from(data, 0)

    pos = _STATEDUMP_HEADER.size
    decoder_library = ""
    decoder_type = ""
    # Type 3 carries two 64-byte decoder strings; other types pad with two
    # 64-byte blanks that we skip (mirrors the Rust nom-skip).
    if unknown_data_type == _CUSTOM_OBJECT_TYPE:
        if pos + 2 * _FIXED_STRING_SIZE > len(data):
            return None
        decoder_library = _cstr(data[pos:pos + _FIXED_STRING_SIZE])
        decoder_type = _cstr(data[pos + _FIXED_STRING_SIZE:pos + 2 * _FIXED_STRING_SIZE])
    pos += 2 * _FIXED_STRING_SIZE

    if pos + _FIXED_STRING_SIZE > len(data):
        return None
    title_name = _cstr(data[pos:pos + _FIXED_STRING_SIZE])
    pos += _FIXED_STRING_SIZE

    statedump_data = data[pos:pos + unknown_data_size]

    return Statedump(
        chunk_tag=chunk_tag, chunk_subtag=chunk_sub_tag,
        chunk_data_size=chunk_data_size, first_proc_id=first_proc_id,
        second_proc_id=second_proc_id, ttl=ttl, continuous_time=continuous_time,
        activity_id=activity_id, uuid=uuid_bytes.hex().upper(),
        unknown_data_type=unknown_data_type, unknown_data_size=unknown_data_size,
        decoder_library=decoder_library, decoder_type=decoder_type,
        title_name=title_name, statedump_data=statedump_data,
    )


def parse_simpledump(data: bytes) -> SimpleDump | None:
    """Parse a Simpledump sub-chunk (full bytes, including the 16-byte preamble)."""
    if len(data) < _SIMPLEDUMP_HEADER.size:
        log.debug("simpledump: truncated header (%d bytes)", len(data))
        return None
    (
        chunk_tag, chunk_sub_tag, chunk_data_size, first_proc_id, second_proc_id,
        continuous_time, thread_id, unknown_offset, unknown_ttl, unknown_type,
        sender_uuid, dsc_uuid, n_msg_strings, size_subsystem, size_message,
    ) = _SIMPLEDUMP_HEADER.unpack_from(data, 0)

    pos = _SIMPLEDUMP_HEADER.size
    subsystem = ""
    message_string = ""
    if size_subsystem:
        subsystem = _cstr(data[pos:pos + size_subsystem])
        pos += size_subsystem
    if size_message:
        message_string = _cstr(data[pos:pos + size_message])
        pos += size_message

    return SimpleDump(
        chunk_tag=chunk_tag, chunk_subtag=chunk_sub_tag,
        chunk_data_size=chunk_data_size, first_proc_id=first_proc_id,
        second_proc_id=second_proc_id, continuous_time=continuous_time,
        thread_id=thread_id, unknown_offset=unknown_offset,
        unknown_ttl=unknown_ttl, unknown_type=unknown_type,
        sender_uuid=sender_uuid.hex().upper(), dsc_uuid=dsc_uuid.hex().upper(),
        unknown_number_message_strings=n_msg_strings,
        subsystem=subsystem, message_string=message_string,
    )


def _json_default(obj: object) -> str:
    """Make plist-only types (datetime / bytes) JSON-serialisable."""
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode("ascii")
    return str(obj)


def decode_statedump_data(sd: Statedump) -> str:
    """Render a Statedump payload to text, mirroring unified_log.rs.

    Binary plists (type 1) are decoded to JSON; protobuf (type 2) and custom
    objects (type 3) are surfaced base64-encoded with an explicit marker, since
    their dedicated binary decoders are not ported. Any other type is read as a
    null-terminated string.
    """
    payload = sd.statedump_data
    if sd.unknown_data_type == _PLIST_TYPE:
        if not payload:
            return "Empty plist data"
        try:
            value = plistlib.loads(payload)
        except Exception as exc:
            log.debug("statedump: plist parse failed: %s", exc)
            return "Failed to get plist data"
        try:
            return json.dumps(value, default=_json_default)
        except Exception as exc:
            log.debug("statedump: plist→json failed: %s", exc)
            return "Failed to convert plist data to json"
    if sd.unknown_data_type == _PROTOBUF_TYPE:
        return f"Failed to parse StateDump protobuf: {base64.b64encode(payload).decode('ascii')}"
    if sd.unknown_data_type == _CUSTOM_OBJECT_TYPE:
        return (
            f"Unsupported Statedump object: {sd.title_name}-"
            f"{base64.b64encode(payload).decode('ascii')}"
        )
    return _cstr(payload)


def statedump_message(sd: Statedump) -> str:
    """Build the human-readable Statedump message (mirrors unified_log.rs)."""
    return (
        f"title: {sd.title_name}\n"
        f"Object Type: {sd.decoder_library}\n"
        f"Object Type: {sd.decoder_type}\n"
        f"{decode_statedump_data(sd)}"
    )
