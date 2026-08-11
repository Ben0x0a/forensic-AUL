"""Parse Apple Unified Log DSC (Shared Cache Strings) files.

DSC files contain format strings shared across many processes (system libraries).
They live in the logarchive's dsc/ directory.

Two format versions exist:
  v1 (up to Big Sur):   range_offset = u32, uuid_index = u32 at start of descriptor
  v2 (Monterey+):       range_offset = u64, uuid_index = u64 at end of descriptor

Binary layout reference: macos-UnifiedLogs/src/dsc.rs
"""

from __future__ import annotations

import bisect
import logging
from pathlib import Path

from forensic_aul.config import FORMAT_STRING_OFFSET_CACHE_MAX
from forensic_aul.engine.models import RangeDescriptor, SharedCacheStrings, UUIDDescriptor
from forensic_aul.engine.parser.reader import reader_from_bytes

log = logging.getLogger(__name__)

DSC_SIGNATURE: int = 0x64736368  # "dsch" LE
DYNAMIC_STRING_OFFSET: int = 0x80000000  # format string is literally "%s"

# Sentinel distinguishing "offset cached as empty" from "offset not cached"
# (a legitimate result can be "", which is falsy — see lookup_dsc_string).
_CACHE_MISS = object()


def parse_dsc(path: Path) -> SharedCacheStrings | None:
    """Parse a DSC shared cache strings file.

    The DSC UUID is derived from the filename (32-char hex, no dashes).

    Args:
        path: Path to a DSC file.

    Returns:
        Parsed SharedCacheStrings, or None on error.
    """
    dsc_uuid = path.stem.upper()
    try:
        data = path.read_bytes()
    except OSError as exc:
        log.error(f"Cannot read DSC file {path}: {exc}")
        return None

    try:
        return _parse(data, dsc_uuid)
    except (EOFError, ValueError) as exc:
        log.error(f"Failed to parse DSC {path}: {exc}")
        return None


def lookup_dsc_string(dsc: SharedCacheStrings, string_offset: int) -> str:
    """Look up a format string by its raw offset in the DSC.

    Args:
        dsc:           Parsed SharedCacheStrings.
        string_offset: The format_string_location from a Firehose entry
                       (combined with large_offset if present).

    Returns:
        The null-terminated format string, or "" if not found.

    The (offset → string) result is memoised on the *dsc* object (bounded by
    FORMAT_STRING_OFFSET_CACHE_MAX, per-process) so a recurring offset skips even
    the binary search below — see lookup_format_string in uuidtext.py for the
    same pattern and rationale.
    """
    cache = getattr(dsc, "_offset_cache", None)
    if cache is None:
        cache = {}
        dsc._offset_cache = cache  # type: ignore[attr-defined]
    cached = cache.get(string_offset, _CACHE_MISS)
    if cached is not _CACHE_MISS:
        return cached  # type: ignore[return-value]

    result = _lookup_dsc_string_uncached(dsc, string_offset)
    if len(cache) < FORMAT_STRING_OFFSET_CACHE_MAX:
        cache[string_offset] = result
    return result


def find_range(
    dsc: SharedCacheStrings, string_offset: int
) -> RangeDescriptor | None:
    """Return the DSC range owning *string_offset*, or ``None``.

    The single definition of "which range covers this offset" — both the format
    string (:func:`lookup_dsc_string`) and the library path
    (``format_string._dsc_library_path``) must select the same range, so the
    rule lives here rather than being written out at each call site.

    HOW: DSC ranges are non-overlapping ``[range_offset, range_offset+range_size)``
    spans. A linear scan is O(ranges) and runs once *per log entry* — on a real
    logarchive (thousands of ranges × millions of entries) that is a multi-minute
    stall. So a sorted index is built once per DSC and binary searched instead:
    O(log ranges) per lookup. The index is cached on the parsed object (one per
    process; workers each hold their own copy).
    """
    starts, ranges_sorted = _range_index(dsc)
    i = bisect.bisect_right(starts, string_offset) - 1
    if i < 0:
        return None
    rng = ranges_sorted[i]
    if string_offset >= rng.range_offset + rng.range_size:
        return None
    return rng


def _lookup_dsc_string_uncached(dsc: SharedCacheStrings, string_offset: int) -> str:
    """Resolve a DSC format string by offset (see lookup_dsc_string for caching)."""
    if string_offset == DYNAMIC_STRING_OFFSET:
        return "%s"

    rng = find_range(dsc, string_offset)
    if rng is not None:
        return _read_cstr(rng.strings, string_offset - rng.range_offset)

    log.debug(
        "DSC %s: offset 0x%x not found in any range", dsc.dsc_uuid, string_offset
    )
    return ""


def _range_index(dsc: SharedCacheStrings) -> tuple[list[int], list[RangeDescriptor]]:
    """Return (sorted range_offsets, ranges sorted by range_offset), cached on *dsc*.

    Built lazily on first lookup and memoised as a private attribute so the
    O(ranges) sort happens once, not on every ``lookup_dsc_string`` call.
    """
    cached = getattr(dsc, "_range_index_cache", None)
    if cached is None:
        ranges_sorted = sorted(dsc.ranges, key=lambda r: r.range_offset)
        starts = [r.range_offset for r in ranges_sorted]
        cached = (starts, ranges_sorted)
        dsc._range_index_cache = cached  # type: ignore[attr-defined]
    return cached


# ── Internal parsing ──────────────────────────────────────────────────────────

def _parse(data: bytes, dsc_uuid: str) -> SharedCacheStrings:
    r = reader_from_bytes(data)

    sig = r.u32()
    if sig != DSC_SIGNATURE:
        raise ValueError(
            f"Invalid DSC signature 0x{sig:08x} (expected 0x{DSC_SIGNATURE:08x})"
        )

    major_version = r.u16()
    minor_version = r.u16()
    number_ranges = r.u32()
    number_uuids = r.u32()

    # ── Parse range descriptors ───────────────────────────────────────────────
    ranges: list[RangeDescriptor] = []
    for _ in range(number_ranges):
        if major_version == 2:
            # v2: range_offset is u64, uuid_index u64 at end
            range_offset = r.u64()
            data_offset = r.u32()
            range_size = r.u32()
            unknown_uuid_index = r.u64()
        else:
            # v1: uuid_index u32 first, range_offset u32 second
            unknown_uuid_index = r.u32()
            range_offset = r.u32()
            data_offset = r.u32()
            range_size = r.u32()

        ranges.append(RangeDescriptor(
            range_offset=range_offset,
            data_offset=data_offset,
            range_size=range_size,
            unknown_uuid_index=unknown_uuid_index,
            strings=b"",  # filled in after UUID parsing
        ))

    # ── Parse UUID descriptors ────────────────────────────────────────────────
    uuids: list[UUIDDescriptor] = []
    for _ in range(number_uuids):
        if major_version == 2:
            text_offset = r.u64()
        else:
            text_offset = r.u32()

        text_size = r.u32()
        uuid_str = r.uuid_be()
        path_offset = r.u32()

        uuids.append(UUIDDescriptor(
            text_offset=text_offset,
            text_size=text_size,
            uuid=uuid_str,
            path_offset=path_offset,
            path_string="",  # filled in below
        ))

    # ── Resolve path strings for UUID descriptors ─────────────────────────────
    for uuid_desc in uuids:
        uuid_desc.path_string = _read_cstr(data, uuid_desc.path_offset)

    # ── Resolve string data for ranges ────────────────────────────────────────
    for rng in ranges:
        end = rng.data_offset + rng.range_size
        if rng.data_offset < len(data) and end <= len(data):
            rng.strings = data[rng.data_offset:end]
        else:
            log.warning(f"DSC {dsc_uuid}: range data_offset=0x{rng.data_offset:x} range_size=0x{rng.range_size:x} out of bounds (file_size=0x{len(data):x})")
            rng.strings = b""

    return SharedCacheStrings(
        signature=sig,
        major_version=major_version,
        minor_version=minor_version,
        number_ranges=number_ranges,
        number_uuids=number_uuids,
        ranges=ranges,
        uuids=uuids,
        dsc_uuid=dsc_uuid,
    )


def _read_cstr(data: bytes, pos: int) -> str:
    if pos >= len(data):
        return ""
    end = data.find(b"\x00", pos)
    if end == -1:
        end = len(data)
    return data[pos:end].decode("utf-8", errors="replace")
