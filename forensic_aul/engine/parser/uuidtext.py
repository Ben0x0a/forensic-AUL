"""Parse Apple Unified Log UUIDText files.

UUIDText files contain the format strings used by log entries. They are stored
in the logarchive under UUID-derived subdirectories (first 2 hex chars as dir,
remaining 30 as filename).

Binary layout reference: macos-UnifiedLogs/src/uuidtext.rs
"""

from __future__ import annotations

import logging
from pathlib import Path

from forensic_aul.config import FORMAT_STRING_OFFSET_CACHE_MAX
from forensic_aul.engine.models import UUIDText, UUIDTextEntry
from forensic_aul.engine.parser.reader import reader_from_bytes

log = logging.getLogger(__name__)

UUIDTEXT_SIGNATURE: int = 0x66778899
# The dynamic format string flag: format string is literally "%s"
DYNAMIC_STRING_OFFSET: int = 0x80000000

# Sentinel distinguishing "offset cached as empty/None" from "offset not cached".
# WHY: a legitimate lookup result can be "" (offset not found); a plain
# ``cache.get(offset)`` returning None could not tell that apart from a miss.
_CACHE_MISS = object()


def parse_uuidtext(path: Path) -> UUIDText | None:
    """Parse a UUIDText file.

    The UUID is derived from the file path: parent-dir name (2 chars) +
    filename (30 chars) = 32-char uppercase hex UUID.

    Args:
        path: Path to the UUIDText file (no extension).

    Returns:
        Parsed UUIDText object, or None on parse error.
    """
    uuid = _uuid_from_path(path)
    try:
        data = path.read_bytes()
    except OSError as exc:
        log.error(f"Cannot read UUIDText file {path}: {exc}")
        return None

    try:
        return _parse(data, uuid)
    except (EOFError, ValueError) as exc:
        log.error(f"Failed to parse UUIDText {path}: {exc}")
        return None


def lookup_format_string(uuidtext: UUIDText, offset: int) -> str:
    """Look up the format string at *offset* within the UUIDText footer data.

    The (offset → string) result is memoised on the *uuidtext* object: the same
    offset recurs across millions of log entries, so caching it removes the
    entry-descriptor scan below from the per-entry hot path. The memo is bounded
    by FORMAT_STRING_OFFSET_CACHE_MAX so a crafted file cannot grow it without
    limit, and is per-process (each parser worker holds its own object copy).

    Args:
        uuidtext: A parsed UUIDText object.
        offset:   The format_string_location value from a Firehose entry.

    Returns:
        The null-terminated format string, or "" if not found.
    """
    cache = getattr(uuidtext, "_offset_cache", None)
    if cache is None:
        cache = {}
        uuidtext._offset_cache = cache  # type: ignore[attr-defined]
    cached = cache.get(offset, _CACHE_MISS)
    if cached is not _CACHE_MISS:
        return cached  # type: ignore[return-value]

    result = _lookup_format_string_uncached(uuidtext, offset)
    # Stop caching once the per-file cap is reached (memory-exhaustion guard);
    # lookups still resolve correctly, just without the memo speed-up.
    if len(cache) < FORMAT_STRING_OFFSET_CACHE_MAX:
        cache[offset] = result
    return result


def _lookup_format_string_uncached(uuidtext: UUIDText, offset: int) -> str:
    """Resolve the format string at *offset* (see lookup_format_string for caching)."""
    if offset == DYNAMIC_STRING_OFFSET:
        return "%s"

    for entry in uuidtext.entry_descriptors:
        start = entry.range_start_offset
        end = start + entry.entry_size
        if start <= offset < end:
            rel = offset - start
            footer = uuidtext.footer_data
            # Walk entry_descriptors to find where in footer_data this range starts.
            # footer_data is a flat pool; entries are laid out in declaration order.
            data_start = _range_offset_in_footer(uuidtext, entry)
            abs_pos = data_start + rel
            return _read_cstr(footer, abs_pos)

    log.debug(
        "UUIDText %s: offset 0x%x not found in any entry descriptor",
        uuidtext.uuid, offset,
    )
    return ""


# ── Internal helpers ──────────────────────────────────────────────────────────

def _uuid_from_path(path: Path) -> str:
    """Derive the 32-char UUID hex string from the file path."""
    dir_part = path.parent.name  # e.g. "1F"
    file_part = path.name        # e.g. "E459BBDC3E19BBF82D58415A2AE9"
    return (dir_part + file_part).upper()


def _parse(data: bytes, uuid: str) -> UUIDText:
    r = reader_from_bytes(data)

    sig = r.u32()
    if sig != UUIDTEXT_SIGNATURE:
        raise ValueError(
            f"Invalid UUIDText signature 0x{sig:08x} (expected 0x{UUIDTEXT_SIGNATURE:08x})"
        )

    major_version = r.u32()
    minor_version = r.u32()
    number_entries = r.u32()

    entries: list[UUIDTextEntry] = []
    for _ in range(number_entries):
        range_start_offset = r.u32()
        entry_size = r.u32()
        entries.append(UUIDTextEntry(
            range_start_offset=range_start_offset,
            entry_size=entry_size,
        ))

    footer_data = data[r.offset:]

    return UUIDText(
        uuid=uuid,
        signature=sig,
        major_version=major_version,
        minor_version=minor_version,
        entry_descriptors=entries,
        footer_data=footer_data,
        image_path=_image_path_from_footer(entries, footer_data),
    )


def _image_path_from_footer(entries: list[UUIDTextEntry], footer_data: bytes) -> str:
    """Return the binary path stored after the string ranges in *footer_data*.

    HOW: footer_data is a flat pool holding each entry's string range back to
    back, in entry_descriptors order (the same layout assumption
    :func:`_range_offset_in_footer` relies on), followed by one null-terminated
    C string — the path of the executable or dylib the file describes. So the
    path starts at the sum of every declared entry_size.

    WHY the guards: entry sizes come straight off disk and are never validated
    against the file length, so a truncated, malformed or hostile UUIDText can
    make that sum overshoot footer_data (or overflow into an absurd value). Such
    a file must degrade to an unnamed process, never abort an extraction that is
    otherwise parsing millions of good entries.
    """
    path_start = 0
    for entry in entries:
        path_start += entry.entry_size
        # Bound the running sum on every step so an inflated entry_size cannot
        # walk the start offset past the pool (and _read_cstr never scans out of
        # the region the ranges actually occupy).
        if path_start > len(footer_data):
            return ""

    return _read_cstr(footer_data, path_start)


def _range_offset_in_footer(uuidtext: UUIDText, target: UUIDTextEntry) -> int:
    """Return the byte offset of *target*'s data within footer_data.

    The footer_data is a flat concatenation of all entry string ranges
    in the order they appear in entry_descriptors.
    """
    offset = 0
    for entry in uuidtext.entry_descriptors:
        if entry is target:
            return offset
        offset += entry.entry_size
    return 0


def _read_cstr(data: bytes, pos: int) -> str:
    if pos >= len(data):
        return ""
    end = data.find(b"\x00", pos)
    if end == -1:
        end = len(data)
    return data[pos:end].decode("utf-8", errors="replace")
