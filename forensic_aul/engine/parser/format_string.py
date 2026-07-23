"""Resolve which format string applies to a parsed Firehose entry.

Given a parsed ``Firehose`` entry, its ``FirehosePreamble`` and the ``Catalog``,
this decides *where* the printf-style format string lives — inline (dynamic), in
a UUIDText file (main executable), in the DSC shared cache, or via an embedded
UUID — and looks it up. It is pure parser logic with no database or pipeline
dependency: the string cache is reached through the small
:class:`FormatStringSource` protocol, so any cache implementation satisfies it
without this module importing the extraction layer.
"""

from __future__ import annotations

from typing import Protocol

from forensic_aul.engine.models import (
    CatalogChunk,
    Firehose,
    FirehosePreamble,
    SharedCacheStrings,
    UUIDText,
)
from forensic_aul.engine.parser.dsc import lookup_dsc_string
from forensic_aul.engine.parser.firehose import (
    ACTIVITY_TYPE_ACTIVITY,
    ACTIVITY_TYPE_SIGNPOST,
)
from forensic_aul.engine.parser.uuidtext import DYNAMIC_STRING_OFFSET, lookup_format_string


class FormatStringSource(Protocol):
    """The slice of a string cache that format-string resolution needs.

    Any object exposing these three lookups (e.g. the extraction pipeline's
    ``StringCacheProvider``) can be passed to :func:`resolve_format_string`.
    """

    def get_uuidtext(self, uuid: str) -> UUIDText | None: ...
    def get_dsc(self, uuid: str) -> SharedCacheStrings | None: ...
    def get_file_id(self, uuid: str) -> int | None: ...


def resolve_format_string(
    firehose: Firehose,
    preamble: FirehosePreamble,
    catalog: CatalogChunk,
    strings: FormatStringSource,
) -> tuple[str, str, str, str, int | None]:
    """Resolve the format string for a Firehose entry.

    Returns (format_string, library_path, library_uuid, process_uuid, format_src_file_id).
    `format_src_file_id` is the source_files.id of the UUIDText or DSC file used,
    or None for dynamic/inline strings.
    """
    fmt = firehose.firehose_non_activity.firehose_formatters
    if firehose.unknown_log_activity_type == ACTIVITY_TYPE_ACTIVITY:
        fmt = firehose.firehose_activity.firehose_formatters
    elif firehose.unknown_log_activity_type == ACTIVITY_TYPE_SIGNPOST:
        fmt = firehose.firehose_signpost.firehose_formatters

    offset = firehose.format_string_location

    # Dynamic/inline strings — no file lookup
    if offset == DYNAMIC_STRING_OFFSET:
        if firehose.message.item_info:
            return firehose.message.item_info[0].message_strings, "", "", "", None
        return "", "", "", "", None

    # UUID-relative: UUID is embedded in the formatter data
    if fmt.uuid_relative:
        uuidtext = strings.get_uuidtext(fmt.uuid_relative)
        file_id = strings.get_file_id(fmt.uuid_relative)
        if uuidtext:
            fs = lookup_format_string(uuidtext, offset)
            return fs, fmt.uuid_relative, fmt.uuid_relative, "", file_id
        return "", "", fmt.uuid_relative, "", file_id

    # Shared cache (DSC)
    if fmt.shared_cache or fmt.large_shared_cache:
        dsc_uuid, main_uuid = _get_process_uuids(preamble, catalog)
        if dsc_uuid:
            dsc = strings.get_dsc(dsc_uuid)
            file_id = strings.get_file_id(dsc_uuid)
            if dsc:
                effective_offset = _dsc_effective_offset(offset, fmt)
                fs = lookup_dsc_string(dsc, effective_offset)
                return fs, dsc_uuid, dsc_uuid, main_uuid, file_id
        return "", "", dsc_uuid, "", None

    # Absolute — an alternative UUID file (chosen by load-address range), NOT the
    # main exe and never the DSC. Must be checked before main_exe.
    if fmt.absolute:
        return _resolve_absolute(firehose, fmt, preamble, catalog, strings, offset)

    # Main executable UUIDText. WHY no large-offset math here: the Rust reference
    # (nonactivity.rs get_firehose_nonactivity_strings) looks this path up with
    # the raw string offset — large offsets only apply to the shared-cache path.
    if fmt.main_exe:
        dsc_uuid, main_uuid = _get_process_uuids(preamble, catalog)
        if main_uuid:
            uuidtext = strings.get_uuidtext(main_uuid)
            file_id = strings.get_file_id(main_uuid)
            if uuidtext:
                fs = lookup_format_string(uuidtext, offset)
                return fs, main_uuid, main_uuid, main_uuid, file_id
        return "", main_uuid, main_uuid, main_uuid, None

    return "", "", "", "", None


def _get_process_uuids(
    preamble: FirehosePreamble,
    catalog: CatalogChunk,
) -> tuple[str, str]:
    """Return (dsc_uuid, main_uuid) from the catalog for the process owning *preamble*."""
    return catalog.get_catalog_dsc(preamble.first_number_proc_id, preamble.second_number_proc_id)


def _get_unknown_pc_id(firehose: Firehose) -> int:
    """Return the per-entry ``unknown_pc_id`` for the entry's activity type.

    Used only on the absolute path; the field lives on the type-specific sub-record.
    """
    if firehose.unknown_log_activity_type == ACTIVITY_TYPE_ACTIVITY:
        return firehose.firehose_activity.unknown_pc_id
    if firehose.unknown_log_activity_type == ACTIVITY_TYPE_SIGNPOST:
        return firehose.firehose_signpost.unknown_pc_id
    return firehose.firehose_non_activity.unknown_pc_id


def _dsc_effective_offset(string_offset: int, fmt) -> int:
    """Compute the DSC lookup offset, mirroring the Rust large-offset rules.

    Ported from ``nonactivity.rs::get_firehose_nonactivity_strings`` (the same
    logic appears in the activity/signpost variants). When ``has_large_offset``
    is zero the raw offset is used. Otherwise the high part is hex-concatenated
    above the 32-bit string offset (``lo << 32 | string_offset``), with two
    special cases mirrored exactly:

    * Recovery: if ``has_large_offset`` disagrees with ``large_shared_cache / 2``
      and the plain ``shared_cache`` flag is **not** set, Apple logs an
      "<Invalid shared cache code pointer offset>" but still resolves using
      ``large_shared_cache / 2`` as the high part.
    * ``shared_cache`` set: the high part is fixed to 8, giving
      ``string_offset + 0x80000000`` (``0x10000000 * 8``).

    WHY exact parity: a wrong high part resolves a different (or no) DSC range,
    silently yielding the wrong format string or an empty one.
    """
    lo = fmt.has_large_offset
    if not lo:
        return string_offset

    # string_offset is a u32; the hex-concat ``f"{lo:X}{string_offset:08X}"`` is
    # therefore exactly ``lo << 32 | (string_offset & 0xFFFFFFFF)``.
    so32 = string_offset & 0xFFFFFFFF
    if lo != fmt.large_shared_cache // 2 and not fmt.shared_cache:
        lo = fmt.large_shared_cache // 2
        return (lo << 32) | so32
    if fmt.shared_cache:
        return string_offset + 0x80000000
    return (lo << 32) | so32


def _resolve_absolute(
    firehose: Firehose,
    fmt,
    preamble: FirehosePreamble,
    catalog: CatalogChunk,
    strings: FormatStringSource,
    offset: int,
) -> tuple[str, str, str, str, int | None]:
    """Resolve an ``absolute`` entry against an alternative UUIDText file.

    Ported from ``message.rs::extract_absolute_strings``:

    1. ``absolute_offset = main_exe_alt_index << 32 | unknown_pc_id`` (hex-concat,
       ``unknown_pc_id`` is a u32).
    2. Pick the library UUID from the catalog process entry's
       ``uuid_info_entries`` — the one whose ``load_address .. load_address+size``
       range contains ``absolute_offset``.
    3. Look up the format string at the original ``format_string_location`` in
       THAT UUIDText file (never the main exe's, never the DSC). ``process_uuid``
       stays the catalog main UUID.

    Returns the same 5-tuple as :func:`resolve_format_string`.
    """
    pc_id = _get_unknown_pc_id(firehose)
    absolute_offset = (fmt.main_exe_alt_index << 32) | (pc_id & 0xFFFFFFFF)

    _, main_uuid = _get_process_uuids(preamble, catalog)

    library_uuid = ""
    proc = catalog.get_process_info(
        preamble.first_number_proc_id, preamble.second_number_proc_id
    )
    if proc is not None:
        for u in proc.uuid_info_entries:
            if u.load_address <= absolute_offset <= u.load_address + u.size:
                library_uuid = u.uuid
                break

    if library_uuid:
        uuidtext = strings.get_uuidtext(library_uuid)
        file_id = strings.get_file_id(library_uuid)
        if uuidtext:
            fs = lookup_format_string(uuidtext, offset)
            return fs, library_uuid, library_uuid, main_uuid, file_id
        return "", library_uuid, library_uuid, main_uuid, file_id
    return "", library_uuid, library_uuid, main_uuid, None
