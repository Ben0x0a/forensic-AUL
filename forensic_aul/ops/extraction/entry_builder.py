"""Firehose-entry → LogEntry assembly.

Defines : _LOG_LEVELS, _EVENT_TYPES, _resolve_oversize, _firehose_to_log_entry
Used by : forensic_aul.ops.extraction.tracev3_parse (_firehose_to_log_entry),
          forensic_aul.ops.extraction.workers (transitively)
Uses    : forensic_aul.ops.extraction.oversize_pass (OversizeCache, OversizeKey),
          forensic_aul.engine.models (Firehose, FirehosePreamble, CatalogChunk, …),
          forensic_aul.engine.parser.format_string (resolve_format_string),
          forensic_aul.engine.parser.message (format_message),
          forensic_aul.engine.parser.firehose (ACTIVITY_TYPE_* constants),
          forensic_aul.engine.parser.string_cache (StringCacheProvider, type only),
          forensic_aul.engine.utils.time (resolve_mach_timestamp)
"""

from __future__ import annotations

import json
import logging

from forensic_aul.engine.models import (
    CatalogChunk,
    Firehose,
    FirehoseItemData,
    FirehoseItemInfo,
    FirehosePreamble,
    LogEntry,
    Oversize,
    SimpleDump,
    Statedump,
    TimesyncBoot,
)
from forensic_aul.engine.parser.firehose import (
    ACTIVITY_TYPE_ACTIVITY,
    ACTIVITY_TYPE_LOSS,
    ACTIVITY_TYPE_NON_ACTIVITY,
    ACTIVITY_TYPE_REMNANT,
    ACTIVITY_TYPE_SIGNPOST,
    ACTIVITY_TYPE_TRACE,
)
from forensic_aul.engine.parser.format_string import resolve_format_string
from forensic_aul.engine.parser.message import format_message
from forensic_aul.engine.parser.statedump import statedump_message
from forensic_aul.engine.parser.string_cache import StringCacheProvider
from forensic_aul.engine.utils.time import resolve_mach_timestamp
from forensic_aul.ops.extraction.oversize_pass import OversizeCache, OversizeKey

# Statedump / Simpledump records carry no firehose preamble; the Rust reference
# resolves their timestamp with base_continuous_time = 1 (a non-zero sentinel so
# _select_anchor walks the records instead of taking the boot fallback).
_NO_FIREHOSE_PREAMBLE: int = 1

log = logging.getLogger(__name__)

# ── Log-level mapping (log_type u8 → string) ─────────────────────────────────
_LOG_LEVELS: dict[int, str] = {
    0x00: "Default",
    0x01: "Info",
    0x02: "Debug",
    0x10: "Error",
    0x11: "Fault",
}

# ── Activity-type → event_type mapping ───────────────────────────────────────
_EVENT_TYPES: dict[int, str] = {
    ACTIVITY_TYPE_ACTIVITY:     "Activity",
    ACTIVITY_TYPE_TRACE:        "Trace",
    ACTIVITY_TYPE_NON_ACTIVITY: "Log",
    ACTIVITY_TYPE_SIGNPOST:     "Signpost",
    ACTIVITY_TYPE_LOSS:         "Loss",
    ACTIVITY_TYPE_REMNANT:      "Log",
}


def _resolve_oversize(
    ov: Oversize,
    strings: StringCacheProvider,
) -> list[FirehoseItemInfo]:
    """Return the message items from an Oversize entry."""
    return ov.message_items.item_info


def _firehose_to_log_entry(
    firehose: Firehose,
    preamble: FirehosePreamble,
    catalog: CatalogChunk,
    strings: StringCacheProvider,
    oversize_cache: OversizeCache,
    timesync_data: dict[str, TimesyncBoot],
    boot_uuid: str,
    tracev3_file_id: int,
    timesync_file_id: int | None,
    anchor_id_map: dict[tuple[int, int], int],
    *,
    chunkset_file_offset: int,
    firehose_inner_offset: int,
    keep_raw: bool,
) -> LogEntry | None:
    """Convert a parsed Firehose entry to a LogEntry ready for the DB.

    Pure (no DB): the timesync_anchors.id is resolved from *anchor_id_map*
    (keyed by ``(timesync_file_id, anchor.file_offset)``), which the main process
    pre-populates before parsing — so this runs unchanged inside worker processes.
    """
    # ── Timestamps ───────────────────────────────────────────────────────
    delta = (
        firehose.continuous_time_delta
        | (firehose.continuous_time_delta_upper << 32)
    )
    continuous_time = preamble.base_continuous_time + delta

    resolution = resolve_mach_timestamp(
        timesync_data, boot_uuid, continuous_time, preamble.base_continuous_time,
    )

    # The chosen anchor was pre-inserted; look up its rowid by byte-offset
    # identity. (file, offset) is the same key the writer dedups on. WHY the
    # anchor's own file id (not the per-boot ``timesync_file_id``): a boot UUID
    # can span two .timesync files, so the anchor records which file it actually
    # came from — using the coarse per-boot id would mis-attribute / miss it.
    timesync_anchor_id: int | None = None
    anchor_file_id = timesync_file_id
    if resolution.anchor is not None:
        anchor_file_id = resolution.anchor.timesync_file_id or timesync_file_id
        if anchor_file_id is not None:
            timesync_anchor_id = anchor_id_map.get(
                (anchor_file_id, resolution.anchor.file_offset)
            )

    # ── Process metadata ─────────────────────────────────────────────────
    first_id = preamble.first_number_proc_id
    second_id = preamble.second_number_proc_id
    pid = catalog.get_pid(first_id, second_id)
    euid = catalog.get_euid(first_id, second_id)

    # ── Format string + library ──────────────────────────────────────────
    fmt_str, library, library_uuid, process_uuid, format_src_file_id = resolve_format_string(
        firehose, preamble, catalog, strings
    )

    # ── Item data (possibly from Oversize) ───────────────────────────────
    item_data = firehose.message

    activity_type = firehose.unknown_log_activity_type
    if activity_type == ACTIVITY_TYPE_NON_ACTIVITY:
        na = firehose.firehose_non_activity
        if na.data_ref_value:
            ov_key: OversizeKey = (first_id, second_id, na.data_ref_value)
            ov = oversize_cache.get(ov_key)
            if ov:
                item_data = FirehoseItemData(
                    item_info=_resolve_oversize(ov, strings),
                    backtrace_strings=item_data.backtrace_strings,
                )

    elif activity_type == ACTIVITY_TYPE_SIGNPOST:
        sp = firehose.firehose_signpost
        if sp.data_ref_value:
            ov_key = (first_id, second_id, sp.data_ref_value)
            ov = oversize_cache.get(ov_key)
            if ov:
                item_data = FirehoseItemData(
                    item_info=_resolve_oversize(ov, strings),
                    backtrace_strings=item_data.backtrace_strings,
                )

    # ── Message formatting ───────────────────────────────────────────────
    if activity_type == ACTIVITY_TYPE_LOSS:
        loss = firehose.firehose_loss
        message = (
            f"<loss: {loss.count} messages dropped "
            f"[{loss.start_time}–{loss.end_time}]>"
        )
    elif activity_type == ACTIVITY_TYPE_TRACE:
        # Trace: items already as strings, no format string
        message = " ".join(i.message_strings for i in item_data.item_info)
    else:
        message = format_message(fmt_str, item_data) if fmt_str else ""

    # ── Subsystem / category ─────────────────────────────────────────────
    subsystem_value = 0
    if activity_type == ACTIVITY_TYPE_NON_ACTIVITY:
        subsystem_value = firehose.firehose_non_activity.subsystem_value
    elif activity_type == ACTIVITY_TYPE_SIGNPOST:
        subsystem_value = firehose.firehose_signpost.subsystem

    subsystem, category = catalog.get_subsystem(subsystem_value, first_id, second_id)

    # ── Activity IDs ─────────────────────────────────────────────────────
    activity_id = 0
    parent_activity_id = 0
    if activity_type == ACTIVITY_TYPE_ACTIVITY:
        act = firehose.firehose_activity
        activity_id = act.unknown_activity_id
        parent_activity_id = act.unknown_activity_id_2

    # ── Process name from UUIDText (or library path) ──────────────────────
    # Use library path as process name fallback — full resolution would
    # require reading the binary's path from UUIDText, which is deferred.
    process_name = library or process_uuid or ""

    # ── raw_data JSON ─────────────────────────────────────────────────────
    # Opt-in (extract --keep-raw): this per-item JSON is often the fattest column
    # in the database, and building it costs a json.dumps on every one of tens of
    # millions of entries — so it is skipped entirely unless requested.
    raw_data = json.dumps([
        {"type": hex(i.item_type), "size": i.item_size, "value": i.message_strings}
        for i in item_data.item_info
    ]) if (keep_raw and item_data.item_info) else None

    return LogEntry(
        tracev3_file_id=tracev3_file_id,
        format_src_file_id=format_src_file_id,
        # The file that actually resolved the timestamp (anchor's own file when a
        # boot spans several .timesync files), falling back to the per-boot id.
        timesync_file_id=anchor_file_id,
        tracev3_chunkset_file_offset=chunkset_file_offset,
        tracev3_firehose_inner_offset=firehose_inner_offset,
        tracev3_entry_inner_offset=firehose.entry_inner_offset,
        format_string_file_offset=None,  # exposed by resolve_format_string in a later pass
        timestamp_iso=resolution.iso,
        timestamp_unix_ns=resolution.unix_ns,
        timestamp_mach=continuous_time,
        timesync_anchor_id=timesync_anchor_id,
        process=process_name,
        pid=pid,
        tid=firehose.thread_id,
        euid=euid,
        log_level=_LOG_LEVELS.get(firehose.unknown_log_type, "Default"),
        event_type=_EVENT_TYPES.get(activity_type, "Log"),
        subsystem=subsystem,
        category=category,
        message=message,
        message_format_string=fmt_str,
        library=library,
        library_uuid=library_uuid,
        process_uuid=process_uuid,
        activity_id=activity_id,
        parent_activity_id=parent_activity_id,
        boot_uuid=boot_uuid,
        raw_data=raw_data,
    )


def _resolve_dump_anchor(
    timesync_data: dict[str, TimesyncBoot],
    boot_uuid: str,
    continuous_time: int,
    timesync_file_id: int | None,
    anchor_id_map: dict[tuple[int, int], int],
):
    """Resolve (resolution, anchor_file_id, anchor_id) for a non-firehose dump.

    Shared by the Statedump/Simpledump builders — same anchor identity rules as
    the firehose path (the anchor's own file id, falling back to the per-boot id).
    """
    resolution = resolve_mach_timestamp(
        timesync_data, boot_uuid, continuous_time, _NO_FIREHOSE_PREAMBLE,
    )
    anchor_file_id = timesync_file_id
    anchor_id: int | None = None
    if resolution.anchor is not None:
        anchor_file_id = resolution.anchor.timesync_file_id or timesync_file_id
        if anchor_file_id is not None:
            anchor_id = anchor_id_map.get(
                (anchor_file_id, resolution.anchor.file_offset)
            )
    return resolution, anchor_file_id, anchor_id


def _statedump_to_log_entry(
    sd: Statedump,
    catalog: CatalogChunk,
    timesync_data: dict[str, TimesyncBoot],
    boot_uuid: str,
    tracev3_file_id: int,
    timesync_file_id: int | None,
    anchor_id_map: dict[tuple[int, int], int],
    *,
    chunkset_file_offset: int,
    firehose_inner_offset: int,
) -> LogEntry:
    """Assemble a LogEntry from a Statedump record (mirrors unified_log.rs)."""
    resolution, anchor_file_id, anchor_id = _resolve_dump_anchor(
        timesync_data, boot_uuid, sd.continuous_time, timesync_file_id, anchor_id_map,
    )
    euid = catalog.get_euid(sd.first_proc_id, sd.second_proc_id)
    return LogEntry(
        tracev3_file_id=tracev3_file_id,
        format_src_file_id=None,
        timesync_file_id=anchor_file_id,
        tracev3_chunkset_file_offset=chunkset_file_offset,
        tracev3_firehose_inner_offset=firehose_inner_offset,
        tracev3_entry_inner_offset=None,
        format_string_file_offset=None,
        timestamp_iso=resolution.iso,
        timestamp_unix_ns=resolution.unix_ns,
        timestamp_mach=sd.continuous_time,
        timesync_anchor_id=anchor_id,
        process="",
        pid=sd.first_proc_id,
        tid=0,
        euid=euid,
        log_level="Default",
        event_type="Statedump",
        subsystem="",
        category="",
        message=statedump_message(sd),
        message_format_string="",
        library="",
        library_uuid="",
        process_uuid="",
        activity_id=sd.activity_id,
        parent_activity_id=0,
        boot_uuid=boot_uuid,
        raw_data=None,
    )


def _simpledump_to_log_entry(
    sd: SimpleDump,
    catalog: CatalogChunk,
    timesync_data: dict[str, TimesyncBoot],
    boot_uuid: str,
    tracev3_file_id: int,
    timesync_file_id: int | None,
    anchor_id_map: dict[tuple[int, int], int],
    *,
    chunkset_file_offset: int,
    firehose_inner_offset: int,
) -> LogEntry:
    """Assemble a LogEntry from a Simpledump record (mirrors unified_log.rs)."""
    resolution, anchor_file_id, anchor_id = _resolve_dump_anchor(
        timesync_data, boot_uuid, sd.continuous_time, timesync_file_id, anchor_id_map,
    )
    euid = catalog.get_euid(sd.first_proc_id, sd.second_proc_id)
    return LogEntry(
        tracev3_file_id=tracev3_file_id,
        format_src_file_id=None,
        timesync_file_id=anchor_file_id,
        tracev3_chunkset_file_offset=chunkset_file_offset,
        tracev3_firehose_inner_offset=firehose_inner_offset,
        tracev3_entry_inner_offset=None,
        format_string_file_offset=None,
        timestamp_iso=resolution.iso,
        timestamp_unix_ns=resolution.unix_ns,
        timestamp_mach=sd.continuous_time,
        timesync_anchor_id=anchor_id,
        process="",
        pid=sd.first_proc_id,
        tid=sd.thread_id,
        euid=euid,
        log_level="Default",
        event_type="Simpledump",
        subsystem=sd.subsystem,
        category="",
        message=sd.message_string,
        message_format_string="",
        library="",
        library_uuid=sd.sender_uuid,
        process_uuid=sd.dsc_uuid,
        activity_id=0,
        parent_activity_id=0,
        boot_uuid=boot_uuid,
        raw_data=None,
    )
