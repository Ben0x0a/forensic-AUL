"""Timesync loading + anchor pre-insertion — enables DB-free worker parsing.

Defines : setup_timesync (parse all *.timesync files, register boots, pre-insert
          anchors — the whole step 4 of the extract pipeline), its result
          container TimesyncSetup, and preinsert_timesync_anchors.
Used by : forensic_aul.ops.extraction.extract (_run_parse)
Uses    : forensic_aul.engine.database.writer (BatchWriter, register_source_file),
          forensic_aul.engine.parser.timesync (parse_timesync_file, merge),
          forensic_aul.ops.extraction.discovery (find_timesync_files),
          forensic_aul.engine.models (TimesyncAnchor, TimesyncBoot)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from forensic_aul.engine.database.writer import BatchWriter, register_source_file
from forensic_aul.engine.models import TimesyncAnchor, TimesyncBoot
from forensic_aul.engine.parser.timesync import merge_timesync_dicts, parse_timesync_file
from forensic_aul.ops.extraction.discovery import find_timesync_files

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class TimesyncSetup:
    """Everything the parse pass needs from the timesync layer."""

    timesync_data: dict[str, TimesyncBoot]          # boot UUID → merged records
    boot_uuid_to_timesync_file_id: dict[str, int]   # coarse per-boot provenance
    anchor_id_map: dict[tuple[int, int], int]       # (file_id, offset) → anchor id


def setup_timesync(
    writer: BatchWriter,
    logarchive: Path,
    file_hashes: dict[str, str],
) -> TimesyncSetup:
    """Step 4 of the extract pipeline: load timesync, register boots + anchors.

    Parses every ``*.timesync`` file, merges the per-boot records, registers each
    boot with its physical first-appearance rank (drives event_order), and
    pre-inserts every selectable anchor so parser workers resolve
    ``timesync_anchor_id`` with a pure map lookup (no DB access in workers).
    """
    timesync_data: dict[str, TimesyncBoot] = {}
    ts_files = find_timesync_files(logarchive)
    boot_uuid_to_timesync_file_id: dict[str, int] = {}
    # Physical boot order for event_order: first-appearance rank as we walk the
    # name-sorted timesync files (append-only, sequence-numbered) and each file's
    # boots in offset order. WHY not boot_time: that is wall-clock at boot, so a
    # clock reset could reorder boots — physical layout is tamper-resilient.
    boot_rank_by_uuid: dict[str, int] = {}
    log.info(f"Found {len(ts_files)} timesync file(s)")
    for ts_file in ts_files:
        try:
            merged = parse_timesync_file(ts_file)
            if merged:
                # Register this timesync file once and stamp its source-file id
                # onto every boot header and record it parsed, so anchor
                # provenance survives a boot UUID spanning multiple files.
                ts_file_id = register_source_file(writer, logarchive, ts_file, "timesync", file_hashes)
                for boot_uuid_key, boot in merged.items():
                    boot.timesync_file_id = ts_file_id
                    for record in boot.timesync:
                        record.timesync_file_id = ts_file_id
                    # First file to mention a boot owns its coarse map entry; the
                    # real per-anchor provenance now travels on each record, so
                    # last-wins (the old bug) is no longer needed here.
                    boot_uuid_to_timesync_file_id.setdefault(boot_uuid_key, ts_file_id)
                    if boot_uuid_key not in boot_rank_by_uuid:
                        boot_rank_by_uuid[boot_uuid_key] = len(boot_rank_by_uuid)
                # WHY merge_timesync_dicts not dict.update: a boot UUID present in
                # a second .timesync file must APPEND its records, not replace the
                # earlier list (forensic loss of anchors otherwise).
                merge_timesync_dicts(timesync_data, merged)
                log.debug(
                    "  %s  →  %d boot record(s)  file_id=%d",
                    ts_file.name, len(merged), ts_file_id,
                )
        except Exception as exc:
            log.warning(f"  {ts_file.name}  parse error: {exc}")
    log.info(f"Timesync loaded : {len(timesync_data)} boot UUID(s)  covering {sum(len(b.timesync) for b in timesync_data.values())} record(s) total")
    # Register every known boot with its physical rank now, so the writer resolves
    # boot_id from its cache during the parse and assign_ordering can sort on the
    # integer boots.rank. Insert in rank order (first-appearance) for tidy ids.
    for boot_uuid_key, rank in sorted(boot_rank_by_uuid.items(), key=lambda kv: kv[1]):
        writer.register_boot(boot_uuid_key, rank)

    # Pre-insert all selectable anchors so parser workers resolve
    # timesync_anchor_id with a pure map lookup (no DB).
    anchor_id_map = preinsert_timesync_anchors(
        writer, timesync_data, boot_uuid_to_timesync_file_id
    )
    log.info(f"Timesync anchors pre-inserted : {len(anchor_id_map)}")

    return TimesyncSetup(timesync_data, boot_uuid_to_timesync_file_id, anchor_id_map)


def preinsert_timesync_anchors(
    writer: BatchWriter,
    timesync_data: dict[str, TimesyncBoot],
    boot_uuid_to_timesync_file_id: dict[str, int],
) -> dict[tuple[int, int], int]:
    """Insert every anchor ``_select_anchor`` could pick; return (file_id, offset)→id.

    For each boot the selectable anchors are exactly: the boot record itself
    (file_offset = boot.file_offset, kernel_time = 0, walltime = boot_time) and
    one per timesync record (its own offset / kernel_time / walltime). Pre-inserting
    them lets parser workers resolve ``timesync_anchor_id`` with a pure dict lookup
    keyed by the same ``(timesync_file_id, file_offset)`` identity the writer dedups
    on — so a worker never touches the DB. Anchors never referenced by an entry are
    harmless extra rows. The timebase (1/1 Intel, 125/3 Apple Silicon) mirrors
    ``forensic_aul/engine/utils/time.py``.
    """
    anchor_id_map: dict[tuple[int, int], int] = {}
    for boot_uuid, boot in timesync_data.items():
        # Each anchor carries its own source-file id (boot header / record), so
        # a boot UUID spanning two files inserts and resolves each anchor against
        # the file it actually came from. The per-boot map is only a coarse
        # fallback for boots with no registered file at all.
        boot_file_id = boot.timesync_file_id or boot_uuid_to_timesync_file_id.get(boot_uuid)
        if boot_file_id is None:
            continue
        if boot.timebase_numerator == 125 and boot.timebase_denominator == 3:
            tb_num, tb_den = 125, 3
        else:
            tb_num, tb_den = 1, 1

        anchors = [
            TimesyncAnchor(
                boot_uuid=boot.boot_uuid,
                file_offset=boot.file_offset,
                kernel_continuous_time=0,
                walltime_unix_ns=boot.boot_time,
                timebase_numerator=tb_num,
                timebase_denominator=tb_den,
                timezone_offset_mins=boot.timezone_offset_mins,
                timesync_file_id=boot_file_id,
            )
        ]
        for rec in boot.timesync:
            anchors.append(
                TimesyncAnchor(
                    boot_uuid=boot.boot_uuid,
                    file_offset=rec.file_offset,
                    kernel_continuous_time=rec.kernel_time,
                    walltime_unix_ns=rec.walltime,
                    timebase_numerator=tb_num,
                    timebase_denominator=tb_den,
                    timezone_offset_mins=rec.timezone,
                    timesync_file_id=rec.timesync_file_id or boot_file_id,
                )
            )

        for anchor in anchors:
            anchor_id = writer.get_or_insert_timesync_anchor(anchor, anchor.timesync_file_id)
            anchor_id_map[(anchor.timesync_file_id, anchor.file_offset)] = anchor_id
    return anchor_id_map
