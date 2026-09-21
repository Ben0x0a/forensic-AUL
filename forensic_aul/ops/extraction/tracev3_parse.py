"""Single-file tracev3 parser — Pass 2 inner loop.

Defines : process_tracev3
Used by : forensic_aul.ops.extraction.workers (worker_parse),
          forensic_aul.ops.extraction.extract (_run_parse, serial path)
Uses    : forensic_aul.ops.extraction.entry_builder (_firehose_to_log_entry),
          forensic_aul.ops.extraction.oversize_pass (OversizeCache),
          forensic_aul.engine.models (CatalogChunk, LogEntry, TimesyncBoot),
          forensic_aul.engine.parser.catalog, .chunkset, .firehose, .header,
          .reader, .tracev3 (chunk/subchunk iterators + parsers),
          forensic_aul.engine.parser.string_cache (StringCacheProvider),
          forensic_aul.engine.utils.cancellation (CancelToken)
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path

from forensic_aul.engine.models import CatalogChunk, LogEntry, TimesyncBoot
from forensic_aul.engine.parser.catalog import parse_catalog_chunk
from forensic_aul.engine.parser.chunkset import (
    CHUNK_TAG_FIREHOSE,
    CHUNK_TAG_SIMPLEDUMP,
    CHUNK_TAG_STATEDUMP,
    decompress_chunkset,
    iter_subchunks,
)
from forensic_aul.engine.parser.firehose import (
    ACTIVITY_TYPE_NON_ACTIVITY,
    parse_firehose_preamble,
)
from forensic_aul.engine.parser.header import parse_header_chunk
from forensic_aul.engine.parser.reader import reader_from_bytes
from forensic_aul.engine.parser.statedump import parse_simpledump, parse_statedump
from forensic_aul.engine.parser.string_cache import StringCacheProvider
from forensic_aul.engine.parser.tracev3 import (
    CHUNK_TAG_CATALOG,
    CHUNK_TAG_CHUNKSET,
    CHUNK_TAG_HEADER,
    iter_chunks,
)
from forensic_aul.ops.extraction.entry_builder import (
    _firehose_to_log_entry,
    _simpledump_to_log_entry,
    _statedump_to_log_entry,
)
from forensic_aul.engine.utils.cancellation import NEVER_CANCELLED, CancelToken
from forensic_aul.errors import OperationCancelled
from forensic_aul.ops.extraction.oversize_pass import OversizeCache

log = logging.getLogger(__name__)


# ── tracev3 file processing ───────────────────────────────────────────────────

def process_tracev3(
    path: Path,
    logarchive_root: Path,
    strings: StringCacheProvider,
    oversize_cache: OversizeCache,
    timesync_data: dict[str, TimesyncBoot],
    boot_uuid_to_timesync_file_id: dict[str, int],
    tracev3_file_id: int,
    anchor_id_map: dict[tuple[int, int], int],
    emit: "Callable[[LogEntry], None]",
    *,
    keep_raw: bool,
    cancel: CancelToken = NEVER_CANCELLED,
) -> tuple[str, str, str, int, int]:
    """Parse one tracev3 file, passing every resolved LogEntry to *emit*.

    Pure with respect to the DB: the file is pre-registered (``tracev3_file_id``)
    and anchors are pre-inserted (``anchor_id_map``), so this runs identically in
    the main process (``emit=writer.add``) and in a worker (``emit=list.append``).

    *cancel* is checked once per top-level chunk. That is the tightest boundary
    that is still free: a chunkset is decompressed and walked as a unit, so a
    finer check would have to sit inside the entry loop and be paid millions of
    times per file for no useful gain. Worst-case latency is therefore one
    chunkset (see the parse-cancel latency note in docs/internal/performance.md).

    Returns (boot_uuid, ios_model, ios_build_version, entries_written, parse_errors).

    Raises:
        OperationCancelled: *cancel* was cancelled mid-file. Whatever was emitted
            before that point has already been handed to *emit*; the caller
            decides what to do with it (``run_extract`` keeps it — the rows are
            genuine — and marks the database incomplete).
    """
    rel = path.relative_to(logarchive_root)
    boot_uuid = ""
    ios_model = ""
    ios_build_version = ""
    catalog: CatalogChunk | None = None

    n_chunks = 0
    n_chunksets = 0
    n_firehose_blocks = 0
    n_entries_written = 0
    n_parse_errors = 0
    n_oversize_hits = 0
    n_statedump = 0
    n_simpledump = 0

    log.debug("%s  →  tracev3_file_id=%d", rel, tracev3_file_id)

    try:
        for raw in iter_chunks(path):
            cancel.check()
            n_chunks += 1
            log.debug(
                "%s  chunk #%d  tag=0x%04x  size=%d B  offset=0x%x",
                rel, n_chunks, raw.tag, raw.data_size, raw.file_offset,
            )

            if raw.tag == CHUNK_TAG_HEADER:
                try:
                    r = reader_from_bytes(raw.data)
                    hdr = parse_header_chunk(r)
                    boot_uuid = hdr.boot_uuid
                    ios_model = hdr.hardware_model_string.rstrip("\x00")
                    ios_build_version = hdr.build_version_string.rstrip("\x00")
                    log.debug(
                        "%s  header → boot_uuid=%s  model=%s  build=%s  "
                        "timebase=%d/%d",
                        rel, boot_uuid, ios_model, ios_build_version,
                        hdr.mach_time_numerator, hdr.mach_time_denominator,
                    )
                except Exception as exc:
                    n_parse_errors += 1
                    log.warning(f"{rel}  header parse error: {exc}")

            elif raw.tag == CHUNK_TAG_CATALOG:
                try:
                    catalog = parse_catalog_chunk(raw.data)
                    log.debug(
                        "%s  catalog → %d process entries  %d UUIDs  %d sub-chunks",
                        rel,
                        catalog.number_process_information_entries,
                        len(catalog.catalog_uuids),
                        catalog.number_sub_chunks,
                    )
                except Exception as exc:
                    n_parse_errors += 1
                    log.warning(f"{rel}  catalog parse error: {exc}")

            elif raw.tag == CHUNK_TAG_CHUNKSET:
                if catalog is None:
                    log.warning(f"{rel}  chunkset at offset 0x{raw.file_offset:x} encountered before catalog — skipped")
                    continue
                n_chunksets += 1
                decompressed = decompress_chunkset(raw.data)
                if decompressed is None:
                    n_parse_errors += 1
                    log.warning(f"{rel}  chunkset #{n_chunksets} decompression failed (offset=0x{raw.file_offset:x})")
                    continue
                log.debug(
                    "%s  chunkset #%d  compressed=%d B → decompressed=%d B",
                    rel, n_chunksets, raw.data_size, len(decompressed),
                )

                n_sub = 0
                for sub in iter_subchunks(decompressed):
                    # Statedump / Simpledump are non-Firehose log records that
                    # `log show` emits as ordinary lines. They carry no firehose
                    # preamble; resolve their timestamp directly and emit a
                    # LogEntry (event_type Statedump/Simpledump). Boot UUID comes
                    # from the file header parsed earlier in this loop.
                    if sub.chunk_tag == CHUNK_TAG_STATEDUMP:
                        tsf_id = boot_uuid_to_timesync_file_id.get(boot_uuid)
                        # Build inside the guard (a malformed record is a *parse*
                        # error to skip); emit OUTSIDE it so a storage failure is
                        # never silently miscounted as a parse error.
                        try:
                            sd = parse_statedump(sub.data)
                            entry = (
                                _statedump_to_log_entry(
                                    sd, catalog, timesync_data, boot_uuid,
                                    tracev3_file_id, tsf_id, anchor_id_map,
                                    chunkset_file_offset=raw.file_offset,
                                    firehose_inner_offset=sub.source_offset,
                                )
                                if sd is not None else None
                            )
                        except Exception as exc:
                            n_parse_errors += 1
                            log.debug("%s  statedump parse error: %s", rel, exc)
                            continue
                        if entry is None:
                            n_parse_errors += 1
                            continue
                        emit(entry)
                        n_statedump += 1
                        n_entries_written += 1
                        continue
                    if sub.chunk_tag == CHUNK_TAG_SIMPLEDUMP:
                        tsf_id = boot_uuid_to_timesync_file_id.get(boot_uuid)
                        try:
                            sdp = parse_simpledump(sub.data)
                            entry = (
                                _simpledump_to_log_entry(
                                    sdp, catalog, timesync_data, boot_uuid,
                                    tracev3_file_id, tsf_id, anchor_id_map,
                                    chunkset_file_offset=raw.file_offset,
                                    firehose_inner_offset=sub.source_offset,
                                )
                                if sdp is not None else None
                            )
                        except Exception as exc:
                            n_parse_errors += 1
                            log.debug("%s  simpledump parse error: %s", rel, exc)
                            continue
                        if entry is None:
                            n_parse_errors += 1
                            continue
                        emit(entry)            # outside the parse guard (see statedump)
                        n_simpledump += 1
                        n_entries_written += 1
                        continue
                    if sub.chunk_tag != CHUNK_TAG_FIREHOSE:
                        log.debug(
                            "%s  chunkset #%d  sub-chunk tag=0x%04x skipped",
                            rel, n_chunksets, sub.chunk_tag,
                        )
                        continue
                    n_sub += 1
                    n_firehose_blocks += 1
                    try:
                        preamble = parse_firehose_preamble(sub.data)
                    except Exception as exc:
                        n_parse_errors += 1
                        log.debug(
                            "%s  chunkset #%d  firehose block #%d  preamble error: %s",
                            rel, n_chunksets, n_sub, exc,
                        )
                        continue
                    if preamble is None:
                        n_parse_errors += 1
                        continue

                    log.debug(
                        "%s  firehose block proc=%d_%d  base_time=%d  "
                        "%d entries  priv_offset=0x%x",
                        rel,
                        preamble.first_number_proc_id,
                        preamble.second_number_proc_id,
                        preamble.base_continuous_time,
                        len(preamble.public_data),
                        preamble.private_data_virtual_offset,
                    )

                    timesync_file_id = boot_uuid_to_timesync_file_id.get(boot_uuid)

                    for entry in preamble.public_data:
                        # Assemble inside the guard (a malformed entry is a *parse*
                        # error to skip); emit OUTSIDE it so a storage failure is
                        # never silently miscounted as a parse error.
                        try:
                            # Track oversize hits before assembly
                            act_type = entry.unknown_log_activity_type
                            if act_type == ACTIVITY_TYPE_NON_ACTIVITY:
                                if entry.firehose_non_activity.data_ref_value:
                                    key = (
                                        preamble.first_number_proc_id,
                                        preamble.second_number_proc_id,
                                        entry.firehose_non_activity.data_ref_value,
                                    )
                                    if key in oversize_cache:
                                        n_oversize_hits += 1

                            log_entry = _firehose_to_log_entry(
                                entry, preamble, catalog, strings,
                                oversize_cache, timesync_data, boot_uuid,
                                tracev3_file_id, timesync_file_id, anchor_id_map,
                                chunkset_file_offset=raw.file_offset,
                                firehose_inner_offset=sub.source_offset,
                                keep_raw=keep_raw,
                            )
                        except Exception as exc:
                            n_parse_errors += 1
                            log.debug(
                                "%s  entry assembly error (type=0x%02x): %s",
                                rel, entry.unknown_log_activity_type, exc,
                            )
                            continue
                        if log_entry is not None:
                            emit(log_entry)
                            n_entries_written += 1

                log.debug(
                    "%s  chunkset #%d done  firehose_blocks=%d",
                    rel, n_chunksets, n_sub,
                )

    except OperationCancelled:
        # WHY ahead of the broad handler: the catch-all below turns any failure
        # into a counted parse error and returns normally, so a cancellation
        # swallowed there would look like a successfully parsed file and the
        # pipeline would carry straight on to the next one.
        log.info(f"{rel}  parse cancelled after {n_entries_written} entries")
        raise
    except Exception as exc:
        n_parse_errors += 1
        log.error(f"{rel}  fatal error after {n_entries_written} entries: {exc}")

    log.info(f"  {str(rel):<45}  chunks={n_chunks:<3}  chunksets={n_chunksets:<3}  entries={n_entries_written:<6}  oversize_hits={n_oversize_hits:<3}  statedump={n_statedump:<3}  simpledump={n_simpledump:<3}  errors={n_parse_errors}")
    return boot_uuid, ios_model, ios_build_version, n_entries_written, n_parse_errors
