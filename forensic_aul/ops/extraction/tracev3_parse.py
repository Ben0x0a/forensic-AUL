"""Single-file tracev3 parser — Pass 2 inner loop.

Defines : process_tracev3 (one file, through _FileParse: a handler per chunk
          and sub-chunk tag) and FileParseStats (what parsing one file produced)
Used by : forensic_aul.ops.extraction.workers (worker_parse),
          forensic_aul.ops.extraction.extract (_run_parse, serial path)
Uses    : forensic_aul.ops.extraction.entry_builder (firehose_to_log_entry),
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
from dataclasses import dataclass
from pathlib import Path

from forensic_aul.engine.models import CatalogChunk, LogEntry, TimesyncBoot
from forensic_aul.engine.parser.catalog import parse_catalog_chunk
from forensic_aul.engine.parser.format import (
    CHUNK_TAG_CATALOG,
    CHUNK_TAG_CHUNKSET,
    CHUNK_TAG_FIREHOSE,
    CHUNK_TAG_HEADER,
    CHUNK_TAG_SIMPLEDUMP,
    CHUNK_TAG_STATEDUMP,
    CHUNK_TAG_OVERSIZE,
)
from forensic_aul.engine.parser.chunkset import (
    SubChunkRef,
    codec_for,
    decompress_chunkset,
    iter_subchunks,
)
from forensic_aul.engine.parser.firehose import (
    ACTIVITY_TYPE_NON_ACTIVITY,
    KNOWN_FLAG_BITS,
    parse_firehose_preamble,
)
from forensic_aul.engine.parser.header import parse_header_chunk
from forensic_aul.engine.parser.reader import reader_from_bytes
from forensic_aul.engine.parser.statedump import parse_simpledump, parse_statedump
from forensic_aul.engine.parser.string_cache import StringCacheProvider
from forensic_aul.engine.parser.tracev3 import RawChunk, iter_chunks
from forensic_aul.ops.extraction.entry_builder import (
    firehose_to_log_entry,
    simpledump_to_log_entry,
    statedump_to_log_entry,
)
from forensic_aul.engine.utils.cancellation import NEVER_CANCELLED, CancelToken
from forensic_aul.ops.extraction import format_watch
from forensic_aul.ops.extraction.format_watch import FormatWatch
from forensic_aul.errors import PARSE_ERRORS, OperationCancelled
from forensic_aul.ops.extraction.oversize_pass import OversizeCache

log = logging.getLogger(__name__)


# ── tracev3 file processing ───────────────────────────────────────────────────

@dataclass(frozen=True)
class FileParseStats:
    """What parsing one tracev3 file produced.

    Crosses the worker → writer process boundary, so it stays a plain, picklable
    record. ``chunksets`` counts every chunkset in the file, ``chunksets_decoded``
    those actually decompressed and walked: their ratio is the file's
    decodability — 0 of N means this tool does not understand the file's format.
    """

    boot_uuid: str
    ios_model: str
    ios_build: str
    entries: int
    errors: int
    chunksets: int
    chunksets_decoded: int
    # (kind, detail, count) — see ops/extraction/format_watch.py.
    observations: tuple[tuple[str, str, int], ...] = ()


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
) -> FileParseStats:
    """Parse one tracev3 file, passing every resolved LogEntry to *emit*.

    Pure with respect to the DB: the file is pre-registered (``tracev3_file_id``)
    and anchors are pre-inserted (``anchor_id_map``), so this runs identically in
    the main process (``emit=writer.add``) and in a worker (``emit=list.append``).

    *cancel* is checked once per top-level chunk. That is the tightest boundary
    that is still free: a chunkset is decompressed and walked as a unit, so a
    finer check would have to sit inside the entry loop and be paid millions of
    times per file for no useful gain. Worst-case latency is therefore one
    chunkset (see the parse-cancel latency note in docs/internal/performance.md).

    Returns a :class:`FileParseStats`.

    Raises:
        OperationCancelled: *cancel* was cancelled mid-file. Whatever was emitted
            before that point has already been handed to *emit*; the caller
            decides what to do with it (``run_extract`` keeps it — the rows are
            genuine — and marks the database incomplete).
    """
    return _FileParse(
        path, logarchive_root, strings, oversize_cache, timesync_data,
        boot_uuid_to_timesync_file_id, tracev3_file_id, anchor_id_map, emit,
        keep_raw=keep_raw, cancel=cancel,
    ).run()


class _FileParse:
    """The parse of one tracev3 file: its state, and one handler per chunk kind.

    WHY a dispatch table: each chunk / sub-chunk kind (header, catalog, chunkset;
    firehose, statedump, simpledump, oversize) has its own handler, found by its
    tag. Supporting a new kind is one method and one table entry, and the three
    near-identical inline branches of the former 250-line function (S13) became
    one handler for both dump kinds.
    """

    def __init__(
        self, path: Path, logarchive_root: Path, strings: StringCacheProvider,
        oversize_cache: OversizeCache, timesync_data: dict[str, TimesyncBoot],
        boot_uuid_to_timesync_file_id: dict[str, int], tracev3_file_id: int,
        anchor_id_map: dict[tuple[int, int], int], emit: "Callable[[LogEntry], None]",
        *, keep_raw: bool, cancel: CancelToken,
    ) -> None:
        self.path, self.strings, self.oversize_cache = path, strings, oversize_cache
        self.timesync_data, self.boot_to_timesync = timesync_data, boot_uuid_to_timesync_file_id
        self.file_id, self.anchor_id_map, self.emit = tracev3_file_id, anchor_id_map, emit
        self.keep_raw, self.cancel = keep_raw, cancel
        self.rel = path.relative_to(logarchive_root)
        self.boot_uuid = self.ios_model = self.ios_build = ""
        self.catalog: CatalogChunk | None = None
        self.watch = FormatWatch()
        self.n_chunks = 0
        self.n_chunksets = 0          # chunksets with a usable catalog (numbers the log lines)
        self.n_chunksets_seen = 0     # every chunkset in the file
        self.n_chunksets_decoded = 0  # decompressed and walked
        self.n_firehose_blocks = 0
        self.n_entries = 0
        self.n_errors = 0
        self.n_oversize_hits = 0
        self.n_dumps = {"statedump": 0, "simpledump": 0}

    # ── the file ─────────────────────────────────────────────────────────────

    def run(self) -> FileParseStats:
        log.debug("%s  →  tracev3_file_id=%d", self.rel, self.file_id)
        handlers = {
            CHUNK_TAG_HEADER: self._on_header,
            CHUNK_TAG_CATALOG: self._on_catalog,
            CHUNK_TAG_CHUNKSET: self._on_chunkset,
        }
        try:
            for raw in iter_chunks(self.path):
                self.cancel.check()
                self.n_chunks += 1
                log.debug(
                    "%s  chunk #%d  tag=0x%04x  size=%d B  offset=0x%x",
                    self.rel, self.n_chunks, raw.tag, raw.data_size, raw.file_offset,
                )
                handler = handlers.get(raw.tag)
                if handler is None:
                    self.watch.note(format_watch.CHUNK_TAG, f"0x{raw.tag:04x}")
                    continue
                handler(raw)
        except OperationCancelled:
            # WHY explicit (OperationCancelled is not a PARSE_ERROR): the handler
            # below turns a failure into a counted parse error and returns normally,
            # so a cancellation swallowed there would look like a successfully
            # parsed file and the pipeline would carry straight on to the next one.
            log.info(f"{self.rel}  parse cancelled after {self.n_entries} entries")
            raise
        except PARSE_ERRORS as exc:
            self.n_errors += 1
            log.error(f"{self.rel}  fatal error after {self.n_entries} entries: {exc}")

        log.info(f"  {str(self.rel):<45}  chunks={self.n_chunks:<3}  chunksets={self.n_chunksets:<3}  "
                 f"entries={self.n_entries:<6}  oversize_hits={self.n_oversize_hits:<3}  "
                 f"statedump={self.n_dumps['statedump']:<3}  simpledump={self.n_dumps['simpledump']:<3}  "
                 f"errors={self.n_errors}")
        return FileParseStats(
            boot_uuid=self.boot_uuid, ios_model=self.ios_model, ios_build=self.ios_build,
            entries=self.n_entries, errors=self.n_errors,
            chunksets=self.n_chunksets_seen, chunksets_decoded=self.n_chunksets_decoded,
            observations=self.watch.rows(),
        )

    # ── top-level chunks ─────────────────────────────────────────────────────

    def _on_header(self, raw: RawChunk) -> None:
        try:
            hdr = parse_header_chunk(reader_from_bytes(raw.data))
        except PARSE_ERRORS as exc:
            self.n_errors += 1
            log.warning(f"{self.rel}  header parse error: {exc}")
            return
        self.boot_uuid = hdr.boot_uuid
        self.ios_model = hdr.hardware_model_string.rstrip("\x00")
        self.ios_build = hdr.build_version_string.rstrip("\x00")
        log.debug(
            "%s  header → boot_uuid=%s  model=%s  build=%s  timebase=%d/%d",
            self.rel, self.boot_uuid, self.ios_model, self.ios_build,
            hdr.mach_time_numerator, hdr.mach_time_denominator,
        )

    def _on_catalog(self, raw: RawChunk) -> None:
        try:
            catalog = parse_catalog_chunk(raw.data)
        except PARSE_ERRORS as exc:
            self.n_errors += 1
            log.warning(f"{self.rel}  catalog parse error: {exc}")
            # WHY reset: the chunksets that follow belong to THIS catalog. Keeping
            # the previous one would decode them against another catalog's
            # process/subsystem table — wrong attribution, silently.
            self.catalog = None
            return
        self.catalog = catalog
        for note in catalog.observations:
            self.watch.note(format_watch.CATALOG_DRIFT, note)
        log.debug(
            "%s  catalog → %d process entries  %d UUIDs  %d sub-chunks",
            self.rel, catalog.number_process_information_entries,
            len(catalog.catalog_uuids), catalog.number_sub_chunks,
        )

    def _on_chunkset(self, raw: RawChunk) -> None:
        self.n_chunksets_seen += 1
        if self.catalog is None:
            # No usable catalog (none yet, or its parse failed): the entries cannot
            # be attributed, so the chunkset is lost — count it. (log show drops it
            # silently; decoding it would give rows with no message and no process.)
            self.n_errors += 1
            log.warning(f"{self.rel}  chunkset at offset 0x{raw.file_offset:x} has no usable catalog — skipped")
            return
        self.n_chunksets += 1
        try:
            self.watch.note(format_watch.CODEC, codec_for(raw.data).name)
            decompressed = decompress_chunkset(raw.data)
        except PARSE_ERRORS as exc:
            self.n_errors += 1
            log.warning(f"{self.rel}  chunkset #{self.n_chunksets} not decoded (offset=0x{raw.file_offset:x}): {exc}")
            return
        self.n_chunksets_decoded += 1
        log.debug("%s  chunkset #%d  compressed=%d B → decompressed=%d B",
                  self.rel, self.n_chunksets, raw.data_size, len(decompressed))
        sub_handlers = {
            CHUNK_TAG_FIREHOSE: self._on_firehose,
            CHUNK_TAG_STATEDUMP: self._on_statedump,
            CHUNK_TAG_SIMPLEDUMP: self._on_simpledump,
            CHUNK_TAG_OVERSIZE: _skip,              # read in pass 1 (oversize_pass)
        }
        self.n_sub = 0
        for sub in iter_subchunks(decompressed):
            handler = sub_handlers.get(sub.chunk_tag)
            if handler is None:
                self.watch.note(format_watch.SUBCHUNK_TAG, f"0x{sub.chunk_tag:04x}")
                continue
            handler(raw, sub)
        log.debug("%s  chunkset #%d done  firehose_blocks=%d", self.rel, self.n_chunksets, self.n_sub)

    # ── sub-chunks ───────────────────────────────────────────────────────────

    def _on_statedump(self, raw: RawChunk, sub: SubChunkRef) -> None:
        self._on_dump(raw, sub, "statedump", parse_statedump, statedump_to_log_entry)

    def _on_simpledump(self, raw: RawChunk, sub: SubChunkRef) -> None:
        self._on_dump(raw, sub, "simpledump", parse_simpledump, simpledump_to_log_entry)

    def _on_dump(self, raw: RawChunk, sub: SubChunkRef, kind: str, parse, to_entry) -> None:  # type: ignore[no-untyped-def]
        """Statedump / Simpledump: non-firehose records ``log show`` prints as
        ordinary lines. No firehose preamble: the timestamp is resolved directly
        and the boot UUID comes from this file's header."""
        tsf_id = self.boot_to_timesync.get(self.boot_uuid)
        # Build inside the guard (a malformed record is a *parse* error to skip);
        # emit OUTSIDE it so a storage failure is never miscounted as a parse error.
        try:
            record = parse(sub.data)
            entry = (
                to_entry(
                    record, self.catalog, self.timesync_data, self.boot_uuid,
                    self.file_id, tsf_id, self.anchor_id_map,
                    chunkset_file_offset=raw.file_offset,
                    firehose_inner_offset=sub.source_offset,
                )
                if record is not None else None
            )
        except PARSE_ERRORS as exc:
            self.n_errors += 1
            log.debug("%s  %s parse error: %s", self.rel, kind, exc)
            return
        if entry is None:
            self.n_errors += 1
            return
        self.emit(entry)
        self.n_dumps[kind] += 1
        self.n_entries += 1

    def _on_firehose(self, raw: RawChunk, sub: SubChunkRef) -> None:
        self.n_sub += 1
        self.n_firehose_blocks += 1
        try:
            preamble = parse_firehose_preamble(sub.data)
        except PARSE_ERRORS as exc:
            self.n_errors += 1
            log.debug("%s  chunkset #%d  firehose block #%d  preamble error: %s",
                      self.rel, self.n_chunksets, self.n_sub, exc)
            return
        log.debug(
            "%s  firehose block proc=%d_%d  base_time=%d  %d entries  priv_offset=0x%x",
            self.rel, preamble.first_number_proc_id, preamble.second_number_proc_id,
            preamble.base_continuous_time, len(preamble.public_data),
            preamble.private_data_virtual_offset,
        )
        # The per-entry loop runs millions of times: bind what it reads to locals.
        timesync_file_id = self.boot_to_timesync.get(self.boot_uuid)
        catalog, strings, oversize_cache = self.catalog, self.strings, self.oversize_cache
        emit, watch, keep_raw = self.emit, self.watch, self.keep_raw
        proc_ids = (preamble.first_number_proc_id, preamble.second_number_proc_id)
        for entry in preamble.public_data:
            unknown_bits = entry.flags & ~KNOWN_FLAG_BITS
            if unknown_bits:
                watch.note(format_watch.FIREHOSE_FLAG, f"0x{unknown_bits:04x}")
            # Assemble inside the guard (a malformed entry is a *parse* error to
            # skip); emit OUTSIDE it so a storage failure is never miscounted.
            try:
                if entry.unknown_log_activity_type == ACTIVITY_TYPE_NON_ACTIVITY:
                    ref = entry.firehose_non_activity.data_ref_value
                    if ref and (*proc_ids, ref) in oversize_cache:
                        self.n_oversize_hits += 1
                log_entry = firehose_to_log_entry(
                    entry, preamble, catalog, strings, oversize_cache,
                    self.timesync_data, self.boot_uuid, self.file_id,
                    timesync_file_id, self.anchor_id_map,
                    chunkset_file_offset=raw.file_offset,
                    firehose_inner_offset=sub.source_offset,
                    keep_raw=keep_raw,
                )
            except PARSE_ERRORS as exc:
                self.n_errors += 1
                log.debug("%s  entry assembly error (type=0x%02x): %s",
                          self.rel, entry.unknown_log_activity_type, exc)
                continue
            if log_entry is not None:
                emit(log_entry)
                self.n_entries += 1


def _skip(raw: RawChunk, sub: SubChunkRef) -> None:
    """A sub-chunk this pass deliberately ignores."""
