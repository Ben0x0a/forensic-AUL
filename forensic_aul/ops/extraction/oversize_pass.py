"""Oversize entry collection — Pass 1 of the tracev3 parse pipeline.

Defines : OversizeKey, OversizeCache (type aliases), collect_oversize (all files,
          serial or across processes) and scan_oversize (one file)
Used by : forensic_aul.ops.extraction.entry_builder (types),
          forensic_aul.ops.extraction.tracev3_parse (types),
          forensic_aul.ops.extraction.workers (types),
          forensic_aul.ops.extraction.extract (collect_oversize)
Uses    : forensic_aul.engine.models (CatalogChunk, Oversize),
          forensic_aul.engine.parser.catalog, .chunkset, .tracev3 (iterators),
          forensic_aul.engine.utils.parallel (parallel_map, when jobs > 1),
          forensic_aul.engine.utils.cancellation (CancelToken)
"""

from __future__ import annotations

import logging
from pathlib import Path

from forensic_aul.engine.models import CatalogChunk, Oversize
from forensic_aul.engine.parser.catalog import parse_catalog_chunk
from forensic_aul.engine.parser.format import (
    CHUNK_TAG_CATALOG,
    CHUNK_TAG_CHUNKSET,
    CHUNK_TAG_OVERSIZE,
)
from forensic_aul.engine.parser.chunkset import (
    decompress_chunkset,
    iter_subchunks,
)
from forensic_aul.engine.parser.tracev3 import iter_chunks
from forensic_aul.engine.utils.cancellation import NEVER_CANCELLED, CancelToken
from forensic_aul.engine.utils.parallel import parallel_map
from forensic_aul.errors import PARSE_ERRORS, OperationCancelled

log = logging.getLogger(__name__)

# ── Oversize cache ─────────────────────────────────────────────────────────────

OversizeKey = tuple[int, int, int]  # (first_proc_id, second_proc_id, data_ref_value)
OversizeCache = dict[OversizeKey, Oversize]


def collect_oversize(
    tracev3_files: list[Path],
    *,
    jobs: int = 1,
    cancel: CancelToken = NEVER_CANCELLED,
) -> OversizeCache:
    """Pass 1: collect the Oversize sub-chunks of every tracev3 file.

    With *jobs* > 1 the files are scanned across that many processes. The
    per-file results are merged in the order of *tracev3_files* whatever the
    order they finish in, so the cache — and so the database — is identical for
    any *jobs*.

    WHY this pass exists, and why it is parallel rather than merged into pass 2:
    an entry may reference oversize data stored in a LATER chunkset or file, so
    every oversize record must be known before the main parse starts. Merging the
    passes would mean holding every decompressed chunkset in memory between them;
    decompressing twice costs CPU instead, and running this pass on every core
    keeps that cost small even for LZBITMAP (pure Python), where a serial pass
    would become the slowest step of a large iOS 27 archive.

    Raises:
        OperationCancelled: *cancel* was cancelled during the scan.
    """
    if jobs <= 1 or len(tracev3_files) < 2:
        per_file = [scan_oversize(path, cancel=cancel) for path in tracev3_files]
    else:
        per_file = parallel_map(
            _scan_oversize_worker, [str(p) for p in tracev3_files], jobs, cancel=cancel,
        )
    cache: OversizeCache = {}
    for found in per_file:
        cache.update(found)
    log.info(f"oversize pass: found {len(cache)} oversize entries")
    return cache


def _scan_oversize_worker(path: str, cancel: CancelToken) -> OversizeCache:
    """Process-pool entry point (module level, so it pickles under spawn)."""
    return scan_oversize(Path(path), cancel=cancel)


def scan_oversize(path: Path, *, cancel: CancelToken = NEVER_CANCELLED) -> OversizeCache:
    """The Oversize sub-chunks of one tracev3 file, keyed for pass 2.

    *cancel* is checked once per chunk.
    """
    from forensic_aul.engine.parser.oversize import parse_oversize_chunk

    cache: OversizeCache = {}
    cancel.check()
    catalog: CatalogChunk | None = None
    try:
        for raw in iter_chunks(path):
            cancel.check()
            if raw.tag == CHUNK_TAG_CATALOG:
                try:
                    catalog = parse_catalog_chunk(raw.data)
                except PARSE_ERRORS as exc:
                    log.warning(f"oversize pass: bad catalog in {path.name}: {exc}")
                    # Same rule as the main pass: never let the following
                    # chunksets borrow the previous catalog.
                    catalog = None
            elif raw.tag == CHUNK_TAG_CHUNKSET and catalog is not None:
                try:
                    decompressed = decompress_chunkset(raw.data)
                except PARSE_ERRORS as exc:
                    # Counted by the main pass, which decodes the same chunkset.
                    log.debug("oversize pass: chunkset not decoded: %s", exc)
                    continue
                for sub in iter_subchunks(decompressed):
                    if sub.chunk_tag != CHUNK_TAG_OVERSIZE:
                        continue
                    try:
                        ov = parse_oversize_chunk(sub.data)
                        if ov is None:
                            continue
                        key: OversizeKey = (
                            ov.first_proc_id,
                            ov.second_proc_id,
                            ov.data_ref_index,
                        )
                        cache[key] = ov
                    except PARSE_ERRORS as exc:
                        log.debug("oversize parse error: %s", exc)
    except OperationCancelled:
        # WHY re-raised explicitly, ahead of the parse handler: a cancellation is
        # not a malformed-file problem to log and carry on from.
        raise
    except PARSE_ERRORS as exc:
        log.warning(f"oversize pass: error in {path.name}: {exc}")
    return cache
