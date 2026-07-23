"""Oversize entry collection — Pass 1 of the tracev3 parse pipeline.

Defines : OversizeKey, OversizeCache (type aliases), collect_oversize
Used by : forensic_aul.ops.extraction.entry_builder (types),
          forensic_aul.ops.extraction.tracev3_parse (types),
          forensic_aul.ops.extraction.workers (types),
          forensic_aul.ops.extraction.extract (collect_oversize)
Uses    : forensic_aul.engine.models (CatalogChunk, Oversize),
          forensic_aul.engine.parser.catalog, .chunkset, .tracev3 (iterators),
          forensic_aul.engine.parser.string_cache (StringCacheProvider, type only)
"""

from __future__ import annotations

import logging
from pathlib import Path

from forensic_aul.engine.models import CatalogChunk, Oversize
from forensic_aul.engine.parser.catalog import parse_catalog_chunk
from forensic_aul.engine.parser.chunkset import (
    CHUNK_TAG_OVERSIZE,
    decompress_chunkset,
    iter_subchunks,
)
from forensic_aul.engine.parser.string_cache import StringCacheProvider
from forensic_aul.engine.parser.tracev3 import (
    CHUNK_TAG_CATALOG,
    CHUNK_TAG_CHUNKSET,
    iter_chunks,
)

log = logging.getLogger(__name__)

# ── Oversize cache ─────────────────────────────────────────────────────────────

OversizeKey = tuple[int, int, int]  # (first_proc_id, second_proc_id, data_ref_value)
OversizeCache = dict[OversizeKey, Oversize]


def collect_oversize(
    tracev3_files: list[Path],
    strings: StringCacheProvider,
) -> OversizeCache:
    """Pass 1: scan all tracev3 files and collect Oversize sub-chunks."""
    from forensic_aul.engine.parser.oversize import parse_oversize_chunk

    cache: OversizeCache = {}
    for path in tracev3_files:
        catalog: CatalogChunk | None = None
        try:
            for raw in iter_chunks(path):
                if raw.tag == CHUNK_TAG_CATALOG:
                    try:
                        catalog = parse_catalog_chunk(raw.data)
                    except Exception as exc:
                        log.warning(f"oversize pass: bad catalog in {path.name}: {exc}")
                elif raw.tag == CHUNK_TAG_CHUNKSET and catalog is not None:
                    decompressed = decompress_chunkset(raw.data)
                    if decompressed is None:
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
                        except Exception as exc:
                            log.debug("oversize parse error: %s", exc)
        except Exception as exc:
            log.warning(f"oversize pass: error in {path.name}: {exc}")
    log.info(f"oversize pass: found {len(cache)} oversize entries")
    return cache
