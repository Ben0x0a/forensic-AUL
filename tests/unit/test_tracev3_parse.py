"""Unit tests for the single-file tracev3 parse loop.

Covers : forensic_aul/ops/extraction/tracev3_parse.py (process_tracev3) and the
         matching catalog handling in forensic_aul/ops/extraction/oversize_pass.py.
Uses    : monkeypatched chunk iterator / catalog parser / decompressor, so the
          loop's control flow is tested without crafting real tracev3 bytes.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from forensic_aul.engine.parser.format import (
    CHUNK_TAG_CATALOG,
    CHUNK_TAG_CHUNKSET,
)
from forensic_aul.engine.parser.tracev3 import RawChunk
from forensic_aul.ops.extraction import oversize_pass, tracev3_parse


def _chunk(tag: int, offset: int) -> RawChunk:
    return RawChunk(tag=tag, sub_tag=0, data_size=0, data=b"", file_offset=offset)


# catalog A (parses) → chunkset 1 → catalog B (fails) → chunkset 2
_STREAM = [
    _chunk(CHUNK_TAG_CATALOG, 0x00),
    _chunk(CHUNK_TAG_CHUNKSET, 0x10),
    _chunk(CHUNK_TAG_CATALOG, 0x20),
    _chunk(CHUNK_TAG_CHUNKSET, 0x30),
]


def _patch_stream(monkeypatch, module) -> list[int]:
    """Feed *module* the stream above; return the offsets it decompressed."""
    # Just the attributes the loop reads when it logs a parsed catalog.
    catalog_a = SimpleNamespace(
        number_process_information_entries=0, catalog_uuids=[], number_sub_chunks=1,
    )
    outcomes = iter([catalog_a, ValueError("bad catalog B")])

    def fake_parse_catalog(_data):
        outcome = next(outcomes)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    decompressed: list[int] = []

    def fake_decompress(data):
        decompressed.append(current["offset"])
        return None                      # stop there: only the decision is under test

    current = {"offset": None}

    def fake_iter_chunks(_path):
        for raw in _STREAM:
            current["offset"] = raw.file_offset
            yield raw

    monkeypatch.setattr(module, "iter_chunks", fake_iter_chunks)
    monkeypatch.setattr(module, "parse_catalog_chunk", fake_parse_catalog)
    monkeypatch.setattr(module, "decompress_chunkset", fake_decompress)
    return decompressed


def test_chunkset_after_a_failed_catalog_is_not_decoded_with_the_previous_one(tmp_path, monkeypatch):
    decompressed = _patch_stream(monkeypatch, tracev3_parse)
    path = tmp_path / "Persist" / "0000000000000001.tracev3"

    _boot, _model, _build, written, errors = tracev3_parse.process_tracev3(
        path, tmp_path, strings=None, oversize_cache={}, timesync_data={},
        boot_uuid_to_timesync_file_id={}, tracev3_file_id=1, anchor_id_map={},
        emit=lambda _entry: None, keep_raw=False,
    )

    assert decompressed == [0x10], "chunkset 2 belongs to the failed catalog B"
    assert written == 0
    # chunkset 1 decompression failure + catalog B failure + chunkset 2 skipped
    assert errors == 3


def test_oversize_pass_does_not_reuse_the_previous_catalog(tmp_path, monkeypatch):
    decompressed = _patch_stream(monkeypatch, oversize_pass)

    oversize_pass.collect_oversize([Path(tmp_path / "f.tracev3")], strings=None)

    assert decompressed == [0x10]
