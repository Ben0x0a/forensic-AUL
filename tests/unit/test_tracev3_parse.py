"""Unit tests for the single-file tracev3 parse loop.

Covers : forensic_aul/ops/extraction/tracev3_parse.py (process_tracev3) and the
         matching catalog handling in forensic_aul/ops/extraction/oversize_pass.py.
Uses    : monkeypatched chunk iterator / catalog parser / decompressor, so the
          loop's control flow is tested without crafting real tracev3 bytes.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from forensic_aul.errors import CorruptRecord
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
        observations=[],
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
        # Stop there: only the decision is under test.
        raise CorruptRecord("not decoded")

    current = {"offset": None}

    def fake_iter_chunks(_path):
        for raw in _STREAM:
            current["offset"] = raw.file_offset
            yield raw

    monkeypatch.setattr(module, "iter_chunks", fake_iter_chunks)
    monkeypatch.setattr(module, "parse_catalog_chunk", fake_parse_catalog)
    monkeypatch.setattr(module, "decompress_chunkset", fake_decompress)
    if hasattr(module, "codec_for"):          # the format watch's codec note
        monkeypatch.setattr(module, "codec_for", lambda _data: SimpleNamespace(name="fake"))
    return decompressed


def test_chunkset_after_a_failed_catalog_is_not_decoded_with_the_previous_one(tmp_path, monkeypatch):
    decompressed = _patch_stream(monkeypatch, tracev3_parse)
    path = tmp_path / "Persist" / "0000000000000001.tracev3"

    stats = tracev3_parse.process_tracev3(
        path, tmp_path, strings=None, oversize_cache={}, timesync_data={},
        boot_uuid_to_timesync_file_id={}, tracev3_file_id=1, anchor_id_map={},
        emit=lambda _entry: None, keep_raw=False,
    )

    assert decompressed == [0x10], "chunkset 2 belongs to the failed catalog B"
    assert stats.entries == 0
    # chunkset 1 decompression failure + catalog B failure + chunkset 2 skipped
    assert stats.errors == 3
    # Both chunksets are counted, neither decoded: the file is undecodable.
    assert (stats.chunksets, stats.chunksets_decoded) == (2, 0)


def test_oversize_pass_does_not_reuse_the_previous_catalog(tmp_path, monkeypatch):
    decompressed = _patch_stream(monkeypatch, oversize_pass)

    oversize_pass.collect_oversize([Path(tmp_path / "f.tracev3")])

    assert decompressed == [0x10]


# ── what a parse loop may swallow ──────────────────────────────────────────────

def _run_with_catalog_raising(tmp_path, monkeypatch, exc: BaseException):
    monkeypatch.setattr(tracev3_parse, "iter_chunks", lambda _p: iter([_chunk(CHUNK_TAG_CATALOG, 0)]))

    def boom(_data):
        raise exc

    monkeypatch.setattr(tracev3_parse, "parse_catalog_chunk", boom)
    return tracev3_parse.process_tracev3(
        tmp_path / "x.tracev3", tmp_path, strings=None, oversize_cache={}, timesync_data={},
        boot_uuid_to_timesync_file_id={}, tracev3_file_id=1, anchor_id_map={},
        emit=lambda _entry: None, keep_raw=False,
    )


def test_bad_bytes_are_counted_as_parse_errors(tmp_path, monkeypatch):
    stats = _run_with_catalog_raising(tmp_path, monkeypatch, CorruptRecord("offset out of bounds"))
    assert stats.errors == 1


def test_a_bug_is_not_disguised_as_damage_in_the_evidence(tmp_path, monkeypatch):
    """S8: an AttributeError is this tool's bug — it must propagate (to the crash
    reporter), not be counted as a parse error in the evidence."""
    with pytest.raises(AttributeError):
        _run_with_catalog_raising(tmp_path, monkeypatch, AttributeError("no such field"))


def test_unknown_chunk_tags_are_recorded_by_the_format_watch(tmp_path, monkeypatch):
    monkeypatch.setattr(tracev3_parse, "iter_chunks", lambda _p: iter([_chunk(0x7777, 0)]))
    stats = tracev3_parse.process_tracev3(
        tmp_path / "x.tracev3", tmp_path, strings=None, oversize_cache={}, timesync_data={},
        boot_uuid_to_timesync_file_id={}, tracev3_file_id=1, anchor_id_map={},
        emit=lambda _entry: None, keep_raw=False,
    )
    assert stats.observations == (("chunk_tag", "0x7777", 1),)
