"""Tests for forensic_aul.engine.parser.chunkset — LZ4 decompression and subchunk iteration.

Fixtures build minimal valid chunkset payloads by hand so tests run without
any real logarchive file.
"""

import struct
import pytest
import lz4.block as lz4_block

from forensic_aul.engine.parser.chunkset import (
    CHUNK_TAG_CHUNKSET,
    CHUNK_TAG_FIREHOSE,
    CHUNK_TAG_OVERSIZE,
    SIG_BV41_COMPRESSED,
    SIG_BV41_UNCOMPRESSED,
    SIG_BV4_FOOTER,
    CHUNK_PREAMBLE_SIZE,
    decompress_chunkset,
    iter_subchunks,
    SubChunkRef,
)


# ── Binary helpers ─────────────────────────────────────────────────────────────

def _preamble(tag: int, sub_tag: int, data_size: int) -> bytes:
    """Build a 16-byte chunk preamble."""
    return struct.pack("<IIQ", tag, sub_tag, data_size)


def _build_uncompressed_chunkset(payload: bytes) -> bytes:
    """Wrap *payload* in an uncompressed (bv41-) chunkset."""
    inner = struct.pack("<II", SIG_BV41_UNCOMPRESSED, len(payload)) + payload
    inner += struct.pack("<I", SIG_BV4_FOOTER)
    outer_preamble = _preamble(CHUNK_TAG_CHUNKSET, 0, len(inner))
    return outer_preamble + inner


def _build_compressed_chunkset(payload: bytes) -> bytes:
    """Wrap *payload* in a bv41 (LZ4) chunkset."""
    compressed = lz4_block.compress(payload, store_size=False)
    inner = (
        struct.pack("<II", SIG_BV41_COMPRESSED, len(payload))
        + struct.pack("<I", len(compressed))
        + compressed
        + struct.pack("<I", SIG_BV4_FOOTER)
    )
    outer_preamble = _preamble(CHUNK_TAG_CHUNKSET, 0, len(inner))
    return outer_preamble + inner


def _build_subchunk(tag: int, body: bytes = b"") -> bytes:
    """Build a single sub-chunk with the given tag and body."""
    return _preamble(tag, 0, len(body)) + body


# ── Tests for decompress_chunkset ─────────────────────────────────────────────

class TestDecompressChunkset:
    def test_uncompressed_passthrough(self):
        payload = b"hello uncompressed world"
        chunk = _build_uncompressed_chunkset(payload)
        result = decompress_chunkset(chunk)
        assert result == payload

    def test_compressed_round_trip(self):
        payload = b"A" * 1024  # highly compressible
        chunk = _build_compressed_chunkset(payload)
        result = decompress_chunkset(chunk)
        assert result == payload

    def test_invalid_signature_returns_none(self, caplog):
        # Build a chunkset with a garbage signature
        bad_sig = b"\xDE\xAD\xBE\xEF"
        inner = bad_sig + struct.pack("<I", 4) + b"\x00" * 4
        chunk = _preamble(CHUNK_TAG_CHUNKSET, 0, len(inner)) + inner
        result = decompress_chunkset(chunk)
        assert result is None

    def test_empty_uncompressed_payload(self):
        chunk = _build_uncompressed_chunkset(b"")
        result = decompress_chunkset(chunk)
        assert result == b""


# ── Tests for iter_subchunks ───────────────────────────────────────────────────

class TestIterSubchunks:
    def test_single_firehose_subchunk(self):
        body = b"firehose_data"
        sub = _build_subchunk(CHUNK_TAG_FIREHOSE, body)
        chunks = list(iter_subchunks(sub))
        assert len(chunks) == 1
        assert chunks[0].chunk_tag == CHUNK_TAG_FIREHOSE

    def test_multiple_subchunks_in_order(self):
        decompressed = (
            _build_subchunk(CHUNK_TAG_FIREHOSE, b"entry1")
            + _build_subchunk(CHUNK_TAG_OVERSIZE, b"oversize_data")
            + _build_subchunk(CHUNK_TAG_FIREHOSE, b"entry2")
        )
        chunks = list(iter_subchunks(decompressed))
        assert len(chunks) == 3
        assert chunks[0].chunk_tag == CHUNK_TAG_FIREHOSE
        assert chunks[1].chunk_tag == CHUNK_TAG_OVERSIZE
        assert chunks[2].chunk_tag == CHUNK_TAG_FIREHOSE

    def test_subchunk_data_includes_preamble(self):
        body = b"payload"
        sub = _build_subchunk(CHUNK_TAG_FIREHOSE, body)
        chunks = list(iter_subchunks(sub))
        assert len(chunks[0].data) == CHUNK_PREAMBLE_SIZE + len(body)

    def test_subchunk_data_size_field(self):
        body = b"x" * 32
        sub = _build_subchunk(CHUNK_TAG_FIREHOSE, body)
        chunks = list(iter_subchunks(sub))
        assert chunks[0].chunk_data_size == len(body)

    def test_unknown_tag_skipped(self, caplog):
        unknown_tag = 0xDEAD
        sub = _build_subchunk(unknown_tag, b"junk")
        chunks = list(iter_subchunks(sub))
        # Unknown tags are logged and skipped
        assert chunks == []

    def test_zero_padding_skipped(self):
        body = b"data"
        decompressed = b"\x00" * 8 + _build_subchunk(CHUNK_TAG_FIREHOSE, body)
        chunks = list(iter_subchunks(decompressed))
        assert len(chunks) == 1

    def test_source_offset_correct(self):
        padding = b"\x00" * 4
        sub = _build_subchunk(CHUNK_TAG_FIREHOSE, b"abc")
        decompressed = padding + sub
        chunks = list(iter_subchunks(decompressed))
        assert chunks[0].source_offset == 4

    def test_empty_data_yields_nothing(self):
        assert list(iter_subchunks(b"")) == []

    def test_truncated_preamble_yields_nothing(self):
        # Less than 16 bytes — can't even read a preamble
        assert list(iter_subchunks(b"\x01\x00\x60\x00")) == []
