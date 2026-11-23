"""Unit tests for the LZBITMAP decoder — forensic_aul/engine/parser/lzbitmap.py.

Covers : decoding a stream encoded by Apple's libcompression (flags 0x09, the
         run-length variant), the same stream converted to the non-run-length
         variant iOS 27 writes (flags 0x0C), the bytes-used result, the size cap,
         and the typed errors on bad input; on macOS, a round trip through
         libcompression on fresh inputs.
Uses    : tests/parser/lzbitmap_fixture.py (synthetic plaintext + its committed
          ZBM stream) and, on macOS only, /usr/lib/libcompression.dylib.
"""

from __future__ import annotations

import ctypes
import random
import sys

import pytest

from forensic_aul.engine.parser import lzbitmap
from forensic_aul.errors import CorruptRecord, TruncatedRecord, UnsupportedFormat
from tests.parser.lzbitmap_fixture import FIXTURE_PATH, fixture_plaintext

_BIG = 1 << 24


def _u24(b: bytes, at: int) -> int:
    return int.from_bytes(b[at:at + 3], "little")


def _to_no_run_length(stream: bytes) -> bytes:
    """Rewrite a 0x09 stream as the equivalent non-run-length one, 0x0D.

    0x0D is 0x0C (what iOS 27 writes) with the large-block bit Apple's encoder
    sets: the same no-run-length decoding path, larger blocks allowed.

    Expands every repeat count into that many copies of its token, re-packs the
    token nibbles, adds the 13th (unused) table entry, and fixes the block sizes.
    The literal, distance and bitmap regions are unchanged.
    """
    assert stream[:4] == b"ZBM\x09"
    out = bytearray(b"ZBM\x0d")
    pos = 4
    while True:
        csize, dsize = _u24(stream, pos), _u24(stream, pos + 3)
        if dsize == 0 or csize == dsize + 6:
            out += stream[pos:pos + (6 if dsize == 0 else csize)]
            if dsize == 0:
                return bytes(out)
            pos += csize
            continue
        block = stream[pos:pos + csize]
        token_at, table_at = _u24(block, 12), csize - 17
        nibbles = [n for b in block[token_at:table_at] for n in (b & 0xF, b >> 4)]
        expanded, i, groups = [], 0, -(-dsize // 8)
        while len(expanded) < groups:
            index = nibbles[i]
            i += 1
            repeat = 1
            if (groups - len(expanded)) * 8 > 8 and nibbles[i] == 0xF:   # same rule as the decoder
                i += 1
                repeat, nibble = 4, 0xF
                while nibble == 0xF:
                    nibble = nibbles[i]
                    i += 1
                    repeat += nibble
            expanded += [index] * repeat
        if len(expanded) % 2:
            expanded.append(0)
        tokens = bytes(expanded[k] | expanded[k + 1] << 4 for k in range(0, len(expanded), 2))
        body = block[6:token_at] + tokens + block[table_at:]
        out += (len(body) + 6).to_bytes(3, "little") + dsize.to_bytes(3, "little") + body
        pos += csize


def test_decodes_an_apple_encoded_stream():
    stream = FIXTURE_PATH.read_bytes()
    data, used = lzbitmap.decompress(stream, max_size=_BIG)
    assert data == fixture_plaintext()
    assert used == len(stream), "the stream ends at its end-of-stream marker"


def test_decodes_the_non_run_length_variant_ios_27_writes():
    stream = _to_no_run_length(FIXTURE_PATH.read_bytes())
    assert stream[3] & 0x04, "no-run-length bit set"
    data, _ = lzbitmap.decompress(stream, max_size=_BIG)
    assert data == fixture_plaintext()


def test_reports_the_bytes_it_used_so_the_caller_can_read_on():
    stream = FIXTURE_PATH.read_bytes() + b"\x06\x00\x00\x00"
    _, used = lzbitmap.decompress(stream, max_size=_BIG)
    assert stream[used:] == b"\x06\x00\x00\x00"


@pytest.mark.parametrize("stream, error", [
    (b"bv41....", UnsupportedFormat),
    (b"ZBM\x07" + b"\x00" * 6, UnsupportedFormat),
    (b"ZBM\x09\x10\x00", TruncatedRecord),
])
def test_bad_streams_raise_typed_errors(stream, error):
    with pytest.raises(error):
        lzbitmap.decompress(stream, max_size=_BIG)


def test_the_output_cap_is_enforced():
    with pytest.raises(CorruptRecord, match="exceed"):
        lzbitmap.decompress(FIXTURE_PATH.read_bytes(), max_size=1000)


def test_a_damaged_block_is_refused_not_misdecoded():
    stream = bytearray(FIXTURE_PATH.read_bytes())
    stream[4 + 9:4 + 12] = (0).to_bytes(3, "little")    # bitmap offset before the distances
    with pytest.raises(CorruptRecord):
        lzbitmap.decompress(bytes(stream), max_size=_BIG)


@pytest.mark.skipif(sys.platform != "darwin", reason="libcompression is macOS-only")
def test_round_trip_through_libcompression_on_fresh_inputs():
    lib = ctypes.CDLL("/usr/lib/libcompression.dylib")
    lib.compression_encode_buffer.restype = ctypes.c_size_t
    rng = random.Random(1)
    for size in (1, 7, 8, 9, 4096, 70_000):
        data = bytes(rng.choice(b"ab\x00\xff log line ") for _ in range(size))
        dst = ctypes.create_string_buffer(size * 2 + 1024)
        n = lib.compression_encode_buffer(dst, len(dst), data, size, None, 0x702)
        stream = dst.raw[:n]
        assert lzbitmap.decompress(stream, max_size=_BIG)[0] == data, size
        assert lzbitmap.decompress(_to_no_run_length(stream), max_size=_BIG)[0] == data, size
