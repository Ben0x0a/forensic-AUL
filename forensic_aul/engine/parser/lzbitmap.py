"""LZBITMAP decompression — the codec of iOS 27 / macOS 27 log chunksets.

Defines : ``decompress`` (one ``ZBM`` stream → bytes, plus how many input bytes
          it used) and ``ZBM_MAGIC``.
Used by : forensic_aul.engine.parser.chunkset (the decompressor registry).
Uses    : forensic_aul.errors (UnsupportedFormat / CorruptRecord / TruncatedRecord)
          and the standard library only.

Attribution: a port of ``lzbitmap.rs`` from mandiant/macos-UnifiedLogs v0.7.0,
itself based on ``dissect/util/compression/lzbitmap.py`` (Fox-IT dissect.util);
both Apache License 2.0 — see THIRD_PARTY_NOTICES.md. It follows the Rust version
because iOS 27 writes the non-run-length variant (flags 0x0C), which the Python
original does not decode. Verified byte-for-byte against Apple's libcompression
(COMPRESSION_LZBITMAP) — see tests/parser/test_lzbitmap.py.

Stream layout (little-endian):

    "ZBM" + flags(u8)
    repeated blocks:  compressed_size(u24) decompressed_size(u24) …
        compressed_size == decompressed_size + 6  → the block is stored raw
        decompressed_size == 0                    → end of stream
        otherwise a coded block: distance_offset(u24) bitmap_offset(u24)
        token_offset(u24), literals from byte 15, then the distance, bitmap and
        token regions, and a 17-byte table of 10-bit (bitmap, distance-size)
        entries at the very end.

Decoding a coded block: each token (a nibble) selects an entry of the table: an
8-bit bitmap (or, for entries 0-2, the next byte of the bitmap region) and how
many bytes of a new match distance to read (0 = keep the previous distance).
Each bitmap bit then yields one output byte: 1 = the next literal, 0 = a copy
from ``distance`` bytes back in the output.
"""

from __future__ import annotations

from forensic_aul.errors import CorruptRecord, TruncatedRecord, UnsupportedFormat

ZBM_MAGIC = b"ZBM"

# flags: bit 0 = large blocks (32 KiB instead of 16 KiB), bit 2 = tokens are NOT
# run-length encoded. 0x09 and 0x0C are seen in the wild; 0x08 / 0x0D are the
# other two valid combinations (accepted, as upstream does).
_FLAG_LARGE = 0x01
_FLAG_NO_RUN_LENGTH = 0x04
_KNOWN_FLAGS = frozenset({0x08, 0x09, 0x0C, 0x0D})

_BLOCK_HEADER = 6       # compressed_size(u24) + decompressed_size(u24)
_CODED_HEADER = 15      # + distance/bitmap/token offsets (3 × u24)
_TABLE_SIZE = 17        # the 10-bit bitmap/distance table at the end of a block
_REPEAT_TOKEN = 0xF     # run-length marker (run-length variant only)


def _u24(data: bytes, at: int) -> int:
    return data[at] | data[at + 1] << 8 | data[at + 2] << 16


def _runs(bitmap: int) -> tuple[tuple[bool, int], ...]:
    """The 8 bits of *bitmap*, low bit first, as (is_literal, length) runs."""
    runs: list[tuple[bool, int]] = []
    for bit in range(8):
        literal = bool(bitmap >> bit & 1)
        if runs and runs[-1][0] == literal:
            runs[-1] = (literal, runs[-1][1] + 1)
        else:
            runs.append((literal, 1))
    return tuple(runs)


# WHY precomputed runs: emitting byte by byte costs one Python step per output
# byte (seconds per MiB); a run of literals or of copied bytes is one slice.
_RUNS = tuple(_runs(b) for b in range(256))


def decompress(src: bytes, *, max_size: int) -> tuple[bytes, int]:
    """Decode the ``ZBM`` stream at the start of *src*.

    Returns ``(data, used)``: the decompressed bytes and how many bytes of *src*
    the stream occupied (through its end-of-stream marker), so the caller can read
    what follows. *max_size* bounds the output — a crafted stream cannot make the
    decoder allocate more.

    Raises:
        UnsupportedFormat: not a ZBM stream, or a flags value never seen.
        CorruptRecord: a size, offset, token or distance that does not fit.
        TruncatedRecord: *src* ends inside the stream.
    """
    if len(src) < 4 or src[:3] != ZBM_MAGIC:
        raise UnsupportedFormat("not an LZBITMAP stream (no ZBM magic)")
    flags = src[3]
    if flags not in _KNOWN_FLAGS:
        raise UnsupportedFormat(f"LZBITMAP flags 0x{flags:02x} not supported")
    max_block = 0x8000 if flags & _FLAG_LARGE else 0x4000
    run_length = not flags & _FLAG_NO_RUN_LENGTH
    table_entries = 12 if run_length else 13

    out = bytearray()
    pos = 4
    while True:
        if pos + _BLOCK_HEADER > len(src):
            raise TruncatedRecord(f"LZBITMAP block header at {pos} past the end of the data")
        csize, dsize = _u24(src, pos), _u24(src, pos + 3)
        if dsize == 0:
            return bytes(out), pos + _BLOCK_HEADER          # end-of-stream marker
        if csize > dsize + _BLOCK_HEADER or dsize > max_block:
            raise CorruptRecord(f"LZBITMAP block at {pos}: sizes {csize}/{dsize} do not fit")
        if len(out) + dsize > max_size:
            raise CorruptRecord(f"LZBITMAP output would exceed {max_size} bytes")
        if pos + csize > len(src):
            raise TruncatedRecord(f"LZBITMAP block at {pos} needs {csize} bytes")
        if csize == dsize + _BLOCK_HEADER:                  # stored raw
            out += src[pos + _BLOCK_HEADER:pos + csize]
        else:
            _decode_block(src[pos:pos + csize], dsize, out, table_entries, run_length)
        pos += csize


def _decode_block(
    block: bytes, dsize: int, out: bytearray, table_entries: int, run_length: bool,
) -> None:
    """Append the *dsize* bytes coded in *block* to *out*."""
    csize = len(block)
    if csize < _CODED_HEADER + _TABLE_SIZE:
        raise CorruptRecord(f"LZBITMAP coded block of {csize} bytes is too small")
    distance_at, bitmap_at, token_at = _u24(block, 6), _u24(block, 9), _u24(block, 12)
    table_at = csize - _TABLE_SIZE
    # WHY: the regions must follow each other in this order inside the block;
    # anything else would make the reads below wander into the wrong region.
    if not _CODED_HEADER <= distance_at <= bitmap_at <= token_at <= table_at:
        raise CorruptRecord("LZBITMAP region offsets out of order")

    bits = int.from_bytes(block[table_at:], "little")
    # Entries 0-2: bitmap from the bitmap region, read 0 / 1 / 2 distance bytes.
    table: list[tuple[int, int]] = [(-1, 0), (-1, 1), (-1, 2)]
    for i in range(table_entries):
        value = bits >> (i * 10)
        table.append((value & 0xFF, value >> 8 & 3))

    tokens = [n for b in block[token_at:table_at] for n in (b & 0xF, b >> 4)]
    n_tokens = len(tokens)
    literal_at, ti, distance = _CODED_HEADER, 0, 8   # distance persists across tokens

    while dsize > 0:
        if ti >= n_tokens:
            raise CorruptRecord("LZBITMAP ran out of tokens")
        index = tokens[ti]
        ti += 1
        repeat = 1
        if run_length:
            if index == _REPEAT_TOKEN:
                raise CorruptRecord("LZBITMAP repeat marker where a token was expected")
            # A following 0xF nibble introduces a repeat count (4 + the sum of the
            # nibbles up to the first one that is not 0xF). Not looked for in the
            # last group of the block, which may have no token after it.
            if dsize > 8:
                if ti >= n_tokens:
                    raise CorruptRecord("LZBITMAP ran out of tokens")
                if tokens[ti] == _REPEAT_TOKEN:
                    ti += 1
                    repeat, nibble = 4, _REPEAT_TOKEN
                    while nibble == _REPEAT_TOKEN:
                        if ti >= n_tokens:
                            raise CorruptRecord("LZBITMAP repeat count runs past the tokens")
                        nibble = tokens[ti]
                        ti += 1
                        repeat += nibble
        if index >= len(table):
            raise CorruptRecord(f"LZBITMAP token {index} has no table entry")

        for _ in range(repeat):
            bitmap, distance_bytes = table[index]
            if bitmap < 0:
                if bitmap_at >= table_at:
                    raise CorruptRecord("LZBITMAP bitmap region exhausted")
                bitmap = block[bitmap_at]
                bitmap_at += 1
            if distance_bytes == 1:
                distance = block[distance_at]
                distance_at += 1
            elif distance_bytes == 2:
                distance = block[distance_at] | block[distance_at + 1] << 8
                distance_at += 2
            elif distance_bytes == 3:
                raise CorruptRecord("LZBITMAP distance size 3 is invalid")

            if dsize >= 8:
                for literal, length in _RUNS[bitmap]:
                    literal_at = _emit(block, out, literal, length, literal_at, distance)
                dsize -= 8
            else:                                   # the block's last, partial group
                for bit in range(dsize):
                    literal_at = _emit(block, out, bool(bitmap >> bit & 1), 1, literal_at, distance)
                dsize = 0
            if dsize == 0:
                break


def _emit(block: bytes, out: bytearray, literal: bool, length: int, literal_at: int, distance: int) -> int:
    """Append *length* literal or copied bytes to *out*; return the new literal offset."""
    if literal:
        end = literal_at + length
        if end > len(block):
            raise CorruptRecord("LZBITMAP literals run past the block")
        out += block[literal_at:end]
        return end
    if distance == 0 or distance > len(out):
        raise CorruptRecord(f"LZBITMAP match distance {distance} outside the output")
    start = len(out) - distance
    if distance >= length:
        out += out[start:start + length]
    else:                                           # overlapping copy: a repeating pattern
        pattern = out[start:]
        out += (pattern * (length // distance + 1))[:length]
    return literal_at
