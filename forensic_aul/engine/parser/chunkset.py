"""Parse Apple Unified Log Chunkset chunks (tag 0x600d).

A chunkset chunk is a compressed (or stored) container holding the actual log
sub-chunks (Firehose, Oversize, Statedump, Simpledump).

Defines : ``decompress_chunkset`` (the decompressor registry: the payload's magic
          selects the codec), ``CODECS`` (that registry), ``iter_subchunks`` and
          ``SubChunkRef``.
Used by : forensic_aul.ops.extraction.tracev3_parse and .oversize_pass.
Uses    : forensic_aul.engine.parser.lzbitmap, the ``lz4`` package,
          forensic_aul.engine.parser.format (tags, signatures),
          forensic_aul.errors (typed format errors), forensic_aul.config (size cap).

WHY a registry keyed by magic: the payload names its own codec (``bv41`` LZ4,
``bv4-`` stored, ``ZBM`` LZBITMAP since iOS 27 / macOS 27, and an archive may mix
them). Adding a codec is one entry here; an unknown magic is an UnsupportedFormat
— counted and reported as "this version cannot read it", never silently dropped.

Binary layout reference: macos-UnifiedLogs/src/chunkset.rs
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Generator

try:
    import lz4.block as lz4_block
    _HAS_LZ4 = True
except ImportError:
    _HAS_LZ4 = False

from forensic_aul.config import MAX_CHUNKSET_DECOMPRESSED_SIZE
from forensic_aul.engine.parser import lzbitmap
from forensic_aul.engine.parser.format import (
    CHUNK_PREAMBLE_SIZE,
    SIG_BV4_FOOTER,
    SIG_BV41_COMPRESSED,
    SIG_BV41_UNCOMPRESSED,
)
from forensic_aul.errors import CorruptRecord, TruncatedRecord, UnsupportedFormat

log = logging.getLogger(__name__)

# LZ4 block compression cannot expand data by more than ~255x; a claimed
# uncompressed size beyond (compressed_size * this) is implausible → corrupt/crafted.
_LZ4_MAX_RATIO: int = 255


@dataclass
class SubChunkRef:
    """A reference to a raw sub-chunk payload within a decompressed chunkset."""
    chunk_tag: int
    chunk_sub_tag: int
    chunk_data_size: int
    data: bytes            # full bytes including the 16-byte preamble
    source_offset: int     # byte offset of this sub-chunk in the decompressed data


@dataclass(frozen=True)
class Codec:
    """One chunkset codec: the magic its payload starts with, and its decoder.

    ``decode`` takes the payload (after the 16-byte chunk preamble) and returns
    the decompressed bytes, raising the typed format errors on bad input.
    """

    name: str
    magic: bytes
    decode: Callable[[bytes], bytes]


def _u32(data: bytes, at: int) -> int:
    if at + 4 > len(data):
        raise TruncatedRecord(f"chunkset: 4 bytes needed at {at}, {len(data) - at} left")
    return int.from_bytes(data[at:at + 4], "little")


def _check_size(claimed: int) -> None:
    # Refuse an implausible size before anything is allocated: a larger value
    # means a corrupt or crafted tracev3 — drop this chunkset, keep the rest.
    if claimed > MAX_CHUNKSET_DECOMPRESSED_SIZE:
        raise CorruptRecord(f"chunkset: claimed decompressed size {claimed} exceeds the "
                            f"{MAX_CHUNKSET_DECOMPRESSED_SIZE}-byte safety cap")


def _footer(payload: bytes, at: int) -> None:
    """The trailing ``bv4$`` footer: logged if absent or wrong, never fatal — the
    data before it has already been read out successfully."""
    if at + 4 > len(payload):
        log.debug("chunkset: footer truncated (no trailing bv4$)")
        return
    footer = _u32(payload, at)
    if footer != SIG_BV4_FOOTER:
        log.warning(f"chunkset: unexpected footer 0x{footer:08x} (expected bv4$=0x{SIG_BV4_FOOTER:08x})")


def _decode_stored(payload: bytes) -> bytes:
    """``bv4-``: stored uncompressed (observed in Special/)."""
    size = _u32(payload, 4)
    _check_size(size)
    if 8 + size > len(payload):
        raise TruncatedRecord(f"chunkset: stored payload of {size} bytes is truncated")
    _footer(payload, 8 + size)
    return payload[8:8 + size]


def _decode_lz4(payload: bytes) -> bytes:
    """``bv41``: one LZ4 block."""
    if not _HAS_LZ4:
        raise RuntimeError("lz4 library not installed. Run: pip install lz4")
    size, block_size = _u32(payload, 4), _u32(payload, 8)
    _check_size(size)
    if size > block_size * _LZ4_MAX_RATIO + CHUNK_PREAMBLE_SIZE:
        raise CorruptRecord(f"chunkset: claimed size {size} implausible for {block_size} "
                            f"compressed bytes (>{_LZ4_MAX_RATIO}x)")
    if 12 + block_size > len(payload):
        raise TruncatedRecord(f"chunkset: LZ4 block of {block_size} bytes is truncated")
    try:
        data = lz4_block.decompress(payload[12:12 + block_size], uncompressed_size=size)
    except lz4_block.LZ4BlockError as exc:
        raise CorruptRecord(f"LZ4 decompression failed: {exc}") from exc
    if len(data) != size:
        raise CorruptRecord(f"chunkset: decompressed {len(data)} bytes, expected {size}")
    _footer(payload, 12 + block_size)
    return data


def _decode_lzbitmap(payload: bytes) -> bytes:
    """``ZBM``: an LZBITMAP stream (iOS 27 / macOS 27); it ends at its own
    end-of-stream marker, which is the "footer" upstream reads."""
    data, _used = lzbitmap.decompress(payload, max_size=MAX_CHUNKSET_DECOMPRESSED_SIZE)
    return data


# The registry. Order matters only if one magic were a prefix of another.
CODECS: tuple[Codec, ...] = (
    Codec("lz4", SIG_BV41_COMPRESSED.to_bytes(4, "little"), _decode_lz4),
    Codec("stored", SIG_BV41_UNCOMPRESSED.to_bytes(4, "little"), _decode_stored),
    Codec("lzbitmap", lzbitmap.ZBM_MAGIC, _decode_lzbitmap),
)


def codec_for(chunk_data: bytes) -> Codec:
    """The codec a raw chunkset (preamble included) declares by its magic."""
    payload = chunk_data[CHUNK_PREAMBLE_SIZE:]
    for codec in CODECS:
        if payload.startswith(codec.magic):
            return codec
    raise UnsupportedFormat(f"chunkset: unknown compression magic {payload[:4].hex()}")


def decompress_chunkset(chunk_data: bytes) -> bytes:
    """Decompress (or pass through) a raw chunkset; *chunk_data* includes the
    16-byte outer preamble.

    Raises:
        UnsupportedFormat: an unknown codec magic.
        CorruptRecord / TruncatedRecord: the payload does not decode.
    """
    return codec_for(chunk_data).decode(chunk_data[CHUNK_PREAMBLE_SIZE:])


def iter_subchunks(decompressed: bytes) -> Generator[SubChunkRef, None, None]:
    """Iterate over sub-chunks in decompressed chunkset data.

    Yields one SubChunkRef per sub-chunk, known or not: the caller decides what to
    parse and records an unknown tag (the format watch). Zero-padding between
    chunks is consumed.
    """
    pos = 0
    total = len(decompressed)

    while pos < total:
        # Skip zero padding
        while pos < total and decompressed[pos] == 0:
            pos += 1

        if pos + CHUNK_PREAMBLE_SIZE > total:
            break

        chunk_tag = int.from_bytes(decompressed[pos:pos+4], "little")
        chunk_sub_tag = int.from_bytes(decompressed[pos+4:pos+8], "little")
        chunk_data_size = int.from_bytes(decompressed[pos+8:pos+16], "little")

        total_chunk_size = CHUNK_PREAMBLE_SIZE + chunk_data_size

        if pos + total_chunk_size > total:
            log.warning(f"Subchunk at 0x{pos:x} claims size {total_chunk_size} but only {total - pos} bytes remain")
            break

        chunk_bytes = decompressed[pos : pos + total_chunk_size]

        yield SubChunkRef(
            chunk_tag=chunk_tag,
            chunk_sub_tag=chunk_sub_tag,
            chunk_data_size=chunk_data_size,
            data=chunk_bytes,
            source_offset=pos,
        )

        pos += total_chunk_size
