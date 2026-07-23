"""Parse Apple Unified Log Chunkset chunks (tag 0x600d).

A chunkset chunk is a compressed (LZ4 block) or uncompressed container that
holds the actual log sub-chunks (Firehose, Oversize, Statedump, Simpledump).

Binary layout reference: macos-UnifiedLogs/src/chunkset.rs
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Generator

try:
    import lz4.block as lz4_block
    _HAS_LZ4 = True
except ImportError:
    _HAS_LZ4 = False

from forensic_aul.config import MAX_CHUNKSET_DECOMPRESSED_SIZE
from forensic_aul.engine.parser.reader import BinaryReader, reader_from_bytes

log = logging.getLogger(__name__)

# LZ4 block compression cannot expand data by more than ~255x; a claimed
# uncompressed size beyond (compressed_size * this) is implausible → corrupt/crafted.
_LZ4_MAX_RATIO: int = 255

# Outer chunk tag
CHUNK_TAG_CHUNKSET: int = 0x600D

# bv41 compression signatures (LE u32). The signatures are 4-byte ASCII tags.
SIG_BV41_COMPRESSED: int = 825521762    # b"bv41" — LZ4-compressed payload follows
SIG_BV41_UNCOMPRESSED: int = 758412898  # b"bv4-" — payload is stored uncompressed
SIG_BV4_FOOTER: int = 0x24347662        # b"bv4$" — terminator after payload

# Sub-chunk tags in the decompressed data
CHUNK_TAG_FIREHOSE: int = 0x6001
CHUNK_TAG_OVERSIZE: int = 0x6002
CHUNK_TAG_STATEDUMP: int = 0x6003
CHUNK_TAG_SIMPLEDUMP: int = 0x6004

CHUNK_PREAMBLE_SIZE: int = 16  # tag(4) + sub_tag(4) + data_size(8)


@dataclass
class SubChunkRef:
    """A reference to a raw sub-chunk payload within a decompressed chunkset."""
    chunk_tag: int
    chunk_sub_tag: int
    chunk_data_size: int
    data: bytes            # full bytes including the 16-byte preamble
    source_offset: int     # byte offset of this sub-chunk in the decompressed data


def decompress_chunkset(chunk_data: bytes) -> bytes | None:
    """Decompress (or pass through) a raw chunkset payload.

    *chunk_data* begins at the chunk_tag field (i.e. includes the 16-byte
    outer preamble).

    Returns:
        Decompressed bytes, or None on error.
    """
    if not _HAS_LZ4:
        raise RuntimeError(
            "lz4 library not installed. Run: pip install lz4"
        )

    r = reader_from_bytes(chunk_data)
    # Skip outer preamble (already parsed by the tracev3 iterator)
    r.skip(CHUNK_PREAMBLE_SIZE)

    sig = r.u32()
    uncompress_size = r.u32()

    # Refuse an implausible decompressed size before it reaches lz4 (which would
    # pre-allocate it). Real chunksets are well under the cap; a larger value
    # means a corrupt/crafted tracev3 — drop this chunkset, keep parsing the rest.
    if uncompress_size > MAX_CHUNKSET_DECOMPRESSED_SIZE:
        log.error(f"Chunkset: claimed decompressed size {uncompress_size} exceeds the {MAX_CHUNKSET_DECOMPRESSED_SIZE}-byte safety cap — refusing (corrupt or crafted chunk)")
        return None

    if sig == SIG_BV41_UNCOMPRESSED:
        # Data is stored uncompressed (observed in Special/ directory).
        raw = r.read(uncompress_size)
        _consume_bv4_footer(r)
        return raw

    if sig != SIG_BV41_COMPRESSED:
        log.error(f"Chunkset: unexpected signature 0x{sig:08x} (expected bv41=0x{SIG_BV41_COMPRESSED:08x} or bv4-=0x{SIG_BV41_UNCOMPRESSED:08x})")
        return None

    block_size = r.u32()
    compressed = r.read(block_size)

    # Tighter, per-chunk bound: LZ4 cannot expand beyond ~255x, so a claimed size
    # larger than that for this block is corrupt — refuse before allocating.
    if uncompress_size > block_size * _LZ4_MAX_RATIO + CHUNK_PREAMBLE_SIZE:
        log.error(f"Chunkset: claimed decompressed size {uncompress_size} implausible for {block_size} compressed bytes (>{_LZ4_MAX_RATIO}x) — refusing")
        return None

    try:
        decompressed = lz4_block.decompress(
            compressed, uncompressed_size=uncompress_size
        )
    except lz4_block.LZ4BlockError as exc:
        log.error(f"LZ4 decompression failed: {exc}")
        return None

    if len(decompressed) != uncompress_size:
        log.error(f"Chunkset: decompressed size {len(decompressed)} != expected {uncompress_size}")
        return None

    _consume_bv4_footer(r)
    return decompressed


def _consume_bv4_footer(r: BinaryReader) -> None:
    """Read and validate the trailing ``bv4$`` footer.

    A truncated stream (no footer) or a wrong footer is logged but does not
    abort the caller — by that point the payload has already been read out
    successfully and the rest of the file is still parseable.
    """
    try:
        footer = r.u32()
    except EOFError:
        log.debug("chunkset: footer truncated (no trailing bv4$)")
        return
    if footer != SIG_BV4_FOOTER:
        log.warning(f"chunkset: unexpected footer 0x{footer:08x} (expected bv4$=0x{SIG_BV4_FOOTER:08x})")


def iter_subchunks(decompressed: bytes) -> Generator[SubChunkRef, None, None]:
    """Iterate over sub-chunks in decompressed chunkset data.

    Yields one SubChunkRef per sub-chunk (Firehose, Oversize, Statedump, Simpledump).
    Unknown tags are logged and skipped. Zero-padding between chunks is consumed.
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

        if chunk_tag in (
            CHUNK_TAG_FIREHOSE,
            CHUNK_TAG_OVERSIZE,
            CHUNK_TAG_STATEDUMP,
            CHUNK_TAG_SIMPLEDUMP,
        ):
            yield SubChunkRef(
                chunk_tag=chunk_tag,
                chunk_sub_tag=chunk_sub_tag,
                chunk_data_size=chunk_data_size,
                data=chunk_bytes,
                source_offset=pos,
            )
        else:
            log.warning(f"Subchunk: unknown tag 0x{chunk_tag:04x} at offset 0x{pos:x} (size {total_chunk_size}), skipping")

        pos += total_chunk_size
