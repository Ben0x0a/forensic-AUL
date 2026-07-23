"""Iterate over top-level chunks in an Apple Unified Log tracev3 file.

A tracev3 file is a sequence of variable-length chunks.  Each chunk starts
with a 16-byte preamble:

    chunk_tag      u32 LE   — 0x1000 = Header, 0x600b = Catalog, 0x600d = Chunkset
    chunk_sub_tag  u32 LE
    chunk_data_size u64 LE  — payload bytes that follow the preamble

After the preamble + payload, the chunk is **padded to the next 8-byte
boundary** (i.e. the next chunk starts at ``ceil((offset + 16 + data_size) / 8) * 8``).
Catalogs and Headers happen to be already aligned; Chunksets almost never are.

`iter_chunks()` is a pure generator that yields raw chunk bytes (preamble
included, *without* the trailing alignment padding) and their file offset.
Higher-level callers decide which tags to parse.

Reference: macos-UnifiedLogs/src/iterator.rs, macos-UnifiedLogs/src/parser.rs
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Generator

log = logging.getLogger(__name__)

CHUNK_PREAMBLE_SIZE: int = 16  # 4 + 4 + 8
CHUNK_ALIGNMENT:    int = 8   # each chunk is padded to a multiple of 8 bytes

CHUNK_TAG_HEADER: int = 0x1000
CHUNK_TAG_CATALOG: int = 0x600B
CHUNK_TAG_CHUNKSET: int = 0x600D


@dataclass
class RawChunk:
    """A raw chunk read from a tracev3 file."""
    tag: int          # u32 — chunk type tag
    sub_tag: int      # u32
    data_size: int    # u64 — payload bytes (not counting the 16-byte preamble)
    data: bytes       # full bytes: 16-byte preamble + data_size payload bytes
    file_offset: int  # byte offset of the preamble in the source file


def iter_chunks(path: Path | str) -> Generator[RawChunk, None, None]:
    """Iterate over all top-level chunks in *path* (a tracev3 file).

    Yields one RawChunk per chunk in file order.  Truncated or malformed
    chunks are logged and the iteration stops.

    The generator reads the file sequentially in one open() call; callers
    that need random access should read the returned bytes themselves.
    """
    path = Path(path)
    file_size = path.stat().st_size

    with path.open("rb") as fh:
        while True:
            offset = fh.tell()

            preamble = fh.read(CHUNK_PREAMBLE_SIZE)
            if not preamble:
                break  # clean EOF

            if len(preamble) < CHUNK_PREAMBLE_SIZE:
                log.warning(f"tracev3 {path.name}: truncated preamble at 0x{offset:x} ({len(preamble)} bytes, need {CHUNK_PREAMBLE_SIZE})")
                break

            tag = int.from_bytes(preamble[0:4], "little")
            sub_tag = int.from_bytes(preamble[4:8], "little")
            data_size = int.from_bytes(preamble[8:16], "little")

            # Sanity check: payload must fit in the remaining file
            remaining = file_size - offset - CHUNK_PREAMBLE_SIZE
            if data_size > remaining:
                log.warning(f"tracev3 {path.name}: chunk tag=0x{tag:04x} at 0x{offset:x} claims {data_size} payload bytes but only {remaining} remain — truncated file?")
                break

            if data_size > 0:
                payload = fh.read(data_size)
                if len(payload) != data_size:
                    log.warning(f"tracev3 {path.name}: short read at 0x{offset + CHUNK_PREAMBLE_SIZE:x} (got {len(payload)}, expected {data_size})")
                    break
            else:
                payload = b""

            # Skip alignment padding so the next read lands on an 8-byte boundary.
            total = CHUNK_PREAMBLE_SIZE + data_size
            pad   = (-total) % CHUNK_ALIGNMENT  # bytes needed to reach next multiple of 8
            if pad:
                fh.read(pad)  # consume and discard padding bytes

            chunk_bytes = preamble + payload

            if tag not in (CHUNK_TAG_HEADER, CHUNK_TAG_CATALOG, CHUNK_TAG_CHUNKSET):
                log.debug(
                    "tracev3 %s: unknown chunk tag 0x%04x at 0x%x (size %d), skipping",
                    path.name, tag, offset, data_size,
                )
                # Still yield so callers can handle unknown tags if desired,
                # but they typically filter by tag.

            yield RawChunk(
                tag=tag,
                sub_tag=sub_tag,
                data_size=data_size,
                data=chunk_bytes,
                file_offset=offset,
            )
