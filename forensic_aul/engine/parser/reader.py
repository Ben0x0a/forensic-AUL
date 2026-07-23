"""Low-level binary reader for Apple Unified Log binary structures.

All multi-byte integers are little-endian unless otherwise noted.
This is the single source of all struct.unpack calls in the entire codebase.
"""

from __future__ import annotations

import struct
from io import BufferedReader, BytesIO
from typing import Union


class BinaryReader:
    """Stateful reader over a binary stream with typed read helpers.

    The reader tracks the current byte offset for traceability — every parse
    error can be reported with a precise file offset.

    Args:
        stream: An open binary file or a BytesIO buffer.
    """

    def __init__(self, stream: Union[BufferedReader, BytesIO]) -> None:
        self._stream = stream
        self._offset: int = 0

    # ── Position ──────────────────────────────────────────────────────────────

    @property
    def offset(self) -> int:
        """Current byte offset from the start of the stream."""
        return self._offset

    def seek(self, position: int) -> None:
        """Seek to an absolute byte position."""
        self._stream.seek(position)
        self._offset = position

    def skip(self, n: int) -> None:
        """Advance the position by n bytes without reading."""
        self._stream.seek(n, 1)
        self._offset += n

    def remaining(self) -> int:
        """Return the number of bytes remaining until EOF."""
        current = self._stream.tell()
        self._stream.seek(0, 2)
        end = self._stream.tell()
        self._stream.seek(current)
        return end - current

    # ── Raw bytes ─────────────────────────────────────────────────────────────

    def read(self, n: int) -> bytes:
        """Read exactly n bytes; raises EOFError if the stream ends early."""
        data = self._stream.read(n)
        if len(data) != n:
            raise EOFError(
                f"Expected {n} bytes at offset 0x{self._offset:x}, "
                f"got {len(data)}"
            )
        self._offset += n
        return data

    def peek(self, n: int) -> bytes:
        """Read n bytes without advancing the position."""
        data = self._stream.read(n)
        self._stream.seek(-len(data), 1)
        return data

    # ── Unsigned integers (little-endian) ────────────────────────────────────

    def u8(self) -> int:
        return struct.unpack_from("<B", self.read(1))[0]

    def u16(self) -> int:
        return struct.unpack_from("<H", self.read(2))[0]

    def u32(self) -> int:
        return struct.unpack_from("<I", self.read(4))[0]

    def u64(self) -> int:
        return struct.unpack_from("<Q", self.read(8))[0]

    # ── Signed integers (little-endian) ──────────────────────────────────────

    def i8(self) -> int:
        return struct.unpack_from("<b", self.read(1))[0]

    def i16(self) -> int:
        return struct.unpack_from("<h", self.read(2))[0]

    def i32(self) -> int:
        return struct.unpack_from("<i", self.read(4))[0]

    def i64(self) -> int:
        return struct.unpack_from("<q", self.read(8))[0]

    # ── Big-endian ────────────────────────────────────────────────────────────

    def u128_be(self) -> int:
        """Read a 16-byte big-endian unsigned 128-bit integer."""
        return int.from_bytes(self.read(16), "big")

    # ── Strings ───────────────────────────────────────────────────────────────

    def cstr_fixed(self, size: int) -> str:
        """Read a fixed-width null-terminated (or null-padded) C string."""
        raw = self.read(size)
        end = raw.find(b"\x00")
        if end == -1:
            end = size
        return raw[:end].decode("utf-8", errors="replace")

    def uuid_be(self) -> str:
        """Read 16 bytes big-endian and return an uppercase hex UUID string (no dashes)."""
        return format(self.u128_be(), "032X")

    # ── Context manager ───────────────────────────────────────────────────────

    def __enter__(self) -> "BinaryReader":
        return self

    def __exit__(self, *_: object) -> None:
        self._stream.close()


def reader_from_bytes(data: bytes) -> BinaryReader:
    """Wrap a bytes object in a BinaryReader."""
    return BinaryReader(BytesIO(data))
