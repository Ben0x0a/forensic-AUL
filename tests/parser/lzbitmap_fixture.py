"""The synthetic LZBITMAP fixture: its plaintext, and how it was produced.

Defines : ``fixture_plaintext`` (the deterministic input), ``FIXTURE_PATH`` (the
          committed ``ZBM`` stream, encoded once by Apple's libcompression) and,
          run as a script on macOS, its regeneration.
Used by : tests/parser/test_lzbitmap.py.
Uses    : the standard library; ctypes + /usr/lib/libcompression.dylib only when
          run as a script (macOS).

WHY synthetic: real chunksets are someone's device logs and never enter the
repository. The text below only imitates their shape (short tokens, repeats,
binary bytes) so the encoder exercises literals, matches and repeat counts.

Regenerate (macOS only):  python tests/parser/lzbitmap_fixture.py
"""

from __future__ import annotations

import ctypes
import random
from pathlib import Path

FIXTURE_PATH = Path(__file__).with_name("data") / "lzbitmap_09.zbm"
_COMPRESSION_LZBITMAP = 0x702
_SIZE = 100_000


def fixture_plaintext() -> bytes:
    """The fixture's decompressed content (deterministic: seeded generator)."""
    rng = random.Random(27)
    words = [b"locationd", b"Wi-Fi", b"authorized", b"camera", b"session",
             b"%{public}s", b"\x00\x01\x02", b"0x1f5"]
    out = bytearray()
    while len(out) < _SIZE:
        out += b" ".join(rng.choice(words) for _ in range(rng.randint(1, 9)))
        out += bytes([rng.randrange(256)])
    return bytes(out[:_SIZE])


def _encode(data: bytes) -> bytes:
    lib = ctypes.CDLL("/usr/lib/libcompression.dylib")
    lib.compression_encode_buffer.restype = ctypes.c_size_t
    dst = ctypes.create_string_buffer(len(data) * 2 + 1024)
    n = lib.compression_encode_buffer(dst, len(dst), data, len(data), None, _COMPRESSION_LZBITMAP)
    if not n:
        raise RuntimeError("libcompression could not encode the fixture")
    return dst.raw[:n]


if __name__ == "__main__":
    FIXTURE_PATH.parent.mkdir(exist_ok=True)
    FIXTURE_PATH.write_bytes(_encode(fixture_plaintext()))
    print(f"wrote {FIXTURE_PATH} ({FIXTURE_PATH.stat().st_size} bytes)")
