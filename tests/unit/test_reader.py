"""Tests for forensic_aul.engine.parser.reader — BinaryReader primitives."""

import struct
import pytest
from forensic_aul.engine.parser.reader import BinaryReader, reader_from_bytes


def r(data: bytes) -> BinaryReader:
    return reader_from_bytes(data)


class TestUnsignedIntegers:
    def test_u8(self):
        assert r(b"\xff").u8() == 255

    def test_u16_le(self):
        assert r(b"\x01\x00").u16() == 1
        assert r(b"\xff\xff").u16() == 65535

    def test_u32_le(self):
        data = struct.pack("<I", 0xDEADBEEF)
        assert r(data).u32() == 0xDEADBEEF

    def test_u64_le(self):
        data = struct.pack("<Q", 0x0102030405060708)
        assert r(data).u64() == 0x0102030405060708


class TestSignedIntegers:
    def test_i8_negative(self):
        assert r(b"\xff").i8() == -1

    def test_i16_negative(self):
        data = struct.pack("<h", -1000)
        assert r(data).i16() == -1000

    def test_i32_negative(self):
        data = struct.pack("<i", -123456)
        assert r(data).i32() == -123456

    def test_i64_negative(self):
        data = struct.pack("<q", -(2**62))
        assert r(data).i64() == -(2**62)


class TestBigEndian:
    def test_u128_be(self):
        data = bytes(range(16))
        val = r(data).u128_be()
        expected = int.from_bytes(bytes(range(16)), "big")
        assert val == expected

    def test_uuid_be(self):
        # 16 bytes → 32-char uppercase hex string, no dashes
        data = bytes.fromhex("AABBCCDD" * 4)
        assert r(data).uuid_be() == "AABBCCDDAABBCCDDAABBCCDDAABBCCDD"


class TestStrings:
    def test_cstr_fixed_null_padded(self):
        data = b"hello\x00\x00\x00"
        assert r(data).cstr_fixed(8) == "hello"

    def test_cstr_fixed_full(self):
        data = b"fullstr!"
        assert r(data).cstr_fixed(8) == "fullstr!"

    def test_cstr_fixed_terminates_at_null(self):
        # cstr_fixed(8) on a 3-char + null-padded string returns just the 3 chars
        data = b"abc\x00\x00\x00\x00\x00"
        assert r(data).cstr_fixed(8) == "abc"


class TestPosition:
    def test_offset_tracks_reads(self):
        rd = r(b"\x01\x02\x03\x04")
        assert rd.offset == 0
        rd.u8()
        assert rd.offset == 1
        rd.u16()
        assert rd.offset == 3

    def test_skip(self):
        rd = r(b"\x00" * 10 + b"\xff")
        rd.skip(10)
        assert rd.u8() == 0xFF

    def test_seek(self):
        rd = r(b"\xAA\xBB\xCC")
        rd.seek(2)
        assert rd.u8() == 0xCC

    def test_remaining(self):
        rd = r(b"\x01\x02\x03")
        assert rd.remaining() == 3
        rd.u8()
        assert rd.remaining() == 2

    def test_peek_does_not_advance(self):
        rd = r(b"\xAB\xCD")
        peeked = rd.peek(1)
        assert peeked == b"\xAB"
        assert rd.offset == 0


class TestEOF:
    def test_read_beyond_eof_raises(self):
        with pytest.raises(EOFError):
            r(b"\x01").u16()

    def test_empty_u8_raises(self):
        with pytest.raises(EOFError):
            r(b"").u8()
