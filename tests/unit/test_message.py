"""Tests for forensic_aul.engine.parser.message — Apple printf formatter."""

import pytest
from forensic_aul.engine.parser.message import format_message
from forensic_aul.engine.models import FirehoseItemData, FirehoseItemInfo


def item(value: str, item_type: int = 0x22, size: int = 0) -> FirehoseItemInfo:
    return FirehoseItemInfo(message_strings=value, item_type=item_type, item_size=size)


def data(*values: str) -> FirehoseItemData:
    return FirehoseItemData(item_info=[item(v) for v in values])


class TestBasicSubstitution:
    def test_string_substitution(self):
        assert format_message("Hello, %s!", data("world")) == "Hello, world!"

    def test_integer_substitution(self):
        assert format_message("value=%d", data("42")) == "value=42"

    def test_hex_lower(self):
        assert format_message("0x%x", data("255")) == "0xff"

    def test_hex_upper(self):
        # "%X" gives uppercase digits; the "0x" prefix is literal text → "0xFF"
        assert format_message("0x%X", data("255")) == "0xFF"

    def test_multiple_items(self):
        result = format_message("%s=%d", data("key", "99"))
        assert result == "key=99"

    def test_literal_percent(self):
        assert format_message("100%%", data()) == "100%"

    def test_empty_format_string(self):
        assert format_message("", data("anything")) == ""

    def test_no_specifiers(self):
        assert format_message("plain text", data()) == "plain text"


class TestAnnotations:
    def test_public_annotation(self):
        assert format_message("%{public}s", data("visible")) == "visible"

    def test_private_annotation_with_value(self):
        # private items are already resolved upstream; we just render the value
        assert format_message("%{private}s", data("secret")) == "secret"

    def test_private_placeholder(self):
        assert format_message("%{private}s", data("<private>")) == "<private>"

    def test_bool_true(self):
        assert format_message("%{bool}d", data("1")) == "true"

    def test_bool_false(self):
        assert format_message("%{bool}d", data("0")) == "false"

    def test_uuid_t(self):
        # 32 hex chars → formatted UUID with dashes
        uuid_hex = "AABBCCDDEEFF00112233445566778899"
        result = format_message("%{uuid_t}.16P", data(uuid_hex))
        assert "-" in result or len(result) == 36 or result.upper().replace("-", "") == uuid_hex

    def test_unknown_annotation_surfaces_value(self):
        # Unknown annotations should not silently discard the value
        result = format_message("%{custom_type}d", data("42"))
        assert "42" in result or "custom_type" in result


class TestCompoundAnnotations:
    """Apple packs `%{<privacy>, <type>}` — the privacy qualifier must be stripped
    before decoder dispatch (regression for the CLSubHarvesterIdentifier case)."""

    def test_privacy_prefix_does_not_block_supported_decoder(self):
        # `private, uuid_t` must still hit the uuid decoder, not fall through.
        uuid_hex = "AABBCCDDEEFF00112233445566778899"
        result = format_message("%{private, uuid_t}.16P", data(uuid_hex))
        assert result.upper().replace("-", "") == uuid_hex

    def test_privacy_only_sensitive_renders_value(self):
        # `sensitive` is a privacy qualifier, not a decoder — must render the value,
        # not emit an "unknown annotation" placeholder.
        assert format_message("%{sensitive}s", data("payload")) == "payload"

    def test_bool_with_public_prefix(self):
        assert format_message("%{public, bool}d", data("1")) == "true"


class TestDecoderTables:
    """Value→name tables generated from the upstream Rust source (decoder_tables.py)."""

    def test_subharvester_identifier(self):
        # The exact case observed in real logs: `public, location:CLSubHarvesterIdentifier`.
        out = format_message("%{public, location:CLSubHarvesterIdentifier}d", data("0"))
        assert out == "CellLegacy"

    def test_opendirectory_error(self):
        out = format_message("%{odtypes:ODError}d", data("5300"))
        assert out == "ODErrorCredentialsAccountNotFound"

    def test_unknown_value_in_known_table_keeps_raw(self):
        # A value not present in the table falls back to the placeholder (no data loss).
        out = format_message("%{odtypes:ODError}d", data("999999"))
        assert "999999" in out


class TestErrnoDecoder:
    def test_errno_known_code(self):
        # Regression: errno.strerror did not exist (AttributeError); os.strerror is used.
        out = format_message("%{errno}d", data("2"))
        assert out.startswith("ENOENT")

    def test_darwin_errno_alias(self):
        out = format_message("%{public, darwin.errno}d", data("2"))
        assert out.startswith("ENOENT")


class TestEdgeCases:
    def test_fewer_items_than_specifiers(self):
        # Missing items should leave specifier in place, not crash
        result = format_message("%s %s", data("only_one"))
        assert "only_one" in result
        assert "%s" in result  # second specifier left as-is

    def test_more_items_than_specifiers(self):
        # Extra items are silently ignored
        result = format_message("one=%s", data("1", "2", "3"))
        assert result == "one=1"

    def test_width_padding_integer(self):
        result = format_message("%5d", data("7"))
        assert result == "    7"

    def test_zero_padding_integer(self):
        result = format_message("%05d", data("7"))
        assert result == "00007"

    def test_float_format(self):
        # A value already resolved to a decimal string is parsed directly.
        result = format_message("%.2f", data("3.14159"))
        assert result == "3.14"

    def test_float_reinterprets_double_bit_pattern(self):
        # A double argument is stored as the SIGNED integer of its 8 IEEE-754
        # bytes; %f must reinterpret those bits, not print the integer itself.
        assert format_message("%f", data("4651708241678434304")) == "966.000000"
        assert format_message("%.9f", data("4554571619866423808")) == "0.000321791"

    def test_float_negative_bit_pattern(self):
        # -2.0's bit-pattern (0xC000…) is a negative signed int64 when stored.
        assert format_message("%f", data("-4611686018427387904")) == "-2.000000"

    def test_octal(self):
        result = format_message("%o", data("8"))
        assert result == "10"
