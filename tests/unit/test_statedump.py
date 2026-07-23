"""Tests for Statedump / Simpledump parsing (L5).

Byte vectors and expected values are taken verbatim from the Rust reference unit
tests (``chunks/statedump.rs`` / ``chunks/simpledump.rs``) so the Python port is
checked against the same ground truth.
"""

from forensic_aul.engine.parser.statedump import (
    decode_statedump_data,
    parse_simpledump,
    parse_statedump,
    statedump_message,
)

# ── Rust test vectors ────────────────────────────────────────────────────────

_STATEDUMP = bytes([
    3, 96, 0, 0, 0, 0, 0, 0, 32, 1, 0, 0, 0, 0, 0, 0, 113, 0, 0, 0, 0, 0, 0, 0, 208, 1, 0,
    0, 14, 0, 0, 0, 13, 179, 213, 232, 0, 0, 0, 0, 118, 4, 0, 0, 0, 0, 0, 128, 92, 216,
    221, 238, 4, 56, 58, 56, 136, 119, 16, 34, 124, 90, 10, 86, 3, 0, 0, 0, 40, 0, 0, 0,
    108, 111, 99, 97, 116, 105, 111, 110, 0, 0, 187, 44, 255, 127, 0, 0, 42, 144, 225, 173,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 83, 78, 41, 126, 255, 127,
    0, 0, 6, 144, 225, 173, 0, 0, 0, 0, 148, 242, 123, 124, 255, 127, 0, 0, 95, 67, 76, 68,
    97, 101, 109, 111, 110, 83, 116, 97, 116, 117, 115, 83, 116, 97, 116, 101, 84, 114, 97,
    99, 107, 101, 114, 83, 116, 97, 116, 101, 0, 144, 225, 173, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 72, 78, 41, 126, 255, 127, 0, 0, 67, 76, 68, 97, 101,
    109, 111, 110, 83, 116, 97, 116, 117, 115, 83, 116, 97, 116, 101, 84, 114, 97, 99, 107,
    101, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 240, 191, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0,
])

_SIMPLEDUMP = bytes([
    4, 96, 0, 0, 0, 0, 0, 0, 219, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
    0, 0, 0, 0, 45, 182, 196, 71, 133, 4, 0, 0, 3, 234, 0, 0, 0, 0, 0, 0, 118, 118, 1, 0,
    0, 0, 0, 0, 13, 207, 62, 139, 73, 35, 50, 62, 179, 229, 84, 115, 7, 207, 14, 172, 61,
    5, 132, 95, 63, 101, 53, 143, 158, 191, 34, 54, 231, 114, 172, 1, 1, 0, 0, 0, 79, 0, 0,
    0, 56, 0, 0, 0, 117, 115, 101, 114, 47, 53, 48, 49, 47, 99, 111, 109, 46, 97, 112, 112,
    108, 101, 46, 109, 100, 119, 111, 114, 107, 101, 114, 46, 115, 104, 97, 114, 101, 100,
    46, 48, 66, 48, 48, 48, 48, 48, 48, 45, 48, 48, 48, 48, 45, 48, 48, 48, 48, 45, 48, 48,
    48, 48, 45, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 32, 91, 52, 50, 50, 57, 93,
    0, 115, 101, 114, 118, 105, 99, 101, 32, 101, 120, 105, 116, 101, 100, 58, 32, 100,
    105, 114, 116, 121, 32, 61, 32, 48, 44, 32, 115, 117, 112, 112, 111, 114, 116, 101,
    100, 32, 112, 114, 101, 115, 115, 117, 114, 101, 100, 45, 101, 120, 105, 116, 32, 61,
    32, 49, 0, 0, 0, 0, 0, 0,
])


class TestParseStatedump:
    def test_fields_match_reference(self):
        sd = parse_statedump(_STATEDUMP)
        assert sd is not None
        assert sd.chunk_tag == 24579  # 0x6003
        assert sd.chunk_data_size == 288
        assert sd.first_proc_id == 113
        assert sd.second_proc_id == 464
        assert sd.ttl == 14
        assert sd.continuous_time == 3906319117
        assert sd.activity_id == 9223372036854776950
        assert sd.uuid == "5CD8DDEE04383A38887710227C5A0A56"
        assert sd.unknown_data_type == 3
        assert sd.unknown_data_size == 40
        assert sd.decoder_library == "location"
        assert sd.decoder_type == "_CLDaemonStatusStateTrackerState"
        assert sd.title_name == "CLDaemonStatusStateTracker"
        assert len(sd.statedump_data) == 40

    def test_custom_object_message_is_honest_fallback(self):
        sd = parse_statedump(_STATEDUMP)
        # Type 3 custom object: not decoded, surfaced base64 with a marker.
        data_string = decode_statedump_data(sd)
        assert data_string.startswith("Unsupported Statedump object: CLDaemonStatusStateTracker-")
        msg = statedump_message(sd)
        assert msg.startswith("title: CLDaemonStatusStateTracker\n")
        assert "Object Type: location" in msg
        assert "Object Type: _CLDaemonStatusStateTrackerState" in msg

    def test_truncated_returns_none(self):
        assert parse_statedump(_STATEDUMP[:10]) is None


class TestParseSimpledump:
    def test_fields_match_reference(self):
        sd = parse_simpledump(_SIMPLEDUMP)
        assert sd is not None
        assert sd.chunk_tag == 24580  # 0x6004
        assert sd.chunk_data_size == 219
        assert sd.first_proc_id == 1
        assert sd.second_proc_id == 1
        assert sd.continuous_time == 4970481235501
        assert sd.thread_id == 59907
        assert sd.unknown_offset == 95862
        assert sd.sender_uuid == "0DCF3E8B4923323EB3E5547307CF0EAC"
        assert sd.dsc_uuid == "3D05845F3F65358F9EBF2236E772AC01"
        assert sd.subsystem == (
            "user/501/com.apple.mdworker.shared.0B000000-0000-0000-0000-000000000000 [4229]"
        )
        assert sd.message_string == "service exited: dirty = 0, supported pressured-exit = 1"

    def test_truncated_returns_none(self):
        assert parse_simpledump(_SIMPLEDUMP[:10]) is None


class TestDecodePlist:
    def test_binary_plist_to_json(self):
        import plistlib

        payload = plistlib.dumps({"a": 1, "b": "x"}, fmt=plistlib.FMT_BINARY)
        from forensic_aul.engine.models.dumps import Statedump

        sd = Statedump(
            chunk_tag=0x6003, chunk_subtag=0, chunk_data_size=0, first_proc_id=0,
            second_proc_id=0, ttl=0, continuous_time=0, activity_id=0, uuid="",
            unknown_data_type=1, unknown_data_size=len(payload), decoder_library="",
            decoder_type="", title_name="t", statedump_data=payload,
        )
        out = decode_statedump_data(sd)
        assert '"a": 1' in out and '"b": "x"' in out
