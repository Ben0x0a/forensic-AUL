"""Unit tests for format-string resolution offset math (L2/L3 regressions).

L2: the DSC large-offset must be hex-concatenated above the 32-bit string offset
(``lo << 32 | offset``), with the Apple recovery rule and the shared_cache=8 case,
matching ``nonactivity.rs``. The earlier code did ``(large_shared_cache << 16) |
(offset & 0xFFFF)`` and also wrongly applied a large offset on the main_exe path.

L3: ``absolute`` entries resolve against an alternative UUIDText file chosen by
load-address range, not the main exe.

Also covers the library-path slot of the returned tuple: it must carry the real
image path (from the UUIDText footer or the DSC UUID descriptor), never a UUID.
"""

import struct

from forensic_aul.engine.models import (
    CatalogChunk,
    Firehose,
    FirehoseFormatters,
    FirehoseNonActivity,
    FirehosePreamble,
    ProcessInfoEntry,
    ProcessUUIDEntry,
    RangeDescriptor,
    SharedCacheStrings,
    UUIDDescriptor,
    UUIDText,
)
from forensic_aul.engine.parser.format_string import (
    _dsc_effective_offset,
    _dsc_library_path,
    resolve_format_string,
)
from forensic_aul.engine.parser.uuidtext import parse_uuidtext


class TestDscEffectiveOffset:
    def test_no_large_offset_returns_raw(self):
        fmt = FirehoseFormatters(shared_cache=True)
        assert _dsc_effective_offset(0x1234, fmt) == 0x1234

    def test_hex_concat_high_part(self):
        # has_large_offset agrees with large_shared_cache/2 → plain concat.
        fmt = FirehoseFormatters(has_large_offset=2, large_shared_cache=4)
        # lo (2) == 4//2 → else-branch: 2 << 32 | offset
        assert _dsc_effective_offset(0xABCD, fmt) == (2 << 32) | 0xABCD

    def test_recovery_when_mismatch_and_not_shared_cache(self):
        # has_large_offset disagrees with large_shared_cache/2 and shared_cache
        # is unset → recover using large_shared_cache/2 as the high part.
        fmt = FirehoseFormatters(has_large_offset=1, large_shared_cache=6)
        assert _dsc_effective_offset(0x10, fmt) == ((6 // 2) << 32) | 0x10

    def test_shared_cache_uses_eight(self):
        # shared_cache set → high part fixed to 8 → offset + 0x80000000.
        fmt = FirehoseFormatters(has_large_offset=1, large_shared_cache=2, shared_cache=True)
        assert _dsc_effective_offset(0x20, fmt) == 0x20 + 0x80000000

    def test_not_the_old_buggy_formula(self):
        fmt = FirehoseFormatters(has_large_offset=2, large_shared_cache=4)
        old_buggy = (fmt.large_shared_cache << 16) | (0xABCD & 0xFFFF)
        assert _dsc_effective_offset(0xABCD, fmt) != old_buggy


# ── Fakes for the absolute-path test ────────────────────────────────────────────

class _FakeStrings:
    def __init__(self, uuidtexts, dscs=None):
        self._uuidtexts = uuidtexts
        self._dscs = dscs or {}

    def get_uuidtext(self, uuid):
        return self._uuidtexts.get(uuid)

    def get_dsc(self, uuid):
        return self._dscs.get(uuid)

    def get_file_id(self, uuid):
        if uuid in self._uuidtexts or uuid in self._dscs:
            return 99
        return None


def _empty_uuidtext(uuid, image_path=""):
    """A minimal empty UUIDText — the test asserts *selection*, not byte parsing."""
    return UUIDText(
        uuid=uuid, signature=0x66778899, major_version=2, minor_version=0,
        entry_descriptors=[], footer_data=b"", image_path=image_path,
    )


def _catalog_with_uuid_ranges():
    proc = ProcessInfoEntry(
        index=0, unknown=0, catalog_main_uuid_index=0, catalog_dsc_uuid_index=1,
        first_number_proc_id=1, second_number_proc_id=2, pid=10, effective_user_id=0,
        unknown2=0, number_uuids_entries=2, unknown3=0,
        uuid_info_entries=[
            ProcessUUIDEntry(size=0x1000, unknown=0, catalog_uuid_index=0,
                             load_address=0x0, uuid="LIB_LOW"),
            ProcessUUIDEntry(size=0x1000, unknown=0, catalog_uuid_index=1,
                             load_address=0x500000000, uuid="LIB_HIGH"),
        ],
        number_subsystems=0, unknown4=0, subsystem_entries=[],
        main_uuid="MAIN", dsc_uuid="DSC",
    )
    return CatalogChunk(
        chunk_tag=0x600b, chunk_sub_tag=0, chunk_data_size=0,
        catalog_subsystem_strings_offset=0, catalog_process_info_entries_offset=0,
        number_process_information_entries=1, catalog_offset_sub_chunks=0,
        number_sub_chunks=0, unknown=b"", earliest_firehose_timestamp=0,
        catalog_uuids=["MAIN", "DSC"], catalog_subsystem_strings=b"",
        catalog_process_info_entries={"1_2": proc}, catalog_subchunks=[],
    )


class TestAbsoluteResolution:
    def test_picks_library_uuid_by_load_address_range(self):
        # absolute_offset = main_exe_alt_index << 32 | pc_id.
        # alt_index=5, pc_id=0 → 0x500000000, which falls in LIB_HIGH's range.
        fmt = FirehoseFormatters(absolute=True, main_exe_alt_index=5)
        fh = Firehose(
            unknown_log_activity_type=0x4, unknown_log_type=0, flags=0,
            format_string_location=0x100, thread_id=0, continuous_time_delta=0,
            continuous_time_delta_upper=0, data_size=0,
            firehose_non_activity=FirehoseNonActivity(
                unknown_pc_id=0, firehose_formatters=fmt),
        )
        preamble = FirehosePreamble(
            chunk_tag=0, chunk_sub_tag=0, chunk_data_size=0,
            first_number_proc_id=1, second_number_proc_id=2, ttl=0, collapsed=0,
            unknown=b"\x00\x00", public_data_size=0, private_data_virtual_offset=0x1000,
            unknown2=0, unknown3=0, base_continuous_time=0,
        )
        catalog = _catalog_with_uuid_ranges()
        strings = _FakeStrings({"LIB_HIGH": _empty_uuidtext("LIB_HIGH")})

        fs, library, library_uuid, process_uuid, file_id = resolve_format_string(
            fh, preamble, catalog, strings
        )
        # The high library was selected (not the main exe, not the low library).
        assert library_uuid == "LIB_HIGH"
        assert process_uuid == "MAIN"
        assert file_id == 99


# ── UUIDText image-path parsing ─────────────────────────────────────────────────

_SPRINGBOARD = "/System/Library/CoreServices/SpringBoard.app/SpringBoard"


def _write_uuidtext(tmp_path, entries, footer: bytes):
    """Write a synthetic UUIDText file and return its path.

    *entries* is a list of ``(range_start_offset, entry_size)`` descriptors and
    *footer* the raw pool that follows the header — deliberately independent, so
    a test can declare sizes that the pool does not actually contain.
    """
    data = struct.pack("<IIII", 0x66778899, 2, 0, len(entries))
    for start, size in entries:
        data += struct.pack("<II", start, size)
    directory = tmp_path / "1F"
    directory.mkdir(exist_ok=True)
    path = directory / "E459BBDC3E19BBF82D58415A2AE9AB"
    path.write_bytes(data + footer)
    return path


class TestUUIDTextImagePath:
    def test_path_follows_the_string_ranges(self, tmp_path):
        # One 16-byte range, then the null-terminated binary path.
        pool = b"Hello %s\x00".ljust(16, b"\x00")
        path = _write_uuidtext(
            tmp_path, [(0x100, 16)], pool + _SPRINGBOARD.encode() + b"\x00"
        )
        uuidtext = parse_uuidtext(path)
        assert uuidtext is not None
        assert uuidtext.image_path == _SPRINGBOARD

    def test_format_string_lookup_still_works(self, tmp_path):
        # The path must not disturb the range pool the format strings live in.
        from forensic_aul.engine.parser.uuidtext import lookup_format_string

        pool = b"Hello %s\x00".ljust(16, b"\x00")
        path = _write_uuidtext(
            tmp_path, [(0x100, 16)], pool + _SPRINGBOARD.encode() + b"\x00"
        )
        uuidtext = parse_uuidtext(path)
        assert lookup_format_string(uuidtext, 0x100) == "Hello %s"

    def test_truncated_before_path_yields_empty(self, tmp_path):
        # entry_size claims 64 bytes but the pool holds 16 — the path is gone.
        path = _write_uuidtext(tmp_path, [(0x100, 64)], b"Hello %s\x00".ljust(16, b"\x00"))
        uuidtext = parse_uuidtext(path)
        assert uuidtext is not None
        assert uuidtext.image_path == ""

    def test_footer_exactly_the_ranges_yields_empty(self, tmp_path):
        path = _write_uuidtext(tmp_path, [(0x100, 16)], b"Hello %s\x00".ljust(16, b"\x00"))
        uuidtext = parse_uuidtext(path)
        assert uuidtext.image_path == ""

    def test_zero_entry_descriptors_reads_path_at_offset_zero(self, tmp_path):
        path = _write_uuidtext(tmp_path, [], _SPRINGBOARD.encode() + b"\x00")
        uuidtext = parse_uuidtext(path)
        assert uuidtext is not None
        assert uuidtext.entry_descriptors == []
        assert uuidtext.image_path == _SPRINGBOARD

    def test_zero_entry_descriptors_and_empty_footer(self, tmp_path):
        path = _write_uuidtext(tmp_path, [], b"")
        uuidtext = parse_uuidtext(path)
        assert uuidtext is not None
        assert uuidtext.image_path == ""

    def test_unterminated_path_does_not_raise(self, tmp_path):
        # No trailing NUL — the reader must stop at the end of the pool.
        path = _write_uuidtext(tmp_path, [], _SPRINGBOARD.encode())
        uuidtext = parse_uuidtext(path)
        assert uuidtext.image_path == _SPRINGBOARD

    def test_absurd_entry_size_does_not_raise(self, tmp_path):
        # A hostile descriptor claiming 4 GiB must degrade to no path, not blow up.
        path = _write_uuidtext(tmp_path, [(0, 0xFFFFFFFF)], b"junk")
        uuidtext = parse_uuidtext(path)
        assert uuidtext is not None
        assert uuidtext.image_path == ""


# ── Library slot: real paths, never UUIDs ───────────────────────────────────────

def _main_exe_firehose():
    fmt = FirehoseFormatters(main_exe=True)
    return Firehose(
        unknown_log_activity_type=0x4, unknown_log_type=0, flags=0,
        format_string_location=0x100, thread_id=0, continuous_time_delta=0,
        continuous_time_delta_upper=0, data_size=0,
        firehose_non_activity=FirehoseNonActivity(firehose_formatters=fmt),
    )


def _preamble():
    return FirehosePreamble(
        chunk_tag=0, chunk_sub_tag=0, chunk_data_size=0,
        first_number_proc_id=1, second_number_proc_id=2, ttl=0, collapsed=0,
        unknown=b"\x00\x00", public_data_size=0, private_data_virtual_offset=0x1000,
        unknown2=0, unknown3=0, base_continuous_time=0,
    )


class TestMainExeLibraryPath:
    def test_library_slot_is_the_image_path(self):
        strings = _FakeStrings({"MAIN": _empty_uuidtext("MAIN", _SPRINGBOARD)})
        _, library, library_uuid, process_uuid, _ = resolve_format_string(
            _main_exe_firehose(), _preamble(), _catalog_with_uuid_ranges(), strings
        )
        assert library == _SPRINGBOARD
        # Identity columns are unchanged — still the UUIDs.
        assert library_uuid == "MAIN"
        assert process_uuid == "MAIN"

    def test_missing_uuidtext_gives_empty_library_but_keeps_uuids(self):
        _, library, library_uuid, process_uuid, file_id = resolve_format_string(
            _main_exe_firehose(), _preamble(), _catalog_with_uuid_ranges(),
            _FakeStrings({}),
        )
        assert library == ""
        assert library_uuid == "MAIN"
        assert process_uuid == "MAIN"
        assert file_id is None


# ── DSC range → UUID descriptor → library path ──────────────────────────────────

def _dsc_with_two_images():
    return SharedCacheStrings(
        signature=0x64736368, major_version=2, minor_version=0,
        number_ranges=2, number_uuids=2,
        ranges=[
            RangeDescriptor(range_offset=0x1000, data_offset=0, range_size=0x10,
                            unknown_uuid_index=0, strings=b"first %s\x00"),
            RangeDescriptor(range_offset=0x2000, data_offset=0, range_size=0x10,
                            unknown_uuid_index=1, strings=b"second %s\x00"),
        ],
        uuids=[
            UUIDDescriptor(text_offset=0, text_size=0, uuid="U0", path_offset=0,
                           path_string="/usr/lib/libA.dylib"),
            UUIDDescriptor(text_offset=0, text_size=0, uuid="U1", path_offset=0,
                           path_string="/usr/lib/libSystem.B.dylib"),
        ],
        dsc_uuid="DSC",
    )


class TestDscLibraryPath:
    def test_range_maps_to_its_uuid_descriptor_path(self):
        dsc = _dsc_with_two_images()
        assert _dsc_library_path(dsc, 0x1000) == "/usr/lib/libA.dylib"
        assert _dsc_library_path(dsc, 0x2008) == "/usr/lib/libSystem.B.dylib"

    def test_offset_outside_every_range_yields_empty(self):
        dsc = _dsc_with_two_images()
        assert _dsc_library_path(dsc, 0x500) == ""
        assert _dsc_library_path(dsc, 0x1500) == ""

    def test_out_of_bounds_uuid_index_yields_empty(self):
        dsc = _dsc_with_two_images()
        dsc.ranges[0].unknown_uuid_index = 99
        assert _dsc_library_path(dsc, 0x1000) == ""

    def test_resolve_returns_dsc_path_in_library_slot(self):
        fmt = FirehoseFormatters(shared_cache=True)
        fh = Firehose(
            unknown_log_activity_type=0x4, unknown_log_type=0, flags=0,
            format_string_location=0x2000, thread_id=0, continuous_time_delta=0,
            continuous_time_delta_upper=0, data_size=0,
            firehose_non_activity=FirehoseNonActivity(firehose_formatters=fmt),
        )
        strings = _FakeStrings({}, {"DSC": _dsc_with_two_images()})
        fs, library, library_uuid, process_uuid, _ = resolve_format_string(
            fh, _preamble(), _catalog_with_uuid_ranges(), strings
        )
        assert fs == "second %s"
        assert library == "/usr/lib/libSystem.B.dylib"
        assert library_uuid == "DSC"
        assert process_uuid == "MAIN"
