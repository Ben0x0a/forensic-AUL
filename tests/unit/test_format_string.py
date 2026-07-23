"""Unit tests for format-string resolution offset math (L2/L3 regressions).

L2: the DSC large-offset must be hex-concatenated above the 32-bit string offset
(``lo << 32 | offset``), with the Apple recovery rule and the shared_cache=8 case,
matching ``nonactivity.rs``. The earlier code did ``(large_shared_cache << 16) |
(offset & 0xFFFF)`` and also wrongly applied a large offset on the main_exe path.

L3: ``absolute`` entries resolve against an alternative UUIDText file chosen by
load-address range, not the main exe.
"""

from forensic_aul.engine.models import (
    CatalogChunk,
    Firehose,
    FirehoseFormatters,
    FirehoseNonActivity,
    FirehosePreamble,
    ProcessInfoEntry,
    ProcessUUIDEntry,
    UUIDText,
)
from forensic_aul.engine.parser.format_string import (
    _dsc_effective_offset,
    resolve_format_string,
)


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
    def __init__(self, uuidtexts):
        self._uuidtexts = uuidtexts

    def get_uuidtext(self, uuid):
        return self._uuidtexts.get(uuid)

    def get_dsc(self, uuid):
        return None

    def get_file_id(self, uuid):
        return 99 if uuid in self._uuidtexts else None


def _empty_uuidtext(uuid):
    """A minimal empty UUIDText — the test asserts *selection*, not byte parsing."""
    return UUIDText(
        uuid=uuid, signature=0x66778899, major_version=2, minor_version=0,
        entry_descriptors=[], footer_data=b"",
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
