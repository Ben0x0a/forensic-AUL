"""Unit tests for forensic_aul.ops.extraction.entry_builder._firehose_to_log_entry.

Builds synthetic Firehose / FirehosePreamble / CatalogChunk objects and asserts
that the assembled LogEntry has the correct field values for each activity type,
oversize substitution, keep_raw toggle, and normalised-field population.
"""

from __future__ import annotations

import json

import pytest

from forensic_aul.engine.models import (
    CatalogChunk,
    Firehose,
    FirehoseActivity,
    FirehoseFormatters,
    FirehoseItemData,
    FirehoseItemInfo,
    FirehoseLoss,
    FirehoseNonActivity,
    FirehosePreamble,
    FirehoseTrace,
    Oversize,
    ProcessInfoEntry,
    UUIDText,
)
from forensic_aul.engine.parser.firehose import (
    ACTIVITY_TYPE_ACTIVITY,
    ACTIVITY_TYPE_LOSS,
    ACTIVITY_TYPE_NON_ACTIVITY,
    ACTIVITY_TYPE_TRACE,
)
from forensic_aul.engine.parser.uuidtext import DYNAMIC_STRING_OFFSET
from forensic_aul.ops.extraction.entry_builder import _firehose_to_log_entry
from forensic_aul.ops.extraction.oversize_pass import OversizeCache

# ── Boot UUID matching conftest.py fixtures ───────────────────────────────────

_BOOT_UUID = "AABBCCDDEEFF00112233445566778899"
_BOOT_TIME_NS: int = 1_705_315_200_000_000_000


# ── Minimal CatalogChunk (all methods return empty defaults) ──────────────────

def _minimal_catalog() -> CatalogChunk:
    return CatalogChunk(
        chunk_tag=0x600B,
        chunk_sub_tag=0,
        chunk_data_size=0,
        catalog_subsystem_strings_offset=0,
        catalog_process_info_entries_offset=0,
        number_process_information_entries=0,
        catalog_offset_sub_chunks=0,
        number_sub_chunks=0,
        unknown=b"\x00" * 6,
        earliest_firehose_timestamp=0,
        catalog_uuids=[],
        catalog_subsystem_strings=b"",
        catalog_process_info_entries={},
        catalog_subchunks=[],
    )


# ── Minimal FirehosePreamble ──────────────────────────────────────────────────

def _preamble(first_proc_id: int = 1, second_proc_id: int = 2) -> FirehosePreamble:
    return FirehosePreamble(
        chunk_tag=0,
        chunk_sub_tag=0,
        chunk_data_size=0,
        first_number_proc_id=first_proc_id,
        second_number_proc_id=second_proc_id,
        ttl=0,
        collapsed=0,
        unknown=b"\x00\x00",
        public_data_size=0,
        private_data_virtual_offset=0x1000,
        unknown2=0,
        unknown3=0,
        base_continuous_time=0,
    )


# ── Minimal Firehose skeleton (no type-specific payload) ──────────────────────

def _base_firehose(activity_type: int, log_type: int = 0x00) -> Firehose:
    return Firehose(
        unknown_log_activity_type=activity_type,
        unknown_log_type=log_type,
        flags=0,
        format_string_location=DYNAMIC_STRING_OFFSET,
        thread_id=999,
        continuous_time_delta=0,
        continuous_time_delta_upper=0,
        data_size=0,
    )


# ── Stub StringCacheProvider (satisfies FormatStringSource protocol) ──────────

class _StubStrings:
    def get_uuidtext(self, uuid: str):
        return None

    def get_dsc(self, uuid: str):
        return None

    def get_file_id(self, uuid: str):
        return None


# ── Shared call helper ────────────────────────────────────────────────────────

def _call(
    firehose: Firehose,
    preamble: FirehosePreamble | None = None,
    oversize_cache: OversizeCache | None = None,
    timesync_data: dict | None = None,
    boot_uuid: str = _BOOT_UUID,
    *,
    keep_raw: bool = False,
):
    from forensic_aul.engine.models import TimesyncBoot, TimesyncEntry

    ts_entry = TimesyncEntry(
        signature=0x207354,
        unknown_flags=0,
        kernel_time=1_000_000,
        walltime=_BOOT_TIME_NS + 500_000_000,
        timezone=0,
        daylight_savings=0,
    )
    boot = TimesyncBoot(
        signature=0xBBB0,
        header_size=48,
        unknown=0,
        boot_uuid=_BOOT_UUID,
        timebase_numerator=1,
        timebase_denominator=1,
        boot_time=_BOOT_TIME_NS,
        timezone_offset_mins=0,
        daylight_savings=0,
        timesync=[ts_entry],
    )
    td = timesync_data if timesync_data is not None else {_BOOT_UUID: boot}

    return _firehose_to_log_entry(
        firehose=firehose,
        preamble=preamble or _preamble(),
        catalog=_minimal_catalog(),
        strings=_StubStrings(),
        oversize_cache=oversize_cache or {},
        timesync_data=td,
        boot_uuid=boot_uuid,
        tracev3_file_id=1,
        timesync_file_id=None,
        anchor_id_map={},
        chunkset_file_offset=0,
        firehose_inner_offset=0,
        keep_raw=keep_raw,
    )


# ── Test: NonActivity (type 0x4) — basic log entry ───────────────────────────

class TestNonActivity:
    def test_returns_log_entry(self):
        fh = _base_firehose(ACTIVITY_TYPE_NON_ACTIVITY)
        fh.message = FirehoseItemData(
            item_info=[FirehoseItemInfo(message_strings="Hello world", item_type=0x22, item_size=4)],
        )
        entry = _call(fh)
        assert entry is not None

    def test_event_type_is_log(self):
        fh = _base_firehose(ACTIVITY_TYPE_NON_ACTIVITY)
        entry = _call(fh)
        assert entry.event_type == "Log"

    def test_log_level_default(self):
        fh = _base_firehose(ACTIVITY_TYPE_NON_ACTIVITY, log_type=0x00)
        assert _call(fh).log_level == "Default"

    def test_log_level_info(self):
        fh = _base_firehose(ACTIVITY_TYPE_NON_ACTIVITY, log_type=0x01)
        assert _call(fh).log_level == "Info"

    def test_log_level_fault(self):
        fh = _base_firehose(ACTIVITY_TYPE_NON_ACTIVITY, log_type=0x11)
        assert _call(fh).log_level == "Fault"

    def test_boot_uuid_propagated(self):
        fh = _base_firehose(ACTIVITY_TYPE_NON_ACTIVITY)
        assert _call(fh).boot_uuid == _BOOT_UUID

    def test_thread_id_propagated(self):
        fh = _base_firehose(ACTIVITY_TYPE_NON_ACTIVITY)
        fh.thread_id = 12345
        assert _call(fh).tid == 12345

    def test_tracev3_file_id_propagated(self):
        fh = _base_firehose(ACTIVITY_TYPE_NON_ACTIVITY)
        entry = _firehose_to_log_entry(
            firehose=fh,
            preamble=_preamble(),
            catalog=_minimal_catalog(),
            strings=_StubStrings(),
            oversize_cache={},
            timesync_data={},
            boot_uuid=_BOOT_UUID,
            tracev3_file_id=42,
            timesync_file_id=None,
            anchor_id_map={},
            chunkset_file_offset=0,
            firehose_inner_offset=0,
            keep_raw=False,
        )
        assert entry is not None
        assert entry.tracev3_file_id == 42


# ── Test: Loss (type 0x7) ────────────────────────────────────────────────────

class TestLoss:
    def test_event_type_is_loss(self):
        fh = _base_firehose(ACTIVITY_TYPE_LOSS)
        fh.firehose_loss = FirehoseLoss(start_time=100, end_time=200, count=5)
        entry = _call(fh)
        assert entry is not None
        assert entry.event_type == "Loss"

    def test_message_format(self):
        fh = _base_firehose(ACTIVITY_TYPE_LOSS)
        fh.firehose_loss = FirehoseLoss(start_time=100, end_time=200, count=5)
        entry = _call(fh)
        assert "5 messages dropped" in entry.message
        assert "100" in entry.message
        assert "200" in entry.message


# ── Test: Trace (type 0x3) ───────────────────────────────────────────────────

class TestTrace:
    def test_event_type_is_trace(self):
        fh = _base_firehose(ACTIVITY_TYPE_TRACE)
        fh.message = FirehoseItemData(
            item_info=[
                FirehoseItemInfo(message_strings="part1", item_type=0x22, item_size=2),
                FirehoseItemInfo(message_strings="part2", item_type=0x22, item_size=2),
            ],
        )
        entry = _call(fh)
        assert entry is not None
        assert entry.event_type == "Trace"

    def test_message_joins_items(self):
        fh = _base_firehose(ACTIVITY_TYPE_TRACE)
        fh.message = FirehoseItemData(
            item_info=[
                FirehoseItemInfo(message_strings="alpha", item_type=0x22, item_size=2),
                FirehoseItemInfo(message_strings="beta", item_type=0x22, item_size=2),
            ],
        )
        entry = _call(fh)
        assert entry.message == "alpha beta"

    def test_empty_items_gives_empty_message(self):
        fh = _base_firehose(ACTIVITY_TYPE_TRACE)
        fh.message = FirehoseItemData(item_info=[])
        entry = _call(fh)
        assert entry.message == ""


# ── Test: Activity (type 0x2) ─────────────────────────────────────────────────

class TestActivity:
    def test_event_type_is_activity(self):
        fh = _base_firehose(ACTIVITY_TYPE_ACTIVITY)
        fh.firehose_activity = FirehoseActivity(
            unknown_activity_id=111,
            unknown_activity_id_2=222,
        )
        entry = _call(fh)
        assert entry is not None
        assert entry.event_type == "Activity"

    def test_activity_ids_captured(self):
        fh = _base_firehose(ACTIVITY_TYPE_ACTIVITY)
        fh.firehose_activity = FirehoseActivity(
            unknown_activity_id=0xABCD,
            unknown_activity_id_2=0x1234,
        )
        entry = _call(fh)
        assert entry.activity_id == 0xABCD
        assert entry.parent_activity_id == 0x1234

    def test_non_activity_has_zero_activity_ids(self):
        fh = _base_firehose(ACTIVITY_TYPE_NON_ACTIVITY)
        entry = _call(fh)
        assert entry.activity_id == 0
        assert entry.parent_activity_id == 0


# ── Test: Oversize substitution ───────────────────────────────────────────────

class TestOversizeSubstitution:
    def _make_oversize(self, items: list[FirehoseItemInfo]) -> Oversize:
        return Oversize(
            chunk_tag=0,
            chunk_sub_tag=0,
            chunk_data_size=0,
            first_proc_id=1,
            second_proc_id=2,
            ttl=0,
            continuous_time=0,
            data_ref_index=99,
            public_data_size=0,
            private_data_size=0,
            message_items=FirehoseItemData(item_info=items),
        )

    def test_oversize_replaces_message_items(self):
        oversize_items = [FirehoseItemInfo(message_strings="LARGE", item_type=0x22, item_size=5)]
        oversize = self._make_oversize(oversize_items)

        key = (1, 2, 99)
        cache: OversizeCache = {key: oversize}

        fh = _base_firehose(ACTIVITY_TYPE_NON_ACTIVITY)
        fh.firehose_non_activity = FirehoseNonActivity(data_ref_value=99)
        fh.message = FirehoseItemData(
            item_info=[FirehoseItemInfo(message_strings="small", item_type=0x22, item_size=2)],
        )

        entry = _call(fh, oversize_cache=cache, keep_raw=True)
        assert entry is not None
        # raw_data is built from item_data after oversize substitution
        parsed = json.loads(entry.raw_data)
        assert any(item["value"] == "LARGE" for item in parsed)

    def test_no_oversize_when_ref_zero(self):
        cache: OversizeCache = {}
        fh = _base_firehose(ACTIVITY_TYPE_NON_ACTIVITY)
        fh.firehose_non_activity = FirehoseNonActivity(data_ref_value=0)
        fh.message = FirehoseItemData(
            item_info=[FirehoseItemInfo(message_strings="original", item_type=0x22, item_size=4)],
        )
        entry = _call(fh, oversize_cache=cache, keep_raw=True)
        parsed = json.loads(entry.raw_data)
        assert parsed[0]["value"] == "original"


# ── Test: keep_raw toggle ────────────────────────────────────────────────────

class TestKeepRaw:
    def _fh_with_items(self) -> Firehose:
        fh = _base_firehose(ACTIVITY_TYPE_NON_ACTIVITY)
        fh.message = FirehoseItemData(
            item_info=[FirehoseItemInfo(message_strings="val", item_type=0x22, item_size=3)],
        )
        return fh

    def test_keep_raw_false_gives_none(self):
        entry = _call(self._fh_with_items(), keep_raw=False)
        assert entry.raw_data is None

    def test_keep_raw_true_gives_json(self):
        entry = _call(self._fh_with_items(), keep_raw=True)
        assert entry.raw_data is not None
        parsed = json.loads(entry.raw_data)
        assert isinstance(parsed, list)
        assert parsed[0]["value"] == "val"
        assert parsed[0]["type"] == hex(0x22)
        assert parsed[0]["size"] == 3

    def test_keep_raw_true_no_items_still_none(self):
        # Empty item_info → raw_data stays None even with keep_raw=True
        fh = _base_firehose(ACTIVITY_TYPE_NON_ACTIVITY)
        fh.message = FirehoseItemData(item_info=[])
        entry = _call(fh, keep_raw=True)
        assert entry.raw_data is None

    def test_json_dumps_not_called_when_keep_raw_false(self, monkeypatch):
        # Confirm json.dumps is never reached — patch it to crash if called.
        import forensic_aul.ops.extraction.entry_builder as eb
        monkeypatch.setattr(eb.json, "dumps", lambda *a, **kw: (_ for _ in ()).throw(AssertionError("json.dumps called")))
        fh = _base_firehose(ACTIVITY_TYPE_NON_ACTIVITY)
        fh.message = FirehoseItemData(
            item_info=[FirehoseItemInfo(message_strings="x", item_type=0x22, item_size=1)],
        )
        entry = _call(fh, keep_raw=False)
        assert entry.raw_data is None


# ── Test: normalised field population ────────────────────────────────────────

class TestNormalisedFields:
    def test_timestamp_mach_is_continuous_time(self):
        fh = _base_firehose(ACTIVITY_TYPE_NON_ACTIVITY)
        fh.continuous_time_delta = 1000
        fh.continuous_time_delta_upper = 0
        p = _preamble()
        p.base_continuous_time = 500
        entry = _call(fh, preamble=p)
        assert entry.timestamp_mach == 1500

    def test_unknown_log_type_falls_back_to_default(self):
        fh = _base_firehose(ACTIVITY_TYPE_NON_ACTIVITY, log_type=0xFF)
        entry = _call(fh)
        assert entry.log_level == "Default"

    def test_chunkset_offset_stored(self):
        fh = _base_firehose(ACTIVITY_TYPE_NON_ACTIVITY)
        entry = _firehose_to_log_entry(
            firehose=fh,
            preamble=_preamble(),
            catalog=_minimal_catalog(),
            strings=_StubStrings(),
            oversize_cache={},
            timesync_data={},
            boot_uuid=_BOOT_UUID,
            tracev3_file_id=1,
            timesync_file_id=None,
            anchor_id_map={},
            chunkset_file_offset=0xDEAD,
            firehose_inner_offset=0xBEEF,
            keep_raw=False,
        )
        assert entry is not None
        assert entry.tracev3_chunkset_file_offset == 0xDEAD
        assert entry.tracev3_firehose_inner_offset == 0xBEEF

    def test_format_string_file_offset_always_none(self):
        # This field is populated in a later pass, not during entry assembly.
        fh = _base_firehose(ACTIVITY_TYPE_NON_ACTIVITY)
        entry = _call(fh)
        assert entry.format_string_file_offset is None


# ── Test: process name resolution ────────────────────────────────────────────

_SPRINGBOARD = "/System/Library/CoreServices/SpringBoard.app/SpringBoard"
_MAIN_UUID = "1FE459BBDC3E19BBF82D58415A2AE9AB"


def _uuidtext(uuid: str, image_path: str) -> UUIDText:
    return UUIDText(
        uuid=uuid, signature=0x66778899, major_version=2, minor_version=0,
        entry_descriptors=[], footer_data=b"", image_path=image_path,
    )


def _catalog_with_main_uuid() -> CatalogChunk:
    """A catalog whose single process resolves to _MAIN_UUID as its main exe."""
    proc = ProcessInfoEntry(
        index=0, unknown=0, catalog_main_uuid_index=0, catalog_dsc_uuid_index=0,
        first_number_proc_id=1, second_number_proc_id=2, pid=10, effective_user_id=0,
        unknown2=0, number_uuids_entries=0, unknown3=0, uuid_info_entries=[],
        number_subsystems=0, unknown4=0, subsystem_entries=[],
        main_uuid=_MAIN_UUID, dsc_uuid="",
    )
    catalog = _minimal_catalog()
    catalog.catalog_uuids = [_MAIN_UUID]
    catalog.catalog_process_info_entries = {"1_2": proc}
    return catalog


class _MainExeStrings:
    """String source resolving _MAIN_UUID to a UUIDText with an image path."""

    def __init__(self, image_path: str | None = _SPRINGBOARD):
        self._image_path = image_path

    def get_uuidtext(self, uuid: str):
        if uuid == _MAIN_UUID and self._image_path is not None:
            return _uuidtext(uuid, self._image_path)
        return None

    def get_dsc(self, uuid: str):
        return None

    def get_file_id(self, uuid: str):
        return None


def _main_exe_firehose() -> Firehose:
    fh = _base_firehose(ACTIVITY_TYPE_NON_ACTIVITY)
    fh.format_string_location = 0x100  # not DYNAMIC — forces a real lookup
    fh.firehose_non_activity = FirehoseNonActivity(
        firehose_formatters=FirehoseFormatters(main_exe=True),
    )
    return fh


def _call_with_strings(fh: Firehose, strings, catalog: CatalogChunk):
    return _firehose_to_log_entry(
        firehose=fh,
        preamble=_preamble(),
        catalog=catalog,
        strings=strings,
        oversize_cache={},
        timesync_data={},
        boot_uuid=_BOOT_UUID,
        tracev3_file_id=1,
        timesync_file_id=None,
        anchor_id_map={},
        chunkset_file_offset=0,
        firehose_inner_offset=0,
        keep_raw=False,
    )


class TestProcessName:
    def test_process_is_basename_of_the_image_path(self):
        entry = _call_with_strings(
            _main_exe_firehose(), _MainExeStrings(), _catalog_with_main_uuid()
        )
        assert entry.process == "SpringBoard"

    def test_library_keeps_the_full_path(self):
        entry = _call_with_strings(
            _main_exe_firehose(), _MainExeStrings(), _catalog_with_main_uuid()
        )
        assert entry.library == _SPRINGBOARD

    def test_process_is_never_the_raw_uuid_when_a_path_exists(self):
        entry = _call_with_strings(
            _main_exe_firehose(), _MainExeStrings(), _catalog_with_main_uuid()
        )
        assert entry.process != _MAIN_UUID
        assert entry.process_uuid == _MAIN_UUID

    def test_falls_back_to_the_uuid_without_a_uuidtext(self):
        entry = _call_with_strings(
            _main_exe_firehose(), _StubStrings(), _catalog_with_main_uuid()
        )
        assert entry.process == _MAIN_UUID
        assert entry.library == ""

    def test_falls_back_to_the_uuid_when_the_path_is_empty(self):
        entry = _call_with_strings(
            _main_exe_firehose(), _MainExeStrings(image_path=""),
            _catalog_with_main_uuid(),
        )
        assert entry.process == _MAIN_UUID

    def test_empty_process_when_nothing_resolves(self):
        entry = _call(_base_firehose(ACTIVITY_TYPE_NON_ACTIVITY))
        assert entry.process == ""

    def test_image_path_lookup_is_memoised(self):
        # The provider must be consulted once per process UUID, not per entry.
        class _CountingStrings(_MainExeStrings):
            calls = 0

            def get_uuidtext(self, uuid: str):
                _CountingStrings.calls += 1
                return super().get_uuidtext(uuid)

        strings = _CountingStrings()
        catalog = _catalog_with_main_uuid()
        for _ in range(5):
            _call_with_strings(_main_exe_firehose(), strings, catalog)
        # resolve_format_string performs one lookup per entry; the process-name
        # memo must add only the single extra lookup for the first entry.
        assert _CountingStrings.calls == 6
