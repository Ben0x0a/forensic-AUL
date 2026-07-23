"""Unit tests for cross-file timesync merging (L4 regression).

A boot UUID can appear in more than one ``.timesync`` file. The earlier bug used
``dict.update`` at the extract call site, which *replaced* the earlier record
list, and a per-boot file-id map that kept only the last file — so anchors for
records that came from the first file were silently lost or mis-attributed.

These tests exercise the building blocks directly (no logarchive needed):
``merge_timesync_dicts`` for the append semantics, and ``_select_anchor`` for
per-record source-file attribution after the extract step stamps file ids.
"""

from forensic_aul.engine.models import TimesyncBoot, TimesyncEntry
from forensic_aul.engine.parser.timesync import merge_timesync_dicts
from forensic_aul.engine.utils.time import _select_anchor

_BOOT_UUID = "AABBCCDDEEFF00112233445566778899"
_OTHER_UUID = "00112233445566778899AABBCCDDEEFF"
_BOOT_TIME_NS = 1_705_315_200_000_000_000


def _entry(kernel_time: int, walltime: int, *, offset: int) -> TimesyncEntry:
    return TimesyncEntry(
        signature=0x207354, unknown_flags=0,
        kernel_time=kernel_time, walltime=walltime,
        timezone=0, daylight_savings=0, file_offset=offset,
    )


def _boot(uuid: str, records: list[TimesyncEntry], *, offset: int = 0) -> TimesyncBoot:
    return TimesyncBoot(
        signature=0xBBB0, header_size=48, unknown=0, boot_uuid=uuid,
        timebase_numerator=1, timebase_denominator=1, boot_time=_BOOT_TIME_NS,
        timezone_offset_mins=0, daylight_savings=0,
        timesync=list(records), file_offset=offset,
    )


def _stamp(data: dict[str, TimesyncBoot], file_id: int) -> dict[str, TimesyncBoot]:
    """Mirror extract step 4: stamp the source-file id onto boot + records."""
    for boot in data.values():
        boot.timesync_file_id = file_id
        for rec in boot.timesync:
            rec.timesync_file_id = file_id
    return data


class TestMergeTimesyncDicts:
    def test_shared_boot_uuid_appends_records(self):
        base = {_BOOT_UUID: _boot(_BOOT_UUID, [_entry(1_000, _BOOT_TIME_NS + 100, offset=48)])}
        new = {_BOOT_UUID: _boot(_BOOT_UUID, [_entry(5_000, _BOOT_TIME_NS + 500, offset=48)])}
        merge_timesync_dicts(base, new)
        # Records APPEND, not replace — the earlier file's record survives.
        assert [r.kernel_time for r in base[_BOOT_UUID].timesync] == [1_000, 5_000]

    def test_distinct_boot_uuid_added(self):
        base = {_BOOT_UUID: _boot(_BOOT_UUID, [_entry(1_000, _BOOT_TIME_NS + 100, offset=48)])}
        new = {_OTHER_UUID: _boot(_OTHER_UUID, [_entry(2_000, _BOOT_TIME_NS + 200, offset=48)])}
        merge_timesync_dicts(base, new)
        assert set(base) == {_BOOT_UUID, _OTHER_UUID}


class TestPerRecordFileAttribution:
    def test_anchor_carries_originating_file_id(self):
        # File 10 contributes an early record, file 11 a later one for the SAME boot.
        file_a = _stamp({_BOOT_UUID: _boot(_BOOT_UUID, [_entry(1_000, _BOOT_TIME_NS + 100, offset=48)])}, 10)
        file_b = _stamp({_BOOT_UUID: _boot(_BOOT_UUID, [_entry(5_000, _BOOT_TIME_NS + 500, offset=48)])}, 11)
        merge_timesync_dicts(file_a, file_b)
        boot = file_a[_BOOT_UUID]

        # A target after the early record but before the late one → file 10's record.
        anchor_early = _select_anchor(boot, 3_000, firehose_preamble_time=1, timebase_num=1, timebase_den=1)
        assert anchor_early.timesync_file_id == 10
        assert anchor_early.kernel_continuous_time == 1_000

        # A target after the late record → file 11's record.
        anchor_late = _select_anchor(boot, 9_000, firehose_preamble_time=1, timebase_num=1, timebase_den=1)
        assert anchor_late.timesync_file_id == 11
        assert anchor_late.kernel_continuous_time == 5_000

    def test_boot_fallback_uses_boot_file_id(self):
        boot = _stamp({_BOOT_UUID: _boot(_BOOT_UUID, [], offset=0)}, 7)[_BOOT_UUID]
        # preamble_time == 0 → boot record itself is the anchor.
        anchor = _select_anchor(boot, 0, firehose_preamble_time=0, timebase_num=1, timebase_den=1)
        assert anchor.timesync_file_id == 7
        assert anchor.kernel_continuous_time == 0
