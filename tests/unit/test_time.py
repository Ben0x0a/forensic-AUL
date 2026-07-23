"""Tests for forensic_aul.engine.utils.time — mach→wall clock conversion."""

import pytest
from forensic_aul.engine.utils.time import (
    iso8601_from_unix_ns,
    mach_to_iso8601,
    mach_to_wall_ns,
)
from forensic_aul.engine.models import TimesyncBoot, TimesyncEntry

# Shared constants (mirrored from conftest for standalone readability)
_BOOT_UUID     = "AABBCCDDEEFF00112233445566778899"
_BOOT_TIME_NS  = 1_705_315_200_000_000_000   # 2024-01-15 12:00:00 UTC
_SYNC_K_TIME   = 1_000_000                   # kernel_time of sync record
_SYNC_WALL_NS  = _BOOT_TIME_NS + 500_000_000 # wall time at sync record


def _make_boot(*, num=1, den=1, sync_records=None) -> tuple[dict, str]:
    """Return (timesync_data dict, boot_uuid) for the given timebase."""
    entry = TimesyncEntry(
        signature=0x207354, unknown_flags=0,
        kernel_time=_SYNC_K_TIME, walltime=_SYNC_WALL_NS,
        timezone=0, daylight_savings=0,
    )
    boot = TimesyncBoot(
        signature=0xBBB0, header_size=48, unknown=0,
        boot_uuid=_BOOT_UUID,
        timebase_numerator=num, timebase_denominator=den,
        boot_time=_BOOT_TIME_NS,
        timezone_offset_mins=0, daylight_savings=0,
        timesync=sync_records if sync_records is not None else [entry],
    )
    return {_BOOT_UUID: boot}, _BOOT_UUID


class TestMachToWallNs:
    def test_unknown_boot_uuid_returns_zero(self):
        ts, _ = _make_boot()
        assert mach_to_wall_ns(ts, "UNKNOWNUUID", 999, 0) == 0

    def test_before_sync_record_uses_sync_as_anchor(self):
        # When preamble_time != 0 and target < first sync record's kernel_time,
        # the implementation uses the first sync record as anchor (extrapolates backward).
        ts, uuid = _make_boot()
        target = 500_000  # before sync record at kernel_time=1_000_000
        result = mach_to_wall_ns(ts, uuid, target, _BOOT_TIME_NS)
        # anchor = sync record (1_000_000, _SYNC_WALL_NS), delta = -500_000
        expected = _SYNC_WALL_NS + (target - _SYNC_K_TIME)  # _SYNC_WALL_NS - 500_000
        assert result == expected

    def test_after_sync_record_uses_sync_anchor(self):
        ts, uuid = _make_boot()
        target = _SYNC_K_TIME + 200_000  # 200µs after sync
        result = mach_to_wall_ns(ts, uuid, target, _BOOT_TIME_NS)
        expected = _SYNC_WALL_NS + 200_000
        assert result == expected

    def test_arm_timebase_scaling(self):
        # ARM: 125/3 ≈ 41.67 ns per tick
        ts, uuid = _make_boot(num=125, den=3)
        # At exactly the sync point → 0 delta
        result = mach_to_wall_ns(ts, uuid, _SYNC_K_TIME, _BOOT_TIME_NS)
        assert result == _SYNC_WALL_NS

    def test_arm_delta_scaled_correctly(self):
        ts, uuid = _make_boot(num=125, den=3)
        delta_ticks = 3  # should scale to 125 ns
        result = mach_to_wall_ns(ts, uuid, _SYNC_K_TIME + delta_ticks, _BOOT_TIME_NS)
        assert result == _SYNC_WALL_NS + 125  # 3 * 125 / 3 = 125 ns

    def test_preamble_zero_uses_boot_time(self):
        ts, uuid = _make_boot()
        result = mach_to_wall_ns(ts, uuid, 0, 0)
        assert result == _BOOT_TIME_NS

    def test_multiple_sync_records_picks_last_before_target(self):
        records = [
            TimesyncEntry(0x207354, 0, kernel_time=1_000, walltime=_BOOT_TIME_NS + 100, timezone=0, daylight_savings=0),
            TimesyncEntry(0x207354, 0, kernel_time=5_000, walltime=_BOOT_TIME_NS + 500, timezone=0, daylight_savings=0),
            TimesyncEntry(0x207354, 0, kernel_time=9_000, walltime=_BOOT_TIME_NS + 900, timezone=0, daylight_savings=0),
        ]
        ts, uuid = _make_boot(sync_records=records)
        target = 7_000  # between record[1] and record[2]
        result = mach_to_wall_ns(ts, uuid, target, 1)  # preamble non-zero
        # anchor should be record at kernel_time=5_000
        expected = _BOOT_TIME_NS + 500 + (7_000 - 5_000)
        assert result == expected


class TestMachToIso8601:
    def test_output_format(self, timesync_data):
        iso = mach_to_iso8601(timesync_data, _BOOT_UUID, _SYNC_K_TIME, _BOOT_TIME_NS)
        # Must be parseable ISO 8601: "YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ"
        import re
        pattern = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z"
        assert re.fullmatch(pattern, iso), f"Unexpected format: {iso!r}"

    def test_unknown_uuid_returns_epoch(self, timesync_data):
        result = mach_to_iso8601(timesync_data, "UNKNOWN", 0, 0)
        assert result == "1970-01-01T00:00:00.000000000Z"

    def test_known_timestamp_value(self, timesync_data):
        # _SYNC_K_TIME with preamble=_BOOT_TIME_NS → wall = _SYNC_WALL_NS
        # _BOOT_TIME_NS = 1_705_315_200_000_000_000 ns = 2024-01-15T10:40:00 UTC
        iso = mach_to_iso8601(timesync_data, _BOOT_UUID, _SYNC_K_TIME, _BOOT_TIME_NS)
        assert iso.startswith("2024-01-15T10:40:00.")
        assert iso.endswith("Z")
        assert len(iso) == len("2024-01-15T10:40:00.000000000Z")


class TestIso8601SubSecond:
    """Regression for L1: the sub-second fraction must be preserved in full.

    The earlier bug built ``dt`` from whole seconds (so ``dt.microsecond`` was
    always 0) and appended only ``ns % 1000`` — printing ``.000000<3 digits>``.
    All previous tests used second-aligned values, so it slipped through. These
    cases use a non-second-aligned nanosecond instant on purpose.
    """

    def test_full_nanosecond_fraction_preserved(self):
        # 2024-01-01T00:00:00 UTC + 123_456_789 ns
        ns = 1_704_067_200_000_000_000 + 123_456_789
        assert iso8601_from_unix_ns(ns) == "2024-01-01T00:00:00.123456789Z"

    def test_microsecond_part_not_dropped(self):
        # A value whose µs part is non-zero (the part the old code dropped).
        ns = 1_704_067_200_000_000_000 + 500_000_000  # .5 s exactly
        assert iso8601_from_unix_ns(ns) == "2024-01-01T00:00:00.500000000Z"

    def test_sub_microsecond_only(self):
        ns = 1_704_067_200_000_000_000 + 789  # 789 ns, no µs
        assert iso8601_from_unix_ns(ns) == "2024-01-01T00:00:00.000000789Z"

    def test_second_aligned_still_all_zeros(self):
        ns = 1_704_067_200_000_000_000
        assert iso8601_from_unix_ns(ns) == "2024-01-01T00:00:00.000000000Z"
