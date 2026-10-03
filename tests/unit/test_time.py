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


# ── Anchor selection: binary search must equal the linear walk ────────────────

def _linear_select_anchor(boot, target, preamble):
    """The pre-2026-08 linear walk, kept HERE as the oracle for the new search.

    Deliberately a copy rather than an import: its whole purpose is to be the
    implementation the production code no longer is, so that a change to
    _select_anchor cannot silently change this too.
    """
    chosen = None
    boot_fallback = preamble == 0
    for record in boot.timesync:
        if record.kernel_time > target:
            if chosen is None and not boot_fallback:
                chosen = record
            break
        chosen = record
    if chosen is not None:
        return chosen.kernel_time, chosen.walltime, chosen.timesync_file_id
    if boot_fallback:
        return 0, boot.boot_time, boot.timesync_file_id
    return None


def _boot_with(kernel_times, *, file_id=3):
    records = [
        TimesyncEntry(
            signature=0x207354, unknown_flags=0, kernel_time=kt,
            walltime=_BOOT_TIME_NS + kt, timezone=0, daylight_savings=0,
            file_offset=i * 32, timesync_file_id=file_id,
        )
        for i, kt in enumerate(kernel_times)
    ]
    return TimesyncBoot(
        signature=0xBBB0, header_size=48, unknown=0, boot_uuid=_BOOT_UUID,
        timebase_numerator=1, timebase_denominator=1, boot_time=_BOOT_TIME_NS,
        timezone_offset_mins=0, daylight_savings=0, timesync=records,
        file_offset=0, timesync_file_id=file_id,
    )


class TestAnchorSearchMatchesLinearWalk:
    """The binary search must pick the SAME anchor the linear walk picked.

    This is not a micro-optimisation that can be waved through: the anchor is
    what a timestamp is computed from and what makes the conversion auditable, so
    picking a different one silently moves evidence. Every case below compares
    against the oracle above rather than against a hand-written expectation.
    """

    @pytest.mark.parametrize("preamble", [0, 1])
    @pytest.mark.parametrize("kernel_times", [
        [],                          # no records at all
        [1_000],                     # single record
        [1_000, 2_000, 3_000],       # ordinary ascending run
        [0, 1_000],                  # a record AT zero
        [1_000, 1_000, 2_000],       # duplicate keys — must keep the LAST
    ])
    def test_matches_for_every_target(self, kernel_times, preamble):
        from forensic_aul.engine.utils.time import _select_anchor

        boot = _boot_with(kernel_times)
        # Probe below, on, between and above every record boundary.
        targets = [0, 500, 999, 1_000, 1_001, 1_500, 2_000, 2_500, 3_000, 9_999]
        for target in targets:
            got = _select_anchor(boot, target, preamble, 1, 1)
            want = _linear_select_anchor(boot, target, preamble)
            if want is None:
                assert got is None, f"target={target}: expected no anchor"
                continue
            assert got is not None, f"target={target}: expected an anchor"
            assert (got.kernel_continuous_time, got.walltime_unix_ns,
                    got.timesync_file_id) == want, f"target={target}"

    def test_unsorted_records_fall_back_to_the_walk(self, caplog):
        """Out-of-order records must keep the old behaviour, not a wrong answer.

        A binary search over unsorted keys is undefined; the walk's answer ("stop
        at the first overshoot") is the one every existing database was built
        with, so that is what must survive.
        """
        import logging

        from forensic_aul.engine.utils.time import _select_anchor

        boot = _boot_with([1_000, 5_000, 2_000])
        with caplog.at_level(logging.WARNING):
            got = _select_anchor(boot, 3_000, 1, 1, 1)
        assert "not in ascending" in caplog.text
        want = _linear_select_anchor(boot, 3_000, 1)
        assert (got.kernel_continuous_time, got.walltime_unix_ns,
                got.timesync_file_id) == want

    def test_index_is_rebuilt_when_records_are_merged_in(self):
        """A boot that GAINS records must not answer from the stale index.

        merge_timesync_dicts appends one .timesync file's records to another's
        for the same boot, and it can run after the anchor search has already
        cached an index — so the cache has to notice the list grew.
        """
        from forensic_aul.engine.utils.time import _select_anchor

        boot = _boot_with([1_000])
        first = _select_anchor(boot, 9_000, 1, 1, 1)
        assert first.kernel_continuous_time == 1_000

        boot.timesync.append(TimesyncEntry(
            signature=0x207354, unknown_flags=0, kernel_time=5_000,
            walltime=_BOOT_TIME_NS + 5_000, timezone=0, daylight_savings=0,
            file_offset=64, timesync_file_id=11,
        ))
        second = _select_anchor(boot, 9_000, 1, 1, 1)
        assert second.kernel_continuous_time == 5_000, "stale index was reused"
        assert second.timesync_file_id == 11
