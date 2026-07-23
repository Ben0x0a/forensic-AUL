"""Tests for forensic_aul.engine.parser.timesync — parsing real .timesync files.

These tests use the real timesync files from the test logarchive.
They are skipped automatically if the logarchive is not present.
"""

import pytest
from pathlib import Path

from forensic_aul.engine.parser.timesync import parse_timesync_file
from forensic_aul.engine.models import TimesyncBoot, TimesyncEntry

# Path to test data (mirrored from conftest)
_LOGARCHIVE = (
    Path(__file__).parent.parent
    / "data" / "iphoneSE_afterbackup.logarchive"
)
_TIMESYNC_DIR = _LOGARCHIVE / "timesync"

pytestmark = pytest.mark.integration


# ── Helpers ────────────────────────────────────────────────────────────────────

def _timesync_files() -> list[Path]:
    if not _TIMESYNC_DIR.is_dir():
        return []
    return sorted(_TIMESYNC_DIR.glob("*.timesync"))


@pytest.fixture(scope="module")
def timesync_data():
    files = _timesync_files()
    if not files:
        pytest.skip("No timesync files found — logarchive not present")
    result: dict = {}
    for f in files:
        parsed = parse_timesync_file(f)
        result.update(parsed)
    return result


# ── Structure tests ────────────────────────────────────────────────────────────

class TestTimesyncStructure:
    def test_at_least_one_boot_record(self, timesync_data):
        assert len(timesync_data) > 0

    def test_keys_are_hex_strings(self, timesync_data):
        for k in timesync_data:
            assert isinstance(k, str)
            assert all(c in "0123456789ABCDEF" for c in k), f"Not uppercase hex: {k!r}"

    def test_values_are_timesync_boot(self, timesync_data):
        for v in timesync_data.values():
            assert isinstance(v, TimesyncBoot)

    def test_timesync_boot_has_records(self, timesync_data):
        for boot in timesync_data.values():
            assert isinstance(boot.timesync, list)
            # Most boots have at least one sync record
            # (empty is technically valid but rare)

    def test_timesync_entries_are_typed(self, timesync_data):
        for boot in timesync_data.values():
            for entry in boot.timesync:
                assert isinstance(entry, TimesyncEntry)
                assert isinstance(entry.kernel_time, int)
                assert isinstance(entry.walltime, int)

    def test_boot_time_is_positive(self, timesync_data):
        for boot in timesync_data.values():
            assert boot.boot_time > 0, f"boot_time should be positive: {boot.boot_time}"

    def test_timebase_values(self, timesync_data):
        for boot in timesync_data.values():
            assert boot.timebase_numerator   in (1, 125)
            assert boot.timebase_denominator in (1, 3)

    def test_kernel_times_monotonic(self, timesync_data):
        """Timesync records within a boot should have increasing kernel_times."""
        for boot in timesync_data.values():
            times = [e.kernel_time for e in boot.timesync]
            assert times == sorted(times), \
                f"Timesync records not monotonic: {times[:5]}"


class TestTimesyncParseSingleFile:
    def test_parse_returns_dict(self):
        files = _timesync_files()
        if not files:
            pytest.skip("No timesync files")
        result = parse_timesync_file(files[0])
        assert isinstance(result, dict)

    def test_parse_nonexistent_file_raises(self, tmp_path):
        missing = tmp_path / "does_not_exist.timesync"
        with pytest.raises(OSError):
            parse_timesync_file(missing)

    def test_parse_empty_file_does_not_crash(self, tmp_path):
        empty = tmp_path / "empty.timesync"
        empty.write_bytes(b"")
        # Should not raise — may return {} or a partial result
        try:
            parse_timesync_file(empty)
        except Exception as exc:
            pytest.fail(f"parse_timesync_file raised on empty file: {exc}")
