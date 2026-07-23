"""Global pytest fixtures shared across all test layers."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from forensic_aul.engine.database.schema import apply_pragmas, init_schema
from forensic_aul.engine.database.writer import BatchWriter
from forensic_aul.engine.models import (
    LogEntry,
    TimesyncBoot,
    TimesyncEntry,
)

# ── Paths to test data ─────────────────────────────────────────────────────────

_TESTS = Path(__file__).parent
LOGARCHIVE_PATH  = _TESTS / "data"  / "iphoneSE_afterbackup.logarchive"
NDJSON_PATH      = _TESTS / "results" / "expected" / "iphoneSE_afterbackup.ndjson"


# ── Database fixtures ──────────────────────────────────────────────────────────

@pytest.fixture
def conn() -> sqlite3.Connection:
    """In-memory SQLite connection with full schema applied."""
    c = sqlite3.connect(":memory:")
    apply_pragmas(c)
    init_schema(c)
    yield c
    c.close()


@pytest.fixture
def writer(conn) -> BatchWriter:
    """BatchWriter backed by the in-memory connection."""
    return BatchWriter(conn, batch_size=100)


# ── Timesync fixtures ──────────────────────────────────────────────────────────

_BOOT_UUID = "AABBCCDDEEFF00112233445566778899"

# Wall time reference: 2024-01-15 12:00:00 UTC in ns
_BOOT_TIME_NS: int = 1_705_315_200_000_000_000
# A later timesync record anchored at kernel_time = 1_000_000 (≈1 ms)
_SYNC_KERNEL_TIME: int = 1_000_000
_SYNC_WALLTIME_NS: int = _BOOT_TIME_NS + 500_000_000  # 0.5 s later


@pytest.fixture
def timesync_entry() -> TimesyncEntry:
    return TimesyncEntry(
        signature=0x207354,
        unknown_flags=0,
        kernel_time=_SYNC_KERNEL_TIME,
        walltime=_SYNC_WALLTIME_NS,
        timezone=0,
        daylight_savings=0,
    )


@pytest.fixture
def timesync_boot(timesync_entry) -> TimesyncBoot:
    """Intel-style (1/1) TimesyncBoot with one sync record."""
    return TimesyncBoot(
        signature=0xBBB0,
        header_size=48,
        unknown=0,
        boot_uuid=_BOOT_UUID,
        timebase_numerator=1,
        timebase_denominator=1,
        boot_time=_BOOT_TIME_NS,
        timezone_offset_mins=0,
        daylight_savings=0,
        timesync=[timesync_entry],
    )


@pytest.fixture
def timesync_boot_arm(timesync_entry) -> TimesyncBoot:
    """ARM-style (125/3) TimesyncBoot — tests timebase scaling."""
    return TimesyncBoot(
        signature=0xBBB0,
        header_size=48,
        unknown=0,
        boot_uuid=_BOOT_UUID,
        timebase_numerator=125,
        timebase_denominator=3,
        boot_time=_BOOT_TIME_NS,
        timezone_offset_mins=0,
        daylight_savings=0,
        timesync=[timesync_entry],
    )


@pytest.fixture
def timesync_data(timesync_boot) -> dict:
    return {_BOOT_UUID: timesync_boot}


@pytest.fixture
def timesync_data_arm(timesync_boot_arm) -> dict:
    return {_BOOT_UUID: timesync_boot_arm}


# ── LogEntry fixture ───────────────────────────────────────────────────────────

@pytest.fixture
def sample_log_entry() -> LogEntry:
    # FK fields are None so tests can write without pre-inserting source_files rows.
    # Likewise the byte-offset fields are None — they'd point into source files
    # that the test does not provide.
    return LogEntry(
        tracev3_file_id=None,
        format_src_file_id=None,
        timesync_file_id=None,
        tracev3_chunkset_file_offset=None,
        tracev3_firehose_inner_offset=None,
        tracev3_entry_inner_offset=None,
        format_string_file_offset=None,
        timestamp_iso="2024-01-15T12:00:01.000000000Z",
        timestamp_unix_ns=1_705_315_201_000_000_000,
        timestamp_mach=1_001_000_000,
        timesync_anchor_id=None,
        process="syslogd",
        pid=42,
        tid=101,
        euid=0,
        log_level="Default",
        event_type="Log",
        subsystem="com.apple.system",
        category="syslog",
        message="Hello, world!",
        message_format_string="Hello, %s!",
        library="/usr/lib/libSystem.B.dylib",
        library_uuid="DEADBEEFDEADBEEFDEADBEEFDEADBEEF",
        process_uuid="CAFEBABECAFEBABECAFEBABECAFEBABE",
        activity_id=0,
        parent_activity_id=0,
        boot_uuid=_BOOT_UUID,
        raw_data=None,
    )
