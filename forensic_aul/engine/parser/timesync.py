"""Parse Apple Unified Log timesync files.

Timesync files contain records that map mach continuous time to wall-clock time.
They are stored in the logarchive's timesync/ directory.

Binary layout reference: macos-UnifiedLogs/src/timesync.rs
"""

from __future__ import annotations

import logging
from pathlib import Path

from forensic_aul.engine.models import TimesyncBoot, TimesyncEntry

log = logging.getLogger(__name__)

# File-level signatures
SIG_BOOT: int = 0xBBB0        # u16 — start of a TimesyncBoot record
SIG_RECORD: int = 0x207354    # u32 — start of a Timesync record

BOOT_HEADER_SIZE: int = 48    # total size of the boot record header


def parse_timesync_file(path: Path) -> dict[str, TimesyncBoot]:
    """Parse a single .timesync file and return a dict keyed by boot_uuid.

    Multiple boot records may exist in one file. If the same boot_uuid appears
    across multiple files, timesync records are merged into the existing entry.

    Args:
        path: Path to a .timesync file.

    Returns:
        dict mapping boot_uuid (uppercase hex, no dashes) to TimesyncBoot.

    Raises:
        OSError: if the file cannot be opened.
        EOFError: if the file is truncated unexpectedly.
    """
    result: dict[str, TimesyncBoot] = {}
    data = path.read_bytes()
    pos = 0
    current_boot: TimesyncBoot | None = None

    while pos < len(data):
        if len(data) - pos < 4:
            break

        # Peek at the signature to decide record type.
        # Boot signature is u16; timesync record signature is u32.
        sig_u32 = int.from_bytes(data[pos : pos + 4], "little")

        if sig_u32 == SIG_RECORD:
            if current_boot is None:
                log.warning(f"Timesync record at offset 0x{pos:x} has no preceding boot record in {path}")
                pos += _TIMESYNC_RECORD_SIZE
                continue
            record_offset = pos
            entry, consumed = _parse_timesync_record(data, pos)
            if entry is None:
                break
            entry.file_offset = record_offset
            current_boot.timesync.append(entry)
            pos += consumed

        else:
            # Should be a boot record; commit current boot first
            if current_boot is not None:
                _merge_boot(result, current_boot)

            boot_offset = pos
            boot, consumed = _parse_timesync_boot(data, pos)
            if boot is None:
                log.error(f"Failed to parse timesync boot record at offset 0x{pos:x} in {path}")
                break
            boot.file_offset = boot_offset
            current_boot = boot
            pos += consumed

    if current_boot is not None:
        _merge_boot(result, current_boot)

    return result


def merge_timesync_dicts(
    base: dict[str, TimesyncBoot], new: dict[str, TimesyncBoot]
) -> None:
    """Merge *new* into *base* in-place, appending timesync records for matching UUIDs."""
    for uuid, boot in new.items():
        if uuid in base:
            base[uuid].timesync.extend(boot.timesync)
        else:
            base[uuid] = boot


# ── Internal helpers ──────────────────────────────────────────────────────────

_BOOT_PAYLOAD_SIZE: int = 46  # after the u16 signature
_TIMESYNC_RECORD_SIZE: int = 32


def _parse_timesync_boot(
    data: bytes, pos: int
) -> tuple[TimesyncBoot | None, int]:
    """Parse one TimesyncBoot record starting at *pos*.

    Returns (TimesyncBoot, bytes_consumed) or (None, 0) on error.
    """
    start = pos
    needed = 2 + 2 + 4 + 16 + 4 + 4 + 8 + 4 + 4  # = 48 bytes
    if pos + needed > len(data):
        log.error(f"Truncated timesync boot record at 0x{pos:x}")
        return None, 0

    sig = int.from_bytes(data[pos : pos + 2], "little")
    if sig != SIG_BOOT:
        log.error(f"Invalid timesync boot signature 0x{sig:x} at offset 0x{pos:x} (expected 0x{SIG_BOOT:x})")
        return None, 0

    pos += 2
    header_size = int.from_bytes(data[pos : pos + 2], "little")
    pos += 2
    unknown = int.from_bytes(data[pos : pos + 4], "little")
    pos += 4
    boot_uuid = format(int.from_bytes(data[pos : pos + 16], "big"), "032X")
    pos += 16
    timebase_numerator = int.from_bytes(data[pos : pos + 4], "little")
    pos += 4
    timebase_denominator = int.from_bytes(data[pos : pos + 4], "little")
    pos += 4
    boot_time = int.from_bytes(data[pos : pos + 8], "little", signed=True)
    pos += 8
    timezone_offset_mins = int.from_bytes(data[pos : pos + 4], "little")
    pos += 4
    daylight_savings = int.from_bytes(data[pos : pos + 4], "little")
    pos += 4

    consumed = pos - start
    return (
        TimesyncBoot(
            signature=sig,
            header_size=header_size,
            unknown=unknown,
            boot_uuid=boot_uuid,
            timebase_numerator=timebase_numerator,
            timebase_denominator=timebase_denominator,
            boot_time=boot_time,
            timezone_offset_mins=timezone_offset_mins,
            daylight_savings=daylight_savings,
        ),
        consumed,
    )


def _parse_timesync_record(
    data: bytes, pos: int
) -> tuple[TimesyncEntry | None, int]:
    """Parse one Timesync record starting at *pos* (32 bytes total).

    Returns (TimesyncEntry, bytes_consumed) or (None, 0) on error.
    """
    if pos + _TIMESYNC_RECORD_SIZE > len(data):
        log.error(f"Truncated timesync record at 0x{pos:x}")
        return None, 0

    sig = int.from_bytes(data[pos : pos + 4], "little")
    if sig != SIG_RECORD:
        log.error(f"Invalid timesync record signature 0x{sig:x} at 0x{pos:x} (expected 0x{SIG_RECORD:x})")
        return None, 0

    unknown_flags = int.from_bytes(data[pos + 4 : pos + 8], "little")
    kernel_time = int.from_bytes(data[pos + 8 : pos + 16], "little")
    walltime = int.from_bytes(data[pos + 16 : pos + 24], "little", signed=True)
    timezone = int.from_bytes(data[pos + 24 : pos + 28], "little")
    daylight_savings = int.from_bytes(data[pos + 28 : pos + 32], "little")

    return (
        TimesyncEntry(
            signature=sig,
            unknown_flags=unknown_flags,
            kernel_time=kernel_time,
            walltime=walltime,
            timezone=timezone,
            daylight_savings=daylight_savings,
        ),
        _TIMESYNC_RECORD_SIZE,
    )


def _merge_boot(dest: dict[str, TimesyncBoot], boot: TimesyncBoot) -> None:
    if boot.boot_uuid in dest:
        dest[boot.boot_uuid].timesync.extend(boot.timesync)
    else:
        dest[boot.boot_uuid] = boot
