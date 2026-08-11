"""Mach continuous time → wall clock time conversion.

Algorithm ported from macos-UnifiedLogs/src/timesync.rs :: TimesyncBoot::get_timestamp().

The public entry point is :func:`resolve_mach_timestamp`, which returns a
:class:`TimestampResolution` carrying the ISO string, the unix-nanosecond
value, and the *anchor* used to compute them. The anchor is the link back
to the source .timesync file (file id + byte offset) and is what makes
the conversion forensically reproducible.

Two thin compatibility wrappers (:func:`mach_to_wall_ns`,
:func:`mach_to_iso8601`) are kept for older callers and tests.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from forensic_aul.engine.models import (
    TimestampResolution,
    TimesyncAnchor,
    TimesyncBoot,
)

log = logging.getLogger(__name__)

# Nanoseconds per second — used for final conversion to datetime
_NS_PER_SEC: int = 1_000_000_000

_DEFAULT_ISO_ON_FAILURE = "1970-01-01T00:00:00.000000000Z"


_DURATION_RE = re.compile(r"(\d+(?:\.\d+)?)\s*([smhd])")
_DURATION_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration_seconds(value: str) -> int | None:
    """Parse a short duration like ``10m`` / ``1h`` / ``24h`` / ``7d`` / ``30s``.

    Returns the number of seconds, or None if *value* is not a recognised
    ``<number><s|m|h|d>`` duration. Consumed by the shared
    ``last`` filter of the query/export readers (ops/query/reader.py).
    """
    m = _DURATION_RE.fullmatch(value.strip().lower())
    if not m:
        return None
    amount, unit = float(m.group(1)), m.group(2)
    return int(amount * _DURATION_UNIT_SECONDS[unit])


def resolve_mach_timestamp(
    timesync_data: dict[str, TimesyncBoot],
    boot_uuid: str,
    firehose_log_delta_time: int,
    firehose_preamble_time: int,
) -> TimestampResolution:
    """Convert a mach continuous time to wall-clock time, with traceability.

    Mirrors ``TimesyncBoot::get_timestamp()`` from the Rust reference and
    additionally captures the anchor used so the conversion can be audited.

    Args:
        timesync_data: dict[boot_uuid → TimesyncBoot], loaded from timesync files.
        boot_uuid: boot UUID from the tracev3 HeaderChunk.
        firehose_log_delta_time:
            ``base_continuous_time + (continuous_time_delta | (delta_upper << 32))``
        firehose_preamble_time:
            ``base_continuous_time`` from FirehosePreamble (0 means use boot_time).

    Returns:
        :class:`TimestampResolution`. On failure (unknown boot, no anchor),
        the returned object has ``unix_ns == 0``, an epoch ISO string and
        ``anchor is None`` so callers can persist the failure visibly.
    """
    boot = timesync_data.get(boot_uuid)
    if boot is None:
        log.warning(f"boot_uuid {boot_uuid} not found in timesync data")
        return _failure_resolution()

    # Determine timebase scaling factor.
    # Intel: 1/1 ; Apple Silicon: 125/3.
    if boot.timebase_numerator == 125 and boot.timebase_denominator == 3:
        timebase_num, timebase_den = 125, 3
    else:
        timebase_num, timebase_den = 1, 1

    anchor = _select_anchor(
        boot,
        firehose_log_delta_time,
        firehose_preamble_time,
        timebase_num,
        timebase_den,
    )
    if anchor is None:
        log.warning(f"no usable timesync anchor for boot_uuid={boot_uuid} (kernel_time={firehose_log_delta_time})")
        return _failure_resolution()

    # delta_ns = (target - anchor_kernel_time) * timebase_num / timebase_den
    # Integer math throughout so we keep nanosecond precision exactly.
    delta_raw = firehose_log_delta_time - anchor.kernel_continuous_time
    delta_ns = (delta_raw * timebase_num) // timebase_den
    unix_ns = anchor.walltime_unix_ns + delta_ns

    return TimestampResolution(
        unix_ns=unix_ns,
        iso=_format_iso8601(unix_ns),
        anchor=anchor,
    )


# ── Anchor selection ──────────────────────────────────────────────────────────

def _select_anchor(
    boot: TimesyncBoot,
    firehose_log_delta_time: int,
    firehose_preamble_time: int,
    timebase_num: int,
    timebase_den: int,
) -> TimesyncAnchor | None:
    """Pick the anchor that best resolves *firehose_log_delta_time*.

    Mirrors the Rust reference :

    * If the firehose preamble's base time is zero, start with the *boot
      record* (kernel_time = 0, walltime = boot_time) as a fallback anchor.
    * Walk the timesync records and keep the latest one whose
      ``kernel_time ≤ firehose_log_delta_time``. A later record always wins
      over the boot fallback because it carries a more recent walltime.
    * If even the first record already overshoots and no boot fallback is
      available, surface that first record so the result stays monotonically
      consistent with the timesync data.
    """
    # Boot anchor is the fallback used both when ``firehose_preamble_time`` is
    # zero and when no record satisfies ``kernel_time ≤ target``. We do NOT
    # return early here: subsequent records, if any, are more accurate.
    chosen_kernel: int | None
    chosen_walltime: int | None
    chosen_offset: int
    chosen_tz: int
    # File id of the source .timesync file the chosen anchor came from. Tracked
    # alongside the offset so a boot spanning two files attributes each anchor to
    # the correct file (see TimesyncEntry.timesync_file_id).
    chosen_file_id: int

    if firehose_preamble_time == 0:
        chosen_kernel = 0
        chosen_walltime = boot.boot_time
        chosen_offset = boot.file_offset
        chosen_tz = boot.timezone_offset_mins
        chosen_file_id = boot.timesync_file_id
    else:
        chosen_kernel = None
        chosen_walltime = None
        chosen_offset = 0
        chosen_tz = 0
        chosen_file_id = 0

    for record in boot.timesync:
        if record.kernel_time > firehose_log_delta_time:
            # Overshoot. Fall back to this record only when nothing else has
            # been chosen so far (no boot fallback either).
            if chosen_kernel is None:
                chosen_kernel = record.kernel_time
                chosen_walltime = record.walltime
                chosen_offset = record.file_offset
                chosen_tz = record.timezone
                chosen_file_id = record.timesync_file_id
            break
        chosen_kernel = record.kernel_time
        chosen_walltime = record.walltime
        chosen_offset = record.file_offset
        chosen_tz = record.timezone
        chosen_file_id = record.timesync_file_id

    if chosen_kernel is None or chosen_walltime is None:
        return None

    return TimesyncAnchor(
        boot_uuid=boot.boot_uuid,
        file_offset=chosen_offset,
        kernel_continuous_time=chosen_kernel,
        walltime_unix_ns=chosen_walltime,
        timebase_numerator=timebase_num,
        timebase_denominator=timebase_den,
        timezone_offset_mins=chosen_tz,
        timesync_file_id=chosen_file_id,
    )


# ── ISO formatting ────────────────────────────────────────────────────────────

def _format_iso8601(unix_ns: int) -> str:
    """Format a unix-nanosecond instant as ISO 8601 UTC with ns precision."""
    secs, ns_remainder = divmod(unix_ns, _NS_PER_SEC)
    try:
        dt = datetime.fromtimestamp(secs, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        log.warning(f"Could not convert timestamp {unix_ns} ns to datetime (secs={secs})")
        return _DEFAULT_ISO_ON_FAILURE

    # HOW: ``dt`` is built from whole seconds (``secs``), so ``dt.microsecond``
    # is always 0 and carries no fraction — the sub-second part lives entirely
    # in ``ns_remainder`` (0..999_999_999). We therefore print ``ns_remainder``
    # itself, zero-padded to 9 digits, as the full nanosecond fraction.
    # WHY: the previous code read ``dt.microsecond`` (always 0) and appended
    # only ``ns_remainder % 1000``, so every timestamp printed as
    # ``.000000<last-3-digits>`` — silently dropping the µs/sub-µs part of every
    # human-readable timestamp (CSV/JSON exports, identify, case metadata, GUI).
    return (
        f"{dt.year:04d}-{dt.month:02d}-{dt.day:02d}T"
        f"{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}."
        f"{ns_remainder:09d}Z"
    )


def _failure_resolution() -> TimestampResolution:
    return TimestampResolution(
        unix_ns=0,
        iso=_DEFAULT_ISO_ON_FAILURE,
        anchor=None,
    )


# ── Backwards-compatible thin wrappers ────────────────────────────────────────

def iso8601_from_unix_ns(unix_ns: int) -> str:
    """Public ISO 8601 (ns-precise, UTC) formatter for a unix-nanosecond instant.

    The ``logs`` table stores only ``timestamp_unix_ns`` (the ISO string is not
    persisted — see schema.py), so the export/diff readers and the extract
    time-range summary format it on read through this single helper. Consumed by:
    ops/export/exporter.py, ops/identify/diff.py, ops/extraction/extract.py.
    """
    return _format_iso8601(unix_ns)


# The timestamp renderings a display layer may ask for. "utc" is the canonical,
# portable form and the one every stored/exported value uses; the others exist
# only for reading on screen. Consumed by: format_timestamp, gui.settings_store
# ("tz" preference), gui.views.screens_prefs.
TIMESTAMP_MODES = ("utc", "local", "raw")


def format_timestamp(unix_ns: int, mode: str = "utc") -> str:
    """Render *unix_ns* for display in the given *mode*.

    * ``utc``   — ISO 8601, nanosecond-precise, UTC (identical to
      :func:`iso8601_from_unix_ns`; what is stored and exported).
    * ``local`` — the same instant in this workstation's zone, with its UTC
      offset appended so the reading is never ambiguous.
    * ``raw``   — the stored integer, for cross-checking against the database.

    An unknown *mode* falls back to ``utc`` rather than raising: this is a
    display preference read from a JSON file a user can hand-edit, and a bad
    value must not stop a table from rendering.

    WHY only display: nothing derived from this is stored, exported or hashed.
    Case data stays UTC everywhere so it remains portable between examiners —
    see the note in the Settings screen.
    """
    if unix_ns == 0:
        # The failure sentinel: an unresolved timestamp renders empty rather than
        # as a misleading 1970 date (same rule as LogRow.timestamp_iso).
        return ""
    if mode == "raw":
        return str(unix_ns)
    if mode == "local":
        dt = datetime.fromtimestamp(unix_ns / 1_000_000_000, tz=timezone.utc).astimezone()
        # Sub-second precision comes from the integer, not from the float above,
        # which cannot hold nanoseconds for present-day epochs.
        return f"{dt:%Y-%m-%dT%H:%M:%S}.{unix_ns % 1_000_000_000:09d}{dt:%z}"
    return _format_iso8601(unix_ns)


def mach_to_wall_ns(
    timesync_data: dict[str, TimesyncBoot],
    boot_uuid: str,
    firehose_log_delta_time: int,
    firehose_preamble_time: int,
) -> int:
    """Convenience wrapper returning only ``unix_ns``.

    Kept so existing callers (tests, simple consumers) need not adopt the
    full :class:`TimestampResolution` API.
    """
    return resolve_mach_timestamp(
        timesync_data, boot_uuid, firehose_log_delta_time, firehose_preamble_time,
    ).unix_ns


def mach_to_iso8601(
    timesync_data: dict[str, TimesyncBoot],
    boot_uuid: str,
    firehose_log_delta_time: int,
    firehose_preamble_time: int,
) -> str:
    """Convenience wrapper returning only the ISO string."""
    return resolve_mach_timestamp(
        timesync_data, boot_uuid, firehose_log_delta_time, firehose_preamble_time,
    ).iso
