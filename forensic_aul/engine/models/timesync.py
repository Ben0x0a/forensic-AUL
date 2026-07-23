"""Timesync data models — mach↔wall-clock anchors and resolution output.

All structures mirror the Rust macos-unifiedlogs library field-for-field.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TimesyncEntry:
    """A single timesync record mapping mach continuous time to wall time."""
    signature: int         # u32 — must be 0x207354
    unknown_flags: int     # u32
    kernel_time: int       # u64 — mach continuous time
    walltime: int          # i64 — nanoseconds since UNIX epoch
    timezone: int          # u32
    daylight_savings: int  # u32
    # Byte offset of this record inside its source .timesync file, for forensic
    # traceability. Always set by the parser; defaults to 0 only for synthetic
    # entries built in tests.
    file_offset: int = 0
    # source_files.id of the .timesync file this record came from. Stamped in
    # extract step 4 after the file is registered. WHY per-record (not per-boot):
    # a boot UUID can appear in more than one .timesync file; without this the
    # anchor would be attributed to the wrong source file. 0 only for synthetic
    # entries built in tests.
    timesync_file_id: int = 0


@dataclass
class TimesyncBoot:
    """A boot timesync record with associated timesync entries."""
    signature: int               # u16 — must be 0xbbb0
    header_size: int             # u16
    unknown: int                 # u32
    boot_uuid: str               # 16-byte big-endian UUID, uppercase hex, no dashes
    timebase_numerator: int      # u32 — 1 on Intel, 125 on ARM
    timebase_denominator: int    # u32 — 1 on Intel, 3 on ARM
    boot_time: int               # i64 — nanoseconds since UNIX epoch at boot
    timezone_offset_mins: int    # u32
    daylight_savings: int        # u32
    timesync: list[TimesyncEntry] = field(default_factory=list)
    # Byte offset of the boot header inside its source .timesync file. Used as
    # the forensic anchor offset whenever ``firehose_preamble_time == 0`` (i.e.
    # the boot record itself is the chosen anchor).
    file_offset: int = 0
    # source_files.id of the .timesync file this boot header came from (see the
    # note on TimesyncEntry.timesync_file_id). 0 only for synthetic test boots.
    timesync_file_id: int = 0


@dataclass
class TimesyncAnchor:
    """Forensic record of the anchor selected to resolve one mach timestamp.

    Two flavours:

    * **Boot anchor** — picked when the firehose preamble's ``base_continuous_time``
      is zero. ``kernel_continuous_time`` is then ``0`` and ``walltime_unix_ns``
      is the boot record's ``boot_time``.
    * **Record anchor** — a specific :class:`TimesyncEntry` whose
      ``kernel_time`` is the largest one ≤ the queried continuous time.

    In both cases ``file_offset`` points back to the source .timesync file so
    an investigator can verify the bytes by hand.
    """
    boot_uuid: str
    file_offset: int             # byte offset in the source .timesync file
    kernel_continuous_time: int  # u64
    walltime_unix_ns: int        # i64 — nanoseconds since 1970
    timebase_numerator: int
    timebase_denominator: int
    timezone_offset_mins: int
    # source_files.id of the .timesync file the chosen anchor came from. Carries
    # the per-record provenance through to the (file_id, offset) anchor lookup so
    # a boot spanning two files attributes each anchor to the right file. 0 for
    # anchors built in tests (no registered source file).
    timesync_file_id: int = 0


@dataclass
class TimestampResolution:
    """Output of the mach → wall-clock conversion with full traceability."""
    unix_ns: int                       # nanoseconds since 1970, 0 on failure
    iso: str                           # ISO 8601 UTC string, "1970-…Z" on failure
    anchor: TimesyncAnchor | None      # None when no usable anchor was found
