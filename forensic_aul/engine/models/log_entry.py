"""The assembled log-entry models — resolved message data and the DB row.

``LogEntry`` is the fully resolved entry the writer inserts into SQLite;
``MessageData`` is the intermediate format-string + library bundle. Both mirror
the Rust macos-unifiedlogs library field-for-field.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class MessageData:
    """Format string and associated metadata resolved from UUIDText or DSC."""
    library: str
    format_string: str
    process: str
    library_uuid: str
    process_uuid: str


@dataclass
class LogEntry:
    """Fully resolved log entry ready for insertion into the SQLite database."""

    # ── Source traceability (FK → source_files.id) ────────────────────────────
    tracev3_file_id: int               # .tracev3 file containing the raw Firehose entry
    format_src_file_id: Optional[int]  # UUIDText or DSC file that provided the format string
    timesync_file_id: Optional[int]    # .timesync file whose boot record converted the timestamp

    # ── Byte offsets back into the source files (forensic provenance) ─────────
    tracev3_chunkset_file_offset: Optional[int]   # offset of the chunkset in the .tracev3 file
    tracev3_firehose_inner_offset: Optional[int]  # offset of the firehose preamble within the (decompressed) chunkset
    tracev3_entry_inner_offset: Optional[int]     # offset of this entry within the firehose preamble
    format_string_file_offset: Optional[int]      # offset of the format string in the UUIDText/DSC file (None for dynamic)

    # ── Timing ────────────────────────────────────────────────────────────────
    timestamp_iso: str           # ISO 8601 UTC (e.g. "2024-03-15T10:23:45.123456789Z")
    timestamp_unix_ns: int       # nanoseconds since 1970-01-01 UTC
    timestamp_mach: int          # raw mach continuous time (kernel ticks, exact integer)
    timesync_anchor_id: Optional[int]  # FK → timesync_anchors.id; None on failure

    # ── Process ───────────────────────────────────────────────────────────────
    process: str
    pid: int
    tid: int
    euid: int

    # ── Classification ────────────────────────────────────────────────────────
    log_level: str               # Debug / Info / Default / Error / Fault
    event_type: str              # Log / Activity / Trace / Signpost / Loss
    subsystem: str
    category: str

    # ── Message ───────────────────────────────────────────────────────────────
    message: str                 # printf-formatted final message
    message_format_string: str   # raw format string (for forensic filtering)

    # ── Library / UUID ────────────────────────────────────────────────────────
    library: str
    library_uuid: str
    process_uuid: str

    # ── Activity ──────────────────────────────────────────────────────────────
    activity_id: int
    parent_activity_id: int
    boot_uuid: str

    # ── Raw forensic data ─────────────────────────────────────────────────────
    raw_data: Optional[str] = None  # JSON-serialised FirehoseItemInfo list
