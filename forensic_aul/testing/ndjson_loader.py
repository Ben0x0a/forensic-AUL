"""Load Apple ``log show --style ndjson`` output into a normalised structure.

The ndjson produced by Apple's ``log show`` contains one JSON object per line.
Some files have a few non-JSON lines at the start or end (separator lines,
file paths) which are silently skipped.

eventType mapping to our event_type values
------------------------------------------
logEvent            → "Log"
activityCreateEvent → "Activity"
signpostEvent       → "Signpost"
lossEvent           → "Loss"
userActionEvent     → "Log"   (conservative — counted separately)
stateEvent          → skipped (Statedump, not parsed by our extractor)
timesyncEvent       → skipped (metadata markers, not log entries)

messageType → log_level
-----------------------
Default  → "Default"
Info     → "Info"
Debug    → "Debug"
Error    → "Error"
Fault    → "Fault"
(empty)  → ""  (Activity, Signpost, etc.)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

log = logging.getLogger(__name__)

# eventTypes that are NOT log entries in our DB
_SKIP_EVENT_TYPES: frozenset[str] = frozenset(["timesyncEvent", "stateEvent"])

# eventType → our event_type
_EVENT_TYPE_MAP: dict[str, str] = {
    "logEvent":            "Log",
    "activityCreateEvent": "Activity",
    "signpostEvent":       "Signpost",
    "lossEvent":           "Loss",
    "userActionEvent":     "Log",   # conservative
}

# messageType → our log_level
_MSG_TYPE_MAP: dict[str, str] = {
    "Default": "Default",
    "Info":    "Info",
    "Debug":   "Debug",
    "Error":   "Error",
    "Fault":   "Fault",
}


@dataclass(frozen=True)
class RefKey:
    """Composite key used to match a reference record to a DB row."""
    boot_uuid: str       # uppercase, no dashes
    mach_timestamp: int
    thread_id: int


@dataclass
class RefRecord:
    """A single normalised reference record from the Apple ndjson."""
    key: RefKey

    # Structural fields
    event_type: str       # our vocabulary
    log_level: str        # our vocabulary (empty for non-logEvent)
    pid: int
    tid: int
    euid: int
    subsystem: str
    category: str
    activity_id: int
    parent_activity_id: int
    boot_uuid: str        # original casing from file
    mach_timestamp: int

    # Apple wall-clock timestamp parsed once at load time. Apple's ``timestamp``
    # field is the human-readable string with timezone offset; we keep it for
    # debugging and pre-compute the microsecond integer for efficient compare.
    timestamp_str: str = ""
    timestamp_unix_us: int | None = None

    # Message fields
    event_message: str = ""    # formatted message from Apple
    format_string: str = ""    # raw format string

    # Library / UUID fields
    process_image_path: str = ""
    process_image_uuid: str = ""
    sender_image_path: str = ""
    sender_image_uuid: str = ""

    # Flags
    is_user_action: bool = False  # True for userActionEvent


@dataclass
class LoadResult:
    """Result of loading an ndjson reference file."""
    records: dict[RefKey, RefRecord]   # key → record (first seen wins on collision)
    collisions: int = 0                # keys that appeared more than once
    skipped_event_types: dict[str, int] = field(default_factory=dict)
    unknown_event_types: dict[str, int] = field(default_factory=dict)
    user_action_count: int = 0
    parse_errors: int = 0
    total_lines: int = 0

    @property
    def count(self) -> int:
        return len(self.records)


_EPOCH_UTC = datetime(1970, 1, 1, tzinfo=timezone.utc)
_ONE_US = timedelta(microseconds=1)


def _parse_apple_timestamp_us(value: str) -> int | None:
    """Parse Apple's ``log show`` timestamp and return microseconds since epoch.

    Apple emits timestamps in the local timezone, e.g.
    ``"2026-03-27 02:01:31.878112-0700"``. We accept the canonical form first
    and fall back to a stripped/normalised form for the few quirks observed
    in the wild (missing fractional seconds, ``T`` separator, ``Z`` zone).

    Returns ``None`` if no recognised form matches — the caller decides
    whether to skip or count as a parse error.
    """
    if not value:
        return None

    candidates = (
        "%Y-%m-%d %H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S%z",
    )
    normalised = value.strip().replace("Z", "+0000")
    for fmt in candidates:
        try:
            dt = datetime.strptime(normalised, fmt)
        except ValueError:
            continue
        delta = dt.astimezone(timezone.utc) - _EPOCH_UTC
        # ``//`` on timedeltas is exact and integer-only — avoids the float
        # rounding you would get from `dt.timestamp() * 1_000_000`.
        return delta // _ONE_US

    return None


def _coerce_int(value: object) -> int:
    """Best-effort cast to int — Apple sometimes encodes IDs as strings."""
    if value is None:
        return 0
    if isinstance(value, bool):  # bool is a subclass of int, but we never want it as one here
        return int(value)
    if isinstance(value, int):
        return value
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def _normalise_uuid(s: str) -> str:
    """Return uppercase UUID without dashes."""
    return s.upper().replace("-", "")


def load_ndjson(path: Path | str) -> LoadResult:
    """Parse an Apple ``log show --style ndjson`` file.

    Returns a :class:`LoadResult` containing all comparable records indexed
    by their :class:`RefKey`.  Non-comparable eventTypes (timesyncEvent,
    stateEvent) are counted in ``skipped_event_types`` but not stored.
    """
    path = Path(path)
    result = LoadResult(records={})

    # Stream line-by-line: a multi-GB ndjson would not fit in RAM otherwise.
    with path.open("rb") as fh:
        for raw_line in fh:
            raw_line = raw_line.strip()
            result.total_lines += 1

            if not raw_line or not raw_line.startswith(b"{"):
                log.debug("ndjson_loader: skipping non-JSON line: %r", raw_line[:60])
                continue

            try:
                obj: dict = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                result.parse_errors += 1
                log.debug("ndjson_loader: JSON parse error: %s  line=%r", exc, raw_line[:80])
                continue

            _consume_obj(obj, result)

    log.info(f"ndjson_loader: {result.count} records loaded  collisions={result.collisions}  skipped={dict(result.skipped_event_types)}  unknown={dict(result.unknown_event_types)}  errors={result.parse_errors}")
    return result


def _consume_obj(obj: dict, result: LoadResult) -> None:
    """Convert one parsed JSON object and record it into *result*."""
    et = obj.get("eventType", "")

    # Skip non-entry event types
    if et in _SKIP_EVENT_TYPES:
        result.skipped_event_types[et] = result.skipped_event_types.get(et, 0) + 1
        return

    if et and et not in _EVENT_TYPE_MAP:
        result.unknown_event_types[et] = result.unknown_event_types.get(et, 0) + 1

    event_type = _EVENT_TYPE_MAP.get(et, "Log")
    is_user_action = (et == "userActionEvent")
    if is_user_action:
        result.user_action_count += 1

    boot_uuid_raw: str = obj.get("bootUUID", "")
    mach_ts = _coerce_int(obj.get("machTimestamp"))
    thread_id = _coerce_int(obj.get("threadID"))

    key = RefKey(
        boot_uuid=_normalise_uuid(boot_uuid_raw),
        mach_timestamp=mach_ts,
        thread_id=thread_id,
    )

    if key in result.records:
        result.collisions += 1
        log.debug(
            "ndjson_loader: duplicate key boot=%s mach=%d tid=%d",
            key.boot_uuid, key.mach_timestamp, key.thread_id,
        )
        return

    timestamp_str = obj.get("timestamp", "") or ""
    timestamp_unix_us = _parse_apple_timestamp_us(timestamp_str)

    result.records[key] = RefRecord(
        key=key,
        event_type=event_type,
        log_level=_MSG_TYPE_MAP.get(obj.get("messageType", ""), ""),
        pid=_coerce_int(obj.get("processID")),
        tid=thread_id,
        euid=_coerce_int(obj.get("userID")),
        subsystem=obj.get("subsystem", ""),
        category=obj.get("category", ""),
        activity_id=_coerce_int(obj.get("activityIdentifier")),
        parent_activity_id=_coerce_int(obj.get("parentActivityIdentifier")),
        boot_uuid=boot_uuid_raw,
        mach_timestamp=mach_ts,
        timestamp_str=timestamp_str,
        timestamp_unix_us=timestamp_unix_us,
        event_message=obj.get("eventMessage", ""),
        format_string=obj.get("formatString", ""),
        process_image_path=obj.get("processImagePath", ""),
        process_image_uuid=obj.get("processImageUUID", ""),
        sender_image_path=obj.get("senderImagePath", ""),
        sender_image_uuid=obj.get("senderImageUUID", ""),
        is_user_action=is_user_action,
    )
