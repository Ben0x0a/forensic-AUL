"""Export DB records to an ndjson file using Apple's field names.

The output mirrors the format produced by ``log show --style ndjson`` so that
the two files can be compared side-by-side with standard diff tools:

    diff <(jq -S . ref.ndjson) <(jq -S . our.ndjson)

or with a purpose-built tool such as ``delta`` or ``meld``.

Reverse mappings applied
------------------------
event_type   → eventType
    "Log"        → "logEvent"
    "Activity"   → "activityCreateEvent"
    "Signpost"   → "signpostEvent"
    "Loss"       → "lossEvent"
    (other)      → as-is

log_level    → messageType
    "Default" / "Info" / "Debug" / "Error" / "Fault" → same
    ""           → omitted
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from forensic_aul.testing.comparator import DbRecord
from forensic_aul.testing.ndjson_loader import RefKey

log = logging.getLogger(__name__)

# Our vocabulary → Apple's eventType string
_EVENT_TYPE_REVERSE: dict[str, str] = {
    "Log":       "logEvent",
    "Activity":  "activityCreateEvent",
    "Signpost":  "signpostEvent",
    "Loss":      "lossEvent",
}


def _record_to_obj(rec: DbRecord) -> dict[str, object]:
    """Convert a :class:`DbRecord` to an Apple-compatible ndjson object."""
    obj: dict[str, object] = {
        "eventType":              _EVENT_TYPE_REVERSE.get(rec.event_type, rec.event_type),
        "machTimestamp":          rec.mach_timestamp,
        "bootUUID":               rec.boot_uuid,
        "threadID":               rec.tid,
        "processID":              rec.pid,
        "userID":                 rec.euid,
        "subsystem":              rec.subsystem,
        "category":               rec.category,
        "activityIdentifier":     rec.activity_id,
        "parentActivityIdentifier": rec.parent_activity_id,
        "eventMessage":           rec.message,
        "formatString":           rec.message_format_string,
        "processImageUUID":       rec.process_uuid,
        "senderImageUUID":        rec.library_uuid,
    }
    if rec.log_level:
        obj["messageType"] = rec.log_level
    return obj


def export_db_to_ndjson(
    db_records: dict[RefKey, DbRecord],
    output_path: Path,
    *,
    sort_by_mach: bool = True,
) -> int:
    """Write *db_records* as ndjson to *output_path*.

    Records are sorted by ``mach_timestamp`` by default so the output is in
    chronological order (matching Apple's ``log show`` output ordering).

    Returns the number of records written.
    """
    records = list(db_records.values())
    if sort_by_mach:
        records.sort(key=lambda r: r.mach_timestamp)

    # Atomic write: write to a sibling .tmp file then rename, so an
    # interrupted run never leaves a partial ndjson on disk.
    tmp_path = output_path.with_suffix(output_path.suffix + ".tmp")
    written = 0
    try:
        # newline="\n" prevents the OS from translating \n → \r\n on Windows,
        # which would break ndjson tooling.
        with tmp_path.open("w", encoding="utf-8", newline="\n") as fh:
            for rec in records:
                fh.write(json.dumps(_record_to_obj(rec), ensure_ascii=False))
                fh.write("\n")
                written += 1
        os.replace(tmp_path, output_path)
    except OSError:
        log.exception(f"Could not write ndjson output to {output_path}")
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass
        return 0

    log.info(f"ndjson_exporter: {written} records written to {output_path}")
    return written
