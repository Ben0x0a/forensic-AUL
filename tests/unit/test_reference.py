"""Unit tests for the log show reference — validation/ndjson_loader.py and log_show.py.

Covers : log show's closing summary is not an entry (it used to be a phantom
         "missing" record, mach=0, in every comparison) and its count is kept;
         state events are compared as Statedump (they used to be skipped); the
         full-window view hard-links the archive, never writes to it, and widens
         Info.plist as consistent (continuous, wall) pairs.
Uses    : files built in tmp_path; no macOS tool is run.
"""

from __future__ import annotations

import json
import plistlib

from forensic_aul.validation.log_show import full_window_view
from forensic_aul.validation.ndjson_loader import load_ndjson

_BOOT = "5B080966-4373-47F2-8DB4-703FB1C8B47F"


def _event(event_type: str, mach: int) -> dict:
    return {"eventType": event_type, "bootUUID": _BOOT, "machTimestamp": mach, "threadID": 1,
            "timestamp": "2026-11-22 21:10:12.000000+0100", "messageType": "Default"}


def test_the_closing_summary_is_not_an_entry(tmp_path):
    lines = [_event("logEvent", 10), _event("stateEvent", 20), _event("timesyncEvent", 0),
             {"count": 3, "finished": 1}]
    path = tmp_path / "ref.ndjson"
    path.write_text("\n".join(json.dumps(x) for x in lines) + "\n", encoding="utf-8")

    result = load_ndjson(path)

    assert result.count == 2, "the log entry and the state event; not the marker, not the summary"
    assert result.summary_count == 3
    assert {r.event_type for r in result.records.values()} == {"Log", "Statedump"}
    assert all(r.mach_timestamp for r in result.records.values()), "no phantom mach=0 record"


def test_full_window_view_widens_the_declared_window(tmp_path):
    archive = tmp_path / "case.logarchive"
    (archive / "Persist").mkdir(parents=True)
    (archive / "Persist" / "0.tracev3").write_bytes(b"not parsed here")
    oldest = {"ContinuousTime": 3_000, "UUID": _BOOT, "WallTime": 1_000_000_000}
    info = {"PersistMetadata": {"OldestTimeRef": dict(oldest)},
            "EndTimeRef": {"ContinuousTime": 6_000, "UUID": _BOOT, "WallTime": 1_000_000_000 + 3_000 * 125 // 3}}
    with (archive / "Info.plist").open("wb") as fh:
        plistlib.dump(info, fh)
    original_plist = (archive / "Info.plist").read_bytes()

    view = full_window_view(archive, tmp_path / "view" / archive.name)

    assert (archive / "Info.plist").read_bytes() == original_plist, "the evidence is never written to"
    assert (view / "Persist" / "0.tracev3").stat().st_nlink == 2, "hard-linked, not copied"
    with (view / "Info.plist").open("rb") as fh:
        widened = plistlib.load(fh)
    o = widened["PersistMetadata"]["OldestTimeRef"]
    # Moved to the boot's start as a consistent pair: 3,000 ticks of 125/3 ns earlier.
    assert (o["ContinuousTime"], o["WallTime"]) == (0, 1_000_000_000 - 125_000)
    assert widened["EndTimeRef"]["WallTime"] > info["EndTimeRef"]["WallTime"]
