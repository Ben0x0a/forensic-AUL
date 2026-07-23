"""Unit tests for the flat-memory sort-merge comparator — forensic_aul/testing/merge_compare.py.

The contract that must not regress: the streaming ``merge_compare`` produces the
**same** ``ComparisonReport`` as the in-RAM ``comparator.compare`` — same
matched/missing/extra sets and the same Level-3 tallies — on a fixture built as a
real (tiny) SQLite DB + Apple-style ndjson. Also checks the external-sort stream
comes out in the exact key order the merge relies on.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forensic_aul.testing import merge_compare
from forensic_aul.testing.comparator import compare, load_db_records
from forensic_aul.testing.ndjson_loader import load_ndjson

# One boot, a few threads. Each spec: where it lives + fields. "both_diff" is a
# matched key whose message differs (exercises the mismatch tallies).
_BOOT = "AABBCCDD-1122-3344-5566-778899AABBCC"
_BOOT_NORM = _BOOT.upper().replace("-", "")

_SPECS = [
    # kind,      mach,   tid, pid, subsystem,   msg
    ("both",     500,    9,   10,  "com.a",     "hello world"),
    ("both",     100,    9,   10,  "com.a",     "earliest"),
    ("both",     300,    7,   11,  "com.b",     "middle"),
    ("both_diff", 400,   7,   11,  "com.b",     "ref-text"),      # matched, msg differs
    ("ref_only", 250,    5,   12,  "com.c",     "only in ref"),   # → missing
    ("ref_only", 600,    5,   12,  "com.c",     "also missing"),
    ("db_only",  700,    3,   13,  "com.d",     "only in db"),    # → extra
]


def _apple_ts(mach: int) -> str:
    # A valid Apple timestamp; the exact value is irrelevant to key matching.
    secs = 1_700_000_000 + mach
    from datetime import datetime, timezone
    return datetime.fromtimestamp(secs, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f%z")


def _write_ndjson(path: Path) -> None:
    lines = []
    for kind, mach, tid, pid, subsystem, msg in _SPECS:
        if kind == "db_only":
            continue
        lines.append(json.dumps({
            "eventType": "logEvent", "bootUUID": _BOOT, "machTimestamp": mach,
            "threadID": tid, "processID": pid, "userID": 0, "subsystem": subsystem,
            "category": "cat", "activityIdentifier": 0, "parentActivityIdentifier": 0,
            "timestamp": _apple_ts(mach), "eventMessage": msg, "formatString": "%s",
            "messageType": "Default", "processImagePath": f"/bin/{subsystem}",
        }))
    # A skipped event type + a junk line, to exercise the parser filters.
    lines.append(json.dumps({"eventType": "timesyncEvent", "bootUUID": _BOOT}))
    path.write_text("garbage header\n" + "\n".join(lines) + "\n", encoding="utf-8")


_SCHEMA = """
CREATE TABLE boots(id INTEGER PRIMARY KEY, boot_uuid TEXT);
CREATE TABLE event_types(id INTEGER PRIMARY KEY, name TEXT);
CREATE TABLE log_levels(id INTEGER PRIMARY KEY, name TEXT);
CREATE TABLE subsystems(id INTEGER PRIMARY KEY, name TEXT);
CREATE TABLE categories(id INTEGER PRIMARY KEY, name TEXT);
CREATE TABLE libraries(id INTEGER PRIMARY KEY, uuid TEXT);
CREATE TABLE format_strs(id INTEGER PRIMARY KEY, value TEXT);
CREATE TABLE process_uuids(id INTEGER PRIMARY KEY, uuid TEXT);
CREATE TABLE logs(
    id INTEGER PRIMARY KEY, timestamp_mach INTEGER, timestamp_unix_ns INTEGER,
    boot_id INTEGER, event_type_id INTEGER, log_level_id INTEGER,
    pid INTEGER, tid INTEGER, euid INTEGER,
    subsystem_id INTEGER, category_id INTEGER,
    activity_id INTEGER, parent_activity_id INTEGER,
    message TEXT, format_str_id INTEGER, process_uuid_id INTEGER, library_id INTEGER);
"""


def _build_db(path: Path) -> None:
    conn = sqlite3.connect(str(path))
    try:
        conn.executescript(_SCHEMA)
        conn.execute("INSERT INTO boots(id, boot_uuid) VALUES (1, ?)", (_BOOT,))
        conn.execute("INSERT INTO event_types(id, name) VALUES (1, 'Log')")
        conn.execute("INSERT INTO log_levels(id, name) VALUES (1, 'Default')")
        conn.execute("INSERT INTO format_strs(id, value) VALUES (1, '%s')")
        subs: dict[str, int] = {}
        for i, (kind, mach, tid, pid, subsystem, msg) in enumerate(_SPECS, start=1):
            if kind == "ref_only":
                continue
            sid = subs.setdefault(subsystem, len(subs) + 1)
            conn.execute("INSERT OR IGNORE INTO subsystems(id, name) VALUES (?, ?)", (sid, subsystem))
            # matched keys share the message; "both_diff" gets a different DB message.
            db_msg = "db-text" if kind == "both_diff" else msg
            conn.execute(
                "INSERT INTO logs(id, timestamp_mach, timestamp_unix_ns, boot_id, "
                "event_type_id, log_level_id, pid, tid, euid, subsystem_id, "
                "category_id, activity_id, parent_activity_id, message, format_str_id) "
                "VALUES (?,?,?,1,1,1,?,?,0,?,NULL,0,0,?,1)",
                (i, mach, (1_700_000_000 + mach) * 1_000_000_000, pid, tid, sid, db_msg),
            )
        conn.commit()
    finally:
        conn.close()


def _report_tuple(rep):
    """The comparison-relevant scalars, for equality assertions."""
    return (
        rep.ref_total, rep.db_total, rep.matched, rep.missing, rep.extra,
        rep.msg_exact, rep.msg_normalised, rep.msg_format_match,
        rep.ts_total, rep.ts_us_match, rep.ts_us_within_1,
        {f.name: (f.match, f.total) for f in rep.field_stats},
        rep.missing_by_process, rep.missing_by_format_string,
    )


def test_merge_matches_inram_compare(tmp_path):
    db = tmp_path / "case.db"
    ndjson = tmp_path / "ref.ndjson"
    _build_db(db)
    _write_ndjson(ndjson)

    streamed = merge_compare.merge_compare(db, ndjson, max_samples=10)
    inram = compare(load_ndjson(ndjson), load_db_records(db), max_samples=10)

    assert _report_tuple(streamed) == _report_tuple(inram)
    # Sanity on the fixture itself: 4 matched (incl. the diff), 2 missing, 1 extra.
    assert (streamed.matched, streamed.missing, streamed.extra) == (4, 2, 1)
    assert streamed.msg_exact == 3  # the "both_diff" pair is not exact


def test_missing_and_extra_samples_are_key_ordered(tmp_path):
    db = tmp_path / "case.db"
    ndjson = tmp_path / "ref.ndjson"
    _build_db(db)
    _write_ndjson(ndjson)
    rep = merge_compare.merge_compare(db, ndjson, max_samples=10)
    missing_mach = [s.key.mach_timestamp for s in rep.missing_samples]
    assert missing_mach == sorted(missing_mach)      # ascending by mach
    assert {s.key.mach_timestamp for s in rep.missing_samples} == {250, 600}
    assert {k.mach_timestamp for k in rep.extra_samples} == {700}


def test_ndjson_sorted_stream_is_key_ordered(tmp_path):
    ndjson = tmp_path / "ref.ndjson"
    _write_ndjson(ndjson)
    recs = list(merge_compare._ndjson_sorted_stream(ndjson, tmp_path))
    keys = [merge_compare._ordkey(r) for r in recs]
    assert keys == sorted(keys)
    # All boots normalised; the timesync line was filtered out.
    assert all(r.key.boot_uuid == _BOOT_NORM for r in recs)
    assert len(recs) == 6  # 3 both + 1 both_diff + 2 ref_only (timesync line filtered)
