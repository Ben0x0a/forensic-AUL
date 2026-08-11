"""Unit tests for forensic_aul.ops.export.exporter — filtered CSV/JSON/JSONL export.

Builds a tiny on-disk analysis database (logs + lookups, optionally the KB
annotation tables) and exercises ``run_export`` end-to-end plus the pure parsing
helpers. ``run_export`` opens its own connection by path, so the fixtures write a
real file rather than an in-memory database.
"""

from __future__ import annotations

import csv
import json
import sqlite3
from pathlib import Path

import pytest

from forensic_aul.ops.annotation.matcher import init_annotation_schema
from forensic_aul.engine.database.ordering import assign_ordering
from forensic_aul.engine.database.schema import apply_pragmas, init_schema
from forensic_aul.ops.export.exporter import (
    ExportFilters,
    _infer_format,
    run_export,
)
from forensic_aul.ops.query.reader import _to_unix_ns
from forensic_aul.engine.utils.time import parse_duration_seconds as _parse_duration_seconds

# Wall-clock base: 2024-01-15T12:00:01Z, in nanoseconds since the Unix epoch.
# Kept consistent with the timestamp_iso strings inserted below so that time-window
# filters (which convert the ISO bound to ns) compare against matching values.
_BASE_NS = 1_705_320_001_000_000_000


def _make_db(path: Path, *, with_kb: bool = False, annotate: bool = False) -> None:
    """Create a populated analysis DB at *path* (3 logs, 2 processes).

    With ``with_kb`` the KB tables are created and one signature is inserted;
    with ``annotate`` the locationd row (id=2) additionally carries an annotation
    with two extracted fields.
    """
    conn = sqlite3.connect(str(path))
    apply_pragmas(conn)
    init_schema(conn)

    conn.executemany("INSERT INTO processes(id, name) VALUES (?, ?)",
                     [(1, "syslogd"), (2, "locationd")])
    conn.executemany("INSERT INTO subsystems(id, name) VALUES (?, ?)",
                     [(1, "com.apple.system"), (2, "com.apple.locationd")])
    conn.executemany("INSERT INTO categories(id, name) VALUES (?, ?)",
                     [(1, "syslog"), (2, "loc")])

    # (id, unix_ns, mach, pid, tid, level, event_type, message, proc, subsys, cat)
    rows = [
        (1, _BASE_NS + 0,             1000, 42, 101,
         "Default", "Log", "Hello world",      1, 1, 1),
        (2, _BASE_NS + 1_000_000_000, 2000, 55, 102,
         "Error",   "Log", "Location updated",  2, 2, 2),
        (3, _BASE_NS + 2_000_000_000, 3000, 42, 103,
         "Info",    "Log", "Goodbye",           1, 1, 1),
    ]
    # log_level / event_type are normalised — resolve the seeded ids inline.
    conn.executemany(
        "INSERT INTO logs(id, timestamp_unix_ns, timestamp_mach, "
        "pid, tid, log_level_id, event_type_id, message, process_id, subsystem_id, category_id) "
        "VALUES (?, ?, ?, ?, ?, "
        "(SELECT id FROM log_levels WHERE name=?), "
        "(SELECT id FROM event_types WHERE name=?), ?, ?, ?, ?)",
        rows,
    )

    if with_kb:
        init_annotation_schema(conn)
        conn.execute(
            "INSERT INTO kb_signatures(id, signature_id, action, description, confidence, "
            "tags, source_file, kb_version, kb_sha256, applied_at, match_count) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (1, "loc.update", "Location was updated", "desc", "high",
             json.dumps(["location", "privacy"]), "loc.yaml", "1.0.0", "deadbeef",
             "2024-01-15T00:00:00+00:00", 1),
        )
        if annotate:
            conn.execute(
                "INSERT INTO log_annotations(id, log_id, kb_signature_id) VALUES (?, ?, ?)",
                (1, 2, 1),
            )
            conn.executemany(
                "INSERT INTO extracted_values(log_annotation_id, label, value) VALUES (?, ?, ?)",
                [(1, "lat", "48.8"), (1, "lon", "2.3")],
            )
    conn.commit()
    conn.close()


def _read_csv(path: Path) -> tuple[list[str], list[list[str]]]:
    with path.open("r", newline="", encoding="utf-8-sig") as fp:
        rows = list(csv.reader(fp))
    return rows[0], rows[1:]


# ── Pure helpers ──────────────────────────────────────────────────────────────

class TestHelpers:
    @pytest.mark.parametrize("name,expected", [
        ("out.csv", "csv"), ("OUT.CSV", "csv"),
        ("out.json", "json"), ("out.jsonl", "jsonl"),
        ("out.txt", None), ("out", None),
    ])
    def test_infer_format(self, name, expected):
        assert _infer_format(Path(name)) == expected

    @pytest.mark.parametrize("value,seconds", [
        ("30s", 30), ("10m", 600), ("1h", 3600), ("2d", 172800), ("1.5h", 5400),
    ])
    def test_parse_duration(self, value, seconds):
        assert _parse_duration_seconds(value) == seconds

    @pytest.mark.parametrize("value", ["", "10x", "abc", "10"])
    def test_parse_duration_bad(self, value):
        assert _parse_duration_seconds(value) is None

    def test_to_unix_ns_utc(self):
        # Naive datetime is treated as UTC.
        assert _to_unix_ns("2024-01-15T12:00:01") == _BASE_NS

    def test_to_unix_ns_trailing_z(self):
        assert _to_unix_ns("2024-01-15T12:00:01Z") == _BASE_NS

    def test_to_unix_ns_bad_raises(self):
        with pytest.raises(ValueError):
            _to_unix_ns("not-a-date")


# ── CSV / JSON / JSONL output (no knowledge base) ─────────────────────────────

class TestBasicExport:
    def test_csv_all_rows(self, tmp_path):
        db = tmp_path / "a.db"
        _make_db(db)
        out = tmp_path / "out.csv"
        n = run_export(db, out)
        assert n.rows == 3
        header, data = _read_csv(out)
        # No KB → exactly the base columns (no per-signature field columns).
        assert header == [
            "timestamp", "timestamp_unix_ns", "event_order", "source_order", "source_file",
            "process", "pid", "tid",
            "log_level", "event_type", "subsystem", "category", "message",
            "matched_signatures",
        ]
        assert len(data) == 3
        messages = [r[header.index("message")] for r in data]
        assert messages == ["Hello world", "Location updated", "Goodbye"]
        # matched_signatures empty when there are no annotations.
        assert all(r[header.index("matched_signatures")] == "" for r in data)

    def test_csv_has_bom(self, tmp_path):
        db = tmp_path / "a.db"
        _make_db(db)
        out = tmp_path / "out.csv"
        run_export(db, out)
        assert out.read_bytes().startswith(b"\xef\xbb\xbf")

    def test_json_array(self, tmp_path):
        db = tmp_path / "a.db"
        _make_db(db)
        out = tmp_path / "out.json"
        n = run_export(db, out)
        assert n.rows == 3
        objs = json.loads(out.read_text(encoding="utf-8"))
        assert isinstance(objs, list) and len(objs) == 3
        assert objs[0]["process"] == "syslogd"
        assert objs[1]["message"] == "Location updated"
        assert objs[0]["matched_signatures"] == []

    def test_jsonl(self, tmp_path):
        db = tmp_path / "a.db"
        _make_db(db)
        out = tmp_path / "out.jsonl"
        n = run_export(db, out)
        assert n.rows == 3
        lines = [ln for ln in out.read_text(encoding="utf-8").splitlines() if ln.strip()]
        assert len(lines) == 3
        assert all(json.loads(ln)["message"] for ln in lines)

    def test_explicit_format_overrides_suffix(self, tmp_path):
        db = tmp_path / "a.db"
        _make_db(db)
        out = tmp_path / "out.txt"  # unknown suffix
        n = run_export(db, out, ExportFilters(fmt="csv"))
        assert n.rows == 3
        header, _ = _read_csv(out)
        assert header[0] == "timestamp"


# ── Error handling ────────────────────────────────────────────────────────────

class TestErrors:
    def test_missing_database(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            run_export(tmp_path / "absent.db", tmp_path / "out.csv")

    def test_uninferable_format(self, tmp_path):
        db = tmp_path / "a.db"
        _make_db(db)
        with pytest.raises(ValueError):
            run_export(db, tmp_path / "out.txt")  # no fmt, unknown suffix

    def test_kb_filter_without_kb_tables(self, tmp_path):
        db = tmp_path / "a.db"
        _make_db(db, with_kb=False)
        with pytest.raises(ValueError):
            run_export(db, tmp_path / "out.csv", ExportFilters(annotated_only=True))


# ── Log-column filters ────────────────────────────────────────────────────────

class TestLogFilters:
    def test_process_filter(self, tmp_path):
        db = tmp_path / "a.db"
        _make_db(db)
        out = tmp_path / "out.csv"
        n = run_export(db, out, ExportFilters(process=["syslogd"]))
        assert n.rows == 2  # id 1 and 3
        header, data = _read_csv(out)
        assert {r[header.index("process")] for r in data} == {"syslogd"}

    def test_level_filter(self, tmp_path):
        db = tmp_path / "a.db"
        _make_db(db)
        out = tmp_path / "out.csv"
        n = run_export(db, out, ExportFilters(level=["Error"]))
        assert n.rows == 1
        header, data = _read_csv(out)
        assert data[0][header.index("message")] == "Location updated"

    def test_like_filter(self, tmp_path):
        db = tmp_path / "a.db"
        _make_db(db)
        out = tmp_path / "out.csv"
        n = run_export(db, out, ExportFilters(like="%Location%"))
        assert n.rows == 1

    def test_time_window(self, tmp_path):
        db = tmp_path / "a.db"
        _make_db(db)
        out = tmp_path / "out.csv"
        # from the 2nd row's instant (inclusive) → drops the 1st row.
        n = run_export(db, out, ExportFilters(time_from="2024-01-15T12:00:02"))
        assert n.rows == 2
        n2 = run_export(db, out, ExportFilters(
            time_from="2024-01-15T12:00:02", time_to="2024-01-15T12:00:03"))
        assert n2.rows == 1  # upper bound exclusive → only the 2nd row

    def test_unknown_process_yields_no_rows(self, tmp_path):
        db = tmp_path / "a.db"
        _make_db(db)
        out = tmp_path / "out.csv"
        n = run_export(db, out, ExportFilters(process=["does-not-exist"]))
        assert n.rows == 0


# ── Knowledge-base aware export ───────────────────────────────────────────────

class TestKbExport:
    def test_csv_fields_become_columns(self, tmp_path):
        db = tmp_path / "a.db"
        _make_db(db, with_kb=True, annotate=True)
        out = tmp_path / "out.csv"
        n = run_export(db, out)
        assert n.rows == 3
        header, data = _read_csv(out)
        # One column per extracted label (no signature prefix).
        assert "lat" in header
        assert "lon" in header
        lat = header.index("lat")
        msg_col = header.index("message")
        annotated = [r for r in data if r[msg_col] == "Location updated"][0]
        assert annotated[lat] == "48.8"
        assert annotated[header.index("matched_signatures")] == "loc.update"
        # Non-annotated rows leave the label columns blank.
        other = next(r for r in data if r[msg_col] == "Hello world")
        assert other[lat] == ""

    def test_no_fields_option(self, tmp_path):
        db = tmp_path / "a.db"
        _make_db(db, with_kb=True, annotate=True)
        out = tmp_path / "out.csv"
        run_export(db, out, ExportFilters(include_fields=False))
        header, _ = _read_csv(out)
        assert "lat" not in header and "lon" not in header

    def test_json_nested_fields(self, tmp_path):
        db = tmp_path / "a.db"
        _make_db(db, with_kb=True, annotate=True)
        out = tmp_path / "out.json"
        run_export(db, out)
        objs = json.loads(out.read_text(encoding="utf-8"))
        annotated = [o for o in objs if o["message"] == "Location updated"][0]
        assert annotated["matched_signatures"] == ["loc.update"]
        assert annotated["extracted_values"] == {"lat": "48.8", "lon": "2.3"}

    def test_annotated_only(self, tmp_path):
        db = tmp_path / "a.db"
        _make_db(db, with_kb=True, annotate=True)
        out = tmp_path / "out.csv"
        n = run_export(db, out, ExportFilters(annotated_only=True))
        assert n.rows == 1
        header, data = _read_csv(out)
        assert data[0][header.index("message")] == "Location updated"

    def test_signature_filter(self, tmp_path):
        db = tmp_path / "a.db"
        _make_db(db, with_kb=True, annotate=True)
        out = tmp_path / "out.csv"
        assert run_export(db, out, ExportFilters(signature=["loc.update"])).rows == 1
        assert run_export(db, out, ExportFilters(signature=["nope"])).rows == 0

    def test_action_substring_filter(self, tmp_path):
        db = tmp_path / "a.db"
        _make_db(db, with_kb=True, annotate=True)
        out = tmp_path / "out.csv"
        assert run_export(db, out, ExportFilters(action="location")).rows == 1  # case-insensitive

    def test_tag_filter(self, tmp_path):
        db = tmp_path / "a.db"
        _make_db(db, with_kb=True, annotate=True)
        out = tmp_path / "out.csv"
        assert run_export(db, out, ExportFilters(tag=["privacy"])).rows == 1
        assert run_export(db, out, ExportFilters(tag=["nonexistent"])).rows == 0


# ── source_order / source_file (L10 completion) ───────────────────────────────

def _make_db_multi_source(path: Path) -> None:
    """Two tracev3 files (2 logs each), ordering assigned by the real production
    pass (``assign_ordering``, not hand-computed) so the test exercises the same
    code path ``extract`` uses. Mirrors the fixture pattern in
    ``tests/unit/test_ordering.py``.
    """
    conn = sqlite3.connect(str(path))
    apply_pragmas(conn)
    init_schema(conn)

    conn.executemany(
        "INSERT INTO source_files (id, file_path, file_type, parsed_at) VALUES (?, ?, ?, ?)",
        [
            (1, "logdata/a.tracev3", "tracev3", "2024-01-15T00:00:00Z"),
            (2, "logdata/b.tracev3", "tracev3", "2024-01-15T00:00:00Z"),
        ],
    )
    conn.execute("INSERT INTO boots (id, boot_uuid, rank) VALUES (1, 'BOOT-A', 0)")

    # (id, tracev3_file_id, chunkset_offset, mach) — source_order is per-file rank
    # by chunkset offset; event_order is the merged rank by mach across both files.
    rows = [
        (1, 1, 100, 10),
        (2, 1, 200, 30),
        (3, 2, 50, 20),
        (4, 2, 150, 40),
    ]
    for rid, file_id, chunk, mach in rows:
        conn.execute(
            "INSERT INTO logs (id, tracev3_file_id, tracev3_chunkset_file_offset, "
            "tracev3_firehose_inner_offset, tracev3_entry_inner_offset, boot_id, "
            "timestamp_unix_ns, timestamp_mach, message) "
            "VALUES (?, ?, ?, 0, 0, 1, ?, ?, ?)",
            (rid, file_id, chunk, _BASE_NS + mach, mach, f"row {rid}"),
        )
    conn.commit()
    assign_ordering(conn)
    conn.commit()
    conn.close()


class TestSourceOrdering:
    def test_source_order_and_source_file_in_csv(self, tmp_path):
        db = tmp_path / "multi.db"
        _make_db_multi_source(db)
        out = tmp_path / "out.csv"
        n = run_export(db, out)
        assert n.rows == 4
        header, data = _read_csv(out)
        assert "source_order" in header
        assert "source_file" in header
        so_col, sf_col, msg_col = (
            header.index("source_order"), header.index("source_file"), header.index("message"),
        )
        by_msg = {r[msg_col]: r for r in data}
        # File a: rows 1, 2 → source_order restarts at 1.
        assert by_msg["row 1"][sf_col] == "logdata/a.tracev3"
        assert by_msg["row 1"][so_col] == "1"
        assert by_msg["row 2"][sf_col] == "logdata/a.tracev3"
        assert by_msg["row 2"][so_col] == "2"
        # File b: rows 3, 4 → source_order restarts at 1 too (per-file, not global).
        assert by_msg["row 3"][sf_col] == "logdata/b.tracev3"
        assert by_msg["row 3"][so_col] == "1"
        assert by_msg["row 4"][sf_col] == "logdata/b.tracev3"
        assert by_msg["row 4"][so_col] == "2"

    def test_event_order_does_not_restart_across_files(self, tmp_path):
        db = tmp_path / "multi.db"
        _make_db_multi_source(db)
        out = tmp_path / "out.csv"
        run_export(db, out)
        header, data = _read_csv(out)
        eo_col, msg_col = header.index("event_order"), header.index("message")
        by_msg = {r[msg_col]: int(r[eo_col]) for r in data}
        # Merged mach order spans both files: row1(10) < row3(20) < row2(30) < row4(40).
        assert by_msg["row 1"] < by_msg["row 3"] < by_msg["row 2"] < by_msg["row 4"]
        # One ever-increasing sequence — unlike source_order it never restarts.
        assert sorted(by_msg.values()) == [1, 2, 3, 4]

    def test_json_keys_include_source_order_and_source_file(self, tmp_path):
        db = tmp_path / "multi.db"
        _make_db_multi_source(db)
        out = tmp_path / "out.json"
        run_export(db, out)
        objs = json.loads(out.read_text(encoding="utf-8"))
        assert all("source_order" in o and "source_file" in o for o in objs)
        row1 = next(o for o in objs if o["message"] == "row 1")
        assert row1["source_order"] == 1
        assert row1["source_file"] == "logdata/a.tracev3"


# ── Result object ─────────────────────────────────────────────────────────────

class TestResultObject:
    def test_export_result_fields(self, tmp_path):
        db = tmp_path / "a.db"
        _make_db(db)
        out = tmp_path / "out.jsonl"
        res = run_export(db, out)
        assert res.output_path == out
        assert res.rows == 3
        assert res.fmt == "jsonl"
