"""Tests for forensic_aul.validation.comparator — comparison engine and report renderer."""

import pytest
from forensic_aul.validation.ndjson_loader import RefKey, RefRecord, LoadResult
from forensic_aul.validation.comparator import (
    DbRecord,
    ComparisonReport,
    FieldStats,
    MessageMismatch,
    compare,
    render_report,
    _table,
    _pct_bar,
)


# ── Fixtures ───────────────────────────────────────────────────────────────────

def _ref_key(mach: int = 1000, tid: int = 1) -> RefKey:
    return RefKey(
        boot_uuid="AABBCCDDEEFF00112233445566778899",
        mach_timestamp=mach,
        thread_id=tid,
    )


def _ref_record(mach: int = 1000, tid: int = 1, msg: str = "hello") -> RefRecord:
    key = _ref_key(mach, tid)
    return RefRecord(
        key=key,
        event_type="Log",
        log_level="Default",
        pid=42, tid=tid, euid=0,
        subsystem="com.apple.system",
        category="syslog",
        activity_id=0, parent_activity_id=0,
        boot_uuid="AABBCCDDEEFF00112233445566778899",
        mach_timestamp=mach,
        event_message=msg,
        format_string="hello",
        process_image_path="",
        process_image_uuid="",
        sender_image_path="",
        sender_image_uuid="",
        is_user_action=False,
    )


def _db_record(mach: int = 1000, tid: int = 1, msg: str = "hello") -> DbRecord:
    key = _ref_key(mach, tid)
    return DbRecord(
        key=key,
        mach_timestamp=mach,
        timestamp_unix_ns=0,
        boot_uuid="AABBCCDDEEFF00112233445566778899",
        event_type="Log",
        log_level="Default",
        pid=42, tid=tid, euid=0,
        subsystem="com.apple.system",
        category="syslog",
        activity_id=0, parent_activity_id=0,
        message=msg,
        message_format_string="hello",
        process_uuid="", library_uuid="",
    )


def _make_ref(*records: RefRecord) -> LoadResult:
    d = {r.key: r for r in records}
    return LoadResult(
        records=d,
        collisions=0,
        skipped_event_types={},
        user_action_count=0,
    )


# ── Tests for compare() ────────────────────────────────────────────────────────

class TestCompare:
    def test_perfect_match(self):
        r = _ref_record()
        d = _db_record()
        ref = _make_ref(r)
        db  = {r.key: d}
        report = compare(ref, db)
        assert report.matched  == 1
        assert report.missing  == 0
        assert report.extra    == 0
        assert report.msg_exact == 1

    def test_all_missing(self):
        ref = _make_ref(_ref_record(1), _ref_record(2), _ref_record(3))
        report = compare(ref, {})
        assert report.missing == 3
        assert report.matched == 0

    def test_all_extra(self):
        ref = _make_ref()
        db = {
            _ref_key(1): _db_record(1),
            _ref_key(2): _db_record(2),
        }
        report = compare(ref, db)
        assert report.extra   == 2
        assert report.matched == 0

    def test_message_mismatch_detected(self):
        r = _ref_record(msg="expected message")
        d = _db_record(msg="wrong message")
        ref = _make_ref(r)
        db  = {r.key: d}
        report = compare(ref, db)
        assert report.matched   == 1
        assert report.msg_exact == 0
        assert len(report.msg_mismatches) > 0

    def test_normalised_match(self):
        r = _ref_record(msg="Hello World")
        d = _db_record(msg="hello world")  # same after lowercase
        ref = _make_ref(r)
        db  = {r.key: d}
        report = compare(ref, db)
        assert report.msg_exact      == 0
        assert report.msg_normalised == 1

    def test_counts_are_correct(self):
        records_ref = [_ref_record(i) for i in range(10)]
        records_db  = [_db_record(i)  for i in range(7)]   # 7 matched, 3 missing
        ref = _make_ref(*records_ref)
        db  = {d.key: d for d in records_db}
        report = compare(ref, db)
        assert report.ref_total == 10
        assert report.db_total  == 7
        assert report.matched   == 7
        assert report.missing   == 3
        assert report.extra     == 0

    def test_max_samples_respected(self):
        ref = _make_ref(*[_ref_record(i) for i in range(50)])
        report = compare(ref, {}, max_samples=5)
        assert len(report.missing_samples) <= 5


# ── Tests for render_report() ──────────────────────────────────────────────────

class TestRenderReport:
    def _minimal_report(self) -> ComparisonReport:
        return ComparisonReport(
            ref_total=100, db_total=100,
            ref_user_action_count=0,
            matched=98, missing=2, extra=0,
            missing_samples=[], extra_samples=[],
            msg_exact=95, msg_normalised=97, msg_format_match=90,
            msg_mismatches=[],
            field_stats=[
                FieldStats("pid",      98, 98),
                FieldStats("log_level", 98, 97),
            ],
        )

    def test_returns_string(self):
        report = self._minimal_report()
        text = render_report(report, log_fn=lambda *_: None)
        assert isinstance(text, str)
        assert len(text) > 0

    def test_contains_level_headers(self):
        report = self._minimal_report()
        text = render_report(report, log_fn=lambda *_: None)
        assert "Level 1" in text
        assert "Level 2" in text
        assert "Level 3" in text

    def test_contains_counts(self):
        report = self._minimal_report()
        text = render_report(report, log_fn=lambda *_: None)
        assert "100" in text   # ref_total
        assert "98"  in text   # matched

    def test_contains_unicode_box_chars(self):
        report = self._minimal_report()
        text = render_report(report, log_fn=lambda *_: None)
        assert "╔" in text
        assert "╚" in text

    def test_mismatch_samples_shown(self):
        report = self._minimal_report()
        report.msg_mismatches = [
            MessageMismatch(
                key=_ref_key(),
                expected="expected msg",
                got="got msg",
                format_str_expected="fmt",
                format_str_got="fmt",
            )
        ]
        text = render_report(report, log_fn=lambda *_: None)
        assert "expected msg" in text or "got msg" in text


# ── Tests for table helpers ────────────────────────────────────────────────────

class TestTableHelper:
    def test_output_is_list_of_strings(self):
        lines = _table(["A", "B"], [["1", "2"], ["3", "4"]])
        assert isinstance(lines, list)
        assert all(isinstance(l, str) for l in lines)

    def test_has_top_and_bottom_borders(self):
        lines = _table(["H"], [["v"]])
        assert lines[0].startswith("╔")
        assert lines[-1].startswith("╚")

    def test_data_rows_have_same_column_separator_count(self):
        lines = _table(["Col1", "Col2", "Col3"], [["a", "b", "c"], ["d", "e", "f"]])
        # Border lines (╔╚╠) have no ║; header and data rows do
        data_lines = [l for l in lines if l.startswith("║")]
        counts = [l.count("║") for l in data_lines]
        assert len(set(counts)) == 1, f"Inconsistent ║ counts: {counts}"


class TestPctBar:
    def test_full_bar(self):
        bar = _pct_bar(100.0)
        assert "░" not in bar
        assert "█" in bar

    def test_empty_bar(self):
        bar = _pct_bar(0.0)
        assert "█" not in bar

    def test_half_bar(self):
        bar = _pct_bar(50.0, width=20)
        assert bar.count("█") == 10
        assert bar.count("░") == 10

    def test_correct_total_width(self):
        for pct in (0, 25, 50, 75, 100):
            bar = _pct_bar(float(pct), width=20)
            assert len(bar) == 20
