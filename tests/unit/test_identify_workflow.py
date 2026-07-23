"""Unit tests for forensic_aul.ops.identify.workflow — the identify orchestration.

Device collection is hardware-bound (optional pymobiledevice3), and the extract /
diff steps are covered by their own suites, so every external step is
monkeypatched (same approach as test_acquire.py). What is exercised here is the
workflow's control flow: callback sequencing, abort paths, path safety, the
still-pause / t0 semantics, integrity gating, KB annotation, progress reporting,
and the IdentifyResult assembly.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import forensic_aul.ops.identify.workflow as wf
from forensic_aul.engine.utils.progress import ProgressEvent
from forensic_aul.ops.acquisition.acquire import AcquisitionAborted
from forensic_aul.ops.identify.workflow import _IDENTIFY_PHASES, run_identify_workflow
from forensic_aul.outcomes import DiffResult

_PHASE_ORDER = [name for name, _ in _IDENTIFY_PHASES]


def _fake_device(imei: str = "356938035643809") -> SimpleNamespace:
    return SimpleNamespace(imei=imei, udid="00008030-001A2B3C4D5E",
                           display_table=lambda: "(device table)")


@pytest.fixture
def patched(monkeypatch, tmp_path):
    """Patch connect / collect / hash / report / extract / annotate / diff with fakes.

    Returns a namespace with the fake device, the call log, and lists capturing
    the kwargs passed to run_extract / annotate_database so tests can assert on
    them without re-deriving the workflow's internals.
    """
    device = _fake_device()
    calls: list[str] = []
    extract_calls: list[dict] = []
    annotate_calls: list[tuple] = []
    collect_starts: dict[str, int] = {}

    async def fake_connect(udid=None):
        calls.append("connect")
        return ("LOCKDOWN", device)

    async def fake_close(lockdown):
        calls.append("close")

    async def fake_collect(lockdown, out, *, size_limit, age_limit, start_unix):
        name = Path(out).name
        calls.append(f"collect:{name}")
        collect_starts[name] = start_unix
        Path(out).mkdir(parents=True, exist_ok=True)

    def fake_hash(path):
        calls.append(f"hash:{Path(path).name}")
        return "deadbeef", {"Persist/0.tracev3": "aa"}

    def fake_report(**kwargs):
        calls.append("report")
        return Path(str(kwargs["logarchive_path"])).with_suffix(".acquisition.json")

    def fake_run_extract(archive, db, **kwargs):
        calls.append(f"extract:{Path(db).name}")
        extract_calls.append(kwargs)
        progress_cb = kwargs.get("progress")
        if progress_cb is not None:
            progress_cb(ProgressEvent(1.0, "extract", 1.0, "done"))
        Path(db).write_bytes(b"")
        return SimpleNamespace(db_path=Path(db))

    def fake_annotate_database(db, kb):
        calls.append("annotate")
        annotate_calls.append((db, kb))

    def fake_run_diff(baseline_db, action_db, csv_out, sqlite_out):
        calls.append("diff")
        return DiffResult(csv_path=csv_out, sqlite_path=sqlite_out, retained=3, excluded=7)

    monkeypatch.setattr(wf, "connect_device", fake_connect)
    monkeypatch.setattr(wf, "close_lockdown", fake_close)
    monkeypatch.setattr(wf, "collect_logarchive", fake_collect)
    monkeypatch.setattr(wf, "hash_logarchive", fake_hash)
    monkeypatch.setattr(wf, "write_acquisition_report",
                        lambda **kw: fake_report(**kw))
    # run_extract / annotate_database are imported inside the function body —
    # patch their home modules (same approach the original fixture already used).
    import forensic_aul.ops.extraction.extract as extract_mod
    import forensic_aul.ops.annotation.matcher as matcher_mod
    monkeypatch.setattr(extract_mod, "run_extract", fake_run_extract)
    monkeypatch.setattr(matcher_mod, "annotate_database", fake_annotate_database)
    monkeypatch.setattr(wf, "run_diff", fake_run_diff)

    return SimpleNamespace(
        device=device, calls=calls, out=tmp_path / "out",
        extract_calls=extract_calls, annotate_calls=annotate_calls,
        collect_starts=collect_starts,
    )


class TestWorkflow:
    def test_full_sequence_and_result(self, patched):
        seen: list[str] = []
        res = run_identify_workflow(
            "CASE-1",
            output_dir=patched.out,
            confirm=lambda device: True,
            wait_for_action=lambda: seen.append("action"),
            status=seen.append,
        )
        # Both acquisitions happened, in order, with the action wait between them.
        collects = [c for c in patched.calls if c.startswith("collect:")]
        assert len(collects) == 2
        assert "baseline" in collects[0] and "action" in collects[1]
        assert "action" in seen  # wait_for_action ran
        # Both archives extracted, then diffed; the connection was closed.
        assert [c for c in patched.calls if c.startswith("extract:")]
        assert patched.calls[-1] == "diff" and "close" in patched.calls
        # Result carries the four artefacts + the nested diff.
        assert res.baseline_archive.name.endswith("-baseline.logarchive")
        assert res.action_archive.name.endswith("-action.logarchive")
        assert res.baseline_db.suffix == ".db" and res.action_db.suffix == ".db"
        assert res.diff.retained == 3 and res.diff.excluded == 7
        # Chain-of-custody prefix embeds case + IMEI.
        assert res.baseline_db.name.startswith("CASE-1-356938035643809-")

    def test_confirm_decline_aborts_before_collection(self, patched):
        with pytest.raises(AcquisitionAborted):
            run_identify_workflow(
                "CASE-1",
                output_dir=patched.out,
                confirm=lambda device: False,
                wait_for_action=lambda: None,
            )
        assert not any(c.startswith("collect:") for c in patched.calls)
        assert "close" in patched.calls  # connection released on the abort path

    def test_wait_callback_can_abort(self, patched):
        def bail() -> None:
            raise AcquisitionAborted("operator interrupted")

        with pytest.raises(AcquisitionAborted):
            run_identify_workflow(
                "CASE-1", output_dir=patched.out,
                confirm=None, wait_for_action=bail,
            )
        # The baseline was collected, the post-action acquisition never ran.
        collects = [c for c in patched.calls if c.startswith("collect:")]
        assert len(collects) == 1 and "baseline" in collects[0]
        assert "close" in patched.calls

    def test_unusable_case_number_raises(self, patched, monkeypatch):
        # sanitise_filename_token replaces (never drops) forbidden characters, so
        # no ordinary non-empty string actually sanitises to "" any more — force
        # the edge case to exercise the guard directly (still-truthy case_number
        # whose sanitised form is empty). An empty/falsy case_number is a
        # *different* path — it falls back to the "identify-<UTC>" prefix rather
        # than raising (see test_no_case_number_uses_identify_prefix).
        monkeypatch.setattr(wf, "sanitise_filename_token",
                            lambda value: "" if value == "UNSANITISABLE" else value)
        with pytest.raises(ValueError, match="filename characters"):
            run_identify_workflow("UNSANITISABLE", output_dir=patched.out)

    def test_no_case_number_uses_identify_prefix(self, patched):
        res = run_identify_workflow(
            None, output_dir=patched.out,
            confirm=None, wait_for_action=None,
        )
        assert res.baseline_db.name.startswith("identify-")
        assert res.action_db.name.startswith("identify-")

    def test_wait_still_called_before_first_collect_with_t0_start(self, patched):
        seen: list[str] = []

        def still(seconds: int) -> None:
            seen.append(f"still:{seconds}")
            assert not any(c.startswith("collect:") for c in patched.calls)

        run_identify_workflow(
            "CASE-1", output_dir=patched.out, still_seconds=42,
            confirm=None, wait_still=still, wait_for_action=None,
        )
        assert seen == ["still:42"]
        # Baseline start_unix is t0 — captured before the still wait, so it must
        # be at or before "now" at the time collect ran (never in the future).
        import time as time_mod
        baseline_key = next(k for k in patched.collect_starts if "baseline" in k)
        assert patched.collect_starts[baseline_key] <= int(time_mod.time())

    def test_still_seconds_zero_skips_wait_still(self, patched):
        seen: list[str] = []
        run_identify_workflow(
            "CASE-1", output_dir=patched.out, still_seconds=0,
            confirm=None, wait_still=lambda s: seen.append(s), wait_for_action=None,
        )
        assert seen == []
        collects = [c for c in patched.calls if c.startswith("collect:")]
        assert len(collects) == 2

    def test_wait_still_none_skips_wait_still(self, patched):
        run_identify_workflow(
            "CASE-1", output_dir=patched.out, still_seconds=60,
            confirm=None, wait_still=None, wait_for_action=None,
        )
        collects = [c for c in patched.calls if c.startswith("collect:")]
        assert len(collects) == 2

    def test_wait_still_raising_aborts_before_any_collect(self, patched):
        def bail(seconds: int) -> None:
            raise AcquisitionAborted("operator refused the still pause")

        with pytest.raises(AcquisitionAborted):
            run_identify_workflow(
                "CASE-1", output_dir=patched.out, still_seconds=10,
                confirm=None, wait_still=bail, wait_for_action=None,
            )
        assert not any(c.startswith("collect:") for c in patched.calls)
        assert "close" in patched.calls

    def test_integrity_off_by_default_skips_hash_and_report(self, patched):
        run_identify_workflow(
            "CASE-1", output_dir=patched.out,
            confirm=None, wait_for_action=None,
        )
        assert not any(c.startswith("hash:") for c in patched.calls)
        assert "report" not in patched.calls

    def test_integrity_full_runs_hash_and_report(self, patched):
        run_identify_workflow(
            "CASE-1", output_dir=patched.out, integrity="full",
            confirm=None, wait_for_action=None,
        )
        assert any(c.startswith("hash:") for c in patched.calls)
        assert "report" in patched.calls

    def test_kb_given_annotates_action_db_only(self, patched):
        sentinel_kb = object()
        run_identify_workflow(
            "CASE-1", output_dir=patched.out, kb=sentinel_kb,
            confirm=None, wait_for_action=None,
        )
        assert len(patched.annotate_calls) == 1
        annotated_db, used_kb = patched.annotate_calls[0]
        assert used_kb is sentinel_kb
        assert "action" in Path(annotated_db).name

    def test_kb_annotate_raising_still_completes_run(self, patched, monkeypatch):
        import forensic_aul.ops.annotation.matcher as matcher_mod

        def boom(db, kb):
            raise RuntimeError("annotation blew up")

        monkeypatch.setattr(matcher_mod, "annotate_database", boom)
        res = run_identify_workflow(
            "CASE-1", output_dir=patched.out, kb=object(),
            confirm=None, wait_for_action=None,
        )
        assert res.diff.retained == 3  # the run still completed through diff

    def test_run_extract_kwargs_carry_through(self, patched):
        run_identify_workflow(
            "CASE-1", output_dir=patched.out,
            jobs=4, fts=True, integrity="fingerprint", batch_size=500,
            confirm=None, wait_for_action=None,
        )
        assert len(patched.extract_calls) == 2
        for kwargs in patched.extract_calls:
            assert kwargs["jobs"] == 4
            assert kwargs["fts"] is True
            assert kwargs["integrity"] == "fingerprint"
            assert kwargs["batch_size"] == 500
            assert callable(kwargs["progress"])

    def test_progress_phases_in_order_and_reach_1_0(self, patched):
        events: list[ProgressEvent] = []
        run_identify_workflow(
            "CASE-1", output_dir=patched.out, kb=object(),
            confirm=None,
            wait_still=lambda s: None, still_seconds=1,
            wait_for_action=lambda: None,
            progress=events.append,
        )
        assert events, "progress sink received no events"
        seen_phases = []
        for ev in events:
            if not seen_phases or seen_phases[-1] != ev.phase:
                seen_phases.append(ev.phase)
        # Every phase encountered must appear in declared order (a subset when
        # phases are skipped, e.g. "still" only fires because we passed wait_still).
        filtered_order = [p for p in _PHASE_ORDER if p in seen_phases]
        assert seen_phases == filtered_order
        overalls = [ev.overall for ev in events]
        assert overalls == sorted(overalls)  # non-decreasing
        assert overalls[-1] == 1.0

    def test_progress_wait_phase_fires_before_wait_for_action(self, patched):
        events: list[ProgressEvent] = []
        order: list[str] = []

        def wait_for_action() -> None:
            order.append("wait_for_action")

        # Wrap the sink so we record when the "wait" phase event arrives
        # relative to wait_for_action's invocation.
        def sink(ev: ProgressEvent) -> None:
            events.append(ev)
            if ev.phase == "wait":
                order.append("progress:wait")

        run_identify_workflow(
            "CASE-1", output_dir=patched.out,
            confirm=None, wait_for_action=wait_for_action,
            progress=sink,
        )
        assert order[0] == "progress:wait"
        assert "wait_for_action" in order
        assert order.index("progress:wait") < order.index("wait_for_action")

    def test_write_csv_false_passes_none_to_run_diff(self, patched, monkeypatch):
        captured = {}

        def fake_run_diff(baseline_db, action_db, csv_out, sqlite_out):
            captured["csv_out"] = csv_out
            return DiffResult(csv_path=csv_out, sqlite_path=sqlite_out, retained=0, excluded=0)

        monkeypatch.setattr(wf, "run_diff", fake_run_diff)
        run_identify_workflow(
            "CASE-1", output_dir=patched.out, write_csv=False,
            confirm=None, wait_for_action=None,
        )
        assert captured["csv_out"] is None
