"""Headless tests for the pipeline views + controllers (gui.controllers.pipeline).

Covers the light-MVC split for Acquire/Extract without running any real core op:

- the views import no ``forensic_aul.ops`` (logic lives in the controllers);
- the controllers validate inputs before dispatching, and only call the view's
  ``run_task`` host when the form is complete (``run_task`` is stubbed so the real
  ``acquire`` / ``run_extract`` never executes);
- Extract prefill and the acquisition-sidecar auto-fill (including the
  ``only_empty`` guard) populate the case fields as designed;
- Acquire's post-run hand-off builds the Extract prefill payload and navigates.

Skipped automatically if PySide6 is unavailable (it is an optional extra).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

# Qt must run head-less in CI / on a build box — set before importing PySide6.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication  # noqa: E402

import gui.recent_store as recent_store  # noqa: E402
import gui.settings_store as settings_store  # noqa: E402
from gui.recent_store import RecentStore  # noqa: E402
from gui.settings_store import SettingsStore  # noqa: E402
from gui.views import screens_pipeline  # noqa: E402
from gui.views.screens_pipeline import AcquireScreen, ExtractScreen  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    """A single QApplication for the module (Qt allows only one per process)."""
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture(autouse=True)
def _tmp_config(tmp_path, monkeypatch):
    """Redirect settings/recents persistence to tmp so tests never touch ~/.config."""
    monkeypatch.setattr(settings_store, "_SETTINGS_PATH", tmp_path / "settings.json")
    monkeypatch.setattr(recent_store, "_RECENTS_PATH", tmp_path / "recents.json")


def _stub_run_task(screen):
    """Replace the screen's off-thread host with a recorder; return the call list.

    The recorded callable (the real op) is intentionally never invoked — these
    tests assert dispatch/validation, not extraction.
    """
    calls: list[tuple] = []

    def record(task, on_finished, on_failed=None):
        calls.append((task, on_finished, on_failed))

    screen.run_task = record  # type: ignore[method-assign]
    return calls


def _make_extract():
    return ExtractScreen(SettingsStore(), RecentStore())


def _make_acquire():
    return AcquireScreen(SettingsStore(), RecentStore())


def _buttons_in(layout):
    """Return every direct-child QPushButton of a QHBoxLayout/QVBoxLayout, in order."""
    return [
        layout.itemAt(i).widget()
        for i in range(layout.count())
        if layout.itemAt(i).widget() is not None
    ]


def _button_named(layout, text):
    return next(b for b in _buttons_in(layout) if b.text() == text)


# ── View / controller separation ────────────────────────────────────────────────

def test_views_do_not_import_core_ops():
    # The logic moved to gui.controllers.pipeline; the view module must not bind
    # any core op (that is the whole point of the split).
    for name in ("run_extract", "acquire", "list_connected_devices", "load_acquisition_report"):
        assert not hasattr(screens_pipeline, name), f"view leaks core op: {name}"


# ── Extract: validation + dispatch ───────────────────────────────────────────────

def test_extract_validation_blocks_incomplete_form(qapp):
    ext = _make_extract()
    calls = _stub_run_task(ext)
    ext._ctrl.start()  # all fields empty
    assert not calls, "start dispatched despite an incomplete form"
    assert ext._result_host.count() == 1, "no validation message shown"


def test_extract_dispatches_when_complete(qapp, tmp_path):
    ext = _make_extract()
    calls = _stub_run_task(ext)
    src = tmp_path / "case.logarchive"
    src.mkdir()
    ext._src.set_path(str(src))
    ext._out.set_path(str(tmp_path / "out.sqlite"))
    ext.fill_fields(case="CASE-1", imei="123456", only_empty=False)

    ext._ctrl.start()
    assert len(calls) == 1, "a complete form should dispatch exactly one run_task"


def test_extract_prefill_populates_fields(qapp):
    ext = _make_extract()
    ext.prefill({
        "logarchive": "/tmp/x.logarchive", "case": "C-9",
        "imei": "42", "exhibit_number": "E", "analyst": "Bob",
    })
    assert (ext.case_text(), ext.imei_text(), ext.exhibit_text(),
            ext.analyst_text(), ext.source_path()) == (
        "C-9", "42", "E", "Bob", "/tmp/x.logarchive")


# ── Extract: acquisition-sidecar auto-fill ────────────────────────────────────────

def _write_sidecar(arc: Path, *, case: str, imei: str, exhibit: str = "", analyst: str = ""):
    (arc.parent / (arc.name + ".acquisition.json")).write_text(json.dumps({
        "case": {"case_number": case, "exhibit_number": exhibit, "analyst": analyst},
        "device": {"imei": imei},
    }))


def test_extract_sidecar_autofills_empty_fields(qapp, tmp_path):
    ext = _make_extract()
    arc = tmp_path / "case.logarchive"
    arc.mkdir()
    _write_sidecar(arc, case="CASE-SIDE", imei="999", exhibit="EX9", analyst="Al")

    ext._src.set_path(str(arc))  # triggers controller.on_source_changed
    assert (ext.case_text(), ext.imei_text(), ext.exhibit_text(), ext.analyst_text()) == (
        "CASE-SIDE", "999", "EX9", "Al")
    assert ext._sidecar_note.text(), "sidecar note should report the auto-fill"


def test_extract_sidecar_does_not_clobber_typed_values(qapp, tmp_path):
    ext = _make_extract()
    ext._case.setText("MANUAL")  # analyst already typed a case number
    arc = tmp_path / "case.logarchive"
    arc.mkdir()
    _write_sidecar(arc, case="FROM-SIDECAR", imei="7")

    ext._src.set_path(str(arc))
    assert ext.case_text() == "MANUAL", "only_empty guard must not overwrite typed input"
    assert ext.imei_text() == "7", "an empty field should still be filled"


def test_extract_no_sidecar_leaves_fields_empty(qapp, tmp_path):
    ext = _make_extract()
    arc = tmp_path / "lonely.logarchive"
    arc.mkdir()  # no sidecar written

    ext._src.set_path(str(arc))
    assert ext.case_text() == "" and ext.imei_text() == ""
    assert not ext._sidecar_note.isVisibleTo(ext)


# ── Extract: jobs dropdown ────────────────────────────────────────────────────────

def test_extract_jobs_dropdown_has_auto_and_capped_choices(qapp):
    ext = _make_extract()
    data = [ext._jobs.itemData(i) for i in range(ext._jobs.count())]
    assert data[0] == 0, "first entry must be Auto (data 0)"
    assert 1 in data, "serial (1) must always be offered"
    assert all(n <= max(8, 1) for n in data if n), "explicit choices stay within the cap"


# ── Acquire: validation + hand-off ────────────────────────────────────────────────

def test_acquire_validation_blocks_without_case(qapp, tmp_path):
    acq = _make_acquire()
    calls = _stub_run_task(acq)
    acq._out.set_path(str(tmp_path))  # output set, but case empty
    acq._ctrl.start()
    assert not calls, "acquire dispatched without a case number"
    assert acq._result_host.count() == 1


class _FakeAcquireResult:
    logarchive_path = "/tmp/c.logarchive"
    logarchive_sha256 = "abc123def456"

    class device:  # noqa: N801 - stand-in for DeviceInfo
        imei = "356000000000001"


def test_acquire_on_done_builds_payload_and_navigates(qapp):
    acq = _make_acquire()
    acq._case.setText("CASE-A")
    acq._analyst.setText("Ana")

    acq._ctrl.on_done(_FakeAcquireResult())
    payload = acq._ctrl._prefill_payload
    assert payload == {
        "logarchive": "/tmp/c.logarchive",
        "imei": "356000000000001",
        "case": "CASE-A",
        "exhibit_number": None,
        "analyst": "Ana",
    }
    assert not acq._continue_btn.isHidden(), "Continue shortcut should appear after a run"

    navigated: list[tuple] = []
    acq.navigate = lambda screen_id, **kw: navigated.append((screen_id, kw))
    acq._ctrl.continue_to_extract()
    assert navigated == [("extract", {"prefill": payload})]


# ── Button language: one primary (violet) button per action row ─────────────────
# Every terminal state (idle / running / done) may show at most one
# variant="primary" button — everything else must be variant="ghost". Covers
# both AcquireScreen (persistent buttons, relabelled in place) and
# ExtractScreen (the action row is rebuilt per state via clear_layout).

def test_acquire_idle_state_has_one_primary_button(qapp):
    acq = _make_acquire()
    assert acq._start_btn.property("variant") == "primary"
    assert acq._reset_btn.property("variant") == "ghost"
    assert acq._continue_btn.isHidden(), "Continue shortcut is idle-only, not visible yet"


def test_acquire_running_state_keeps_primary_relabelled(qapp):
    acq = _make_acquire()
    acq.set_running(True)
    # Running swaps neither the widget nor its variant — only text + enabled —
    # so the row still shows exactly one primary button, now disabled.
    assert acq._start_btn.property("variant") == "primary"
    assert acq._start_btn.text() == "Acquiring…"
    assert not acq._start_btn.isEnabled()


def test_acquire_done_state_demotes_start_to_ghost(qapp):
    acq = _make_acquire()
    acq.set_running(False)
    acq.set_continue_visible(True)
    # "Continue to Extract" is now the row's forward action; "Start
    # acquisition" must be demoted so only one primary button remains.
    assert acq._continue_btn.property("variant") == "primary"
    assert acq._start_btn.property("variant") == "ghost"

    acq.set_continue_visible(False)  # a fresh run / reset restores it
    assert acq._start_btn.property("variant") == "primary"


def test_extract_idle_state_has_one_primary_button(qapp):
    ext = _make_extract()
    ext.show_idle_actions()
    buttons = _buttons_in(ext._actions)
    primaries = [b for b in buttons if b.property("variant") == "primary"]
    assert len(primaries) == 1
    assert primaries[0].text() == "Start extraction"
    assert all(b.property("variant") in ("primary", "ghost") for b in buttons)


def test_extract_running_state_keeps_primary_relabelled(qapp):
    ext = _make_extract()
    ext.show_running_actions()
    buttons = _buttons_in(ext._actions)
    assert len(buttons) == 1
    running = buttons[0]
    assert running.property("variant") == "primary", (
        "the running state must relabel the primary button, not swap in a ghost"
    )
    assert running.text() == "Extracting…"
    assert not running.isEnabled()


def test_extract_done_state_has_one_primary_button(qapp):
    ext = _make_extract()
    ext.show_done_actions()
    buttons = _buttons_in(ext._actions)
    primaries = [b for b in buttons if b.property("variant") == "primary"]
    assert len(primaries) == 1, "exactly one primary button in the done-state row"
    assert primaries[0].text() == "Open in Exploit"
    assert _button_named(ext._actions, "Extract new").property("variant") == "ghost"
    assert _button_named(ext._actions, "Export").property("variant") == "ghost"


# ── Extract: Notes field ─────────────────────────────────────────────────────────

def test_extract_notes_field_exists_and_is_readable(qapp):
    ext = _make_extract()
    ext._notes.setText("  seized during a consent search  ")
    assert ext.notes_text() == "seized during a consent search"


def test_extract_notes_reach_run_extract(qapp, tmp_path, monkeypatch):
    """Notes typed on Extract must reach run_extract.

    Acquire already collected notes and the op already accepted them, so the
    hand-off silently dropped case context an examiner had deliberately written
    down (review item G8).
    """
    ext = _make_extract()
    src = tmp_path / "case.logarchive"
    src.mkdir()
    ext._src.set_path(str(src))
    ext._out.set_path(str(tmp_path / "out.sqlite"))
    ext.fill_fields(case="CASE-1", imei="123456", only_empty=False)
    ext._notes.setText("collected in the lab")

    captured: dict = {}

    def fake_run_extract(*args, **kwargs):
        captured.update(kwargs)
        raise RuntimeError("stop before any real extraction runs")

    import gui.controllers.pipeline as pipeline_module

    monkeypatch.setattr(pipeline_module, "run_extract", fake_run_extract)
    calls = _stub_run_task(ext)
    ext._ctrl.start()
    assert len(calls) == 1
    task = calls[0][0]
    try:
        task()
    except RuntimeError:
        pass
    assert captured.get("notes") == "collected in the lab"


# ── Extract: recents must never populate the output field ───────────────────────

def test_extract_has_no_recent_databases_list(qapp):
    """The output field is a destination the operator is about to write to; an
    existing case.sqlite is neither a safe autofill for it (one Overwrite tick
    from clobbering a previous case) nor a valid Source (it is not a raw
    logarchive/.tar.gz/.zip). So, unlike Acquire, Extract has no recents list
    at all — see the WHY comment above the Output section in screens_pipeline.py."""
    ext = _make_extract()
    assert not hasattr(ext, "_recent_list")
    assert not hasattr(ext, "_pick_db")


def test_extract_jobs_default_comes_from_settings(qapp, tmp_path, monkeypatch):
    """The extractJobs preference pre-selects the dropdown (Phase 4 wiring)."""
    import gui.settings_store as settings_store
    from gui.settings_store import SettingsStore
    from gui.views.screens_pipeline import ExtractScreen, _job_options

    monkeypatch.setattr(settings_store, "_SETTINGS_PATH", tmp_path / "settings.json")
    options = _job_options()
    if len(options) < 2:
        pytest.skip("host offers too few core choices to test a non-Auto default")

    store = SettingsStore()
    store.set("extractJobs", options[-1])
    screen = ExtractScreen(store, RecentStore())
    assert screen.jobs_value() == options[-1]
    screen.deleteLater()


def test_extract_jobs_falls_back_to_auto_on_a_smaller_host(qapp, tmp_path, monkeypatch):
    """A preference the host cannot honour must not invent a core count."""
    import gui.settings_store as settings_store
    from gui.settings_store import SettingsStore
    from gui.views.screens_pipeline import ExtractScreen

    monkeypatch.setattr(settings_store, "_SETTINGS_PATH", tmp_path / "settings.json")
    store = SettingsStore()
    store.set("extractJobs", 256)          # more cores than any test host has
    screen = ExtractScreen(store, RecentStore())
    assert screen.jobs_value() == 0        # Auto
    screen.deleteLater()
