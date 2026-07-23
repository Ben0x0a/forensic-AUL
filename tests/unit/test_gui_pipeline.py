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
        "imei": "42", "exhibit": "E", "analyst": "Bob",
    })
    assert (ext.case_text(), ext.imei_text(), ext.exhibit_text(),
            ext.analyst_text(), ext.source_path()) == (
        "C-9", "42", "E", "Bob", "/tmp/x.logarchive")


# ── Extract: acquisition-sidecar auto-fill ────────────────────────────────────────

def _write_sidecar(arc: Path, *, case: str, imei: str, exhibit: str = "", analyst: str = ""):
    (arc.parent / (arc.name + ".acquisition.json")).write_text(json.dumps({
        "case": {"case_number": case, "exhibit": exhibit, "analyst": analyst},
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
        "exhibit": None,
        "analyst": "Ana",
    }
    assert not acq._continue_btn.isHidden(), "Continue shortcut should appear after a run"

    navigated: list[tuple] = []
    acq.navigate = lambda screen_id, **kw: navigated.append((screen_id, kw))
    acq._ctrl.continue_to_extract()
    assert navigated == [("extract", {"prefill": payload})]
