"""Headless tests for the Identify wizard (view + controller).

Covers the wizard's setup validation, the two interactive pauses (still countdown
+ action wait) driven through real threads, abort handling, the DONE summary, the
"View results" navigation hand-off, and the DevicePicker states — all without a
real device or ``run_identify_workflow`` (a fake workflow drives the controller's
``wait_still`` / ``wait_for_action`` callbacks from a worker thread exactly as the
real one does).

Skipped automatically if PySide6 is unavailable (it is an optional extra).
"""

from __future__ import annotations

import os
import threading

import pytest

# Qt must run head-less in CI / on a build box — set before importing PySide6.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication  # noqa: E402

import gui.controllers.identify as identify_ctrl  # noqa: E402
import gui.recent_store as recent_store  # noqa: E402
import gui.settings_store as settings_store  # noqa: E402
from forensic_aul import OperationCancelled  # noqa: E402
from forensic_aul.outcomes import DiffResult, IdentifyResult  # noqa: E402
from gui.recent_store import RecentStore  # noqa: E402
from gui.settings_store import SettingsStore  # noqa: E402
from gui.views.screens_identify import IdentifyScreen, _State  # noqa: E402
from gui.widgets.device_picker import DevicePicker  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture(autouse=True)
def _tmp_config(tmp_path, monkeypatch):
    monkeypatch.setattr(settings_store, "_SETTINGS_PATH", tmp_path / "settings.json")
    monkeypatch.setattr(recent_store, "_RECENTS_PATH", tmp_path / "recents.json")


class _FakeDevice:
    udid = "UDID-1"
    imei = "356000000000001"
    product_type = "iPhone14,2"
    product_version = "17.5"
    device_name = "Test iPhone"


def _make_screen() -> IdentifyScreen:
    return IdentifyScreen(SettingsStore(), RecentStore())


def _select_device(screen: IdentifyScreen) -> None:
    screen.set_devices([_FakeDevice()])


def _fake_result(sqlite_path="/tmp/x-identified.db", retained=3, excluded=1) -> IdentifyResult:
    from pathlib import Path

    diff = DiffResult(csv_path=None, sqlite_path=Path(sqlite_path),
                      retained=retained, excluded=excluded)
    return IdentifyResult(
        baseline_archive=Path("/tmp/b.logarchive"),
        action_archive=Path("/tmp/a.logarchive"),
        baseline_db=Path("/tmp/b.db"), action_db=Path("/tmp/a.db"), diff=diff,
    )


class _ThreadRunner:
    """Stands in for OperationScreen.run_task: runs the task on a real thread.

    The finished/failed/cancelled callbacks are recorded, not auto-fired, so a
    test can join the worker (after pressing Skip/Continue/Abort from the main
    thread) and then dispatch the recorded callback synchronously — mirroring the
    real GUI-thread delivery without needing a spinning Qt event loop.

    The three-way routing below mirrors gui.workers.base.Worker.run exactly: an
    OperationCancelled goes to on_cancelled as the OBJECT, anything else to
    on_failed as a formatted traceback. A test that only checked "did we get to
    SETUP" would pass either way, so the split has to be real here.
    """

    def __init__(self) -> None:
        self.thread: threading.Thread | None = None
        self._task = None
        self._on_finished = None
        self._on_failed = None
        self._on_cancelled = None
        self._result = None
        self._error: BaseException | None = None

    def run_task(self, task, on_finished, on_failed=None, on_cancelled=None):
        self._on_finished, self._on_failed = on_finished, on_failed
        self._on_cancelled = on_cancelled

        def _body():
            try:
                self._result = task()
            except BaseException as exc:  # noqa: BLE001 — captured to route to on_failed
                self._error = exc

        # Daemon so a failed assertion can never wedge the process on a worker
        # still blocked in a pause (the test releases it, but be defensive).
        self.thread = threading.Thread(target=_body, daemon=True)
        self.thread.start()

    def join_and_dispatch(self, timeout=5.0) -> None:
        assert self.thread is not None
        self.thread.join(timeout)
        assert not self.thread.is_alive(), "worker thread did not finish in time"
        if isinstance(self._error, OperationCancelled):
            if self._on_cancelled is not None:
                self._on_cancelled(self._error)
        elif self._error is not None:
            import traceback

            tb = "".join(traceback.format_exception(
                type(self._error), self._error, self._error.__traceback__))
            if self._on_failed is not None:
                self._on_failed(tb)
        elif self._on_finished is not None:
            self._on_finished(self._result)


def _install_fake_workflow(monkeypatch, screen, *, drives="still", result=None):
    """Patch run_identify_workflow with a fake that drives one pause callback.

    *drives* selects which pause the fake exercises: "still" calls wait_still, "wait"
    fires the ``wait`` progress phase then calls wait_for_action, "none" returns at
    once. The fake runs on the worker thread (via _ThreadRunner).
    """
    runner = _ThreadRunner()
    screen.run_task = runner.run_task  # type: ignore[method-assign]

    def _fake(**kwargs):
        progress = kwargs["progress"]

        class _Ev:
            def __init__(self, overall, phase):
                self.overall, self.phase, self.detail = overall, phase, phase

        if drives == "still":
            kwargs["wait_still"](2)  # ticks a 2s countdown unless skipped/aborted
        elif drives == "wait":
            progress(_Ev(0.4, "wait"))   # switches the view to WAITING
            kwargs["wait_for_action"]()
        return result if result is not None else _fake_result()

    monkeypatch.setattr(identify_ctrl, "run_identify_workflow", _fake)
    # KB loading is irrelevant to these tests — never touch the filesystem KB.
    monkeypatch.setattr(identify_ctrl, "load_kb", lambda _path: None)
    return runner


# ── Setup validation ──────────────────────────────────────────────────────────

def test_setup_requires_device(qapp, monkeypatch):
    screen = _make_screen()
    calls = []
    screen.run_task = lambda *a, **k: calls.append(a)  # type: ignore[method-assign]
    screen._out.set_path("/tmp/out")
    screen._ctrl.start()  # no device selected
    assert not calls, "start dispatched without a device"
    assert screen._result_host.count() == 1


def test_setup_requires_output_dir(qapp, monkeypatch):
    screen = _make_screen()
    calls = []
    screen.run_task = lambda *a, **k: calls.append(a)  # type: ignore[method-assign]
    _select_device(screen)
    screen._ctrl.start()  # no output dir
    assert not calls, "start dispatched without an output dir"
    assert screen._result_host.count() == 1


def test_session_label_is_optional(qapp, monkeypatch):
    screen = _make_screen()
    runner = _install_fake_workflow(monkeypatch, screen, drives="none")
    _select_device(screen)
    screen._out.set_path("/tmp/out")
    # No session label set — must still dispatch.
    screen._ctrl.start()
    assert runner.thread is not None, "a valid form should dispatch a run"
    runner.join_and_dispatch()


# ── Still phase: Skip + Abort ───────────────────────────────────────────────────

def test_still_skip_releases_early(qapp, monkeypatch):
    screen = _make_screen()
    runner = _install_fake_workflow(monkeypatch, screen, drives="still")
    _select_device(screen)
    screen._out.set_path("/tmp/out")
    screen._ctrl.start()
    # Skip from the "GUI thread" while the worker blocks in wait_still.
    screen._ctrl.skip_still()
    runner.join_and_dispatch()
    # Skip is not an abort: the run completes to DONE.
    assert screen._done_host.count() >= 1


def test_abort_during_still_returns_to_setup(qapp, monkeypatch):
    screen = _make_screen()
    runner = _install_fake_workflow(monkeypatch, screen, drives="still")
    _select_device(screen)
    screen._out.set_path("/tmp/out")
    screen._ctrl.start()
    screen._ctrl.abort()  # cancels the token + wakes the pause → OperationCancelled
    runner.join_and_dispatch()
    assert screen._setup_panel.isVisibleTo(screen), "abort should return to SETUP"
    assert screen._result_host.count() == 1, "an informational message is shown"


# ── Action phase: Continue + WAITING switch ─────────────────────────────────────

def test_action_wait_switches_to_waiting_then_continue(qapp, monkeypatch):
    screen = _make_screen()
    runner = _install_fake_workflow(monkeypatch, screen, drives="wait")
    _select_device(screen)
    screen._out.set_path("/tmp/out")
    screen._ctrl.start()
    # The fake fires the "wait" progress phase from the worker thread; the view's
    # _on_progress is delivered via a queued signal, so pump the event loop until
    # the WAITING panel appears (there is no running loop in a headless test).
    _wait_for(lambda: screen._waiting_panel.isVisibleTo(screen), qapp=qapp)
    assert screen._waiting_panel.isVisibleTo(screen)
    screen._ctrl.continue_action()  # release wait_for_action
    runner.join_and_dispatch()
    assert screen._done_host.count() >= 1


# ── Completion + navigation ─────────────────────────────────────────────────────

def test_done_shows_counts_and_view_results_navigates(qapp, monkeypatch):
    screen = _make_screen()
    runner = _install_fake_workflow(
        monkeypatch, screen, drives="none",
        result=_fake_result(sqlite_path="/tmp/case-identified.db", retained=7),
    )
    _select_device(screen)
    screen._out.set_path("/tmp/out")

    navigated: list[tuple] = []
    screen.navigate = lambda screen_id, **kw: navigated.append((screen_id, kw))

    screen._ctrl.start()
    runner.join_and_dispatch()
    assert screen._done_host.count() >= 1, "DONE renders a summary + actions"

    # Click "View results" — it navigates to the Identify hub's Results tab
    # with the db prefill (single sidebar entry; the hub routes to the viewer).
    screen._open_results("/tmp/case-identified.db")
    assert navigated == [
        ("identify", {"prefill": {"tab": "results", "db": "/tmp/case-identified.db"}})
    ]


# ── DevicePicker ────────────────────────────────────────────────────────────────

def test_device_picker_states_and_selection(qapp):
    picker = DevicePicker()
    assert picker.selected_udid() is None  # placeholder entry has no udid
    picker.set_scanning()
    assert picker.selected_udid() is None
    picker.set_devices([_FakeDevice()])
    assert picker.selected_udid() == "UDID-1"
    picker.set_scan_failed()
    assert picker.selected_udid() is None


def _wait_for(predicate, *, qapp=None, timeout=5.0) -> None:
    """Spin until *predicate* holds, pumping the Qt loop so queued signals fire."""
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if qapp is not None:
            qapp.processEvents()  # deliver queued worker→GUI progress signals
        if predicate():
            return
        time.sleep(0.01)


# ── IdentifyHub (single sidebar entry, Run/Results tabs) ───────────────────────

def test_hub_prefill_routes_to_results_tab(qapp, monkeypatch):
    from gui.views.screen_identify_hub import IdentifyHub

    hub = IdentifyHub(SettingsStore(), RecentStore())
    assert hub.current_tab() == "run"

    # Prefill with a results payload switches the tab and forwards the db.
    forwarded: list[dict] = []
    monkeypatch.setattr(hub._results, "prefill", forwarded.append)
    hub.prefill({"tab": "results", "db": "/tmp/x-identified.db"})
    assert hub.current_tab() == "results"
    assert forwarded == [{"tab": "results", "db": "/tmp/x-identified.db"}]

    # And back to the wizard.
    hub.prefill({"tab": "run"})
    assert hub.current_tab() == "run"


def test_hub_relays_wizard_progress(qapp):
    from gui.views.screen_identify_hub import IdentifyHub

    hub = IdentifyHub(SettingsStore(), RecentStore())
    seen: list[tuple] = []
    hub.progressChanged.connect(lambda fraction, label: seen.append((fraction, label)))
    hub._run.emit_progress(0.5, "baseline")
    assert seen == [(0.5, "baseline")]


# ── Controller helpers (no Qt needed) ────────────────────────────────────────

def test_kb_dir_points_at_the_shipped_knowledge_base():
    # CWD-independent: a GUI launched from the Dock has cwd "/", so the KB path
    # must resolve from the package location, not the working directory.
    assert identify_ctrl._KB_DIR.is_absolute()
    assert identify_ctrl._KB_DIR.name == "knowledge_base"
    assert identify_ctrl._KB_DIR.is_dir()


def test_a_crash_is_never_reported_as_an_abort(qapp, monkeypatch):
    """A failure whose MESSAGE mentions an abort must not be read as one.

    This is the trap the controller's old traceback-sniffing existed to avoid,
    and it is now closed structurally rather than textually: a real stop arrives
    on the worker's `cancelled` signal carrying the exception object, everything
    else on `failed`, so the WORDING of an unrelated error cannot change the
    verdict. Asserting on the message, not just on the SETUP state, is the point
    — both paths return to SETUP, so a state-only check would pass either way.
    """
    screen = _make_screen()
    runner = _install_fake_workflow(monkeypatch, screen, drives="none")
    monkeypatch.setattr(
        identify_ctrl, "run_identify_workflow",
        lambda **_kwargs: (_ for _ in ()).throw(
            RuntimeError("wrapped an AcquisitionAborted somewhere")
        ),
    )
    shown: list[tuple[bool, str]] = []
    screen.show_result = lambda ok, message: shown.append((ok, message))

    _select_device(screen)
    screen._out.set_path("/tmp/out")
    screen._ctrl.start()
    runner.join_and_dispatch()

    assert shown, "a failure must be surfaced"
    _, message = shown[-1]
    assert "wrapped an AcquisitionAborted somewhere" in message
    assert not message.startswith("Aborted"), "a crash was misreported as an abort"


def test_an_abort_reports_the_abort_wording(qapp, monkeypatch):
    """The other half: a real stop is reported as one, and says what was kept."""
    screen = _make_screen()
    runner = _install_fake_workflow(monkeypatch, screen, drives="still")
    shown: list[tuple[bool, str]] = []
    screen.show_result = lambda ok, message: shown.append((ok, message))

    _select_device(screen)
    screen._out.set_path("/tmp/out")
    screen._ctrl.start()
    screen._ctrl.abort()
    runner.join_and_dispatch()

    assert shown and shown[-1][1].startswith("Aborted")
