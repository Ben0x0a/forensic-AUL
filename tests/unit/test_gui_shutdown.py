"""Headless tests for closing the app while an operation is running.

Three things are pinned here:

1. **closeEvent must not block.** The old implementation called
   ``thread.wait()`` with no timeout, freezing the GUI thread for as long as the
   extract had left to run. The replacement refuses the close and drains through
   the event loop, so ``closeEvent`` must return essentially instantly even while
   a screen reports itself busy — asserted against a hard wall-clock bound.
2. **A busy Identify hub is detected.** ``IdentifyHub`` is a plain ``QWidget``
   with no ``_thread``, so the old attribute-poke reported it idle and tore a
   running identify down silently. The regression test is that the coordinator
   now sees it.
3. **The cancellation contract** on ``OperationScreen``: ``is_busy()``,
   ``request_cancel()``, and the third worker outcome (``cancelled``) reaching
   the screen's callback instead of arriving as a traceback string.

Skipped automatically if PySide6 is unavailable (it is an optional extra).
"""

from __future__ import annotations

import os
import threading
import time

import pytest

# Qt must run head-less in CI / on a build box — set before importing PySide6.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")

from PySide6.QtCore import QObject, Signal  # noqa: E402
from PySide6.QtGui import QCloseEvent  # noqa: E402
from PySide6.QtWidgets import QApplication, QWidget  # noqa: E402

import gui.recent_store as recent_store  # noqa: E402
import gui.settings_store as settings_store  # noqa: E402
from forensic_aul.errors import OperationCancelled  # noqa: E402
from gui.shutdown import ShutdownCoordinator  # noqa: E402
from gui.views.screen_base import OperationScreen  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture(autouse=True)
def _tmp_config(tmp_path, monkeypatch):
    """Keep settings/recents out of ~/.config for every test in this module."""
    monkeypatch.setattr(settings_store, "_SETTINGS_PATH", tmp_path / "settings.json")
    monkeypatch.setattr(recent_store, "_RECENTS_PATH", tmp_path / "recents.json")


def _settle(screen, timeout_s: float = 5.0) -> None:
    """Let a screen's worker thread finish before it is torn down.

    Destroying a running QThread aborts the interpreter; in the real app the
    event loop keeps spinning so this happens for free.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        QApplication.processEvents()
        thread = getattr(screen, "_thread", None)
        try:
            if thread is None or not thread.isRunning():
                break
            thread.wait(10)
        except RuntimeError:
            break
    QApplication.processEvents()


# ── A screen that reports busy on demand ──────────────────────────────────────

class _FakeBusyScreen(QWidget):
    """Stands in for a screen mid-operation, with no real thread involved."""

    screen_id = "extract"
    busyChanged = Signal(bool)

    def __init__(self) -> None:
        super().__init__()
        self.busy = True
        self.cancel_requests = 0

    def is_busy(self) -> bool:
        return self.busy

    def request_cancel(self) -> bool:
        self.cancel_requests += 1
        return True

    def finish(self) -> None:
        """Simulate the operation stopping (what a real cancel leads to)."""
        self.busy = False
        self.busyChanged.emit(False)


# ── 1. closeEvent must not block ──────────────────────────────────────────────

def test_close_event_returns_immediately_while_a_screen_is_busy(qapp):
    """The hard bound: refusing a close must never wait on a worker thread.

    The old code blocked here for the whole remaining runtime of the extract.
    """
    from gui.views.shell import MainWindow

    window = MainWindow()
    busy = _FakeBusyScreen()
    window._shutdown = ShutdownCoordinator(window, lambda: [busy])

    event = QCloseEvent()
    started = time.monotonic()
    window.closeEvent(event)
    elapsed = time.monotonic() - started

    assert elapsed < 1.0, f"closeEvent blocked for {elapsed:.2f}s — it must never wait"
    assert not event.isAccepted(), "a busy app must refuse the close, not accept it"
    window._shutdown._close_dialog()
    window.deleteLater()
    QApplication.processEvents()


def test_close_event_accepts_when_nothing_is_running(qapp):
    from gui.views.shell import MainWindow

    window = MainWindow()
    window._shutdown = ShutdownCoordinator(window, lambda: [])

    event = QCloseEvent()
    event.accept()
    window.closeEvent(event)
    assert event.isAccepted()
    window.deleteLater()
    QApplication.processEvents()


# ── 2. A busy Identify hub is detected (the regression) ───────────────────────

def test_a_busy_identify_hub_is_seen_by_the_shutdown_path(qapp, monkeypatch):
    """IdentifyHub has no ``_thread``; the old probe reported it idle.

    A running identify was therefore torn down silently on close. The hub now
    answers is_busy()/request_cancel() by delegating to the wizard it wraps.
    """
    from gui.recent_store import RecentStore
    from gui.settings_store import SettingsStore
    from gui.views.screen_identify_hub import IdentifyHub

    hub = IdentifyHub(SettingsStore(), RecentStore())
    coordinator = ShutdownCoordinator(QWidget(), lambda: [hub])

    # The old probe: this is exactly why the bug was invisible.
    assert getattr(hub, "_thread", None) is None
    assert coordinator.busy_screens() == [], "an idle hub must not report busy"

    # Now make the wrapped wizard busy and confirm the hub relays it.
    monkeypatch.setattr(type(hub._run), "is_busy", lambda _self: True)
    assert coordinator.busy_screens() == [hub], (
        "a running Identify must be visible to the shutdown path"
    )

    stopped: list[bool] = []
    monkeypatch.setattr(type(hub._run), "request_cancel", lambda _self: stopped.append(True) or True)
    assert hub.request_cancel() is True
    assert stopped == [True]

    hub.deleteLater()
    QApplication.processEvents()


# ── 3. The coordinator's drain sequence ───────────────────────────────────────

def test_declining_the_prompt_leaves_everything_running(qapp):
    from PySide6.QtWidgets import QMessageBox

    window = QWidget()
    busy = _FakeBusyScreen()
    coordinator = ShutdownCoordinator(window, lambda: [busy])

    assert coordinator.request() is False, "a busy app must not close straight away"
    coordinator._on_answer(QMessageBox.StandardButton.Cancel)

    assert busy.cancel_requests == 0, "declining must not cancel anything"
    assert coordinator.may_close() is False
    window.deleteLater()
    QApplication.processEvents()


def test_confirming_cancels_then_closes_when_the_work_stops(qapp):
    from PySide6.QtWidgets import QMessageBox

    closed: list[bool] = []

    class _Window(QWidget):
        def close(self) -> bool:      # noqa: A003 - Qt override
            closed.append(True)
            return True

    window = _Window()
    busy = _FakeBusyScreen()
    coordinator = ShutdownCoordinator(window, lambda: [busy])

    coordinator.request()
    coordinator._on_answer(QMessageBox.StandardButton.Discard)

    assert busy.cancel_requests == 1, "confirming must ask the screen to stop"
    assert closed == [], "the window must not close while work is still running"

    busy.finish()                       # the operation actually stops
    QApplication.processEvents()

    assert closed == [True], "the window must close once the drain completes"
    coordinator._close_dialog()
    window.deleteLater()
    QApplication.processEvents()


def test_a_second_request_does_not_stack_dialogs(qapp):
    window = QWidget()
    busy = _FakeBusyScreen()
    coordinator = ShutdownCoordinator(window, lambda: [busy])

    coordinator.request()
    first = coordinator._dialog
    assert coordinator.request() is False
    assert coordinator._dialog is first, "a second close must reuse the open dialog"

    coordinator._close_dialog()
    window.deleteLater()
    QApplication.processEvents()


# ── 4. OperationScreen's cancellation contract ────────────────────────────────

def test_idle_screen_is_not_busy_and_cannot_be_cancelled(qapp):
    screen = OperationScreen()
    assert screen.is_busy() is False
    assert screen.request_cancel() is False, "nothing running means nothing to cancel"
    screen.deleteLater()
    QApplication.processEvents()


def test_request_cancel_invokes_the_registered_handler(qapp):
    screen = OperationScreen()
    calls: list[bool] = []
    screen.set_cancel_handler(lambda: calls.append(True))

    release = threading.Event()
    outcome: dict[str, object] = {}
    screen.run_task(
        lambda: release.wait(5) and "done",
        lambda result: outcome.setdefault("result", result),
        lambda tb: outcome.setdefault("error", tb),
    )
    QApplication.processEvents()

    assert screen.is_busy() is True
    assert screen.request_cancel() is True
    assert calls == [True], "the controller's stop must be called"

    release.set()
    _settle(screen)
    assert screen.is_busy() is False
    screen.deleteLater()
    QApplication.processEvents()


def test_a_cancellation_reaches_the_cancelled_callback(qapp):
    """The third outcome (D3): an object, not a traceback string to sniff."""
    screen = OperationScreen()
    outcome: dict[str, object] = {}

    def cancelled_task():
        exc = OperationCancelled("stopped by the analyst")
        exc.partial_db_path = "/cases/x.sqlite.partial"
        raise exc

    screen.run_task(
        cancelled_task,
        lambda result: outcome.setdefault("result", result),
        lambda tb: outcome.setdefault("error", tb),
        lambda exc: outcome.setdefault("cancelled", exc),
    )
    _settle(screen)

    got = outcome.get("cancelled")
    assert isinstance(got, OperationCancelled), "a cancel must not arrive as a failure"
    assert "error" not in outcome, "a cancel must not also fire the failure path"
    assert got.partial_db_path == "/cases/x.sqlite.partial", (
        "the exception object is what carries the partial artefact's path"
    )
    screen.deleteLater()
    QApplication.processEvents()


def test_busy_clears_after_a_cancellation(qapp):
    """A cancelled screen must leave its busy state, or the drain never ends."""
    screen = OperationScreen()
    seen: list[bool] = []
    screen.busyChanged.connect(seen.append)

    screen.run_task(
        lambda: (_ for _ in ()).throw(OperationCancelled("stop")),
        lambda _r: None, lambda _t: None, lambda _e: None,
    )
    _settle(screen)

    assert seen == [True, False]
    assert screen.is_busy() is False
    screen.deleteLater()
    QApplication.processEvents()


def test_a_screen_with_no_cancel_callback_still_leaves_running(qapp):
    """Fallback: without an on_cancelled the failure path resets the form."""
    screen = OperationScreen()
    outcome: dict[str, object] = {}

    screen.run_task(
        lambda: (_ for _ in ()).throw(OperationCancelled("stop")),
        lambda result: outcome.setdefault("result", result),
        lambda tb: outcome.setdefault("error", tb),
    )
    _settle(screen)

    assert "OperationCancelled" in str(outcome.get("error", "")), (
        "a screen that never asked about cancellation must not freeze mid-run"
    )
    screen.deleteLater()
    QApplication.processEvents()


# ── 5. The Worker's third signal ──────────────────────────────────────────────

def test_worker_emits_cancelled_not_failed(qapp):
    from gui.workers.base import Worker

    class _Sink(QObject):
        def __init__(self) -> None:
            super().__init__()
            self.seen: list[tuple[str, object]] = []

    worker = Worker(lambda: (_ for _ in ()).throw(OperationCancelled("stop")))
    sink = _Sink()
    worker.cancelled.connect(lambda exc: sink.seen.append(("cancelled", exc)))
    worker.failed.connect(lambda tb: sink.seen.append(("failed", tb)))
    worker.finished.connect(lambda r: sink.seen.append(("finished", r)))

    worker.run()   # directly, no thread needed for signal routing

    assert [kind for kind, _ in sink.seen] == ["cancelled"]
