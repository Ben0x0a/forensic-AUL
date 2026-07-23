"""Headless regression test for the GUI Worker lifetime.

Guards the off-thread run plumbing in ``gui.views.screen_base.OperationScreen``:

1. A Worker lives on a separate QThread and cannot be parented to the screen, so
   the screen must keep a Python reference to it. Without that reference the
   Worker is garbage-collected before ``run()`` fires and the operation silently
   never completes.
2. The screen's result/error callbacks must run on the GUI thread. They are bound
   to ``@Slot`` methods of the screen (a main-thread QObject) so Qt delivers them
   via a queued connection — not on the worker thread, which would touch widgets
   off-thread.

The test drives a trivial task and a failing task, asserting both outcomes are
delivered rather than swallowed. It polls ``processEvents`` (rather than nesting a
QEventLoop) so the queued callbacks are delivered deterministically.

Skipped automatically if PySide6 is unavailable (it is an optional extra).
"""

from __future__ import annotations

import os
import time

import pytest

# Qt must run head-less in CI / on a build box — set before importing PySide6.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication  # noqa: E402

from gui.views.screen_base import OperationScreen  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    """A single QApplication for the module (Qt allows only one per process)."""
    app = QApplication.instance() or QApplication([])
    yield app


def _run(screen: OperationScreen, task, timeout_s: float = 5.0) -> dict[str, object]:
    """Run *task* on *screen*, pumping the event loop until it settles."""
    captured: dict[str, object] = {}
    screen.run_task(
        task,
        lambda result: captured.setdefault("result", result),
        lambda tb: captured.setdefault("error", tb),
    )

    deadline = time.monotonic() + timeout_s
    while not captured and time.monotonic() < deadline:
        QApplication.processEvents()
        time.sleep(0.003)

    # Let the worker QThread finish and run its queued deleteLater before the
    # screen is torn down — otherwise Python aborts destroying a running QThread
    # (in the real app the event loop keeps spinning, so this happens for free).
    for _ in range(100):
        QApplication.processEvents()
        thread = getattr(screen, "_thread", None)
        try:
            if thread is None or not thread.isRunning():
                break
            thread.wait(10)
        except RuntimeError:
            break
    return captured


def test_operation_screen_runs_task_to_completion(qapp):
    captured = _run(OperationScreen(), lambda: "ECHO-RESULT-42")
    assert captured.get("result") == "ECHO-RESULT-42", (
        "operation did not complete — the Worker was likely GC'd before run() "
        "(OperationScreen must keep a reference to it)"
    )


def test_operation_screen_surfaces_task_error(qapp):
    def boom():
        raise RuntimeError("kaboom")

    captured = _run(OperationScreen(), boom)
    assert "kaboom" in str(captured.get("error", ""))  # failure surfaced, not swallowed
