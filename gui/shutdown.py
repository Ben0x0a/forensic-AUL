"""Closing the application while an operation is still running.

Defines : ShutdownCoordinator — the single place that decides whether the window
          may close, asks the analyst, cancels what is running, and waits for the
          drain **without blocking the GUI thread**.
Used by : gui.views.shell (MainWindow.closeEvent and the SIGINT route),
          launcher.gui (Ctrl+C from the launching terminal).
Uses    : PySide6 only. It knows nothing about any particular screen — just the
          ``is_busy()`` / ``request_cancel()`` / ``busyChanged`` contract that
          gui.views.screen_base.OperationScreen defines and IdentifyHub relays.

Why this exists
---------------
The previous behaviour was a loop in ``closeEvent`` calling ``thread.wait()``.
Two problems, both of which this replaces:

* **It blocked.** ``wait()`` with no timeout parks the GUI thread until the
  operation finishes — on a multi-gigabyte extract, minutes of a frozen,
  unrepainting window with no explanation and no way to intervene. An analyst
  reasonably concludes the tool has hung and kills it.
* **It missed screens.** It looked for a ``_thread`` attribute on each screen, so
  anything that was not itself an ``OperationScreen`` — the Identify hub is a
  plain ``QWidget`` wrapping the wizard — reported "not busy" and had its run
  torn down silently. Asking ``is_busy()`` puts the answer with the screen.

Shape
-----
``closeEvent`` becomes ``event.ignore()`` plus a call to :meth:`request`. The
coordinator then drives the rest through signals: a confirmation dialog opened
non-modally, a cancel request to every busy screen, and a drain dialog that
closes itself when the last ``busyChanged(False)`` arrives. Control returns to
the event loop at every step, so the window keeps painting and stays responsive
throughout.

There is deliberately **no force-quit button** (D4). The operating system
already lets an operator kill the process, and — because every long operation
writes to a ``.partial`` that is only renamed on success — a killed run leaves
exactly the same correctly-marked artefact a cancelled one does. A force-quit
button would add no capability, only a faster route to a worse outcome with our
name on it. The drain dialog says so plainly instead.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from enum import Enum, auto

from PySide6.QtCore import QObject, Qt, QTimer
from PySide6.QtWidgets import QMessageBox, QWidget

_LOG = logging.getLogger(__name__)

# Backstop poll while draining. busyChanged is the primary trigger, but it is not
# sufficient on its own: OperationScreen emits busyChanged(False) from the slot
# handling the worker's outcome, while is_busy() reads thread.isRunning() — and
# the thread's quit is a separate connection off the same worker signal. So the
# signal can arrive while the QThread is still winding down, _recheck sees a busy
# screen, bails, and no further signal is ever emitted. This poll is what closes
# that window; without it the drain dialog can stay up forever.
_DRAIN_POLL_MS = 250


class _Phase(Enum):
    """Where the coordinator is in the close sequence."""

    IDLE = auto()      # nothing pending
    ASKING = auto()    # the confirmation dialog is open
    DRAINING = auto()  # operations are stopping; the drain dialog is open


class ShutdownCoordinator(QObject):
    """Decides whether *window* may close, and drains running work if not.

    *screens* returns the widgets to question — the shell's screen stack. They
    are asked ``is_busy()`` and, once the analyst confirms, ``request_cancel()``;
    both are optional, and a widget exposing neither is simply treated as idle.
    """

    def __init__(self, window: QWidget, screens: Callable[[], list[QWidget]]) -> None:
        super().__init__(window)
        self._window = window
        self._screens = screens
        self._phase = _Phase.IDLE
        self._dialog: QMessageBox | None = None
        self._timer: QTimer | None = None
        # Set once the drain is done, so the close that follows is not caught by
        # this same coordinator and turned into a second prompt.
        self._cleared = False

    # ── Public API ────────────────────────────────────────────────────────────

    def busy_screens(self) -> list[QWidget]:
        """The screens currently running an operation."""
        found = []
        for screen in self._screens():
            probe = getattr(screen, "is_busy", None)
            try:
                if callable(probe) and probe():
                    found.append(screen)
            except RuntimeError:
                # The underlying C++ object went away — it is not running.
                continue
        return found

    def may_close(self) -> bool:
        """True when the window can be closed right now, with nothing to drain."""
        return self._cleared or not self.busy_screens()

    def request(self, *, raise_window: bool = False) -> bool:
        """Begin (or continue) the close sequence. True = close immediately.

        False means the caller must ``ignore()`` the close event: a dialog is now
        open, and the coordinator will close the window itself once the running
        work has stopped.

        *raise_window* brings the window to the front first. It exists for the
        Ctrl+C route: the interrupt is typed at a terminal but the prompt appears
        in the GUI, so without this the analyst sees nothing happen and presses
        Ctrl+C again.
        """
        if raise_window:
            self._window.show()
            self._window.raise_()
            self._window.activateWindow()

        if self._phase is not _Phase.IDLE:
            # Already asking or draining — surface the existing dialog rather than
            # stacking a second one on top of it.
            if self._dialog is not None:
                self._dialog.raise_()
                self._dialog.activateWindow()
            return False

        if self.may_close():
            return True

        self._ask()
        return False

    # ── Step 1: confirm ───────────────────────────────────────────────────────

    def _ask(self) -> None:
        busy = self.busy_screens()
        names = ", ".join(sorted(_screen_name(s) for s in busy)) or "an operation"
        box = QMessageBox(self._window)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("Quit FAUL?")
        box.setText(f"{names} is still running.")
        box.setInformativeText(
            "Quitting will stop it. Whatever has been parsed so far is kept, but "
            "the output stays under its <b>.partial</b> name and is recorded as "
            "incomplete — it is not a finished extract and must be re-run before "
            "it can be relied on.<br><br>Stop and quit?"
        )
        box.setTextFormat(Qt.TextFormat.RichText)
        box.setStandardButtons(
            QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Discard
        )
        box.button(QMessageBox.StandardButton.Discard).setText("Stop and quit")
        box.button(QMessageBox.StandardButton.Cancel).setText("Keep running")
        box.setDefaultButton(QMessageBox.StandardButton.Cancel)
        box.finished.connect(self._on_answer)
        self._dialog = box
        self._phase = _Phase.ASKING
        # open(), never exec(): exec() spins a nested event loop and does not
        # return until the analyst answers, which would make closeEvent block —
        # the exact failure this class exists to remove.
        box.open()

    def _on_answer(self, result: int) -> None:
        self._close_dialog()
        if result != QMessageBox.StandardButton.Discard:
            self._phase = _Phase.IDLE
            return
        self._begin_drain()

    # ── Step 2: cancel and drain ──────────────────────────────────────────────

    def _begin_drain(self) -> None:
        self._phase = _Phase.DRAINING
        stoppable = 0
        for screen in self.busy_screens():
            asked = getattr(screen, "request_cancel", None)
            if callable(asked) and asked():
                stoppable += 1
            # WHY watch busyChanged even for a screen we could not cancel: it will
            # still finish on its own, and that signal is how we learn. A screen
            # with no cancellation simply takes as long as it takes.
            signal = getattr(screen, "busyChanged", None)
            if signal is not None:
                signal.connect(self._recheck)
        _LOG.info(f"Shutdown: cancelling {stoppable} running operation(s)")

        box = QMessageBox(self._window)
        box.setIcon(QMessageBox.Icon.Information)
        box.setWindowTitle("Stopping…")
        box.setText("Stopping the running operation…")
        box.setInformativeText(
            "This finishes the step in progress — usually a few seconds. The "
            "window will close on its own.<br><br>You can force-quit the process "
            "if you must; it leaves the same <b>.partial</b> output, simply "
            "without the final tidy-up."
        )
        box.setTextFormat(Qt.TextFormat.RichText)
        box.setStandardButtons(QMessageBox.StandardButton.NoButton)
        self._dialog = box
        box.open()

        # Backstop: busyChanged is the real trigger, but a screen that never emits
        # it must not leave this dialog up for the rest of the session.
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._recheck)
        self._timer.start(_DRAIN_POLL_MS)
        self._recheck()   # everything may already have stopped

    def _recheck(self, *_args: object) -> None:
        """Close the window once nothing is running any more."""
        if self._phase is not _Phase.DRAINING or self.busy_screens():
            return
        self._stop_timer()
        self._close_dialog()
        self._phase = _Phase.IDLE
        # Latch: the close below re-enters closeEvent, which asks may_close()
        # again. Without this the answer would be recomputed and — if a screen
        # had somehow started something else — the analyst would be prompted a
        # second time by their own confirmed quit.
        self._cleared = True
        _LOG.info("Shutdown: all operations stopped — closing")
        self._window.close()

    # ── Housekeeping ──────────────────────────────────────────────────────────

    def _close_dialog(self) -> None:
        # WHY the reference is cleared BEFORE close(): closing a QMessageBox emits
        # ``finished``, which re-enters this method through _on_answer. Clearing
        # first makes the re-entrant call a no-op; the other order let the inner
        # call null the attribute and the outer one then dereferenced None.
        dialog, self._dialog = self._dialog, None
        if dialog is not None:
            dialog.close()
            dialog.deleteLater()

    def _stop_timer(self) -> None:
        if self._timer is not None:
            self._timer.stop()
            self._timer.deleteLater()
            self._timer = None


def _screen_name(screen: QWidget) -> str:
    """A human label for *screen*, for the confirmation prompt."""
    screen_id = getattr(screen, "screen_id", "") or ""
    return screen_id.replace("-", " ").capitalize() or "An operation"
