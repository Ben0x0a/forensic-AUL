"""Worker base + the start_worker threading helper.

Defines : Worker (a generic QObject that runs a callable off-thread and emits
          finished/failed/cancelled) and start_worker(), the helper that moves a
          worker onto a fresh QThread and wires its lifetime.
Used by : gui.controllers.* — each screen builds a Worker (or a purpose-built
          QObject worker with the same signals) and hands it to start_worker.
Uses    : PySide6, logging, forensic_aul.errors (OperationCancelled).

WHY QObject + moveToThread (not a QThread subclass): Qt's recommended pattern.
The run logic stays in plain methods, the QThread is a generic event-loop host,
and cross-thread finished/failed signals are delivered as queued connections
onto the GUI thread automatically — no manual marshalling.
"""

from __future__ import annotations

import logging
import traceback
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, QThread, Signal, Slot

from forensic_aul.errors import OperationCancelled

_LOG = logging.getLogger(__name__)


class Worker(QObject):
    """Runs one callable off the GUI thread. Single-use: build, connect, start.

    For simple operations, wrap any callable: ``Worker(run_extract, **kwargs)``.
    Purpose-built workers may subclass QObject directly instead, as long as they
    expose the same ``finished(object)`` / ``failed(str)`` / ``cancelled(object)``
    signals.
    """

    finished = Signal(object)   # result payload (whatever the callable returns)
    failed = Signal(str)        # formatted traceback
    # WHY a third outcome rather than reporting a cancellation as a failure: with
    # only two, a cancellation arrives as a traceback STRING and the controller
    # has to sniff the text to tell "the analyst stopped it" from "something
    # broke" — which is what the Identify wizard used to do. This signal states
    # the outcome and, because it carries the exception OBJECT, brings the
    # partial artefact's path along with it.
    cancelled = Signal(object)  # the OperationCancelled instance

    def __init__(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs

    @Slot()
    def run(self) -> None:
        try:
            result = self._fn(*self._args, **self._kwargs)
        except OperationCancelled as exc:
            # An expected outcome: no traceback, no crash report, no error log.
            _LOG.info(f"Worker cancelled: {exc}")
            self.cancelled.emit(exc)
            return
        except Exception:  # noqa: BLE001 — surface any failure to the GUI, never crash the thread
            tb = traceback.format_exc()
            _LOG.error(f"""Worker failed:
{tb}""")
            # Capture a full crash report (frame locals) — this is the single funnel
            # every off-thread GUI operation flows through, and the failed signal
            # only carries the formatted traceback string.
            try:
                from app.diagnostics import capture_exception
                capture_exception({"entrypoint": "gui", "op": getattr(self._fn, "__name__", None)})
            except Exception:  # noqa: BLE001 — crash reporting must never mask the failure
                _LOG.debug("Crash report capture failed", exc_info=True)
            self.failed.emit(tb)
            return
        self.finished.emit(result)


def start_worker(
    owner: QObject,
    worker: QObject,
    on_finished: Callable[[Any], None],
    on_failed: Callable[..., None] | None = None,
    on_cancelled: Callable[..., None] | None = None,
) -> QThread:
    """Move *worker* onto a new QThread, wire signals, and start it.

    Ownership: the QThread is parented to *owner* (a controller, a QObject) so
    Qt keeps it alive via the parent-child registry — no separate job list. The
    worker stays un-parented (Qt forbids a parent on another thread); the
    ``started → run`` connection holds it alive until ``deleteLater`` fires on
    ``thread.finished``. Returns the thread so callers may keep a handle.

    Every signal is probed with ``hasattr`` because a purpose-built worker need
    only expose the outcomes it can actually produce — a worker that cannot be
    cancelled has no ``cancelled`` signal, and wiring one would fail at connect
    time rather than telling us anything useful.
    """
    thread = QThread(owner)
    worker.moveToThread(thread)

    thread.started.connect(worker.run)
    worker.finished.connect(on_finished)
    if on_failed is not None and hasattr(worker, "failed"):
        worker.failed.connect(on_failed)
    if on_cancelled is not None and hasattr(worker, "cancelled"):
        worker.cancelled.connect(on_cancelled)

    # Tear down on ANY outcome. WHY every one matters: a thread whose quit is not
    # wired keeps running its event loop forever, so the screen would report
    # itself busy for the rest of the session and the shutdown drain would never
    # complete.
    worker.finished.connect(thread.quit)
    for outcome in ("failed", "cancelled"):
        if hasattr(worker, outcome):
            getattr(worker, outcome).connect(thread.quit)
    thread.finished.connect(worker.deleteLater)
    thread.finished.connect(thread.deleteLater)

    thread.start()
    return thread
