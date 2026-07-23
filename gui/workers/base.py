"""Worker base + the start_worker threading helper.

Defines : Worker (a generic QObject that runs a callable off-thread and emits
          finished/failed) and start_worker(), the helper that moves a worker
          onto a fresh QThread and wires its lifetime.
Used by : gui.controllers.* — each screen builds a Worker (or a purpose-built
          QObject worker with the same finished/failed signals) and hands it to
          start_worker.
Uses    : PySide6, logging.

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

_LOG = logging.getLogger(__name__)


class Worker(QObject):
    """Runs one callable off the GUI thread. Single-use: build, connect, start.

    For simple operations, wrap any callable: ``Worker(run_extract, **kwargs)``.
    Purpose-built workers may subclass QObject directly instead, as long as they
    expose the same ``finished(object)`` / ``failed(str)`` signals.
    """

    finished = Signal(object)  # result payload (whatever the callable returns)
    failed = Signal(str)       # formatted traceback

    def __init__(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs

    @Slot()
    def run(self) -> None:
        try:
            result = self._fn(*self._args, **self._kwargs)
        except Exception:  # noqa: BLE001 — surface any failure to the GUI, never crash the thread
            tb = traceback.format_exc()
            _LOG.error(f"""Worker failed:
{tb}""")
            self.failed.emit(tb)
            return
        self.finished.emit(result)


def start_worker(
    owner: QObject,
    worker: QObject,
    on_finished: Callable[[Any], None],
    on_failed: Callable[..., None] | None = None,
) -> QThread:
    """Move *worker* onto a new QThread, wire signals, and start it.

    Ownership: the QThread is parented to *owner* (a controller, a QObject) so
    Qt keeps it alive via the parent-child registry — no separate job list. The
    worker stays un-parented (Qt forbids a parent on another thread); the
    ``started → run`` connection holds it alive until ``deleteLater`` fires on
    ``thread.finished``. Returns the thread so callers may keep a handle.
    """
    thread = QThread(owner)
    worker.moveToThread(thread)

    thread.started.connect(worker.run)
    worker.finished.connect(on_finished)
    if on_failed is not None and hasattr(worker, "failed"):
        worker.failed.connect(on_failed)

    # Tear down on either outcome.
    worker.finished.connect(thread.quit)
    if hasattr(worker, "failed"):
        worker.failed.connect(thread.quit)
    thread.finished.connect(worker.deleteLater)
    thread.finished.connect(thread.deleteLater)

    thread.start()
    return thread
