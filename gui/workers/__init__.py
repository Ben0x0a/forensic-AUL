"""Background worker layer — runs blocking core calls off the GUI thread.

Defines : the `workers` subpackage. `base.start_worker` is the shared helper that
          moves a QObject worker onto a fresh QThread and manages its lifetime;
          the per-operation workers (extract, acquire, export, verify) are thin
          QObject wrappers around the forensic_aul public API.
Used by : gui.controllers.* (each screen controller starts its own workers).
Uses    : PySide6, forensic_aul.

WHY a worker layer at all: forensic_aul.run_extract can take minutes (≈277 s on
a real archive). Running it on the GUI thread would freeze the UI; workers move
it to a QThread and report back via queued signals.
"""

from gui.workers.base import Worker, start_worker

__all__ = ["Worker", "start_worker"]
