"""GUI launcher — owns the Qt application lifecycle.

Defines : run_gui(), which creates the QApplication, builds the main widget from
          the `gui` package, shows it, and runs the event loop.
Used by : launcher.cli.main() (invoked when faul.py is run with no subcommand).
Uses    : gui.app.build_main_widget() for the actual UI. Keeping QApplication
          ownership here (launcher) and the widgets in `gui` lets the UI layer
          stay import-light and testable without spinning up an event loop.
"""

from __future__ import annotations

import logging
import signal
import sys

log = logging.getLogger(__name__)


def run_gui() -> int:
    """Boot the GUI. Returns the Qt exit code, or 1 if PySide6 is unavailable."""
    try:
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication
    except ImportError:
        # WHY: PySide6 is an optional extra (clone-&-run users may not install
        # it); fail with guidance rather than a raw ImportError traceback.
        log.error(
            "PySide6 is required for the GUI. Install it with: pip install PySide6"
        )
        return 1

    from gui.app import build_main_widget

    app = QApplication(sys.argv)

    # Install the crash handler before building the UI or running the event loop,
    # so a main-thread (Qt slot) exception is captured. Worker-thread crashes are
    # captured separately in gui.workers.base.Worker.run.
    from app.diagnostics import install_excepthook
    install_excepthook({"entrypoint": "gui"})

    widget = build_main_widget()
    widget.show()

    # Make Ctrl+C from the launching terminal quit the app. WHY this is needed:
    # Qt's event loop runs in C++ and never returns to the interpreter, so a
    # Python SIGINT handler would otherwise never fire. A no-op timer ticking a
    # few times a second wakes the interpreter just long enough to run the
    # handler, which quits cleanly. NOTE: this interrupts a *responsive* loop
    # (e.g. during an extraction, which runs on a worker thread) — a truly wedged
    # main thread still needs an OS kill, as nothing Python-side can run then.
    signal.signal(signal.SIGINT, lambda *_: app.quit())
    sigint_timer = QTimer()
    sigint_timer.timeout.connect(lambda: None)
    sigint_timer.start(200)

    return app.exec()
