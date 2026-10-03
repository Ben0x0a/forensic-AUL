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

    # Fusion, not the platform's native style. WHY: gui/theme.py styles the entire
    # UI through one stylesheet, and the native macOS style ignores much of it —
    # QTabBar in particular is drawn as a native segmented control, so the theme's
    # colours are dropped and its labels elide to "Overvi…". Fusion honours QSS
    # for every widget, which makes the stylesheet the single source of truth for
    # how the app looks on every platform.
    app.setStyle("Fusion")

    # Install the crash handler before building the UI or running the event loop,
    # so a main-thread (Qt slot) exception is captured. Worker-thread crashes are
    # captured separately in gui.workers.base.Worker.run.
    from app.diagnostics import install_excepthook
    install_excepthook({"entrypoint": "gui"})

    widget = build_main_widget()
    widget.show()

    # Make Ctrl+C from the launching terminal ask to quit, exactly as closing the
    # window does. WHY this is needed at all: Qt's event loop runs in C++ and
    # never returns to the interpreter, so a Python SIGINT handler would
    # otherwise never fire. A no-op timer ticking a few times a second wakes the
    # interpreter just long enough to run the handler. NOTE: this interrupts a
    # *responsive* loop (e.g. during an extraction, which runs on a worker
    # thread) — a truly wedged main thread still needs an OS kill, as nothing
    # Python-side can run then.
    #
    # WHY it prompts rather than quitting outright (D2): Ctrl+C here is not a
    # shell command being aborted, it is a request to close a window that may be
    # midway through writing an evidence database. It gets the same question, and
    # the same drain, as the close button. The window is raised first because the
    # keystroke happens in the terminal while the dialog appears in the GUI —
    # without that the analyst sees nothing and presses Ctrl+C again.
    def _on_sigint(*_args: object) -> None:
        shutdown = getattr(widget, "request_shutdown", None)
        if callable(shutdown):
            shutdown(raise_window=True)
        else:
            app.quit()

    signal.signal(signal.SIGINT, _on_sigint)
    sigint_timer = QTimer()
    sigint_timer.timeout.connect(lambda: None)
    sigint_timer.start(200)

    return app.exec()
