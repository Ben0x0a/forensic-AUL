"""GUI assembly entry point — builds the FAUL main window.

Defines : build_main_window(), which constructs the :class:`MainWindow` shell and
          routes application logging into its persistent log panel. The
          QApplication lifecycle is owned by the launcher, not here.
Used by : launcher.gui.run_gui().
Uses    : gui.views.shell (the window), gui.widgets.log_panel (logging → panel).
          All operation logic lives in forensic_aul core — screens only collect
          input, run it off-thread, and render results.
"""

from __future__ import annotations

from PySide6.QtWidgets import QWidget

from gui.views.shell import MainWindow
from gui.widgets.log_panel import attach_log_panel


def build_main_window() -> MainWindow:
    """Build the main window and wire the log panel onto the root logger."""
    window = MainWindow()
    attach_log_panel(window.log_panel)
    return window


def build_main_widget() -> QWidget:
    """Back-compat alias for callers expecting the old factory name."""
    return build_main_window()
