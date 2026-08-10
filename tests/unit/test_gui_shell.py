"""Headless tests for the application shell (gui.views.shell.MainWindow).

Guards the log-panel collapse fix: collapsing the panel must shrink its splitter
pane to roughly the header height (giving the space back to the screen area), and
expanding must restore the previous open size. Without the shell↔panel wiring the
splitter kept the pane's height and the header floated in dead space.

Skipped automatically if PySide6 is unavailable (it is an optional extra).
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication  # noqa: E402

from gui.views.shell import MainWindow  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


def test_log_panel_collapse_shrinks_then_restores_pane(qapp):
    w = MainWindow()
    w.resize(900, 700)
    w.show()
    QApplication.processEvents()

    splitter = w._main_splitter
    open_sizes = splitter.sizes()
    assert open_sizes[1] > w._log_panel.header_height, "log pane should start open"

    # Collapse: the log pane shrinks to ~the header strip, the screen pane grows.
    w._log_panel._toggle_collapsed()
    QApplication.processEvents()
    collapsed = splitter.sizes()
    assert collapsed[1] <= w._log_panel.header_height + 2, "collapsed pane should be ~header height"
    assert collapsed[0] > open_sizes[0], "screen area should reclaim the freed space"

    # Expand: the previous open sizes are restored.
    w._log_panel._toggle_collapsed()
    QApplication.processEvents()
    assert splitter.sizes() == open_sizes, "expanding should restore the open sizes"


def test_report_entry_caption_follows_the_error_reports(qapp, tmp_path, monkeypatch):
    """The one "something is wrong" entry: "Report bug…" while no error report
    exists, "Open error reports" once one does — and filing a BUG report must not
    flip it, or asking for help would make the tool claim it had errored."""
    from app import diagnostics
    from gui import report_actions

    monkeypatch.setattr(diagnostics, "_DEFAULT_CONFIG", diagnostics.CrashConfig(crash_dir=tmp_path))

    w = MainWindow()
    w.show()
    QApplication.processEvents()

    assert w._report_label.text() == report_actions.caption(report_actions.FILE_BUG)

    # A filed BUG report leaves the caption alone …
    diagnostics.write_bug_report(cfg=diagnostics.CrashConfig(crash_dir=tmp_path))
    w._sync_report_entry()
    assert w._report_label.text() == report_actions.caption(report_actions.FILE_BUG)

    # … while a real ERROR report flips it.
    try:
        raise RuntimeError("boom")
    except RuntimeError:
        diagnostics.capture_exception(cfg=diagnostics.CrashConfig(crash_dir=tmp_path))
    w._sync_report_entry()
    assert w._report_label.text() == report_actions.caption(report_actions.OPEN_ERRORS)
