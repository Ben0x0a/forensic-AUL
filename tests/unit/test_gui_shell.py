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


# ── Preferences ─────────────────────────────────────────────────────────────────

def test_every_settings_key_has_a_control(qapp, tmp_path, monkeypatch):
    """A preference with no control is unreachable; one with no consumer is a lie.

    This guards the first half: every key in _DEFAULTS must be bound to a widget
    on the Settings screen.
    """
    import gui.settings_store as settings_store
    from gui.settings_store import _DEFAULTS, SettingsStore
    from gui.views.screens_prefs import SettingsScreen

    monkeypatch.setattr(settings_store, "_SETTINGS_PATH", tmp_path / "settings.json")
    store = SettingsStore()
    screen = SettingsScreen(store)

    touched: set[str] = set()
    store.changed.connect(lambda key, _v: touched.add(key))
    # Drive each control and confirm it writes its key.
    from PySide6.QtWidgets import QCheckBox, QSpinBox

    for widget in screen.findChildren(QSpinBox):
        widget.setValue(widget.value() + widget.singleStep())
    for widget in screen.findChildren(QCheckBox):
        widget.setChecked(not widget.isChecked())
    combos = screen.findChildren(type(screen._combo("tz", [("utc", "UTC")])))
    for combo in combos:
        if combo.count() > 1:
            combo.setCurrentIndex((combo.currentIndex() + 1) % combo.count())

    # kbPath is a path picker (driven separately); everything else must be covered.
    expected = set(_DEFAULTS) - {"kbPath"}
    assert expected <= touched, f"no control writes: {sorted(expected - touched)}"
    screen.deleteLater()


def test_recents_limit_is_applied_live(qapp, tmp_path, monkeypatch):
    import gui.recent_store as recent_store
    from gui.recent_store import RecentStore

    monkeypatch.setattr(recent_store, "_RECENTS_PATH", tmp_path / "recents.json")
    store = RecentStore(limit=5)
    for i in range(10):
        store.add("database", f"/case/{i}.db")
    assert len(store.get("database")) == 5

    store.set_limit(2)
    assert len(store.get("database")) == 2
