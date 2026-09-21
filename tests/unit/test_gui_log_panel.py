"""Headless tests for gui.widgets.log_panel (LogPanel pause/resume, intake).

Covers review item G4: Pause must freeze the *view*, not drop *data* — records
logged while paused must survive into the retained buffer and appear once the
panel is resumed and re-rendered. The previous behaviour early-returned out of
``_append_record`` while paused, so those records never entered ``_records`` at
all and Resume had nothing to catch up on.

Skipped automatically if PySide6 is unavailable (it is an optional extra).
"""

from __future__ import annotations

import os
from collections import deque

import pytest

# Qt must run head-less in CI / on a build box — set before importing PySide6.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication  # noqa: E402

from gui.widgets.log_panel import LogPanel  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    """A single QApplication for the module (Qt allows only one per process)."""
    app = QApplication.instance() or QApplication([])
    yield app


def test_records_logged_while_paused_are_retained(qapp):
    """The core G4 assertion: data survives a pause, even though it isn't shown."""
    panel = LogPanel()
    panel._append_record("2026-08-17 00:00:00.000", "INFO", "before pause")
    panel._toggle_pause()  # pause
    panel._append_record("2026-08-17 00:00:01.000", "INFO", "during pause 1")
    panel._append_record("2026-08-17 00:00:02.000", "ERROR", "during pause 2")

    messages = [r[2] for r in panel._records]
    assert "during pause 1" in messages, "a record logged while paused must not be dropped"
    assert "during pause 2" in messages
    assert len(panel._records) == 3


def test_pause_freezes_the_view_not_the_intake(qapp):
    """Rendering is suppressed while paused; only the retained deque grows."""
    panel = LogPanel()
    panel._toggle_pause()
    before = panel._body.toPlainText()
    panel._append_record("2026-08-17 00:00:00.000", "INFO", "hidden while paused")
    assert panel._body.toPlainText() == before, "the body must not update per record while paused"
    assert len(panel._records) == 1, "but the record must still have been retained"


def test_resume_rerenders_records_buffered_while_paused(qapp):
    """Resume must catch the view up on everything buffered while paused."""
    panel = LogPanel()
    panel._append_record("2026-08-17 00:00:00.000", "INFO", "before pause")
    panel._toggle_pause()  # pause
    panel._append_record("2026-08-17 00:00:01.000", "INFO", "buffered while paused")
    assert "buffered while paused" not in panel._body.toPlainText()

    panel._toggle_pause()  # resume
    assert "buffered while paused" in panel._body.toPlainText(), (
        "resume must re-render so buffered records become visible"
    )
    assert "before pause" in panel._body.toPlainText()


def test_resume_recomputes_visible_count(qapp):
    """The header count must reflect reality again once the view catches up."""
    panel = LogPanel()
    panel._toggle_pause()
    panel._append_record("t0", "INFO", "a")
    panel._append_record("t1", "ERROR", "b")
    panel._append_record("t2", "DEBUG", "c")  # DEBUG is disabled by default

    panel._toggle_pause()  # resume
    assert panel._visible_count == 2, "DEBUG stays filtered out even after a pause"
    assert len(panel._records) == 3


def test_pause_survives_buffer_eviction(qapp):
    """A pause that outlasts the bounded buffer's cap must not corrupt state.

    Shrinks the cap so the test does not have to push 5000 records through.
    """
    panel = LogPanel()
    panel._records = deque(maxlen=3)  # same bounded-deque contract, smaller cap
    panel._toggle_pause()
    for i in range(5):
        panel._append_record(f"t{i}", "INFO", f"msg{i}")
    assert len(panel._records) == 3, "the deque stays bounded even while paused"
    assert [r[2] for r in panel._records] == ["msg2", "msg3", "msg4"], (
        "oldest records are evicted first, exactly as when live"
    )

    panel._toggle_pause()  # resume — _rerender must recompute cleanly post-eviction
    assert panel._visible_count == 3
    assert "msg4" in panel._body.toPlainText()
    assert "msg0" not in panel._body.toPlainText()


# ── P2: the panel must not force global DEBUG logging ─────────────────────────

def test_attach_leaves_the_root_logger_at_info(qapp):
    """Attaching the panel must NOT drag the root logger down to DEBUG.

    Review item P2. With root at DEBUG, every ``log.debug`` in the parse path —
    per chunkset, per firehose block — is formatted, timestamped and pushed
    across a queued Qt signal, then dropped by the panel because its DEBUG button
    is off by default. The GUI paid the whole cost of DEBUG for nothing.
    """
    import logging

    from gui.widgets.log_panel import attach_log_panel

    root = logging.getLogger()
    saved_level, saved_handlers = root.level, list(root.handlers)
    try:
        panel = LogPanel()
        handler = attach_log_panel(panel)
        assert root.level == logging.INFO
        assert not root.isEnabledFor(logging.DEBUG), "debug records still emitted"
    finally:
        root.removeHandler(handler)
        root.setLevel(saved_level)
        root.handlers[:] = saved_handlers


def test_debug_button_raises_and_lowers_the_root_level(qapp):
    """The toggle is what buys DEBUG, and turning it off gives the cost back."""
    import logging

    from gui.widgets.log_panel import attach_log_panel

    root = logging.getLogger()
    saved_level, saved_handlers = root.level, list(root.handlers)
    try:
        panel = LogPanel()
        handler = attach_log_panel(panel)

        panel._toggle_level("DEBUG")          # on
        assert root.level == logging.DEBUG
        assert root.isEnabledFor(logging.DEBUG)

        panel._toggle_level("DEBUG")          # off again
        assert root.level == logging.INFO
        assert not root.isEnabledFor(logging.DEBUG)
    finally:
        root.removeHandler(handler)
        root.setLevel(saved_level)
        root.handlers[:] = saved_handlers


def test_other_level_buttons_do_not_touch_the_root_level(qapp):
    """Only DEBUG changes what is emitted; INFO/WARN/ERROR are view filters.

    Records at those levels are already flowing, so their buttons must stay pure
    view state — moving the root level for them would drop records the panel
    still needs in its buffer for a later re-render.
    """
    import logging

    from gui.widgets.log_panel import attach_log_panel

    root = logging.getLogger()
    saved_level, saved_handlers = root.level, list(root.handlers)
    try:
        panel = LogPanel()
        handler = attach_log_panel(panel)
        for key in ("INFO", "WARN", "ERROR"):
            panel._toggle_level(key)
            assert root.level == logging.INFO, f"{key} moved the root level"
    finally:
        root.removeHandler(handler)
        root.setLevel(saved_level)
        root.handlers[:] = saved_handlers
