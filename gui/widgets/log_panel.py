"""The persistent application-log panel docked at the bottom of the window.

Defines : LogPanel — a collapsible panel with a header (title, visible/total
          count, per-level filter toggles, auto-scroll / pause / clear / collapse
          controls) over a colourised log stream; and attach_log_panel(), which
          wires it onto the root logger via a thread-safe bridge.
Used by : gui.views.shell (docked in the bottom of the main splitter),
          gui.app (calls attach_log_panel at startup).
Uses    : PySide6, gui.widgets.components (icons), stdlib logging.

WHY a QObject bridge rather than touching the widget from the handler: a log
record can arrive on a worker thread, but Qt widgets are GUI-thread only. The
handler emits the *structured* fields (level, time, message) on a Signal, which
Qt delivers as a queued call on the GUI thread — so worker-thread records never
touch the widget directly. The panel keeps the structured record (not a
pre-formatted string) so it can colourise and filter by level.
"""

from __future__ import annotations

import logging
from collections import deque
from datetime import datetime

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from gui.widgets.components import icon_button, make_icon, repolish

# Most records to retain — caps memory on long extraction runs. Consumed by:
# LogPanel._append_record.
_MAX_RECORDS = 5000

# Map the four UI buttons to the stdlib levels each one represents. "WARN" covers
# WARNING; "ERROR" also catches CRITICAL. Consumed by: LogPanel._level_key.
_LEVEL_KEYS = ("DEBUG", "INFO", "WARN", "ERROR")

# Per-level display colours (mirrors the mockup's ``.log-line`` accents).
_LEVEL_COLOUR = {
    "DEBUG": "#545a68",
    "INFO": "#60a5fa",
    "WARN": "#f5b544",
    "ERROR": "#f87171",
}


class _LogBridge(QObject):
    """Carries a structured record from any thread to the GUI thread."""

    record = Signal(str, str, str)  # (asctime, level_key, message)


class _PanelLogHandler(logging.Handler):
    """A logging.Handler that forwards records to a LogPanel via the bridge."""

    def __init__(self, bridge: _LogBridge) -> None:
        super().__init__()
        self._bridge = bridge

    def emit(self, record: logging.LogRecord) -> None:
        try:
            # Full date + time (ms precision) — a forensic log line should be
            # unambiguous across day boundaries, not time-only.
            asctime = datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            message = record.getMessage()
        except Exception:  # noqa: BLE001 — a formatting error must never crash a worker
            self.handleError(record)
            return
        self._bridge.record.emit(asctime, _level_to_key(record.levelno), message)


def _level_to_key(levelno: int) -> str:
    """Collapse a stdlib level number into one of the four UI level keys."""
    if levelno >= logging.ERROR:
        return "ERROR"
    if levelno >= logging.WARNING:
        return "WARN"
    if levelno >= logging.INFO:
        return "INFO"
    return "DEBUG"


class LogPanel(QFrame):
    """Collapsible bottom log panel: header controls + colourised stream."""

    # Emitted when the panel is collapsed (True) or expanded (False). The shell
    # listens and resizes the splitter pane — hiding the body alone does not make
    # the splitter give the space back, so without this the header would float in
    # a pane that keeps its old height.
    collapsedChanged = Signal(bool)

    # Header is fixed; the body collapses to leave only this strip visible.
    _HEADER_H = 28

    @property
    def header_height(self) -> int:
        """Height the panel occupies when collapsed (just the header strip)."""
        return self._HEADER_H

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("logPanel")
        # (asctime, level_key, message) kept so filter toggles can re-render. A
        # bounded deque drops the oldest record in O(1) when full — WHY this matters:
        # the previous list-slice + full re-render on every record past the cap was
        # O(n) per record. During an extraction the worker QThread and this (GUI)
        # thread share one process/GIL, so that per-record main-thread work starved
        # the SQLite writer thread of the GIL and throttled it ~10x (workers then
        # idled waiting for the writer). Intake is now O(1).
        self._records: deque[tuple[str, str, str]] = deque(maxlen=_MAX_RECORDS)
        # Running count of currently-displayed (level-enabled) records, kept O(1)
        # so _update_count never rescans the whole buffer per record.
        self._visible_count = 0
        self._enabled = {"DEBUG": False, "INFO": True, "WARN": True, "ERROR": True}
        self._auto_scroll = True
        self._paused = False

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        outer.addWidget(self._build_header())

        self._body = QTextEdit()
        self._body.setObjectName("logBody")
        self._body.setReadOnly(True)
        self._body.setFrameShape(QFrame.Shape.NoFrame)
        # Let the widget self-trim to the same bound: append() then becomes O(1) and
        # the document never grows without limit, so we never rebuild it per record.
        self._body.document().setMaximumBlockCount(_MAX_RECORDS)
        outer.addWidget(self._body, 1)

    # ── Header ────────────────────────────────────────────────────────────────

    def _build_header(self) -> QWidget:
        header = QWidget()
        header.setObjectName("logPanelHeader")
        header.setFixedHeight(self._HEADER_H)
        row = QHBoxLayout(header)
        row.setContentsMargins(12, 0, 8, 0)
        row.setSpacing(8)

        title = QLabel("APPLICATION LOG")
        title.setObjectName("logPanelTitle")
        self._count = QLabel("0 / 0")
        self._count.setObjectName("logPanelCount")
        row.addWidget(title)
        row.addWidget(self._count)
        row.addStretch(1)

        # Per-level filter toggles.
        self._level_buttons: dict[str, QPushButton] = {}
        for key in _LEVEL_KEYS:
            button = QPushButton(key)
            button.setProperty("lvltoggle", "err" if key == "ERROR" else key.lower())
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.clicked.connect(lambda _checked=False, k=key: self._toggle_level(k))
            row.addWidget(button)
            self._level_buttons[key] = button
        self._refresh_level_buttons()

        row.addWidget(self._separator())

        # "to-bottom" (arrow onto a baseline), NOT the plain "down" chevron:
        # the collapse button beside it shows a down chevron whenever the panel
        # is collapsed, so the two controls were the same glyph meaning
        # different things.
        self._auto_button = self._icon_button(
            "to-bottom", "Auto-scroll to newest", self._toggle_auto, row=row,
        )
        self._pause_button = self._icon_button("stop", "Pause", self._toggle_pause, row=row)
        self._icon_button("x", "Clear display", self.clear, row=row)
        self._collapse_button = self._icon_button("up", "Collapse", self._toggle_collapsed, row=row)
        self._sync_toggle(self._auto_button, self._auto_scroll)
        return header

    def _icon_button(self, name, tooltip, slot, row=None) -> QPushButton:
        """The shared icon button, added to *row* — the header builds four of them."""
        button = icon_button(name, tooltip, slot)
        if row is not None:
            row.addWidget(button)
        return button

    def _separator(self) -> QFrame:
        line = QFrame()
        line.setFixedSize(1, 16)
        line.setStyleSheet("background:#262b34;")
        return line

    # ── Logging intake ──────────────────────────────────────────────────────────

    def _append_record(self, asctime: str, level_key: str, message: str) -> None:
        """Slot: a record arrived on the GUI thread (via the bridge).

        O(1): append to the bounded deque (oldest auto-evicted) and, if the level
        is shown, append one line to the widget (which self-trims via its
        maximumBlockCount). No per-record full re-render — that is what previously
        starved the writer thread.
        """
        if self._paused:
            return
        # If the buffer is full this append evicts the oldest record; adjust the
        # running visible count for that eviction before it disappears.
        if len(self._records) == _MAX_RECORDS:
            evicted_level = self._records[0][1]
            if self._enabled.get(evicted_level, True):
                self._visible_count -= 1
        self._records.append((asctime, level_key, message))
        if self._enabled.get(level_key, True):
            self._visible_count += 1
            self._body.append(self._format_line(asctime, level_key, message))
            if self._auto_scroll:
                self._scroll_to_end()
        self._update_count()

    def _format_line(self, asctime: str, level_key: str, message: str) -> str:
        colour = _LEVEL_COLOUR.get(level_key, "#b8bdc7")
        safe = (message.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
        return (
            f'<span style="color:{colour}">▎</span>'
            f'<span style="color:#545a68">{asctime}</span>&nbsp;&nbsp;'
            f'<span style="color:{colour};font-weight:600">{level_key}</span>&nbsp;&nbsp;'
            f'<span style="color:#b8bdc7">{safe}</span>'
        )

    def _rerender(self) -> None:
        """Rebuild the visible stream from retained records (after a filter change).

        Only invoked on a user filter toggle (rare), never per incoming record, so
        the one-off O(n) rebuild here is fine. Recomputes the visible count.
        """
        visible = [r for r in self._records if self._enabled.get(r[1], True)]
        self._visible_count = len(visible)
        self._body.setHtml("<br>".join(self._format_line(*r) for r in visible))
        if self._auto_scroll:
            self._scroll_to_end()
        self._update_count()

    def _scroll_to_end(self) -> None:
        bar = self._body.verticalScrollBar()
        bar.setValue(bar.maximum())

    def _update_count(self) -> None:
        # O(1): both figures are maintained incrementally (see _append_record /
        # _rerender), so this never rescans the buffer per record.
        self._count.setText(f"{self._visible_count} / {len(self._records)}")

    # ── Header actions ──────────────────────────────────────────────────────────

    def _toggle_level(self, key: str) -> None:
        self._enabled[key] = not self._enabled[key]
        self._refresh_level_buttons()
        self._rerender()

    def _refresh_level_buttons(self) -> None:
        for key, button in self._level_buttons.items():
            button.setProperty("on", "true" if self._enabled[key] else "false")
            repolish(button)

    def _toggle_auto(self) -> None:
        self._auto_scroll = not self._auto_scroll
        self._sync_toggle(self._auto_button, self._auto_scroll)
        if self._auto_scroll:
            self._scroll_to_end()

    def _toggle_pause(self) -> None:
        self._paused = not self._paused
        self._pause_button.setIcon(make_icon("play" if self._paused else "stop", 13, "#545a68"))
        self._sync_toggle(self._pause_button, self._paused)
        self._pause_button.setToolTip("Resume" if self._paused else "Pause")

    def _toggle_collapsed(self) -> None:
        self.set_collapsed(self._body.isVisible())  # visible now ⇒ collapse it

    def is_collapsed(self) -> bool:
        return not self._body.isVisible()

    def set_collapsed(self, collapsed: bool) -> None:
        """Collapse the panel to its header strip, or expand it again.

        Public so a screen that needs the vertical space (the Exploit table) can
        ask for it on entry and hand it back on exit — see
        ``MainWindow.set_current``. A no-op when already in the requested state,
        so a repeated request cannot make the shell forget the restore size.
        """
        if collapsed == self.is_collapsed():
            return
        self._body.setVisible(not collapsed)
        self._collapse_button.setIcon(make_icon("down" if collapsed else "up", 13, "#545a68"))
        self._collapse_button.setToolTip("Expand" if collapsed else "Collapse")
        # Hide the body first (above), then let the shell shrink/restore the pane.
        self.collapsedChanged.emit(collapsed)

    def _sync_toggle(self, button: QPushButton, on: bool) -> None:
        button.setProperty("on", "true" if on else "false")
        repolish(button)

    def clear(self) -> None:
        self._records.clear()
        self._visible_count = 0
        self._body.clear()
        self._update_count()


def attach_log_panel(panel: LogPanel, *, level: int = logging.INFO) -> _PanelLogHandler:
    """Wire *panel* onto the root logger; return the handler for later tuning.

    Call once at startup so initialisation logs appear from the first tick. The
    handler keeps logging at DEBUG so the panel's own level toggles do the
    filtering — the stream retains everything and the view shows what is enabled.
    """
    bridge = _LogBridge()
    # Queued across threads via AutoConnection — see module docstring.
    bridge.record.connect(panel._append_record)

    handler = _PanelLogHandler(bridge)
    handler.setLevel(logging.DEBUG)  # panel filters by level itself

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(handler)
    return handler
