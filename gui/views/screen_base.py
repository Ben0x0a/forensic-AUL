"""Base classes shared by every v1 screen.

Defines : ScrollScreen (a left-aligned, max-width, vertically-scrolling content
          column matching the mockup's ``.content-inner``), OperationScreen
          (adds off-thread run plumbing: build a task, run it on a Worker, route
          success/failure back), RecentList (a clickable "recently opened"
          list backed by real history, refreshable via set_items), and
          OpenDbPanel (the shared "pick a database + recents" OPEN-state panel
          used by the screens that start from an existing database).
Used by : gui.views.screens_pipeline / screens_data / screens_prefs /
          screen_exploit / screen_identify_results.
Uses    : PySide6, gui.workers (Worker/start_worker), gui.widgets.components,
          gui.widgets.path_picker, gui.recent_store.

WHY this base hosts the worker plumbing: it is shared by both the controller-backed
pipeline views and the thin data/preferences views. The heavy pipeline screens
(Acquire, Extract) delegate their logic to gui.controllers.pipeline, which drives
the view through ``run_task`` here; the lighter screens call ops inline. Either way
the off-thread mechanics live in one place (see the run_task QueuedConnection note).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PySide6.QtCore import Qt, Signal, Slot
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from gui.recent_store import RecentStore
from gui.widgets.components import (
    Divider,
    Panel,
    clear_layout,
    field_row,
    h2,
    make_icon,
    primary_button,
    result_panel,
)
from gui.widgets.path_picker import PathPicker
from gui.workers.base import Worker, start_worker


# Content-column widths, named so a screen declares its shape rather than a number.
# WHY a cap at all: a form or a page of prose is unreadable when its lines run the
# full width of a large display. WHY an uncapped option: a log table is the
# opposite — every pixel of width is another column or another few words of the
# message, so capping it wastes the screen.
# Consumed by: every ScrollScreen subclass (screens_pipeline, screens_data,
# screens_prefs, screen_exploit, screen_identify_results).
WIDTH_FORM = 880    # forms and prose — the default
WIDTH_WIDE = 1040   # form-plus-table screens
WIDTH_FULL = None   # data screens: no cap, use the whole window


class ScrollScreen(QWidget):
    """A scrolling screen with a left-aligned, max-width content column.

    Subclasses add widgets to :attr:`content` (a QVBoxLayout). *max_width* caps
    the column so long-line screens stay readable, mirroring the mockup; pass
    :data:`WIDTH_FULL` (``None``) for a data screen that should use the whole
    window.
    """

    def __init__(
        self, max_width: int | None = WIDTH_FORM, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea()
        scroll.setObjectName("contentScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        outer.addWidget(scroll)

        host = QWidget()
        host_layout = QHBoxLayout(host)
        host_layout.setContentsMargins(28, 24, 28, 28)
        host_layout.setSpacing(0)

        column = QWidget()
        if max_width is not None:
            column.setMaximumWidth(max_width)
        self.content = QVBoxLayout(column)
        self.content.setContentsMargins(0, 0, 0, 0)
        self.content.setSpacing(12)

        # Stretch (no alignment flag) so the column fills the width up to its cap;
        # capped by maximumWidth it stays left-aligned with empty space on the
        # right — matching the mockup's full-width-but-bounded content column.
        host_layout.addWidget(column, 1)
        scroll.setWidget(host)

        self._result_host: QVBoxLayout | None = None

    # ── Result line ───────────────────────────────────────────────────────────────

    def make_result_host(self) -> QVBoxLayout:
        """Create (once) and return the layout :meth:`show_result` renders into.

        Screens call this while building :attr:`content`, at the point where the
        outcome line should appear.
        """
        if self._result_host is None:
            self._result_host = QVBoxLayout()
        return self._result_host

    def show_result(self, ok: bool, message: str) -> None:
        """Replace the screen's outcome line with a success/failure panel.

        A no-op on a screen that never called :meth:`make_result_host` — a view
        with nowhere to show an outcome should not crash when an op reports one.
        """
        if self._result_host is None:
            return
        clear_layout(self._result_host)
        self._result_host.addWidget(result_panel(ok, message))

    def clear_result(self) -> None:
        """Remove the outcome line (e.g. when a new run starts)."""
        if self._result_host is not None:
            clear_layout(self._result_host)


class OperationScreen(ScrollScreen):
    """A :class:`ScrollScreen` that can run one core operation off-thread.

    Call :meth:`run_task` with a zero-arg callable; results/errors are delivered
    to the supplied callbacks on the GUI thread. The screen owns the thread/worker
    references so neither is garbage-collected mid-run.
    """

    # Relayed to the shell so the title-bar / status can reflect a running op.
    busyChanged = Signal(bool)
    progressChanged = Signal(float, str)  # fraction 0..1, short phase label

    def __init__(
        self, max_width: int | None = WIDTH_FORM, parent: QWidget | None = None
    ) -> None:
        super().__init__(max_width, parent)
        self._thread = None
        self._worker = None
        self._on_finished_cb: Callable[[Any], None] | None = None
        self._on_failed_cb: Callable[[str], None] | None = None

    def run_task(
        self,
        task: Callable[[], Any],
        on_finished: Callable[[Any], None],
        on_failed: Callable[[str], None] | None = None,
    ) -> None:
        # WHY route through @Slot methods of *self* (a main-thread QObject) rather
        # than connecting the closures directly: a signal connected to a plain
        # Python callable has no receiver thread affinity, so Qt uses a
        # DirectConnection and runs it on the *worker* thread. That would touch
        # widgets off the GUI thread and races loop.quit() against loop.exec().
        # Binding to self forces a QueuedConnection, so callbacks always run on
        # the GUI thread after the event loop is spinning.
        self._on_finished_cb = on_finished
        self._on_failed_cb = on_failed
        self.busyChanged.emit(True)
        self._worker = Worker(task)
        self._thread = start_worker(self, self._worker, self._handle_finished, self._handle_failed)

    @Slot(object)
    def _handle_finished(self, result: Any) -> None:
        self.busyChanged.emit(False)
        if self._on_finished_cb is not None:
            self._on_finished_cb(result)

    @Slot(str)
    def _handle_failed(self, tb: str) -> None:
        self.busyChanged.emit(False)
        if self._on_failed_cb is not None:
            self._on_failed_cb(tb)

    def emit_progress(self, fraction: float, label: str = "") -> None:
        """Thread-safe progress relay (Qt queues the signal to the GUI thread)."""
        self.progressChanged.emit(fraction, label)


class RecentList(QFrame):
    """A clickable list of recently-used paths (real history, never samples).

    *items* are ``{"path", "meta", "ts"}`` dicts (see :class:`gui.recent_store`).
    Calls *on_pick(path)* when a row is clicked. Shows a muted empty state when
    there is no history yet — honest, rather than fabricated rows.
    :meth:`set_items` rebuilds the rows, so screens can refresh the list when
    shown instead of displaying the snapshot taken at construction forever.
    """

    def __init__(
        self,
        items: list[dict[str, str]],
        on_pick: Callable[[str], None] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setProperty("recentList", "true")
        self._on_pick = on_pick
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(0)
        self.set_items(items)

    def set_items(self, items: list[dict[str, str]]) -> None:
        """Replace the displayed rows with *items* (call to refresh the history)."""
        while (child := self._layout.takeAt(0)) is not None:
            if child.widget() is not None:
                child.widget().deleteLater()

        if not items:
            empty = QLabel("No recent items yet — they appear here after your first run.")
            empty.setProperty("role", "help")
            empty.setContentsMargins(14, 12, 14, 12)
            self._layout.addWidget(empty)
            return

        for entry in items:
            self._layout.addWidget(self._row(entry, self._on_pick))

    def _row(self, entry: dict[str, str], on_pick: Callable[[str], None] | None) -> QWidget:
        path = entry.get("path", "")
        meta = entry.get("meta", "")
        ts = entry.get("ts", "")
        button = QPushButton()
        button.setProperty("recentRow", "true")
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        if on_pick is not None:
            button.clicked.connect(lambda _checked=False, p=path: on_pick(p))

        row = QHBoxLayout(button)
        row.setContentsMargins(14, 9, 14, 9)
        row.setSpacing(14)
        name = QLabel(path)
        name.setStyleSheet("font-family:'SF Mono','Menlo',monospace;")
        row.addWidget(name, 1)
        detail = " · ".join(p for p in (meta, ts) if p)
        if detail:
            meta_label = QLabel(detail)
            meta_label.setProperty("role", "mono")
            row.addWidget(meta_label)
        arrow = QLabel()
        arrow.setPixmap(make_icon("right", 13, "#545a68").pixmap(13, 13))
        row.addWidget(arrow)
        return button


class OpenDbPanel(Panel):
    """The shared "pick a database + recents" OPEN-state panel.

    Used by the screens whose entry state is opening an existing database
    (Exploit, Identify results): a titled file picker, a primary Open button,
    and a :class:`RecentList` fed from one :class:`RecentStore` category.
    *on_open(path)* is called with the picker's text on Open (possibly empty —
    the owning screen validates and messages) and with the picked path on a
    recents click. Call :meth:`refresh_recents` when the screen is shown so
    the history reflects work done since construction.
    """

    def __init__(
        self,
        *,
        title: str,
        placeholder: str,
        name_filter: str,
        recents: RecentStore,
        recents_key: str,
        recents_title: str,
        on_open: Callable[[str], None],
    ) -> None:
        super().__init__()
        self._recents = recents
        self._recents_key = recents_key

        self.add(h2(title))
        self._picker = PathPicker("file", placeholder=placeholder, name_filter=name_filter)
        self.add(field_row("Database", self._picker, required=True))
        open_row = QHBoxLayout()
        open_row.addStretch(1)
        open_btn = primary_button("Open", "right")
        open_btn.clicked.connect(lambda: on_open(self._picker.path()))
        open_row.addWidget(open_btn)
        self.body.addLayout(open_row)
        self.add(Divider())
        self.add(h2(recents_title))
        self._recent_list = RecentList(recents.get(recents_key), on_pick=on_open)
        self.add(self._recent_list)

    def refresh_recents(self) -> None:
        """Reload the recents rows from the store (screens call this on show)."""
        self._recent_list.set_items(self._recents.get(self._recents_key))
