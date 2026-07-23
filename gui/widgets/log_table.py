"""A reusable, batched log-table widget over an arbitrary row source.

Defines : ``RowSource`` (a typing.Protocol any windowed table backend implements),
          ``LogTableModel`` (a batched QAbstractTableModel that pulls rows from a
          RowSource on demand), ``LogTablePanel`` (a search box + counts label
          + QTableView + a toolbar slot + a context menu the owning screen fills),
          and the shared table helpers ``make_log_view`` / ``apply_column_stretch``
          (one place for the read-only table configuration, so ad-hoc tables —
          e.g. the Exploit context window — look and behave like the panel's).
          Built deliberately free of any identify-specific knowledge so both the
          identify results viewer and the Exploit (analysis-DB) screen reuse it
          against different RowSources.
Used by : gui.views.screen_identify_results (the identify diff viewer),
          gui.views.screen_exploit (analysis table + context window).
Uses    : PySide6, gui.widgets.components (mono_input).

WHY batched loading (canFetchMore/fetchMore): a diff/analysis table can hold tens
of thousands of rows; materialising them all into the model would stall the UI and
waste memory. The model instead pulls 500-row pages as the view scrolls, querying
the RowSource with LIMIT/OFFSET.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, Protocol, runtime_checkable

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMenu,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from gui.widgets.components import mono_input

# Rows are pulled from the source this many at a time as the view scrolls.
_BATCH = 500

# Debounce window for the search box: wait this long after the last keystroke
# before re-querying, so typing does not fire a query per character.
_SEARCH_DEBOUNCE_MS = 300


@runtime_checkable
class RowSource(Protocol):
    """A windowed, ordered source of dict-like rows for :class:`LogTableModel`."""

    def count(self) -> int:
        """Total number of rows matching the source's current filter."""

    def fetch(self, offset: int, limit: int) -> list[Mapping[str, Any]]:
        """Return up to *limit* rows starting at *offset* (column-name access)."""

    def columns(self) -> list[tuple[str, str]]:
        """Return the ordered ``(key, header label)`` pairs to display."""


class LogTableModel(QAbstractTableModel):
    """A batched table model backed by a :class:`RowSource`.

    Rows load lazily in :data:`_BATCH`-sized pages via canFetchMore/fetchMore.
    *row_style* (optional) returns a foreground :class:`QColor` for a row (used to
    mute background-noise rows) or ``None`` for the default colour.
    """

    def __init__(
        self,
        source: RowSource,
        *,
        row_style: Callable[[Mapping[str, Any]], QColor | None] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._source = source
        self._row_style = row_style
        self._columns = source.columns()
        self._rows: list[Mapping[str, Any]] = []
        self._total = source.count()

    def reset_source(self) -> None:
        """Re-query the source from scratch (after a filter/hide change).

        Raises whatever ``source.count()`` raises (e.g. ValueError for a bad
        filter value). The source is queried BEFORE ``beginResetModel`` so a
        failing count leaves the model — and the attached view — untouched; an
        exception between begin/endResetModel would strand the view mid-reset.
        """
        columns = self._source.columns()
        total = self._source.count()
        self.beginResetModel()
        self._columns = columns
        self._rows = []
        self._total = total
        self.endResetModel()

    # ── Qt model interface ────────────────────────────────────────────────────────

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._columns)

    def canFetchMore(self, parent: QModelIndex) -> bool:  # noqa: N802
        return not parent.isValid() and len(self._rows) < self._total

    def fetchMore(self, parent: QModelIndex) -> None:  # noqa: N802
        if parent.isValid():
            return
        offset = len(self._rows)
        remaining = self._total - offset
        if remaining <= 0:
            return
        take = min(_BATCH, remaining)
        page = self._source.fetch(offset, take)
        if not page:
            return
        first = len(self._rows)
        self.beginInsertRows(QModelIndex(), first, first + len(page) - 1)
        self._rows.extend(page)
        self.endInsertRows()

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        key = self._columns[index.column()][0]
        if role == Qt.ItemDataRole.DisplayRole:
            value = row.get(key)
            return "" if value is None else str(value)
        if role == Qt.ItemDataRole.ForegroundRole and self._row_style is not None:
            return self._row_style(row)
        # WHY no EditRole / sort roles: this table is read-only and its order is the
        # source's forensic order (timestamp asc) — re-sorting would misrepresent
        # the sequence of events, so sorting is deliberately not offered.
        return None

    def headerData(  # noqa: N802
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal and 0 <= section < len(self._columns):
            return self._columns[section][1]
        return None

    def row_dict(self, row: int) -> Mapping[str, Any] | None:
        """The raw row mapping at view-row *row* (for context-menu actions)."""
        if 0 <= row < len(self._rows):
            return self._rows[row]
        return None

    def column_keys(self) -> list[str]:
        """The ordered row-dict keys of the displayed columns."""
        return [key for key, _label in self._columns]


def make_log_view() -> QTableView:
    """A QTableView configured the way every log table here is shown.

    Read-only, row-selecting, no grid, no vertical header — the one place this
    configuration lives, so ad-hoc tables (the context window) cannot drift
    from :class:`LogTablePanel`'s.
    """
    table = QTableView()
    table.setShowGrid(False)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.verticalHeader().hide()
    return table


def apply_column_stretch(
    table: QTableView, column_keys: list[str], stretch_column: str | None
) -> None:
    """Size *table*'s columns to their contents, *stretch_column* absorbing the rest."""
    header = table.horizontalHeader()
    for i, key in enumerate(column_keys):
        mode = (QHeaderView.ResizeMode.Stretch if key == stretch_column
                else QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(i, mode)


class LogTablePanel(QWidget):
    """Search box + counts label + read-only table + toolbar slot + context menu.

    *on_search(text)* is called (debounced) when the search text changes. The
    owning screen adds toolbar widgets via :meth:`add_toolbar_widget` and context
    entries via :meth:`add_context_action`. *stretch_column* is the column key that
    should absorb horizontal space (typically the message column).
    """

    def __init__(
        self,
        *,
        on_search: Callable[[str], None] | None = None,
        stretch_column: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._on_search = on_search
        self._stretch_column = stretch_column
        self._context_actions: list[tuple[str, Callable[[Mapping[str, Any]], None]]] = []
        self._model: LogTableModel | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        # Top row: search + counts + a toolbar slot the screen can populate.
        top = QHBoxLayout()
        top.setSpacing(10)
        self._search = mono_input("search messages…")
        self._search.textChanged.connect(self._on_search_text)
        top.addWidget(self._search, 1)
        self._counts = QLabel("")
        self._counts.setProperty("role", "mono")
        top.addWidget(self._counts)
        self._toolbar = QHBoxLayout()
        self._toolbar.setSpacing(6)
        top.addLayout(self._toolbar)
        layout.addLayout(top)

        # Debounce so typing does not fire a query per keystroke.
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(_SEARCH_DEBOUNCE_MS)
        self._search_timer.timeout.connect(self._fire_search)

        self._table = make_log_view()
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_context_menu)
        layout.addWidget(self._table, 1)

    # ── Model wiring ──────────────────────────────────────────────────────────────

    def set_model(self, model: LogTableModel) -> None:
        self._model = model
        self._table.setModel(model)
        apply_column_stretch(self._table, model.column_keys(), self._stretch_column)

    # ── Toolbar / counts / context menu ───────────────────────────────────────────

    def add_toolbar_widget(self, widget: QWidget) -> None:
        """Add a checkbox/button to the right-side toolbar slot."""
        self._toolbar.addWidget(widget)

    def set_counts(self, text: str) -> None:
        self._counts.setText(text)

    def set_search_enabled(self, enabled: bool, placeholder: str | None = None) -> None:
        """Enable/disable the search box (e.g. no FTS index → no keyword search).

        *placeholder*, when given, replaces the box's placeholder text so the
        disabled state can say WHY the capability is absent instead of showing
        a dead input.
        """
        if not enabled:
            # Clear first (textChanged restarts the debounce), THEN stop the
            # timer — a pending debounce must not fire a search the moment
            # after the capability was declared absent.
            self._search.clear()
            self._search_timer.stop()
        self._search.setEnabled(enabled)
        if placeholder is not None:
            self._search.setPlaceholderText(placeholder)

    def add_context_action(
        self, label: str, callback: Callable[[Mapping[str, Any]], None]
    ) -> None:
        """Register a right-click entry; *callback* receives the clicked row dict."""
        self._context_actions.append((label, callback))

    def _show_context_menu(self, pos: Any) -> None:
        if self._model is None or not self._context_actions:
            return
        index = self._table.indexAt(pos)
        if not index.isValid():
            return
        row = self._model.row_dict(index.row())
        if row is None:
            return
        menu = QMenu(self._table)
        for label, callback in self._context_actions:
            action = menu.addAction(label)
            action.triggered.connect(lambda _checked=False, cb=callback, r=row: cb(r))
        menu.exec(self._table.viewport().mapToGlobal(pos))

    # ── Search debounce ───────────────────────────────────────────────────────────

    def _on_search_text(self, _text: str) -> None:
        self._search_timer.start()

    def _fire_search(self) -> None:
        if self._on_search is not None:
            self._on_search(self._search.text().strip())

    def search_text(self) -> str:
        return self._search.text().strip()

    def clear_search(self) -> None:
        """Empty the search box without firing a search (for a fresh data source)."""
        self._search.clear()          # textChanged restarts the debounce…
        self._search_timer.stop()     # …so stop it: the new source starts unfiltered anyway
