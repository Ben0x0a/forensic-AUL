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

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, QTimer, Slot
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

# Starting width for an auto-sized column, and the cap applied to it. WHY a cap:
# a single very long subsystem or category value would otherwise set the column's
# initial width and crowd out the message. The analyst can still drag past it —
# these bound the *starting* width, not the column.
_DEFAULT_COL_W = 120
_MAX_AUTO_COL_W = 260

# Glyph a boolean cell renders as when true (false renders empty, so a column of
# marks reads as a sparse list of hits rather than a wall of yes/no). A filled
# circle rather than something more decorative: it exists in every font we might
# fall back to, whereas a dingbat silently degrades to a substitute glyph (a "+"
# was what ✦ became on a bare fontconfig).
_MARK = "●"

# Floor for the search box (see LogTablePanel.__init__).
_MIN_SEARCH_W = 220


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
        value = row.get(key)
        if role == Qt.ItemDataRole.DisplayRole:
            # A bool renders as a mark, not as "True"/"False": a yes/no column
            # (e.g. "is this row annotated?") reads far faster as a tick, and the
            # detail drawer carries the specifics behind it.
            if isinstance(value, bool):
                return _MARK if value else ""
            return "" if value is None else str(value)
        if role == Qt.ItemDataRole.TextAlignmentRole and isinstance(value, bool):
            return int(Qt.AlignmentFlag.AlignCenter)
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
    # Ellipsise rather than clip: a column the analyst has narrowed must still
    # show that there is more text than fits.
    table.setTextElideMode(Qt.TextElideMode.ElideRight)
    table.verticalHeader().hide()
    return table


def apply_column_stretch(
    table: QTableView,
    column_keys: list[str],
    stretch_column: str | None,
    *,
    fixed_widths: Mapping[str, int] | None = None,
) -> None:
    """Size *table*'s columns, leaving every one of them draggable by the analyst.

    *stretch_column* absorbs the leftover width; columns named in *fixed_widths*
    get exactly that width; every other column is auto-sized to its contents once
    and then left Interactive.

    WHY not ``ResizeToContents``: that mode (like ``Stretch``) **ignores user
    drags**, so the previous configuration silently made the table un-resizable.
    ``Interactive`` is the only mode that lets a header boundary be dragged, so
    the auto-size is applied as a one-off starting width and the mode is switched
    afterwards.
    """
    header = table.horizontalHeader()
    fixed = dict(fixed_widths or {})

    # Pass 1: let Qt measure sensible starting widths for the content columns.
    for i, key in enumerate(column_keys):
        if key == stretch_column or key in fixed:
            continue
        header.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
    widths = {
        i: header.sectionSize(i)
        for i, key in enumerate(column_keys)
        if key != stretch_column and key not in fixed
    }

    # Pass 2: fix the final modes, restoring the measured widths as the starting
    # point of an Interactive (draggable) column.
    for i, key in enumerate(column_keys):
        if key == stretch_column:
            header.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)
        elif key in fixed:
            header.setSectionResizeMode(i, QHeaderView.ResizeMode.Fixed)
            header.resizeSection(i, fixed[key])
        else:
            header.setSectionResizeMode(i, QHeaderView.ResizeMode.Interactive)
            header.resizeSection(i, min(widths.get(i, _DEFAULT_COL_W), _MAX_AUTO_COL_W))

    # Columns can also be reordered by dragging their headers; the model keys
    # stay in their logical order, so nothing downstream depends on visual order.
    header.setSectionsMovable(True)


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
        fixed_widths: Mapping[str, int] | None = None,
        on_activate: Callable[[Mapping[str, Any]], None] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._on_search = on_search
        self._stretch_column = stretch_column
        self._fixed_widths = dict(fixed_widths or {})
        self._on_activate = on_activate
        self._context_actions: list[tuple[str, Callable[[Mapping[str, Any]], None]]] = []
        self._model: LogTableModel | None = None
        self._follow_selection = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        # Two rows, not one. WHY: the screens put five or six controls in the
        # toolbar slot, and sharing a row with the search box meant whichever
        # came last was clipped off the right edge — on a wide screen as well,
        # because the fixed-size controls win the space fight against a
        # stretchy input. Search + counts on top, filters beneath.
        top = QHBoxLayout()
        top.setSpacing(10)
        self._search = mono_input("search messages…")
        # A minimum width, not just a stretch factor: the toolbar slot beside it
        # holds fixed-size widgets that will otherwise squeeze the search box to
        # a few pixels on a crowded screen.
        self._search.setMinimumWidth(_MIN_SEARCH_W)
        self._search.textChanged.connect(self._on_search_text)
        top.addWidget(self._search, 1)
        # Slot for controls that belong WITH the search box rather than with the
        # filters below it — narrowing "what to look at" rather than "when".
        self._search_slot = QHBoxLayout()
        self._search_slot.setSpacing(6)
        top.addLayout(self._search_slot)
        self._counts = QLabel("")
        self._counts.setProperty("role", "mono")
        top.addWidget(self._counts)
        layout.addLayout(top)

        self._toolbar = QHBoxLayout()
        self._toolbar.setSpacing(6)
        # Trailing stretch so the filters stay left-aligned under the search box
        # instead of spreading across the full width of a wide screen.
        self._toolbar.addStretch(1)
        layout.addLayout(self._toolbar)

        # Debounce so typing does not fire a query per keystroke.
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(_SEARCH_DEBOUNCE_MS)
        self._search_timer.timeout.connect(self._fire_search)

        self._table = make_log_view()
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_context_menu)
        self._table.doubleClicked.connect(self._on_double_clicked)
        layout.addWidget(self._table, 1)

    # ── Model wiring ──────────────────────────────────────────────────────────────

    def set_model(self, model: LogTableModel) -> None:
        self._model = model
        self._table.setModel(model)
        self._resize_columns()
        # WHY re-size once rows arrive: set_model runs before the model has
        # fetched its first page, so sizing to "contents" at this point measures
        # the headers and nothing else — a timestamp column ends up narrower than
        # a timestamp. rowsInserted fires when the first batch lands; the
        # connection is single-shot so a later page never overrides a width the
        # analyst has since dragged.
        model.rowsInserted.connect(self._on_first_rows, Qt.ConnectionType.SingleShotConnection)
        # A fresh model means a fresh selection; re-wire it so a screen watching
        # the current row (the detail drawer) follows this model, not the old one.
        selection = self._table.selectionModel()
        if selection is not None:
            selection.currentRowChanged.connect(self._on_current_row_changed)

    def _resize_columns(self) -> None:
        if self._model is not None:
            apply_column_stretch(
                self._table, self._model.column_keys(), self._stretch_column,
                fixed_widths=self._fixed_widths,
            )

    @Slot()
    def _on_first_rows(self, *_args: Any) -> None:
        self._resize_columns()

    # ── Row activation / selection ────────────────────────────────────────────────
    #
    # WHY both handlers are decorated @Slot: they are connected to signals owned
    # by the table's *selection model*, which Qt destroys as part of tearing the
    # widget down. A plain Python callable stays connected across that teardown
    # and can be invoked against an already-destroyed panel — a segfault rather
    # than an exception. A registered slot lets Qt drop the connection with the
    # receiver.

    @Slot(QModelIndex)
    def _on_double_clicked(self, index: QModelIndex) -> None:
        if self._on_activate is None or self._model is None or not index.isValid():
            return
        row = self._model.row_dict(index.row())
        if row is not None:
            self._on_activate(row)

    @Slot(QModelIndex, QModelIndex)
    def _on_current_row_changed(self, current: QModelIndex, _previous: QModelIndex) -> None:
        # Only forwarded once something is already open: arrow-keying through the
        # table should follow the drawer, but must not *open* it uninvited.
        if self._follow_selection and current.isValid() and self._model is not None:
            row = self._model.row_dict(current.row())
            if row is not None and self._on_activate is not None:
                self._on_activate(row)

    def set_follow_selection(self, follow: bool) -> None:
        """Whether moving the selection should re-fire ``on_activate``.

        The detail drawer turns this on while it is open, so the keyboard walks
        records, and off when closed.
        """
        self._follow_selection = follow

    def row_count(self) -> int:
        return self._model.rowCount() if self._model is not None else 0

    def current_row(self) -> int:
        return self._table.currentIndex().row() if self._table.currentIndex().isValid() else -1

    def select_row(self, row: int) -> Mapping[str, Any] | None:
        """Move the selection to *row* and return its mapping (``None`` if absent).

        Used by the detail drawer's previous/next stepping so the table and the
        drawer never disagree about which record is being shown.
        """
        if self._model is None or not 0 <= row < self._model.rowCount():
            return None
        self._table.selectRow(row)
        self._table.scrollTo(self._model.index(row, 0))
        return self._model.row_dict(row)

    def clear_model(self) -> None:
        """Detach the model from the view, releasing the view→model dependency.

        Qt destroys a view and its model independently, and a view being torn
        down can still call into a model whose backing store has gone. Detaching
        first makes the order deterministic — used when swapping databases and
        when a screen is released.
        """
        self._table.setModel(None)
        self._model = None

    # ── Toolbar / counts / context menu ───────────────────────────────────────────

    def add_search_widget(self, widget: QWidget) -> None:
        """Add a control to the row *beside* the search box."""
        self._search_slot.addWidget(widget)

    def add_toolbar_widget(self, widget: QWidget) -> None:
        """Add a control to the filter row beneath the search box."""
        # Insert before the trailing stretch so controls pack from the left.
        self._toolbar.insertWidget(self._toolbar.count() - 1, widget)

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
