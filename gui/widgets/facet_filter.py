"""A multi-select "value (count)" dropdown for filtering a table by one column.

Defines : ``FacetFilter`` — a compact button that opens a checkable list of the
          distinct values of one field, each with its row count, plus
          select-all / clear / a type-ahead box.
Used by : gui.views.screen_exploit (process / category / subsystem filters).
Uses    : PySide6, gui.widgets.components (mono_input, ghost_button).

WHY a popup rather than a combo box: the values are not mutually exclusive (an
analyst narrows to "these three processes"), there can be hundreds of them, and
each needs its count to be worth choosing between. QComboBox offers none of
that; a QMenu of checkboxes does, and stays one line of toolbar.

WHY the counts are the *unfiltered* totals: they come from the statistics cached
at extract time (see ops/summary/cache.py), so opening this list costs nothing.
Recomputing them against the currently-active filters would mean a GROUP BY over
the whole table on every keystroke — exactly the cost this screen was rebuilt to
remove. The button's tooltip says so, rather than letting the numbers imply a
precision they do not have.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence

from PySide6.QtCore import QPoint, Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from gui.widgets.components import ghost_button, mono_input

# How many values the popup lists before it starts scrolling, and its width.
_POPUP_H = 300
_POPUP_W = 300

# Above this many values the type-ahead box is the only sane way in, so it takes
# focus when the popup opens.
_TYPEAHEAD_THRESHOLD = 12


class FacetFilter(QWidget):
    """A toolbar button opening a checkable, counted list of one field's values.

    *label* names the field ("Process"); *on_changed* is called with the list of
    selected values (empty = no constraint) whenever the selection is applied.
    """

    def __init__(
        self,
        label: str,
        *,
        on_changed: Callable[[list[str]], None],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._label = label
        self._on_changed = on_changed
        self._entries: list[tuple[str, int]] = []
        self._selected: set[str] = set()
        self._boxes: dict[str, QCheckBox] = {}

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self._button = ghost_button(label, "filter")
        self._button.clicked.connect(self._open_popup)
        layout.addWidget(self._button)

        self._popup = _Popup(self)
        self._popup.setVisible(False)

    # ── Data ──────────────────────────────────────────────────────────────────────

    def set_entries(self, entries: Iterable[tuple[str, int]]) -> None:
        """Replace the value list with ``(name, count)`` pairs, highest count first.

        Clears any current selection: the values belong to the database that was
        just opened, and carrying a selection across databases would silently
        filter the new one by the old one's names.
        """
        self._entries = [(name, count) for name, count in entries if name]
        self._selected.clear()
        self._rebuild_popup()
        self._sync_button()

    def selected(self) -> list[str]:
        return sorted(self._selected)

    def clear(self) -> None:
        """Deselect everything and notify (used by the screen's Clear action)."""
        if not self._selected:
            return
        self._selected.clear()
        for box in self._boxes.values():
            box.blockSignals(True)
            box.setChecked(False)
            box.blockSignals(False)
        self._sync_button()
        self._on_changed([])

    # ── Popup ─────────────────────────────────────────────────────────────────────

    def _rebuild_popup(self) -> None:
        self._boxes.clear()
        self._popup.rebuild(self._entries, self._on_box_toggled,
                            on_all=self._select_all, on_none=self.clear)

    def _open_popup(self) -> None:
        if not self._entries:
            self._button.setToolTip("No values — open a database first.")
            return
        below = self._button.mapToGlobal(QPoint(0, self._button.height() + 2))
        self._popup.move(below)
        self._popup.show()
        self._popup.focus_search(len(self._entries) > _TYPEAHEAD_THRESHOLD)

    def _on_box_toggled(self, value: str, checked: bool, box: QCheckBox) -> None:
        self._boxes[value] = box
        if checked:
            self._selected.add(value)
        else:
            self._selected.discard(value)
        self._sync_button()
        self._on_changed(self.selected())

    def _select_all(self) -> None:
        self._selected = {name for name, _ in self._entries}
        for box in self._boxes.values():
            box.blockSignals(True)
            box.setChecked(True)
            box.blockSignals(False)
        self._sync_button()
        self._on_changed(self.selected())

    def _sync_button(self) -> None:
        """Show the selection on the button, so an active filter is never hidden."""
        n = len(self._selected)
        if n == 0:
            self._button.setText(self._label)
        elif n == 1:
            self._button.setText(f"{self._label}: {next(iter(self._selected))}")
        else:
            self._button.setText(f"{self._label}: {n} selected")
        self._button.setProperty("chipOn", "true" if n else "false")
        self._button.style().unpolish(self._button)
        self._button.style().polish(self._button)
        self._button.setToolTip(
            f"{len(self._entries)} distinct values. Counts are for the whole "
            "database, not the current filters."
        )


class _Popup(QFrame):
    """The checkable list itself — a frameless popup owned by its FacetFilter."""

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent, Qt.WindowType.Popup)
        self.setProperty("card", "elev")
        self.setFixedWidth(_POPUP_W)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 8, 8, 8)
        outer.setSpacing(6)

        self._search = mono_input("filter values…")
        self._search.textChanged.connect(self._apply_typeahead)
        outer.addWidget(self._search)

        actions = QHBoxLayout()
        actions.setSpacing(4)
        # Connected once here and re-pointed by rebuild() through these two
        # holders. WHY not disconnect/reconnect per rebuild: PySide6 warns rather
        # than raising when there is nothing to disconnect, so the first rebuild
        # would emit a spurious warning on every construction.
        self._on_all: Callable[[], None] = lambda: None
        self._on_none: Callable[[], None] = lambda: None
        self._all_button = ghost_button("Select all")
        self._none_button = ghost_button("Clear")
        self._all_button.clicked.connect(lambda _checked=False: self._on_all())
        self._none_button.clicked.connect(lambda _checked=False: self._on_none())
        actions.addWidget(self._all_button)
        actions.addWidget(self._none_button)
        actions.addStretch(1)
        outer.addLayout(actions)

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._scroll.setFixedHeight(_POPUP_H)
        self._holder = QWidget()
        self._list = QVBoxLayout(self._holder)
        self._list.setContentsMargins(0, 0, 0, 0)
        self._list.setSpacing(2)
        self._scroll.setWidget(self._holder)
        outer.addWidget(self._scroll)

    def rebuild(
        self,
        entries: Sequence[tuple[str, int]],
        on_toggle: Callable[[str, bool, QCheckBox], None],
        *,
        on_all: Callable[[], None],
        on_none: Callable[[], None],
    ) -> None:
        while self._list.count():
            item = self._list.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        for name, count in entries:
            box = QCheckBox(f"{name}  ({count:,})")
            box.setCursor(Qt.CursorShape.PointingHandCursor)
            box.setProperty("facetValue", name)
            box.toggled.connect(
                lambda checked, n=name, b=box: on_toggle(n, checked, b)
            )
            self._list.addWidget(box)
        self._list.addStretch(1)
        self._on_all, self._on_none = on_all, on_none

    def focus_search(self, focus: bool) -> None:
        self._search.clear()
        if focus:
            self._search.setFocus()

    def _apply_typeahead(self, text: str) -> None:
        needle = text.strip().lower()
        for i in range(self._list.count()):
            widget = self._list.itemAt(i).widget()
            if isinstance(widget, QCheckBox):
                name = str(widget.property("facetValue") or "")
                widget.setVisible(needle in name.lower())
