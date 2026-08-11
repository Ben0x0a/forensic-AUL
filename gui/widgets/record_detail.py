"""A right-hand drawer showing every field of one selected record.

Defines : ``DetailField`` / ``DetailSection`` (what to render) and
          ``RecordDetailPanel`` — a titled, closable panel with previous/next
          record stepping, a copy-to-clipboard action, and label/value rows
          grouped into sections.
Used by : gui.views.screen_exploit (the analysis table's double-click action).
Uses    : PySide6, gui.widgets.components (Panel, headings, buttons).

WHY a drawer rather than a dialog: inspecting a record is something an analyst
does *while* reading the table — stepping from row to row, comparing against the
neighbours still on screen. A modal dialog would hide exactly the context that
makes the record meaningful. It opens on the right so it stays visually distinct
from the "view context" panel, which opens below the table.

WHY sections rather than one flat list: a log record mixes several different
kinds of fact — what happened, values that only mean anything on the machine that
produced them, the message text, what the knowledge base makes of it, and where
in the evidence it came from — and an analyst reads them for different reasons.
Empty sections are omitted entirely rather than shown blank. A section may carry
a *note* explaining how far its values can be trusted.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from gui.widgets.components import (
    Panel,
    clear_layout,
    eyebrow,
    help_label,
    make_icon,
    mono,
)

# Width of the label column. Wide enough for the longest field name we render
# ("Extracted values", "Format string") without wrapping, so the value column
# starts at the same x on every row and the panel reads as a table.
_LABEL_W = 116


@dataclass(frozen=True)
class DetailField:
    """One label/value row. *monospace* suits identifiers, paths and timestamps."""

    label: str
    value: str
    monospace: bool = True


@dataclass(frozen=True)
class DetailSection:
    """A titled group of fields; rendered only when it has any.

    *note* is a short caveat shown under the heading — for values whose meaning
    is bounded (e.g. identifiers that are only valid on the machine that produced
    the log). It is rendered but never copied as a field value.
    """

    title: str
    fields: list[DetailField] = field(default_factory=list)  # mutable default — shared if = []
    note: str = ""

    def is_empty(self) -> bool:
        return not any(f.value for f in self.fields)


class RecordDetailPanel(QWidget):
    """Right-hand drawer rendering :class:`DetailSection`s for one record.

    Deliberately free of any knowledge of what a log record is: the owning screen
    decides which sections and fields exist, so the identify results viewer can
    reuse this against its own row shape.

    *on_step* is called with -1 / +1 when the previous/next buttons are pressed;
    *on_close* when the drawer is dismissed. Both are optional — the buttons are
    hidden when no callback is supplied, rather than shown dead.
    """

    def __init__(
        self,
        *,
        on_step: Callable[[int], None] | None = None,
        on_close: Callable[[], None] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._on_step = on_step
        self._on_close = on_close
        self._sections: list[DetailSection] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._panel = Panel()
        layout.addWidget(self._panel, 1)

        self._panel.body.addLayout(self._build_header())

        # The fields go inside a scroll area. WHY: a record with a long message
        # and several extracted values is taller than the drawer, and a plain
        # layout responds to that by squeezing every row until the text overlaps
        # — unreadable, and silently so. Scrolling keeps each row at its natural
        # height and lets the analyst reach the rest.
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        holder = QWidget()
        self._body = QVBoxLayout(holder)
        self._body.setContentsMargins(0, 0, 0, 0)
        self._body.setSpacing(2)
        scroll.setWidget(holder)
        self._panel.body.addWidget(scroll, 1)

    # ── Header ────────────────────────────────────────────────────────────────────

    def _build_header(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(4)

        if self._on_step is not None:
            self._prev_button = self._icon_button("left", "Previous record",
                                                  lambda: self._on_step(-1))
            self._next_button = self._icon_button("right", "Next record",
                                                  lambda: self._on_step(1))
            row.addWidget(self._prev_button)
            row.addWidget(self._next_button)

        title = QLabel("Record detail")
        title.setProperty("role", "h2")
        row.addWidget(title)
        row.addStretch(1)

        row.addWidget(self._icon_button("copy", "Copy record", self._copy))
        if self._on_close is not None:
            row.addWidget(self._icon_button("x", "Close", self._on_close))
        return row

    @staticmethod
    def _icon_button(icon: str, tooltip: str, slot: Callable[[], None]) -> QPushButton:
        button = QPushButton()
        button.setProperty("iconbtn", "true")
        button.setIcon(make_icon(icon, 12))
        button.setToolTip(tooltip)
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        button.clicked.connect(lambda _checked=False: slot())
        return button

    def set_step_enabled(self, *, previous: bool, next_: bool) -> None:
        """Grey out stepping at the ends of the result set."""
        if self._on_step is None:
            return
        self._prev_button.setEnabled(previous)
        self._next_button.setEnabled(next_)

    # ── Content ───────────────────────────────────────────────────────────────────

    def show_record(self, sections: Sequence[DetailSection]) -> None:
        """Render *sections*, dropping any that carry no populated field."""
        self._sections = [s for s in sections if not s.is_empty()]
        clear_layout(self._body)
        for section in self._sections:
            self._body.addWidget(eyebrow(section.title))
            if section.note:
                self._body.addWidget(help_label(section.note))
            for entry in section.fields:
                if entry.value:
                    self._body.addLayout(self._field_row(entry))
            self._body.addWidget(_spacer())
        self._body.addStretch(1)

    def _field_row(self, entry: DetailField) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(10)
        label = QLabel(entry.label)
        label.setProperty("role", "statLabel")
        label.setFixedWidth(_LABEL_W)
        label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        row.addWidget(label)

        value = mono(entry.value) if entry.monospace else QLabel(entry.value)
        # Wrap rather than elide: a long path or message is precisely what the
        # analyst opened the drawer to read in full, and it is selectable so it
        # can be copied out of a report.
        value.setWordWrap(True)
        value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        row.addWidget(value, 1)
        return row

    # ── Copy ──────────────────────────────────────────────────────────────────────

    def as_text(self) -> str:
        """The rendered record as plain text — what :meth:`_copy` puts on the clipboard."""
        lines: list[str] = []
        for section in self._sections:
            lines.append(f"— {section.title} —")
            if section.note:
                lines.append(f"({section.note})")
            lines.extend(
                f"{entry.label}: {entry.value}" for entry in section.fields if entry.value
            )
            lines.append("")
        return "\n".join(lines).strip()

    def _copy(self) -> None:
        QApplication.clipboard().setText(self.as_text())


def _spacer() -> QFrame:
    """A thin gap between sections (a Divider would over-rule such a dense list)."""
    frame = QFrame()
    frame.setFixedHeight(10)
    frame.setStyleSheet("background: transparent;")
    return frame
