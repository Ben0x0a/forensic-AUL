"""Data screens: Export (step 4) and Verify hash.

Defines : ExportScreen — export filtered rows to CSV / JSON / JSONL (through
          ExportController); VerifyHashScreen — recompute a
          file's digest (SHA-256 / SHA-1 / MD5) and compare it to an expected
          value, keeping a session table of results.
Used by : gui.views.shell (stacked screens).
Uses    : PySide6, gui.views.screen_base, gui.widgets.components,
          gui.widgets.path_picker, gui.controllers.data (every library call),
          gui.navigation (the ExportFrom hand-off).
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from gui.controllers.data import ExportController, VerifyHashController
from gui.navigation import ExportFrom, Payload
from gui.recent_store import RecentStore
from gui.settings_store import SettingsStore
from gui.views.screen_base import OperationScreen, RecentList
from gui.widgets.components import (
    ComboBox,
    ghost_button,
    mono_input,
    primary_button,
    Divider,
    Panel,
    Pill,
    repolish,
    eyebrow,
    field_row,
    h1,
    h2,
    help_label,
    style_combo,
    subtitle,
)
from gui.widgets.path_picker import PathPicker

_DB_FILTER = "SQLite database (*.db *.sqlite *.sqlite3);;All files (*)"
# Output filter per format keeps the save dialog honest about the extension.
_OUT_FILTER = "CSV (*.csv);;JSON (*.json);;JSON Lines (*.jsonl)"



# ── Selectable choice cards ─────────────────────────────────────────────────────

class _ChoiceCard(QPushButton):
    """A selectable card: title + caption, styled via the ``choiceOn`` property."""

    def __init__(self, value: str, title: str, caption: str, *, enabled: bool = True) -> None:
        super().__init__()
        self.value = value
        self.setProperty("choice", "true")
        self.setCheckable(True)
        self.setEnabled(enabled)
        self.setCursor(Qt.CursorShape.PointingHandCursor if enabled else Qt.CursorShape.ArrowCursor)
        # Floor is also set in QSS (min-height); keep the policy fixed-vertical so
        # the row of cards stays a tidy, equal height.
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(4)
        head = QLabel(title)
        head.setStyleSheet("color:#e6e9ef; font-weight:600; font-size:13px;")
        cap = QLabel(caption)
        cap.setProperty("role", "help")
        cap.setWordWrap(True)
        for lbl in (head, cap):
            lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
            layout.addWidget(lbl)


class _ChoiceGroup:
    """Tracks single-selection across a set of :class:`_ChoiceCard`s."""

    def __init__(self, cards: list[_ChoiceCard], value: str) -> None:
        self._cards = cards
        self._value = value
        for card in cards:
            card.clicked.connect(lambda _checked=False, c=card: self.select(c.value))
        self.select(value)

    def select(self, value: str) -> None:
        self._value = value
        for card in self._cards:
            on = card.value == value
            card.setChecked(on)
            card.setProperty("choiceOn", "true" if on else "false")
            repolish(card)

    @property
    def value(self) -> str:
        return self._value


# ── Export ───────────────────────────────────────────────────────────────────

class ExportScreen(OperationScreen):
    """Step 4 — export filtered rows from a database to CSV / JSON / JSONL."""

    screen_id = "export"

    def __init__(self, settings: SettingsStore, recents: RecentStore) -> None:
        super().__init__(max_width=940)
        self._settings = settings
        self._recents = recents
        self._ctrl = ExportController(self)

        self.content.addWidget(eyebrow("Export"))
        self.content.addWidget(h1("Export from a SQLite database"))
        self.content.addWidget(subtitle(
            "Pick the database, scope, and format. Leave filters blank to export "
            "everything; set them to narrow the rows written."
        ))

        self._recent_list: RecentList | None = None
        if self._settings.get("recentDb"):
            recent_panel = Panel()
            recent_panel.add(h2("Recent databases"))
            self._recent_list = RecentList(self._recents.get("database"), on_pick=self._pick_db)
            recent_panel.add(self._recent_list)
            self.content.addWidget(recent_panel)

        form = Panel()
        form.add(h2("Selected database"))
        self._db = PathPicker("file", placeholder="case.sqlite", name_filter=_DB_FILTER)
        self._db.edit.textChanged.connect(self._ctrl.on_database_changed)
        form.add(field_row("File", self._db, required=True))
        self._out = PathPicker("save", placeholder="out.csv / out.json / out.jsonl",
                               name_filter=_OUT_FILTER)
        form.add(field_row("Output", self._out, required=True))
        form.add(Divider())

        # Scope cards — "annotated only" needs the KB, which arrives in v3.
        form.add(h2("Scope"))
        scope_row = QHBoxLayout()
        scope_row.setSpacing(10)
        all_card = _ChoiceCard("all", "All rows",
                               "Every entry — full fidelity.")
        annotated_card = _ChoiceCard("annotated", "Only annotated rows",
                                     "KB-matched rows only. (v3)",
                                     enabled=False)
        scope_row.addWidget(all_card)
        scope_row.addWidget(annotated_card)
        form.body.addLayout(scope_row)
        self._scope = _ChoiceGroup([all_card], "all")
        form.add(Divider())

        # Format cards — CSV / JSON / JSONL are real; PDF is a future report.
        form.add(h2("Format"))
        fmt_row = QHBoxLayout()
        fmt_row.setSpacing(10)
        csv_card = _ChoiceCard("csv", "CSV", "Flat log-table export.")
        json_card = _ChoiceCard("json", "JSON", "All fields + annotations.")
        jsonl_card = _ChoiceCard("jsonl", "JSON Lines", "One object per row.")
        pdf_card = _ChoiceCard("pdf", "PDF report", "Summary + appendices. (later)",
                               enabled=False)
        for card in (csv_card, json_card, jsonl_card, pdf_card):
            fmt_row.addWidget(card)
        form.body.addLayout(fmt_row)
        self._fmt = _ChoiceGroup([csv_card, json_card, jsonl_card], "csv")
        self.content.addWidget(form)

        # Optional filters (the core supports far more; expose the common ones).
        filters = Panel()
        filters.add(h2("Filters (optional)"))
        self._process = mono_input("process names, comma-separated")
        self._subsystem = mono_input("subsystems, comma-separated")
        self._level = mono_input("Default,Error,…")
        self._like = mono_input("SQL LIKE on message, e.g. %wifi%")
        self._last = mono_input("10m / 1h / 24h / 7d")
        self._last.setToolTip("Counted back from the newest log entry in the database, not from now.")
        filters.add(field_row("Process", self._process))
        filters.add(field_row("Subsystem", self._subsystem))
        filters.add(field_row("Level", self._level))
        filters.add(field_row("Message", self._like))
        filters.add(field_row("Last", self._last))
        # Filters handed over from another screen that this form has no input
        # for (see ExportController.receive): shown, with a way to drop them.
        self._carried_row = QWidget()
        carried_layout = QHBoxLayout(self._carried_row)
        carried_layout.setContentsMargins(0, 0, 0, 0)
        self._carried_label = help_label("")
        self._carried_label.setWordWrap(True)
        carried_layout.addWidget(self._carried_label, 1)
        clear_carried = ghost_button("Clear", "x")
        clear_carried.clicked.connect(self._ctrl.clear_carried)
        carried_layout.addWidget(clear_carried)
        self._carried_row.setVisible(False)
        filters.add(self._carried_row)
        self.content.addWidget(filters)

        self.content.addLayout(self.make_result_host())

        actions = QHBoxLayout()
        actions.addStretch(1)
        self._export_btn = primary_button("Export", "export")
        self._export_btn.clicked.connect(self._start)
        actions.addWidget(self._export_btn)
        self.content.addLayout(actions)
        self.content.addStretch(1)

    def showEvent(self, event: Any) -> None:  # noqa: N802 — Qt override
        # Recents grow during the session; refresh on show so the list is live
        # history, not a construction-time snapshot.
        super().showEvent(event)
        if self._recent_list is not None:
            self._recent_list.set_items(self._recents.get("database"))

    def _pick_db(self, path: str) -> None:
        self._db.set_path(path)

    def receive(self, payload: Payload) -> None:
        """Take a hand-off (:class:`ExportFrom`): database and filters."""
        if not isinstance(payload, ExportFrom):
            super().receive(payload)
            return
        self._ctrl.receive(payload)

    def fill_form(self, *, db: str, process: str, subsystem: str, level: str,
                  like: str, last: str) -> None:
        """Replace the database and the filter inputs (a hand-off is authoritative)."""
        self._db.set_path(db)
        for widget, value in ((self._process, process), (self._subsystem, subsystem),
                              (self._level, level), (self._like, like), (self._last, last)):
            widget.setText(value)

    def show_carried(self, description: str) -> None:
        """Show the handed-over filters the form cannot display (hidden when none)."""
        self._carried_label.setText(f"Also applied, from Exploit: {description}" if description else "")
        self._carried_row.setVisible(bool(description))

    def _start(self) -> None:
        self._ctrl.start(
            db=self._db.path(), out=self._out.path(), fmt=self._fmt.value,
            process=self._process.text(), subsystem=self._subsystem.text(),
            level=self._level.text(), like=self._like.text(), last=self._last.text(),
        )

    def set_exporting(self, running: bool) -> None:
        if running:
            self._export_btn.setEnabled(False)
            self._export_btn.setText("Exporting…")
        else:
            self._reset_button()

    def _reset_button(self) -> None:
        self._export_btn.setEnabled(True)
        self._export_btn.setText("Export")


# ── Verify hash ─────────────────────────────────────────────────────────────────

class VerifyHashScreen(OperationScreen):
    """Recompute a file's digest and compare to an expected value (read-only)."""

    screen_id = "verify-hash"

    _ALGORITHMS = (("sha256", "SHA-256"), ("sha1", "SHA-1"), ("md5", "MD5 (legacy)"))

    def __init__(self, settings: SettingsStore, recents: RecentStore) -> None:
        super().__init__(max_width=940)
        self._settings = settings
        self._recents = recents
        self._last_computed = ""
        self._ctrl = VerifyHashController(self)

        self.content.addWidget(eyebrow("Validate tools"))
        self.content.addWidget(h1("Hash verification"))
        self.content.addWidget(subtitle(
            "Recompute a file's digest and compare it to an expected value "
            "(manifest, archive metadata, or supplied checksum). Read-only — no writes."
        ))

        form = Panel()
        form.add(h2("File to verify"))
        self._file = PathPicker("file", placeholder="file to hash")
        form.add(field_row("File", self._file, required=True))
        self._expected = mono_input("expected digest (optional)")
        form.add(field_row("Expected hash", self._expected))
        # Selecting a logarchive that has an acquisition sidecar auto-fills the
        # expected SHA-256 from it (the recorded content hash), so verifying is a
        # one-click compare. _last_sidecar_src de-dupes per-keystroke changes.
        self._last_sidecar_src = ""
        self._file.edit.textChanged.connect(self._on_file_changed)
        self._algo = ComboBox()
        for value, label in self._ALGORITHMS:
            self._algo.addItem(label, value)
        style_combo(self._algo)
        form.add(field_row("Algorithm", self._algo))

        actions = QHBoxLayout()
        actions.addStretch(1)
        self._copy_btn = ghost_button("Copy computed hash", "copy")
        self._copy_btn.setEnabled(False)
        self._copy_btn.clicked.connect(self._copy)
        self._run_btn = primary_button("Recompute & compare")
        self._run_btn.clicked.connect(self._start)
        actions.addWidget(self._copy_btn)
        actions.addWidget(self._run_btn)
        form.body.addLayout(actions)
        self.content.addWidget(form)

        session = Panel()
        head = QHBoxLayout()
        head.addWidget(h2("This session"))
        head.addStretch(1)
        session.body.addLayout(head)
        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["File", "Computed", "Expected", "Status"])
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col in (1, 2, 3):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        session.body.addWidget(self._table)
        self.content.addWidget(session)
        self.content.addStretch(1)

    def _on_file_changed(self, text: str) -> None:
        """Auto-fill the expected hash from an acquisition sidecar, if one exists."""
        src = text.strip()
        if src == self._last_sidecar_src:
            return
        self._last_sidecar_src = src
        if not src or self._expected.text().strip():
            return  # nothing selected, or the analyst already typed a digest
        sha = self._ctrl.expected_from_sidecar(src)
        if sha:
            self._expected.setText(sha)
            # The sidecar records a SHA-256 content hash — match the algorithm.
            index = self._algo.findData("sha256")
            if index >= 0:
                self._algo.setCurrentIndex(index)

    def _start(self) -> None:
        self._ctrl.start(path=self._file.path(), algo=self._algo.currentData(),
                         expected=self._expected.text())

    def set_hashing(self, running: bool, *, computed: str = "") -> None:
        self._run_btn.setEnabled(not running)
        self._run_btn.setText("Hashing…" if running else "Recompute & compare")
        if computed:
            self._last_computed = computed
            self._copy_btn.setEnabled(True)

    def add_row(
        self,
        name: str,
        computed: str,
        expected: str,
        status: tuple[str, str],
        *,
        tooltip: str | None = None,
    ) -> None:
        row = self._table.rowCount()
        self._table.insertRow(row)
        self._table.setItem(row, 0, QTableWidgetItem(name))
        self._table.setItem(row, 1, QTableWidgetItem(_short_hash(computed)))
        self._table.setItem(row, 2, QTableWidgetItem(_short_hash(expected) if expected else "—"))
        pill = Pill(status[0], status[1])
        if tooltip:
            pill.setToolTip(tooltip)
        cell = QWidget()
        cell_layout = QHBoxLayout(cell)
        cell_layout.setContentsMargins(8, 2, 8, 2)
        cell_layout.addWidget(pill)
        cell_layout.addStretch(1)
        self._table.setCellWidget(row, 3, cell)

    def _copy(self) -> None:
        from PySide6.QtWidgets import QApplication

        if self._last_computed:
            QApplication.clipboard().setText(self._last_computed)


# ── Helpers ─────────────────────────────────────────────────────────────────────

def _short_hash(value: str) -> str:
    return f"{value[:8]}…{value[-6:]}" if len(value) > 20 else value
