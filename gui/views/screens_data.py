"""Data screens: Export (step 4) and Verify hash.

Defines : ExportScreen — export filtered rows to CSV / JSON / JSONL via
          ``forensic_aul.ops.export.run_export``; VerifyHashScreen — recompute a
          file's digest (SHA-256 / SHA-1 / MD5) and compare it to an expected
          value, keeping a session table of results.
Used by : gui.views.shell (stacked screens).
Uses    : PySide6, gui.views.screen_base, gui.widgets.components,
          gui.widgets.path_picker, forensic_aul.ops.export, hashlib.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
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

from forensic_aul.ops.acquisition.report import load_sidecar_for
from forensic_aul.ops.export.exporter import ExportFilters, run_export
from gui.recent_store import RecentStore
from gui.settings_store import SettingsStore
from gui.views.screen_base import OperationScreen, RecentList
from gui.widgets.components import (
    ComboBox,
    clear_layout,
    ghost_button,
    mono_input,
    primary_button,
    result_panel,
    Divider,
    Panel,
    Pill,
    _repolish,
    eyebrow,
    field_row,
    h1,
    h2,
    style_combo,
    subtitle,
)
from gui.widgets.path_picker import PathPicker

_DB_FILTER = "SQLite database (*.db *.sqlite *.sqlite3);;All files (*)"
# Output filter per format keeps the save dialog honest about the extension.
_OUT_FILTER = "CSV (*.csv);;JSON (*.json);;JSON Lines (*.jsonl)"

# Read files in chunks so hashing a multi-GB image never loads it whole.
_HASH_CHUNK = 1 << 20  # 1 MiB


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
            _repolish(card)

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
        self.navigate = None

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
        self._grep = mono_input("SQL LIKE on message, e.g. %wifi%")
        self._last = mono_input("10m / 1h / 24h / 7d")
        filters.add(field_row("Process", self._process))
        filters.add(field_row("Subsystem", self._subsystem))
        filters.add(field_row("Level", self._level))
        filters.add(field_row("Message", self._grep))
        filters.add(field_row("Last", self._last))
        self.content.addWidget(filters)

        self._result_host = QVBoxLayout()
        self.content.addLayout(self._result_host)

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

    def _start(self) -> None:
        if not self._db.path():
            self._show_result(False, "Choose a database to export.")
            return
        if not self._out.path():
            self._show_result(False, "Choose an output file.")
            return
        db, out = Path(self._db.path()), Path(self._out.path())
        filters = ExportFilters(
            process=_csv_list(self._process.text()),
            subsystem=_csv_list(self._subsystem.text()),
            level=_csv_list(self._level.text()),
            grep=self._grep.text().strip() or None,
            last=self._last.text().strip() or None,
            fmt=self._fmt.value,
            include_fields=True,
        )
        self._export_btn.setEnabled(False)
        self._export_btn.setText("Exporting…")
        self.run_task(lambda: run_export(db, out, filters), self._on_done, self._on_failed)

    def _on_done(self, result: Any) -> None:
        self._reset_button()
        rows = getattr(result, "rows", 0)
        fmt = getattr(result, "fmt", "") or self._fmt.value
        out = str(getattr(result, "output_path", self._out.path()))
        self._show_result(True, f"Exported {rows:,} row(s) as {fmt.upper()} → {Path(out).name}")

    def _on_failed(self, tb: str) -> None:
        self._reset_button()
        last = tb.strip().splitlines()[-1] if tb.strip() else "export failed"
        self._show_result(False, last)

    def _reset_button(self) -> None:
        self._export_btn.setEnabled(True)
        self._export_btn.setText("Export")

    def _show_result(self, ok: bool, message: str) -> None:
        clear_layout(self._result_host)
        self._result_host.addWidget(result_panel(ok, message))


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
        report = load_sidecar_for(Path(src))
        if report is None:
            return
        sha = (report.get("acquisition") or {}).get("logarchive_sha256")
        if sha:
            self._expected.setText(sha)
            # The sidecar records a SHA-256 content hash — match the algorithm.
            index = self._algo.findData("sha256")
            if index >= 0:
                self._algo.setCurrentIndex(index)

    def _start(self) -> None:
        path = self._file.path()
        if not path:
            return
        algo = self._algo.currentData()
        self._run_btn.setEnabled(False)
        self._run_btn.setText("Hashing…")
        self.run_task(lambda: _hash_file(Path(path), algo), self._on_done, self._on_failed)

    def _on_done(self, computed: str) -> None:
        self._run_btn.setEnabled(True)
        self._run_btn.setText("Recompute & compare")
        self._last_computed = computed
        self._copy_btn.setEnabled(True)
        expected = _normalise_hash(self._expected.text())
        if not expected:
            status = ("INFO", "info")
        elif expected == computed.lower():
            status = ("OK", "ok")
        else:
            status = ("MISMATCH", "err")
        self._add_row(Path(self._file.path()).name, computed, expected, status)

    def _on_failed(self, tb: str) -> None:
        self._run_btn.setEnabled(True)
        self._run_btn.setText("Recompute & compare")
        last = tb.strip().splitlines()[-1] if tb.strip() else "hashing failed"
        self._add_row(Path(self._file.path()).name, "—", "—", ("ERROR", "err"))
        del last  # surfaced via the table status; full TB is in the log panel

    def _add_row(self, name: str, computed: str, expected: str, status: tuple[str, str]) -> None:
        row = self._table.rowCount()
        self._table.insertRow(row)
        self._table.setItem(row, 0, QTableWidgetItem(name))
        self._table.setItem(row, 1, QTableWidgetItem(_short_hash(computed)))
        self._table.setItem(row, 2, QTableWidgetItem(_short_hash(expected) if expected else "—"))
        pill = Pill(status[0], status[1])
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

def _hash_file(path: Path, algo: str) -> str:
    """Stream *path* through *algo* (sha256/sha1/md5) and return the hex digest."""
    digest = hashlib.new(algo)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_HASH_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalise_hash(text: str) -> str:
    return text.strip().lower().replace(" ", "")


def _short_hash(value: str) -> str:
    return f"{value[:8]}…{value[-6:]}" if len(value) > 20 else value


def _csv_list(text: str) -> list[str] | None:
    items = [token.strip() for token in text.split(",") if token.strip()]
    return items or None
