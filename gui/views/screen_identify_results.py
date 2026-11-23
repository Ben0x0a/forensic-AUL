"""Identify results viewer: browse / filter / hide / export a diff database.

Defines : IdentifyResultsScreen — the view (its controller:
          gui.controllers.identify_results) that opens an ``*-identified.db`` produced by run_diff/identify and shows
          its rows in the shared LogTablePanel, with noise/KB-known toggles, a
          hidden-rules panel, a CSV export, and a "hide identical lines" context
          action.
Used by : gui.views.shell (stacked screens).
Uses    : PySide6, gui.views.screen_base (ScrollScreen, OpenDbPanel),
          gui.widgets.log_table, gui.widgets.components,
          gui.controllers.identify_results (every read and write).
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QWidget,
)

from gui.controllers.identify_results import IdentifyResultsController
from gui.recent_store import RecentStore
from gui.settings_store import SettingsStore
from gui.tokens import DARK_TOKENS
from gui.views.dialog_signature import SignatureDialog
from gui.views.screen_base import OpenDbPanel, ScrollScreen
from gui.widgets.components import (
    Panel,
    clear_layout,
    eyebrow,
    ghost_button,
    h1,
    h2,
    help_label,
    mono,
    subtitle,
)
from gui.widgets.log_table import LogTableModel, LogTablePanel

_DB_FILTER = "Identify results (*-identified.db *.db);;All files (*)"
_CSV_FILTER = "CSV (*.csv);;All files (*)"

class IdentifyResultsScreen(ScrollScreen):
    """Viewer for an identify diff DB — OPEN (pick a DB) then TABLE (browse)."""

    screen_id = "identify-results"

    def __init__(self, settings: SettingsStore, recents: RecentStore) -> None:
        super().__init__(max_width=1040)
        self._settings = settings
        self._recents = recents
        self._ctrl = IdentifyResultsController(self, recents)
        self._model: LogTableModel | None = None
        # Muted colour for background-noise rows when shown (existing token only).
        self._noise_colour = QColor(DARK_TOKENS["text_faint"])

        self.content.addWidget(eyebrow("Identify"))
        self.content.addWidget(h1("Identify results"))
        self.content.addWidget(subtitle(
            "Browse the lines attributed to the action. Background noise and "
            "KB-known rows are hidden by default; toggle them or hide more."
        ))

        # OPEN state — pick a DB + recents (the shared OpenDbPanel).
        self._open_panel = OpenDbPanel(
            title="Open a results database",
            placeholder="…-identified.db",
            name_filter=_DB_FILTER,
            recents=self._recents,
            recents_key="identify",
            recents_title="Recent identify runs",
            on_open=self._open_path,
        )
        self.content.addWidget(self._open_panel)

        # TABLE state — the shared panel + toggles + hidden-rules panel.
        self._table_panel = LogTablePanel(on_search=self._on_search, stretch_column="message")
        self._noise_check = QCheckBox("Show background noise")
        self._noise_check.toggled.connect(self._on_noise_toggled)
        self._kb_check = QCheckBox("Show KB-known rows")
        self._kb_check.toggled.connect(self._on_kb_toggled)
        self._hidden_btn = ghost_button("Hidden rules (0)")
        self._hidden_btn.clicked.connect(self._toggle_hidden_panel)
        self._export_btn = ghost_button("Export CSV…", "export")
        self._export_btn.clicked.connect(self._export_csv)
        for widget in (self._noise_check, self._kb_check, self._hidden_btn, self._export_btn):
            self._table_panel.add_toolbar_widget(widget)
        self._table_panel.add_context_action("Hide identical lines", self._hide_row)
        self._table_panel.add_context_action("Create signature…", self._create_signature)
        self.content.addWidget(self._table_panel, 1)

        # Hidden-rules panel (built lazily, toggled by the button).
        self._hidden_panel = Panel()
        self._hidden_panel.setVisible(False)
        self.content.addWidget(self._hidden_panel)

        # Export/result confirmation host.
        self.content.addLayout(self.make_result_host())

        self.content.addStretch(1)
        self._set_open_state()

    # ── Prefill hook (shell navigation from the wizard) ───────────────────────────

    def prefill(self, data: dict[str, Any]) -> None:
        """Open the DB named in ``data['db']`` and land directly in TABLE state.

        Mirrors the Acquire→Extract prefill hook the shell uses (see
        shell.set_current): navigating in from the wizard opens the results at once.
        """
        db = data.get("db")
        if db:
            self._open_path(str(db))

    # ── Open / state ──────────────────────────────────────────────────────────────

    def showEvent(self, event: Any) -> None:  # noqa: N802 — Qt override
        # Recents are written by the identify controller during the session;
        # refresh on show so the list is live history, not a construction-time
        # snapshot.
        super().showEvent(event)
        self._open_panel.refresh_recents()

    def _open_path(self, path: str) -> None:
        self._ctrl.open(path)

    @property
    def _source(self) -> Any:
        return self._ctrl.source

    def render_results(self, source: Any) -> None:
        """Show a diff database the controller has just opened."""
        # Parent the model to the panel so Qt owns its lifetime (setModel does not
        # take ownership); an unparented QAbstractTableModel with a live view
        # attached can crash if Python GCs it out from under the C++ side.
        self._model = LogTableModel(source, row_style=self._row_style, parent=self._table_panel)
        self._table_panel.set_model(self._model)
        self._noise_check.setChecked(False)
        self._kb_check.setChecked(False)
        self._set_table_state()
        self._refresh_counts()
        self._refresh_hidden_button()

    def _set_open_state(self) -> None:
        self._open_panel.setVisible(True)
        self._table_panel.setVisible(False)
        self._hidden_panel.setVisible(False)
        self._export_btn.setVisible(False)

    def _set_table_state(self) -> None:
        self._open_panel.setVisible(False)
        self._table_panel.setVisible(True)
        self._export_btn.setVisible(True)

    def is_table_state(self) -> bool:
        return self._table_panel.isVisibleTo(self)

    # ── Row styling ───────────────────────────────────────────────────────────────

    def _row_style(self, row: Mapping[str, Any]) -> QColor | None:
        # Background-noise rows (only visible when the toggle is on) are muted so
        # the retained lines stand out. `excluded` is 1 for baseline noise.
        if row.get("excluded"):
            return self._noise_colour
        return None

    # ── Toggles / search ──────────────────────────────────────────────────────────

    def _on_noise_toggled(self, checked: bool) -> None:
        if self._source is None:
            return
        self._source.include_noise = checked
        self._reload()

    def _on_kb_toggled(self, checked: bool) -> None:
        if self._source is None:
            return
        self._source.include_kb_known = checked
        self._reload()

    def _on_search(self, text: str) -> None:
        if self._source is None:
            return
        self._source.search = text or None
        self._reload()

    def _reload(self) -> None:
        if self._model is not None:
            self._model.reset_source()
        self._refresh_counts()

    # ── Counts ────────────────────────────────────────────────────────────────────

    def _refresh_counts(self) -> None:
        c = self._ctrl.counts()
        if c is None:
            return
        self._table_panel.set_counts(
            f"{c.retained} retained · {c.noise} noise · {c.kb_known} KB-known · {c.hidden} hidden"
        )

    # ── Hidden-rules panel ────────────────────────────────────────────────────────

    def _refresh_hidden_button(self) -> None:
        if self._ctrl.store is None:
            return
        self._hidden_btn.setText(f"Hidden rules ({len(self._ctrl.hidden_keys())})")

    def _toggle_hidden_panel(self) -> None:
        visible = not self._hidden_panel.isVisible()
        if visible:
            self._rebuild_hidden_panel()
        self._hidden_panel.setVisible(visible)

    def _rebuild_hidden_panel(self) -> None:
        clear_layout(self._hidden_panel.body)
        self._hidden_panel.add(h2("Hidden rules"))
        if self._ctrl.store is None:
            return
        keys = self._ctrl.hidden_keys()
        if not keys:
            self._hidden_panel.add(help_label("No rules hidden yet."))
            return
        for message, process in keys:
            row = QWidget()
            layout = QHBoxLayout(row)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(10)
            label = mono(f"{process or '—'} · {message}")
            label.setWordWrap(True)
            layout.addWidget(label, 1)
            unhide = ghost_button("Unhide")
            unhide.clicked.connect(
                lambda _checked=False, m=message, p=process: self._unhide(m, p)
            )
            layout.addWidget(unhide)
            self._hidden_panel.body.addWidget(row)

    def _unhide(self, message: str, process: str) -> None:
        if self._ctrl.store is None:
            return
        # hidden_keys stores '' for a null process; the controller passes None back.
        self._ctrl.unhide(message, process)
        self._reload()
        self._refresh_hidden_button()
        self._rebuild_hidden_panel()

    # ── Context action: hide identical lines ──────────────────────────────────────

    def _create_signature(self, row: Mapping[str, Any]) -> None:
        """Author a knowledge-base signature from *row*.

        The rows currently in the model are handed to the dialog so its Test
        button can report how many of them a draft pattern would match — a check
        the analyst can reason about without a database scan.
        """
        sample = []
        if self._model is not None:
            sample = [
                r for i in range(self._model.rowCount())
                if (r := self._model.row_dict(i)) is not None
            ]
        dialog = SignatureDialog(
            row, sample_rows=sample, kb_dir=self._settings.kb_dir() if self._settings is not None else None,
            parent=self,
        )
        if dialog.exec() == QDialog.DialogCode.Accepted:
            path = dialog.written_path()
            self.show_result(
                True,
                f"Wrote {path.name} — run `faul kb validate` to check the whole "
                "knowledge base." if path else "Signature written.",
            )

    def _hide_row(self, row: Mapping[str, Any]) -> None:
        if not self._ctrl.hide(row):
            return
        self._reload()
        self._refresh_hidden_button()
        if self._hidden_panel.isVisible():
            self._rebuild_hidden_panel()

    # ── Export ────────────────────────────────────────────────────────────────────

    def _export_csv(self) -> None:
        if self._ctrl.store is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "", _CSV_FILTER)
        if path:
            self._ctrl.export_csv(Path(path))

    # ── Result line ───────────────────────────────────────────────────────────────

