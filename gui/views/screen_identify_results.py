"""Identify results viewer: browse / filter / hide / export a diff database.

Defines : IdentifyResultsScreen — a thin data-screen (no controller, no worker)
          that opens an ``*-identified.db`` produced by run_diff/identify and shows
          its rows in the shared LogTablePanel, with noise/KB-known toggles, a
          hidden-rules panel, a CSV export, and a "hide identical lines" context
          action. It also defines ``_ResultsRowSource``, the RowSource adapter over
          ``forensic_aul.IdentifyResults``.
Used by : gui.views.shell (stacked screens).
Uses    : PySide6, gui.views.screen_base (ScrollScreen, OpenDbPanel),
          gui.widgets.log_table, gui.widgets.components, forensic_aul
          (IdentifyResults) — read only.

WHY no controller/worker (mirroring gui.views.screens_data's thin convention):
IdentifyResults reads are milliseconds on these windowed diff DBs, so the ops run
inline on the GUI thread without a controller — the light data-screen pattern.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from PySide6.QtGui import QColor
from PySide6.QtWidgets import QCheckBox, QFileDialog, QHBoxLayout, QVBoxLayout, QWidget

from forensic_aul import IdentifyResults
from gui.recent_store import RecentStore
from gui.settings_store import SettingsStore
from gui.theme import DARK_TOKENS
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
    result_panel,
    subtitle,
)
from gui.widgets.log_table import LogTableModel, LogTablePanel

_DB_FILTER = "Identify results (*-identified.db *.db);;All files (*)"
_CSV_FILTER = "CSV (*.csv);;All files (*)"

# Displayed columns: (row key, header label). Keys match IdentifyResults.rows()'s
# aliased column names (see ops/identify/results.py: _ROWS_COLUMNS).
_COLUMNS: list[tuple[str, str]] = [
    ("timestamp", "Timestamp"),
    ("process", "Process"),
    ("pid", "PID"),
    ("log_level", "Level"),
    ("subsystem", "Subsystem"),
    ("category", "Category"),
    ("matched_signatures", "Matched"),
    ("message", "Message"),
]


class _ResultsRowSource:
    """A :class:`~gui.widgets.log_table.RowSource` over an IdentifyResults store.

    Holds the current filter flags + search text; ``count``/``fetch`` re-query the
    store with them so the model's batched loading stays consistent with the flags.
    """

    def __init__(self, store: IdentifyResults) -> None:
        self._store = store
        self.include_noise = False
        self.include_kb_known = False
        self.search: str | None = None

    def count(self) -> int:
        # A COUNT(*) with the same flags — never materialises the rows just to
        # take their len(), so sizing the table stays cheap however the diff grows.
        return self._store.count(
            include_noise=self.include_noise,
            include_kb_known=self.include_kb_known,
            search=self.search,
        )

    def fetch(self, offset: int, limit: int) -> list[Mapping[str, Any]]:
        rows = self._store.rows(
            include_noise=self.include_noise,
            include_kb_known=self.include_kb_known,
            search=self.search,
            limit=limit,
            offset=offset,
        )
        # sqlite3.Row has no .get(); convert to plain dicts for the model.
        return [dict(row) for row in rows]

    def columns(self) -> list[tuple[str, str]]:
        return list(_COLUMNS)


class IdentifyResultsScreen(ScrollScreen):
    """Viewer for an identify diff DB — OPEN (pick a DB) then TABLE (browse)."""

    screen_id = "identify-results"

    def __init__(self, settings: SettingsStore, recents: RecentStore) -> None:
        super().__init__(max_width=1040)
        self._settings = settings
        self._recents = recents
        self._store: IdentifyResults | None = None
        self._source: _ResultsRowSource | None = None
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
        self.content.addWidget(self._table_panel, 1)

        # Hidden-rules panel (built lazily, toggled by the button).
        self._hidden_panel = Panel()
        self._hidden_panel.setVisible(False)
        self.content.addWidget(self._hidden_panel)

        # Export/result confirmation host.
        self._result_host = QVBoxLayout()
        self.content.addLayout(self._result_host)

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
        if not path:
            self.show_result(False, "Choose a results database to open.")
            return
        try:
            store = IdentifyResults(Path(path))
        except Exception as exc:  # noqa: BLE001 — surface the open failure to the UI
            self.show_result(False, f"Could not open {Path(path).name}: {exc}")
            return
        if self._store is not None:
            self._store.close()
        self._store = store
        # Record the open so the DB reappears in the recents even when it was
        # produced elsewhere (another session, the CLI).
        self._recents.add("identify", path, f"{store.count()} retained")
        self._source = _ResultsRowSource(store)
        # Parent the model to the panel so Qt owns its lifetime (setModel does not
        # take ownership); an unparented QAbstractTableModel with a live view
        # attached can crash if Python GCs it out from under the C++ side.
        self._model = LogTableModel(self._source, row_style=self._row_style, parent=self._table_panel)
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
        if self._store is None:
            return
        c = self._store.counts()
        self._table_panel.set_counts(
            f"{c.retained} retained · {c.noise} noise · {c.kb_known} KB-known · {c.hidden} hidden"
        )

    # ── Hidden-rules panel ────────────────────────────────────────────────────────

    def _refresh_hidden_button(self) -> None:
        if self._store is None:
            return
        self._hidden_btn.setText(f"Hidden rules ({len(self._store.hidden_keys())})")

    def _toggle_hidden_panel(self) -> None:
        visible = not self._hidden_panel.isVisible()
        if visible:
            self._rebuild_hidden_panel()
        self._hidden_panel.setVisible(visible)

    def _rebuild_hidden_panel(self) -> None:
        clear_layout(self._hidden_panel.body)
        self._hidden_panel.add(h2("Hidden rules"))
        if self._store is None:
            return
        keys = self._store.hidden_keys()
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
        if self._store is None:
            return
        # hidden_keys stores '' for a null process; pass None back through unhide.
        self._store.unhide(message, process or None)
        self._reload()
        self._refresh_hidden_button()
        self._rebuild_hidden_panel()

    # ── Context action: hide identical lines ──────────────────────────────────────

    def _hide_row(self, row: Mapping[str, Any]) -> None:
        if self._store is None:
            return
        # A NULL-message row has no identical-lines key; the store would raise
        # (hidden_keys.message is NOT NULL) — tell the analyst instead.
        if row.get("message") is None:
            self.show_result(False, "This row has no message — nothing to hide by.")
            return
        self._store.hide(row.get("message"), row.get("process"))
        self._reload()
        self._refresh_hidden_button()
        if self._hidden_panel.isVisible():
            self._rebuild_hidden_panel()

    # ── Export ────────────────────────────────────────────────────────────────────

    def _export_csv(self) -> None:
        if self._store is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "", _CSV_FILTER)
        if not path:
            return
        try:
            count = self._store.export_csv(
                Path(path),
                include_noise=self._source.include_noise if self._source else False,
                include_kb_known=self._source.include_kb_known if self._source else True,
            )
        except Exception as exc:  # noqa: BLE001 — surface the export failure
            self.show_result(False, f"Export failed: {exc}")
            return
        self.show_result(True, f"Exported {count} row(s) → {Path(path).name}")

    # ── Result line ───────────────────────────────────────────────────────────────

    def show_result(self, ok: bool, message: str) -> None:
        clear_layout(self._result_host)
        self._result_host.addWidget(result_panel(ok, message))
