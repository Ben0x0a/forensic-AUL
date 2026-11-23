"""Controller for the Identify results screen: one open diff database.

Defines : IdentifyResultsController (open / close a ``*-identified.db``, its row
          source, counts, hidden rules — hide / unhide — and the CSV export),
          ``ResultsRowSource`` and ``COLUMNS``.
Used by : gui.views.screen_identify_results (the view renders; every read and
          write of the diff database goes through here).
Uses    : forensic_aul (IdentifyResults, ForensicAULError), gui.recent_store.

The reads are milliseconds on these windowed diff databases, so they run on the
GUI thread — a controller is about where the logic lives (G6), not threads.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from forensic_aul import ForensicAULError, IdentifyResults
from gui.recent_store import RecentStore

# What opening or writing a diff database can legitimately fail with; anything
# else is a bug and reaches the crash reporter.
_EXPECTED = (OSError, ForensicAULError, ValueError, sqlite3.Error)

# Displayed columns: (row key, header label). Keys match IdentifyResults.rows()'s
# aliased column names (see ops/identify/results.py: _ROWS_COLUMNS).
COLUMNS: list[tuple[str, str]] = [
    ("timestamp", "Timestamp"),
    # new_template / new_values / repeat — which lines to read first (diff.py).
    ("tier", "Tier"),
    ("process", "Process"),
    ("pid", "PID"),
    ("log_level", "Level"),
    ("subsystem", "Subsystem"),
    ("category", "Category"),
    ("matched_signatures", "Matched"),
    ("message", "Message"),
]


class IdentifyResultsController:
    """Logic for the Identify results view (``show_result``, ``render_results``)."""

    def __init__(self, view: Any, recents: RecentStore) -> None:
        self._view = view
        self._recents = recents
        self.store: IdentifyResults | None = None
        self.source: ResultsRowSource | None = None

    def open(self, path: str) -> None:
        if not path:
            self._view.show_result(False, "Choose a results database to open.")
            return
        try:
            store = IdentifyResults(Path(path))
        except _EXPECTED as exc:
            self._view.show_result(False, f"Could not open {Path(path).name}: {exc}")
            return
        self.close()
        self.store = store
        # Record the open so the DB reappears in the recents even when it was
        # produced elsewhere (another session, the CLI).
        self._recents.add("identify", path, f"{store.count()} retained")
        self.source = ResultsRowSource(store)
        self._view.render_results(self.source)

    def close(self) -> None:
        if self.store is not None:
            self.store.close()
            self.store = None

    def counts(self) -> Any:
        return self.store.counts() if self.store is not None else None

    def hidden_keys(self) -> list[Any]:
        return self.store.hidden_keys() if self.store is not None else []

    def hide(self, row: Mapping[str, Any]) -> bool:
        """Hide every line identical to *row*; False (and said why) when impossible."""
        if self.store is None:
            return False
        # A NULL-message row has no identical-lines key; the store would raise
        # (hidden_keys.message is NOT NULL) — tell the analyst instead.
        if row.get("message") is None:
            self._view.show_result(False, "This row has no message — nothing to hide by.")
            return False
        self.store.hide(row.get("message"), row.get("process"))
        return True

    def unhide(self, message: str, process: str) -> None:
        if self.store is not None:
            self.store.unhide(message, process or None)

    def export_csv(self, path: Path) -> None:
        if self.store is None:
            return
        try:
            count = self.store.export_csv(
                path,
                include_noise=self.source.include_noise if self.source else False,
                include_kb_known=self.source.include_kb_known if self.source else True,
            )
        except _EXPECTED as exc:
            self._view.show_result(False, f"Export failed: {exc}")
            return
        self._view.show_result(True, f"Exported {count} row(s) → {path.name}")


class ResultsRowSource:
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
        return list(COLUMNS)
