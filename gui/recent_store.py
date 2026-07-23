"""Recently-used paths, persisted to disk.

Defines : RecentStore — records the real paths a user has acquired / extracted /
          exported, so each pipeline step can offer a "recently opened" list that
          reflects actual prior work (never fabricated samples).
Used by : gui.views.screens_pipeline / gui.views.screens_data (display + record),
          gui.app (construct the single shared store).
Uses    : json, pathlib, datetime. No business-logic or PySide imports.

WHY a real store (not sample data): this is a forensic tool — showing invented
case rows in the UI would be misleading. The mockup's sample "recent" lists are
replaced here by genuine, locally-recorded history, gated for display by the
``recentDb`` preference in :mod:`gui.settings_store`.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

_LOG = logging.getLogger(__name__)

# Where history lives, beside settings.json. Consumed by: RecentStore.
_RECENTS_PATH = Path.home() / ".config" / "faul" / "recents.json"

# Keep at most this many entries per category — the mockup shows "last 3"; we
# retain a few more for the dropdown. Consumed by: RecentStore.add.
_MAX_PER_KEY = 8


class RecentStore:
    """Per-category lists of recently-used paths (most-recent first)."""

    def __init__(self) -> None:
        self._data: dict[str, list[dict[str, str]]] = {}
        self._load()

    def add(self, key: str, path: str, meta: str = "") -> None:
        """Record *path* under *key* with a short *meta* string, de-duplicated."""
        entries = [e for e in self._data.get(key, []) if e.get("path") != path]
        entries.insert(0, {
            "path": path,
            "meta": meta,
            "ts": datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M"),
        })
        self._data[key] = entries[:_MAX_PER_KEY]
        self._save()

    def get(self, key: str) -> list[dict[str, str]]:
        return list(self._data.get(key, []))

    # ── Persistence (best-effort, never raises) ─────────────────────────────────

    def _load(self) -> None:
        try:
            raw = json.loads(_RECENTS_PATH.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except (OSError, ValueError) as exc:
            _LOG.warning(f"Could not read recents ({exc}); starting empty.")
            return
        if isinstance(raw, dict):
            self._data = {k: v for k, v in raw.items() if isinstance(v, list)}

    def _save(self) -> None:
        try:
            _RECENTS_PATH.parent.mkdir(parents=True, exist_ok=True)
            _RECENTS_PATH.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
        except OSError as exc:
            _LOG.warning(f"Could not write recents to {_RECENTS_PATH}: {exc}")
