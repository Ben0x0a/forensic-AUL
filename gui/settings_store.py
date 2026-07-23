"""Workstation display preferences, persisted to disk.

Defines : SettingsStore — a tiny QObject that holds the user-facing display
          preferences (recent-DB list visibility, preferred timezone, reduce-motion)
          and persists them to ``~/.config/faul/settings.json``. Emits ``changed``
          whenever a value is set, for any screen that wants to react live.
Used by : gui.views.screens.* (read prefs), gui.app (construct the single shared
          store).
Uses    : PySide6 (QObject/Signal), json, pathlib. No business-logic imports.

WHY a dedicated store (not scattered globals): the mockup keeps a single
``window.__faulSettings`` object persisted to localStorage; this is the native
equivalent — one source of truth, one persisted file, one change signal — so any
screen reads the same values and the window re-themes from one place.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from PySide6.QtCore import QObject, Signal

_LOG = logging.getLogger(__name__)

# Where preferences live. The mockup's About/Settings copy references this exact
# path, so we honour it. Consumed by: SettingsStore.load/_save.
_SETTINGS_PATH = Path.home() / ".config" / "faul" / "settings.json"

# Workstation display preferences. FAUL ships a single dark theme, so there is no
# appearance/mode key. Consumed by: SettingsStore.__init__.
_DEFAULTS: dict[str, object] = {
    "recentDb": True,          # show the "recent databases" list atop pipeline steps
    "tz": "utc",               # "utc" | "local" | "raw" — timestamp rendering
    "reduceMotion": False,     # suppress non-essential transitions
}

# The keys SettingsStore will persist. Anything outside this set is ignored on
# load so a stray/edited file cannot inject unknown state. Consumed by: load().
_KNOWN_KEYS = frozenset(_DEFAULTS)


class SettingsStore(QObject):
    """Holds display preferences and persists them to ``settings.json``.

    Read values with :meth:`get`; write with :meth:`set` (which persists and
    emits :data:`changed`). The store never raises on I/O problems — a missing
    or corrupt file falls back to defaults, because a forensic tool must still
    open when its (non-essential) preferences file is unreadable.
    """

    changed = Signal(str, object)  # (key, new_value)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._values: dict[str, object] = dict(_DEFAULTS)
        self.load()

    # ── Read / write ──────────────────────────────────────────────────────────

    def get(self, key: str) -> object:
        return self._values.get(key, _DEFAULTS.get(key))

    def set(self, key: str, value: object) -> None:
        # Ignore no-op writes so we don't churn the file or fire spurious signals.
        if self._values.get(key) == value:
            return
        self._values[key] = value
        self._save()
        self.changed.emit(key, value)

    # ── Persistence ─────────────────────────────────────────────────────────────

    def load(self) -> None:
        """Merge any on-disk values over the defaults (best-effort, never raises)."""
        try:
            raw = json.loads(_SETTINGS_PATH.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except (OSError, ValueError) as exc:
            # WHY warn-not-raise: preferences are non-essential; a corrupt file
            # must not stop the GUI from opening. Defaults stand in.
            _LOG.warning(f"Could not read settings ({exc}); using defaults.")
            return
        if isinstance(raw, dict):
            for key, value in raw.items():
                if key in _KNOWN_KEYS:
                    self._values[key] = value

    def _save(self) -> None:
        try:
            _SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
            _SETTINGS_PATH.write_text(
                json.dumps(self._values, indent=2), encoding="utf-8"
            )
        except OSError as exc:
            _LOG.warning(f"Could not write settings to {_SETTINGS_PATH}: {exc}")

    @property
    def path(self) -> Path:
        return _SETTINGS_PATH
