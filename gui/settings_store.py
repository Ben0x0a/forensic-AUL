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

# Workstation preferences. FAUL ships a single dark theme, so there is no
# appearance/mode key. Every key here MUST have a consumer — a preference that
# changes nothing is worse than no preference, because it tells the analyst the
# tool behaves in a way it does not. Consumed by: SettingsStore.__init__.
_DEFAULTS: dict[str, object] = {
    # Interface
    "recentDb": True,          # show the "recent databases" list atop pipeline steps
    "tz": "utc",               # "utc" | "local" | "raw" — timestamp rendering
    "recentsLimit": 5,         # how many entries each recents list keeps
    # Exploit / analysis
    "contextSize": 20,         # rows either side of a line in "view context"
    "rowCap": 5_000,           # most rows the analysis table will materialise
    # Paths & pipeline defaults
    "kbPath": "",              # knowledge base directory ("" = the shipped one)
    "extractJobs": 0,          # default --jobs for Extract (0 = auto/one per core)
}

# Bounds for the integer preferences, so a hand-edited settings.json cannot put a
# nonsensical value into a spin box or make the analysis table try to materialise
# ten million rows. Consumed by: get_int.
_INT_BOUNDS: dict[str, tuple[int, int]] = {
    "recentsLimit": (1, 50),
    "contextSize": (1, 500),
    "rowCap": (1, 1_000_000),
    "extractJobs": (0, 256),
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

    def get_int(self, key: str) -> int:
        """Read *key* as an int, coerced and clamped to its allowed range.

        WHY coerce: values come back from JSON a user can hand-edit, so a string
        or a float can reach a spin box's setValue and raise. Falling back to the
        default keeps a mistyped preferences file from breaking a screen.
        """
        try:
            value = int(self._values.get(key, _DEFAULTS.get(key)))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            value = int(_DEFAULTS.get(key, 0))  # type: ignore[arg-type]
        low, high = _INT_BOUNDS.get(key, (None, None))
        if low is not None:
            value = max(low, min(high, value))
        return value

    def get_str(self, key: str) -> str:
        """Read *key* as a string ("" when unset or of the wrong type)."""
        value = self._values.get(key, _DEFAULTS.get(key))
        return value if isinstance(value, str) else ""

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
