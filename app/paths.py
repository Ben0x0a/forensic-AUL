"""Where the frontends keep their own files (settings, recents, crash reports).

Defines : app_data_dir (the per-user application directory, platform convention)
          and adopt_legacy_app_dir (one-time move of the pre-2026-11 location).
Used by : app/diagnostics.py (crash reports), gui/settings_store.py,
          gui/recent_store.py, launcher/cli.py (calls adopt_legacy_app_dir once).
Uses    : the standard library only (os, sys, shutil, pathlib) — no platformdirs,
          by decision: three platform rules do not justify a dependency.

Conventions:
  macOS   ~/Library/Application Support/faul
  Windows %APPDATA%\\faul  (fallback ~/AppData/Roaming/faul)
  other   $XDG_CONFIG_HOME/faul  (fallback ~/.config/faul)
"""

from __future__ import annotations

import logging
import os
import shutil
import sys
from pathlib import Path

log = logging.getLogger(__name__)

_APP_DIR_NAME = "faul"
# Where every platform stored these files before this module existed.
_LEGACY_DIR = Path.home() / ".config" / _APP_DIR_NAME


def app_data_dir() -> Path:
    """The per-user directory for the application's own files (not created here).

    Pure: no file-system side effect, so it is safe to call at import time.
    """
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    elif sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        base = Path(appdata) if appdata else Path.home() / "AppData" / "Roaming"
    else:
        xdg = os.environ.get("XDG_CONFIG_HOME")
        base = Path(xdg) if xdg else Path.home() / ".config"
    return base / _APP_DIR_NAME


def adopt_legacy_app_dir() -> None:
    """Move the old ``~/.config/faul`` to :func:`app_data_dir` once, if needed.

    Only when the old directory exists, differs from the new one, and the new one
    does not exist yet — so it can never overwrite or merge anything. A failure
    is logged and the old files are left where they were.
    """
    target = app_data_dir()
    if target == _LEGACY_DIR or not _LEGACY_DIR.is_dir() or target.exists():
        return
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(_LEGACY_DIR), str(target))
    except OSError as exc:
        log.warning(f"Could not move {_LEGACY_DIR} to {target}: {exc}; it is left in place.")
        return
    log.info(f"Moved application files from {_LEGACY_DIR} to {target}")
