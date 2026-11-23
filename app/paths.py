"""Where the frontends keep their own files (settings, recents, crash reports).

Defines : APP_ROOT (the application's own folder — the clone holding faul.py) and
          app_data_dir (``<APP_ROOT>/app_data``, git-ignored).
Used by : app/diagnostics/store.py (crash and bug reports), app/diagnostics/redact.py
          (APP_ROOT, to render paths relative to the app), gui/settings_store.py,
          gui/recent_store.py.
Uses    : the standard library only (pathlib).

WHY next to the app and not in a per-user system folder (Application Support,
%APPDATA%, ~/.config): the operator must be able to see, copy and delete what the
tool writes, without knowing a platform convention. fAUL is clone-and-run, so its
folder is writable and belongs to the operator who cloned it.
"""

from __future__ import annotations

from pathlib import Path

# WHY parents[1]: this file is <APP_ROOT>/app/paths.py.
APP_ROOT = Path(__file__).resolve().parents[1]

# The folder name is git-ignored (.gitignore); rename both together.
_APP_DATA_DIR_NAME = "app_data"


def app_data_dir() -> Path:
    """The folder for the application's own files (not created here).

    Pure: no file-system side effect, so it is safe to call at import time.
    """
    return APP_ROOT / _APP_DATA_DIR_NAME
