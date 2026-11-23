"""Unit tests for app/paths.py — where the application keeps its own files.

Covers : APP_ROOT (the folder holding faul.py) and app_data_dir (next to the app,
         git-ignored).
Uses    : the repository layout and .gitignore.
"""

from __future__ import annotations

import subprocess

from app import paths


def test_app_root_is_the_folder_holding_the_launcher():
    assert (paths.APP_ROOT / "faul.py").is_file()


def test_app_data_dir_sits_next_to_the_app():
    assert paths.app_data_dir().parent == paths.APP_ROOT


def test_app_data_dir_is_git_ignored():
    # WHY: it holds settings, recents and crash reports with case paths in them —
    # committing it by accident would publish case data.
    probe = paths.app_data_dir() / "settings.json"
    result = subprocess.run(
        ["git", "check-ignore", "-q", str(probe)], cwd=paths.APP_ROOT, check=False,
    )
    assert result.returncode == 0, f"{probe} must be git-ignored"
