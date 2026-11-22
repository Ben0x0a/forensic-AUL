"""Unit tests for app/paths.py — the per-user application directory.

Covers : app_data_dir (platform conventions) and adopt_legacy_app_dir (the
         one-time move of ~/.config/faul, which must never overwrite or merge).
Uses    : monkeypatch on sys.platform, the environment and the module's home paths.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from app import paths


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(paths, "_LEGACY_DIR", tmp_path / ".config" / "faul")
    monkeypatch.delenv("APPDATA", raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    return tmp_path


@pytest.mark.parametrize("platform, expected", [
    ("darwin", Path("Library/Application Support/faul")),
    ("win32", Path("AppData/Roaming/faul")),
    ("linux", Path(".config/faul")),
])
def test_app_data_dir_follows_the_platform_convention(home, monkeypatch, platform, expected):
    monkeypatch.setattr(sys, "platform", platform)
    assert paths.app_data_dir() == home / expected


def test_app_data_dir_honours_appdata_and_xdg(home, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("APPDATA", str(home / "roam"))
    assert paths.app_data_dir() == home / "roam" / "faul"
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / "xdg"))
    assert paths.app_data_dir() == home / "xdg" / "faul"


def test_legacy_directory_is_moved_once(home, monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    legacy = home / ".config" / "faul"
    legacy.mkdir(parents=True)
    (legacy / "settings.json").write_text("{}", encoding="utf-8")

    paths.adopt_legacy_app_dir()

    assert not legacy.exists()
    assert (paths.app_data_dir() / "settings.json").read_text(encoding="utf-8") == "{}"


def test_legacy_directory_never_overwrites_an_existing_one(home, monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    legacy = home / ".config" / "faul"
    legacy.mkdir(parents=True)
    (legacy / "settings.json").write_text("old", encoding="utf-8")
    current = paths.app_data_dir()
    current.mkdir(parents=True)
    (current / "settings.json").write_text("new", encoding="utf-8")

    paths.adopt_legacy_app_dir()

    assert (legacy / "settings.json").read_text(encoding="utf-8") == "old"
    assert (current / "settings.json").read_text(encoding="utf-8") == "new"
