"""Headless tests for gui.widgets.path_picker.PathPicker.

Covers review item G6: the Extract source field needed to browse to either a
file (.tar.gz / .faul / .zip) or a directory (.logarchive) — no single native
file dialog can return both a file and a directory pick — so PathPicker gained
an ``"any"`` mode offering two explicit Browse affordances instead of one
ambiguous button.

Skipped automatically if PySide6 is unavailable (it is an optional extra).
"""

from __future__ import annotations

import os

import pytest

# Qt must run head-less in CI / on a build box — set before importing PySide6.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication, QFileDialog, QPushButton  # noqa: E402

from gui.widgets.path_picker import PathPicker  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    """A single QApplication for the module (Qt allows only one per process)."""
    app = QApplication.instance() or QApplication([])
    yield app


def _button_texts(picker: PathPicker) -> list[str]:
    return [b.text() for b in picker.findChildren(QPushButton)]


def test_invalid_mode_still_rejected(qapp):
    with pytest.raises(ValueError):
        PathPicker("nonsense")


def test_file_mode_has_a_single_browse_button(qapp):
    picker = PathPicker("file")
    assert _button_texts(picker) == ["Browse…"]


def test_dir_mode_has_a_single_browse_button(qapp):
    picker = PathPicker("dir")
    assert _button_texts(picker) == ["Browse…"]


def test_any_mode_offers_two_explicit_affordances(qapp):
    picker = PathPicker("any")
    assert set(_button_texts(picker)) == {"File…", "Folder…"}, (
        "a single ambiguous Browse… cannot return both a file and a directory pick"
    )


def test_any_mode_folder_browse_sets_path(qapp, monkeypatch, tmp_path):
    picker = PathPicker("any")
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *a, **k: str(tmp_path))
    picker._browse_dir()
    assert picker.path() == str(tmp_path)


def test_any_mode_file_browse_sets_path(qapp, monkeypatch, tmp_path):
    picker = PathPicker("any")
    target = tmp_path / "sysdiagnose.tar.gz"
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (str(target), ""))
    picker._browse_file()
    assert picker.path() == str(target)


def test_any_mode_cancelled_dialog_leaves_path_unchanged(qapp, monkeypatch):
    picker = PathPicker("any")
    picker.set_path("/existing/path")
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *a, **k: "")
    picker._browse_dir()
    assert picker.path() == "/existing/path"
