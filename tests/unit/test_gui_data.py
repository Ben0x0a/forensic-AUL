"""Headless tests for the data screens (gui.views.screens_data).

Covers the Verify-hash acquisition-sidecar auto-fill: selecting a logarchive that
has a sibling ``.acquisition.json`` fills the expected SHA-256 (and selects the
sha256 algorithm), but never overwrites a digest the analyst already typed. Also
checks that combo popups get a consistent item size hint via ``style_combo``.

Skipped automatically if PySide6 is unavailable (it is an optional extra).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication  # noqa: E402

import gui.recent_store as recent_store  # noqa: E402
import gui.settings_store as settings_store  # noqa: E402
from gui.recent_store import RecentStore  # noqa: E402
from gui.settings_store import SettingsStore  # noqa: E402
from gui.views.screens_data import VerifyHashScreen  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture(autouse=True)
def _tmp_config(tmp_path, monkeypatch):
    monkeypatch.setattr(settings_store, "_SETTINGS_PATH", tmp_path / "settings.json")
    monkeypatch.setattr(recent_store, "_RECENTS_PATH", tmp_path / "recents.json")


def _verify():
    return VerifyHashScreen(SettingsStore(), RecentStore())


def _logarchive_with_sidecar(tmp_path, name: str, sha: str) -> Path:
    arc = tmp_path / name
    arc.mkdir()
    (arc.parent / (arc.name + ".acquisition.json")).write_text(
        json.dumps({"acquisition": {"logarchive_sha256": sha}}))
    return arc


def test_verify_autofills_expected_hash_from_sidecar(qapp, tmp_path):
    vh = _verify()
    arc = _logarchive_with_sidecar(tmp_path, "case.logarchive", "a" * 64)
    vh._file.set_path(str(arc))
    assert vh._expected.text() == "a" * 64
    assert vh._algo.currentData() == "sha256", "should match the sidecar's SHA-256"


def test_verify_does_not_overwrite_typed_expected_hash(qapp, tmp_path):
    vh = _verify()
    vh._expected.setText("deadbeef")  # analyst typed a value first
    arc = _logarchive_with_sidecar(tmp_path, "case.logarchive", "b" * 64)
    vh._file.set_path(str(arc))
    assert vh._expected.text() == "deadbeef"


def test_verify_no_sidecar_leaves_expected_empty(qapp, tmp_path):
    vh = _verify()
    plain = tmp_path / "plain.bin"
    plain.write_bytes(b"x")
    vh._file.set_path(str(plain))
    assert vh._expected.text() == ""


def test_combo_items_get_size_hint(qapp):
    from PySide6.QtCore import Qt

    vh = _verify()
    sizes = [vh._algo.itemData(i, Qt.ItemDataRole.SizeHintRole) for i in range(vh._algo.count())]
    assert all(s is not None and s.height() == 28 for s in sizes), "combo items need a uniform height hint"


def test_combo_popup_aligns_under_field(qapp):
    # The themed ComboBox forces its popup to the field's own left edge and width
    # (dropped just beneath it) so the drop-down lines up with the box instead of
    # overhanging left / leaving a sliver of the field on the right.
    from PySide6.QtCore import QPoint

    vh = _verify()
    vh._algo.resize(480, 32)
    vh._algo.show()
    vh._algo.showPopup()
    QApplication.processEvents()
    popup = vh._algo.view().window()
    assert popup.width() == vh._algo.width(), "popup width should match the field"
    assert popup.x() == vh._algo.mapToGlobal(QPoint(0, vh._algo.height())).x(), \
        "popup left edge should align with the field"
