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
from gui.views.screens_data import ExportScreen, VerifyHashScreen  # noqa: E402


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


# ── VerifyHash / Export: G7 — error surfacing must not leak internals or drop
# detail, and a result row must not be mislabelled by a mid-run edit ────────────

def _stub_run_task(screen):
    """Replace the screen's off-thread host with a recorder; return the call list.

    Mirrors test_gui_pipeline.py's helper — the real op is never invoked, tests
    drive ``task`` / ``on_finished`` / ``on_failed`` directly instead.
    """
    calls: list[tuple] = []

    def record(task, on_finished, on_failed=None):
        calls.append((task, on_finished, on_failed))

    screen.run_task = record  # type: ignore[method-assign]
    return calls


def test_verify_hash_row_uses_name_captured_at_dispatch_time(qapp, tmp_path):
    """The result row previously read ``self._file.path()`` *after* hashing
    finished, so editing the field mid-run mislabelled the row. The name must
    be captured when _start() dispatches, before the (possibly slow) hash runs."""
    vh = _verify()
    first = tmp_path / "first.bin"
    first.write_bytes(b"hello")
    vh._file.set_path(str(first))
    calls = _stub_run_task(vh)
    vh._start()
    assert len(calls) == 1
    task, on_finished, _on_failed = calls[0]

    # Simulate the analyst editing the field while the hash is still "running".
    vh._file.set_path(str(tmp_path / "second.bin"))

    computed = task()  # the real hashing function, run synchronously here
    on_finished(computed)
    assert vh._table.item(0, 0).text() == "first.bin", (
        "the row must be labelled with the file that was actually hashed"
    )


def test_verify_hash_failure_reason_is_not_discarded(qapp, tmp_path):
    """A VerifyHash failure previously showed an ERROR pill with the reason
    thrown away (``del last``). The reason must now survive, as a tooltip on
    the status pill — a bare ERROR gives an analyst nothing to act on."""
    from gui.widgets.components import Pill

    vh = _verify()
    vh._file.set_path(str(tmp_path / "missing.bin"))  # never created
    calls = _stub_run_task(vh)
    vh._start()
    _task, _on_finished, on_failed = calls[0]

    tb = (
        'Traceback (most recent call last):\n  File "x.py", line 1, in <module>\n'
        "FileNotFoundError: [Errno 2] No such file or directory: 'missing.bin'\n"
    )
    on_failed(tb)

    pill = vh._table.cellWidget(0, 3).findChild(Pill)
    assert pill is not None
    assert pill.toolTip(), "the failure reason must not be discarded"
    assert "missing.bin" in pill.toolTip()


def test_export_on_failed_uses_phrase_failure(qapp):
    """Export's failure path duplicated the raw last-line logic inline; it must
    go through the same GUI-phrasing map as the pipeline controllers."""
    exp = ExportScreen(SettingsStore(), RecentStore())
    captured: dict = {}
    exp.show_result = lambda ok, msg: captured.update(ok=ok, msg=msg)

    tb = (
        'Traceback (most recent call last):\n  File "x.py", line 1, in <module>\n'
        "FileNotFoundError: /nope.db is not a file\n"
    )
    exp._on_failed(tb)
    assert captured == {"ok": False, "msg": "File not found — /nope.db is not a file"}


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
