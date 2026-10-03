"""Headless tests for the Identify results viewer (screen + RowSource adapter).

Builds a real diff DB with ``run_diff`` over synthetic extract DBs (the fixture
approach of tests/unit/test_identify_results.py), then drives the screen:

- the model row count tracks the store's filtered rows; fetchMore loads them all;
- the noise / KB-known toggles widen the visible set;
- the "Hide identical lines" context action prunes matching rows and bumps the
  hidden count; unhiding from the rules panel restores them;
- the Export button writes a CSV (the save dialog is monkeypatched);
- prefill navigation lands in TABLE state; no prefill shows OPEN state.

Skipped automatically if PySide6 is unavailable.
"""

from __future__ import annotations

import gc
import os
import sqlite3

import re

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")

from PySide6.QtCore import QModelIndex  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

import gui.recent_store as recent_store  # noqa: E402
import gui.settings_store as settings_store  # noqa: E402
import gui.views.screen_identify_results as results_mod  # noqa: E402
from forensic_aul.engine.database.schema import apply_pragmas, init_schema  # noqa: E402
from forensic_aul.ops.annotation.matcher import init_annotation_schema  # noqa: E402
from forensic_aul.ops.identify.diff import run_diff  # noqa: E402
from gui.recent_store import RecentStore  # noqa: E402
from gui.settings_store import SettingsStore  # noqa: E402
from gui.views.screen_identify_results import IdentifyResultsScreen  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture(autouse=True)
def _tmp_config(tmp_path, monkeypatch):
    monkeypatch.setattr(settings_store, "_SETTINGS_PATH", tmp_path / "settings.json")
    monkeypatch.setattr(recent_store, "_RECENTS_PATH", tmp_path / "recents.json")


def _db(path, rows) -> None:
    """rows: list of (unix_ns, message, process_name)."""
    conn = sqlite3.connect(str(path))
    apply_pragmas(conn)
    init_schema(conn)
    procs = {name for _, _, name in rows}
    pid_of = {name: i + 1 for i, name in enumerate(sorted(procs))}
    for name, pid in pid_of.items():
        conn.execute("INSERT INTO processes(id, name) VALUES (?, ?)", (pid, name))
    for i, (ns, msg, proc) in enumerate(rows, 1):
        conn.execute(
            "INSERT INTO logs(id, timestamp_unix_ns, timestamp_mach, message, process_id) "
            "VALUES (?,?,?,?,?)",
            (i, ns, ns, msg, pid_of[proc]),
        )
    conn.commit()
    conn.close()


def _build_diff_db(tmp_path, *, with_kb=False):
    """Same shape as test_identify_results: one noise, one retained, one KB-known."""
    _db(tmp_path / "base.db", [(100, "boot", "p1")])
    action_path = tmp_path / "act.db"
    _db(action_path, [
        (300, "boot", "p1"),                  # baseline noise -> excluded
        (300, "user tapped Camera", "p2"),    # kb-known if with_kb
        (400, "background chatter", "p2"),    # retained
    ])
    if with_kb:
        conn = sqlite3.connect(str(action_path))
        init_annotation_schema(conn)
        conn.execute(
            "INSERT INTO kb_signatures (id, signature_id, action, kb_version, "
            "kb_sha256, applied_at) VALUES (1, 'sig.tap', 'tapped', '1.0.0', "
            "'deadbeef', '2026-01-01T00:00:00Z')"
        )
        log_id = conn.execute(
            "SELECT id FROM logs WHERE message = 'user tapped Camera'"
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO log_annotations (log_id, kb_signature_id) VALUES (?, 1)", (log_id,)
        )
        conn.commit()
        conn.close()
    sqlite_out = tmp_path / "case-identified.db"
    run_diff(tmp_path / "base.db", action_path, None, sqlite_out)
    return sqlite_out


# Screens created during a test are kept alive here and their DB connections
# closed in teardown: an IdentifyResultsScreen holds an open sqlite connection via
# its model's RowSource, and letting Python GC a screen (and its Qt model) mid-run
# under offscreen Qt can segfault. Keeping strong refs avoids the GC race.
_LIVE_SCREENS: list[IdentifyResultsScreen] = []


@pytest.fixture(autouse=True)
def _cleanup_screens():
    yield
    # Destroy the widgets FIRST (the view can still poke the model's RowSource
    # while being torn down), and flush the deletions NOW so the C++ teardown
    # happens inside this module, not mid-way through whichever Qt test runs
    # next — that deferred teardown was a reliable cross-module segfault.
    for screen in _LIVE_SCREENS:
        screen.deleteLater()
    QApplication.processEvents()
    gc.collect()
    # Only then release the stores the (now destroyed) models were reading.
    for screen in _LIVE_SCREENS:
        if screen._store is not None:
            screen._store.close()
    _LIVE_SCREENS.clear()


def _make_screen() -> IdentifyResultsScreen:
    screen = IdentifyResultsScreen(SettingsStore(), RecentStore())
    _LIVE_SCREENS.append(screen)
    return screen


def _load_all(model) -> int:
    """Force the model to fetch every batch; return the final row count."""
    while model.canFetchMore(QModelIndex()):
        model.fetchMore(QModelIndex())
    return model.rowCount()


# ── State ───────────────────────────────────────────────────────────────────────

def test_no_prefill_shows_open_state(qapp):
    screen = _make_screen()
    assert screen._open_panel.isVisibleTo(screen)
    assert not screen.is_table_state()


def test_prefill_lands_in_table_state(qapp, tmp_path):
    db = _build_diff_db(tmp_path)
    screen = _make_screen()
    screen.prefill({"db": str(db)})
    assert screen.is_table_state()
    assert not screen._open_panel.isVisibleTo(screen)


# ── Model ↔ store ─────────────────────────────────────────────────────────────

def test_model_count_matches_store_default_flags(qapp, tmp_path):
    db = _build_diff_db(tmp_path, with_kb=True)
    screen = _make_screen()
    screen.prefill({"db": str(db)})
    # Default flags: noise off, kb-known off → only "background chatter".
    assert _load_all(screen._model) == 1


def test_noise_toggle_adds_excluded_rows(qapp, tmp_path):
    db = _build_diff_db(tmp_path, with_kb=False)
    screen = _make_screen()
    screen.prefill({"db": str(db)})
    assert _load_all(screen._model) == 2  # tapped + chatter (no KB, so both retained)
    screen._noise_check.setChecked(True)
    assert _load_all(screen._model) == 3  # + boot (baseline noise)


def test_kb_toggle_adds_kb_known_rows(qapp, tmp_path):
    db = _build_diff_db(tmp_path, with_kb=True)
    screen = _make_screen()
    screen.prefill({"db": str(db)})
    assert _load_all(screen._model) == 1  # only "background chatter"
    screen._kb_check.setChecked(True)
    assert _load_all(screen._model) == 2  # + "user tapped Camera"


# ── Hide / unhide ─────────────────────────────────────────────────────────────

def test_hide_identical_lines_prunes_and_bumps_hidden(qapp, tmp_path):
    db = _build_diff_db(tmp_path, with_kb=False)
    screen = _make_screen()
    screen.prefill({"db": str(db)})
    before = _load_all(screen._model)
    screen._hide_row({"message": "background chatter", "process": "p2"})
    after = _load_all(screen._model)
    assert after == before - 1
    assert screen._store.counts().hidden == 1
    assert "(1)" in screen._hidden_btn.text()


def test_unhide_from_rules_panel_restores(qapp, tmp_path):
    db = _build_diff_db(tmp_path, with_kb=False)
    screen = _make_screen()
    screen.prefill({"db": str(db)})
    screen._hide_row({"message": "background chatter", "process": "p2"})
    assert _load_all(screen._model) == 1
    screen._unhide("background chatter", "p2")
    assert _load_all(screen._model) == 2
    assert screen._store.counts().hidden == 0


# ── Export ────────────────────────────────────────────────────────────────────

def test_export_button_writes_csv(qapp, tmp_path, monkeypatch):
    db = _build_diff_db(tmp_path, with_kb=True)
    screen = _make_screen()
    screen.prefill({"db": str(db)})
    out = tmp_path / "export.csv"
    monkeypatch.setattr(
        results_mod.QFileDialog, "getSaveFileName",
        staticmethod(lambda *a, **k: (str(out), "")),
    )
    screen._export_csv()
    assert out.is_file()
    text = out.read_text(encoding="utf-8-sig")
    # KB-known is included by default in export_csv, noise excluded.
    assert "background chatter" in text
    assert "boot" not in text


# ── Signature authoring dialog ──────────────────────────────────────────────────

def _kb_copy(tmp_path):
    """A writable copy of the shipped knowledge base."""
    import shutil
    from gui.paths import DEFAULT_KB_DIR

    dest = tmp_path / "kb"
    shutil.copytree(DEFAULT_KB_DIR, dest)
    return dest


def _sample_row():
    return {
        "message": "Associated to HomeNet with bssid aa:bb:cc:dd:ee:ff",
        "process": "wifid",
        "subsystem": "com.apple.wifi",
        "category": "manager",
        "log_level": "Default",
    }


def test_dialog_prefills_from_the_row(qapp, tmp_path):
    from gui.views.dialog_signature import SignatureDialog

    dialog = SignatureDialog(_sample_row(), kb_dir=_kb_copy(tmp_path))
    # The pattern is escaped, so it matches this line and only this line.
    assert dialog._regex.text() == re.escape(_sample_row()["message"])
    assert dialog._id.text().startswith("wifid.")
    # Process is pre-selected as the narrowing constraint; the rest are offered.
    assert dialog._constraints["process"].isChecked()
    assert not dialog._constraints["category"].isChecked()
    dialog.deleteLater()


def test_dialog_preview_round_trips_through_the_loader(qapp, tmp_path):
    """What the preview shows must be what the knowledge base can load."""
    from forensic_aul.ops.knowledge_base.loader import load_kb
    from gui.views.dialog_signature import SignatureDialog

    kb_dir = _kb_copy(tmp_path)
    dialog = SignatureDialog(_sample_row(), kb_dir=kb_dir)
    dialog._id.setText("net.wifi_join")
    dialog._action.setText("Device joined a Wi-Fi network")
    dialog._interpretation.setText("The device was in range of this SSID.")
    assert "net.wifi_join" in dialog._preview.toPlainText()

    dialog._on_save()
    assert dialog.written_path() is not None
    sig = next(s for s in load_kb(kb_dir).signatures if s.id == "net.wifi_join")
    assert sig.action == "Device joined a Wi-Fi network"
    assert sig.interpretation == "The device was in range of this SSID."
    assert sig.status == "draft"          # authored interactively, not yet reviewed
    assert sig.match.process == "wifid"
    dialog.deleteLater()


@pytest.mark.parametrize("bad_id", ["", "Net.WiFi", "9lives!", "-leading"])
def test_dialog_refuses_a_bad_id(qapp, tmp_path, bad_id):
    from gui.views.dialog_signature import SignatureDialog

    dialog = SignatureDialog(_sample_row(), kb_dir=_kb_copy(tmp_path))
    dialog._action.setText("x")
    dialog._id.setText(bad_id)
    assert "id" in dialog._status.text().lower()
    dialog.deleteLater()


def test_dialog_refuses_an_uncompilable_pattern(qapp, tmp_path):
    from gui.views.dialog_signature import SignatureDialog

    dialog = SignatureDialog(_sample_row(), kb_dir=_kb_copy(tmp_path))
    dialog._id.setText("net.ok")
    dialog._action.setText("x")
    dialog._regex.setText("unbalanced (")
    assert "compile" in dialog._status.text()
    dialog.deleteLater()


def test_dialog_refuses_to_overwrite_an_existing_signature(qapp, tmp_path):
    from gui.views.dialog_signature import SignatureDialog

    kb_dir = _kb_copy(tmp_path)
    (kb_dir / "signatures" / "net.taken.yaml").write_text("signatures: []\n", encoding="utf-8")
    dialog = SignatureDialog(_sample_row(), kb_dir=kb_dir)
    dialog._action.setText("x")
    dialog._id.setText("net.taken")
    assert "already exists" in dialog._status.text()
    dialog.deleteLater()


def test_dialog_test_button_counts_matches_on_screen(qapp, tmp_path):
    from gui.views.dialog_signature import SignatureDialog

    rows = [_sample_row(), {"message": "Associated to CafeWiFi with bssid 11:22:33:44:55:66"},
            {"message": "something else entirely"}]
    dialog = SignatureDialog(rows[0], sample_rows=rows, kb_dir=_kb_copy(tmp_path))
    dialog._regex.setText(r"Associated to \S+ with bssid")
    dialog._on_test()
    assert "2" in dialog._status.text() and "3" in dialog._status.text()
    # The wording must not imply it searched the whole database.
    assert "not the whole database" in dialog._status.text()
    dialog.deleteLater()
