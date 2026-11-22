"""End-to-end tests of the ``extract`` command through the real CLI entry point.

Covers : launcher/cli.py (main) → launcher/cmds/extract_cmd.py (run) →
         app/extract_session.py (run_extract_session) → forensic_aul.run_extract,
         i.e. the exact path an operator's ``faul.py extract …`` takes.
Uses    : a synthetic sysdiagnose tarball (no real evidence), pytest's
          monkeypatch to isolate the global state the CLI installs.

WHY this file exists: each layer above had its own tests, but none drove them
together, so a keyword the CLI passed and the session did not accept
(``reset_work_dir``) crashed every ``extract`` run while the suite stayed green.
"""

from __future__ import annotations

import hashlib
import logging
import sqlite3
import sys
import threading
from pathlib import Path

import pytest

import app.diagnostics
from launcher import cli
from tests.synthetic import synthetic_sysdiagnose as _synthetic_sysdiagnose


@pytest.fixture
def isolated_cli(monkeypatch):
    """Undo the process-wide state ``cli.main`` installs (logging + crash hooks).

    The CLI replaces the root logger's handlers and chains ``sys.excepthook`` /
    ``threading.excepthook``; left in place they would leak into every later test.
    """
    root = logging.getLogger()
    saved_handlers, saved_level = list(root.handlers), root.level
    monkeypatch.setattr(sys, "excepthook", sys.excepthook)
    monkeypatch.setattr(threading, "excepthook", threading.excepthook)
    monkeypatch.setattr(app.diagnostics, "_installed", False)
    yield
    for handler in list(root.handlers):
        if handler not in saved_handlers:
            handler.close()
            root.removeHandler(handler)
    for handler in saved_handlers:
        if handler not in root.handlers:
            root.addHandler(handler)
    root.setLevel(saved_level)


def _run_cli(monkeypatch, *argv: str) -> int:
    """Run ``faul.py <argv>`` in-process and return its exit code."""
    monkeypatch.setattr(sys, "argv", ["faul.py", *argv])
    with pytest.raises(SystemExit) as exc_info:
        cli.main()
    return exc_info.value.code


def _extract_args(arc: Path, db: Path, *extra: str) -> list[str]:
    return [
        "extract", str(arc), "-o", str(db),
        "--case-number", "C1", "--imei", "350000000000000",
        "--integrity", "off", *extra,
    ]


def test_extract_cli_runs_end_to_end_and_seals_its_log(tmp_path, monkeypatch, isolated_cli):
    arc, db = _synthetic_sysdiagnose(tmp_path), tmp_path / "out" / "case.db"

    code = _run_cli(monkeypatch, *_extract_args(arc, db))

    assert code == 0
    assert db.is_file(), "a successful extract must leave the database at its final name"
    log_file = db.parent / "C1-AUL-350000000000000.log"
    # Sealed = the closed log's SHA-256 recorded in the evidence database.
    conn = sqlite3.connect(db)
    try:
        stored_path, stored_sha = conn.execute(
            "SELECT log_file_path, log_file_sha256 FROM case_metadata"
        ).fetchone()
    finally:
        conn.close()
    assert Path(stored_path) == log_file
    assert stored_sha == hashlib.sha256(log_file.read_bytes()).hexdigest()


def test_extract_cli_accepts_work_dir_reset(tmp_path, monkeypatch, isolated_cli):
    """``--work-dir`` + ``--reset-work-dir`` reach the pipeline (the original crash)."""
    arc, work = _synthetic_sysdiagnose(tmp_path), tmp_path / "work"

    first = _run_cli(monkeypatch, *_extract_args(arc, tmp_path / "a.db", "--work-dir", str(work)))
    # The kept work root now holds files, so a second run must be told to reset it.
    second = _run_cli(monkeypatch, *_extract_args(
        arc, tmp_path / "b.db", "--work-dir", str(work), "--reset-work-dir",
    ))

    assert (first, second) == (0, 0)
    assert (tmp_path / "b.db").is_file()
