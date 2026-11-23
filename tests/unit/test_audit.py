"""Unit tests for the audited (evidence) extract — forensic_aul/ops/extraction/audit.py.

Covers : run_extract with ExtractOptions(audit_log=True): the case identifiers are
         required before anything is written; the log is sealed into case_metadata
         on success AND on cancellation (into the .partial); the seal never
         conjures a final database; only forensic_aul records reach the file; the
         library's logger level is restored afterwards.
Uses    : tests/synthetic.py (a tiny sysdiagnose), the public forensic_aul API.
"""

from __future__ import annotations

import hashlib
import logging
import sqlite3
from pathlib import Path

import pytest

from forensic_aul import (
    CaseInfo,
    CaseInfoError,
    ExtractOptions,
    OperationCancelled,
    run_extract,
)
from forensic_aul.engine.utils.cancellation import CancelToken
from tests.synthetic import synthetic_sysdiagnose

_CASE = CaseInfo(case_number="C1", imei="350000000000000")
_AUDITED = ExtractOptions(integrity="off", audit_log=True)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _stored_seal(db: Path) -> tuple[str | None, str | None]:
    conn = sqlite3.connect(db)
    try:
        return conn.execute("SELECT log_file_path, log_file_sha256 FROM case_metadata").fetchone()
    finally:
        conn.close()


def test_success_seals_the_log_into_the_database(tmp_path):
    db = tmp_path / "case.db"
    result = run_extract(synthetic_sysdiagnose(tmp_path), db, _CASE, _AUDITED)

    assert result.log_path == tmp_path / "C1-AUL-350000000000000.log"
    assert result.log_sha256 == _sha256(result.log_path)
    assert _stored_seal(db) == (str(result.log_path), result.log_sha256)
    assert "extract session started" in result.log_path.read_text(encoding="utf-8")


def test_cancellation_seals_into_the_partial_and_names_it(tmp_path):
    db = tmp_path / "case.db"
    token = CancelToken()

    def cancel_at_ordering(event) -> None:
        if event.phase == "ordering":
            token.cancel()

    with pytest.raises(OperationCancelled):
        run_extract(synthetic_sysdiagnose(tmp_path), db, _CASE, _AUDITED,
                    progress=cancel_at_ordering, cancel=token)

    partial = tmp_path / "case.db.partial"
    log_file = tmp_path / "C1-AUL-350000000000000.log"
    assert not db.exists(), "sealing must never conjure a file at the final name"
    assert str(partial) in log_file.read_text(encoding="utf-8")
    assert _stored_seal(partial) == (str(log_file), _sha256(log_file))


@pytest.mark.parametrize("case, missing", [
    (CaseInfo(imei="350000000000000"), ("case_number",)),
    (CaseInfo(case_number="C1", imei="  "), ("imei",)),
])
def test_missing_case_fields_are_refused_before_anything_is_written(tmp_path, case, missing):
    with pytest.raises(CaseInfoError) as caught:
        run_extract(synthetic_sysdiagnose(tmp_path), tmp_path / "out" / "case.db", case, _AUDITED)
    assert caught.value.missing == missing
    assert not (tmp_path / "out").exists()


def test_without_audit_no_case_fields_are_needed(tmp_path):
    result = run_extract(synthetic_sysdiagnose(tmp_path), tmp_path / "case.db",
                         opts=ExtractOptions(integrity="off"))
    assert result.log_path is None and not list(tmp_path.glob("*.log"))


def test_only_library_records_reach_the_audit_log(tmp_path):
    """A host library logging during the run must not land in the evidence log."""
    library = logging.getLogger("forensic_aul")
    level_before = library.level

    def host_noise(_event) -> None:
        logging.getLogger("some_host_library").warning("HOST-NOISE")

    result = run_extract(synthetic_sysdiagnose(tmp_path), tmp_path / "case.db", _CASE,
                         _AUDITED, progress=host_noise)

    assert "HOST-NOISE" not in result.log_path.read_text(encoding="utf-8")
    assert library.level == level_before, "the library's logger level must be restored"
    assert not any(isinstance(h, logging.FileHandler) for h in library.handlers)
