"""Unit tests for the common error hierarchy and the analysis-database gate.

Covers: the ``ForensicAULError`` base (every purposeful library error must be
catchable through it), the backward-compatibility contract (new errors still
subclass the builtin types historically raised), and
``open_analysis_database`` — the shared entry gate that turns "file is not a
database" style failures into clear, typed errors for every path-based reader.
"""

from __future__ import annotations

import sqlite3

import pytest

from forensic_aul import (
    ForensicAULError,
    InvalidDatabaseError,
    SourceError,
    query_logs,
    run_export,
    summarise,
)
from forensic_aul.engine.database.access import open_analysis_database
from forensic_aul.ops.acquisition.acquire import AcquisitionAborted, AcquisitionError
from forensic_aul.ops.extraction.source import detect_source_type, prepare_source
from forensic_aul.ops.knowledge_base.loader import KnowledgeBaseError


# ── Hierarchy contracts ───────────────────────────────────────────────────────

class TestHierarchy:
    def test_every_library_error_derives_from_base(self):
        for err in (SourceError, InvalidDatabaseError, AcquisitionError,
                    AcquisitionAborted, KnowledgeBaseError):
            assert issubclass(err, ForensicAULError), err

    def test_backward_compatible_builtin_parents(self):
        # Existing `except ValueError` call sites must keep catching these.
        for err in (SourceError, InvalidDatabaseError, KnowledgeBaseError):
            assert issubclass(err, ValueError), err

    def test_source_errors_are_typed(self, tmp_path):
        with pytest.raises(SourceError):
            detect_source_type(tmp_path / "missing")
        bad = tmp_path / "junk.bin"
        bad.write_bytes(b"\x00\x01\x02\x03 not a container")
        with pytest.raises(SourceError):
            detect_source_type(bad)
        with pytest.raises(SourceError):
            prepare_source(bad)
        # …and remain catchable through the base.
        with pytest.raises(ForensicAULError):
            prepare_source(bad)


# ── open_analysis_database ────────────────────────────────────────────────────

def _make_analysis_db(path) -> None:
    from forensic_aul.engine.database.schema import init_schema

    conn = sqlite3.connect(str(path))
    init_schema(conn)
    conn.commit()
    conn.close()


class TestOpenAnalysisDatabase:
    def test_missing_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            open_analysis_database(tmp_path / "absent.db")

    def test_not_sqlite(self, tmp_path):
        junk = tmp_path / "junk.db"
        junk.write_bytes(b"this is definitely not sqlite" * 100)
        with pytest.raises(InvalidDatabaseError, match="not a SQLite database"):
            open_analysis_database(junk)

    def test_sqlite_without_logs_table(self, tmp_path):
        other = tmp_path / "other.db"
        conn = sqlite3.connect(str(other))
        conn.execute("CREATE TABLE unrelated (id INTEGER)")
        conn.commit()
        conn.close()
        with pytest.raises(InvalidDatabaseError, match="no `logs` table"):
            open_analysis_database(other)

    def test_valid_database_returns_open_connection(self, tmp_path):
        db = tmp_path / "case.db"
        _make_analysis_db(db)
        conn = open_analysis_database(db)
        try:
            assert conn.execute("SELECT COUNT(*) FROM logs").fetchone() == (0,)
        finally:
            conn.close()


# ── The gate is wired into the path-based readers ─────────────────────────────

class TestReadersUseGate:
    def test_query_logs_rejects_non_database(self, tmp_path):
        junk = tmp_path / "junk.db"
        junk.write_bytes(b"nope" * 100)
        with pytest.raises(InvalidDatabaseError):
            next(query_logs(junk))

    def test_run_export_rejects_non_database(self, tmp_path):
        junk = tmp_path / "junk.db"
        junk.write_bytes(b"nope" * 100)
        with pytest.raises(InvalidDatabaseError):
            run_export(junk, tmp_path / "out.csv")

    def test_summarise_rejects_non_database(self, tmp_path):
        junk = tmp_path / "junk.db"
        junk.write_bytes(b"nope" * 100)
        with pytest.raises(InvalidDatabaseError):
            summarise(junk)
