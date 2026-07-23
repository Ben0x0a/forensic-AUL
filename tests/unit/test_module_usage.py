"""Library-usage contract tests — exercise forensic_aul as an imported module.

Mirrors the documented usage flow (``from forensic_aul import run_extract,
prepare_source, load_kb, annotate_database`` …) and validates the path-based
``annotate_database`` so a database can be (re-)annotated *at will* without a
re-extract. The heavy ``run_extract`` end-to-end is covered by the integration
suite; here the analysis database is built synthetically so the test stays fast.
"""

from __future__ import annotations

import sqlite3

import pytest

from forensic_aul import annotate_connection, annotate_database
from forensic_aul.ops.knowledge_base.loader import load_kb
from forensic_aul.engine.database.schema import apply_pragmas, init_schema

# One signature that matches the synthetic row built below.
_KB_YAML = (
    "signatures:\n"
    "  - id: test.greeting\n"
    '    action: "A greeting was logged"\n'
    "    confidence: high\n"
    "    match:\n"
    '      format_str: "Hello %@"\n'
    "      process: greeter\n"
    "    extract-fields:\n"
    "      who: '(?P<who>\\w+)'\n"
    "    tags: [test, greeting]\n"
)


def _write_kb(root) -> None:
    """Create a minimal, valid knowledge base (VERSION + signatures/) at *root*."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "VERSION").write_text("1.0.0\n", encoding="utf-8")
    sigs = root / "signatures"
    sigs.mkdir()
    (sigs / "test.yaml").write_text(_KB_YAML, encoding="utf-8")


def _populate(conn: sqlite3.Connection) -> None:
    """Insert one matching log ('Hello world' from 'greeter') and one that won't."""
    conn.execute("INSERT INTO processes(id, name) VALUES (1, 'greeter')")
    conn.execute("INSERT INTO format_strs(id, value) VALUES (1, 'Hello %@')")
    conn.execute(
        "INSERT INTO logs(id, timestamp_unix_ns, timestamp_mach, "
        "message, process_id, format_str_id) VALUES (1, ?, ?, ?, 1, 1)",
        (1_705_320_001_000_000_000, 1000, "Hello world"),
    )
    conn.execute(
        "INSERT INTO logs(id, timestamp_unix_ns, timestamp_mach, message) "
        "VALUES (2, ?, ?, ?)",
        (1_705_320_002_000_000_000, 2000, "unrelated line"),
    )
    conn.commit()


def _make_extracted_db(path) -> None:
    conn = sqlite3.connect(str(path))
    apply_pragmas(conn)
    init_schema(conn)
    _populate(conn)
    conn.close()


@pytest.fixture
def kb(tmp_path):
    root = tmp_path / "kb"
    _write_kb(root)
    return load_kb(root)


# ── Public import surface ─────────────────────────────────────────────────────

def test_public_api_imports():
    # The exact import line a downstream app would use, plus the rest of __all__.
    from forensic_aul import (  # noqa: F401
        ExportFilters,
        KnowledgeBaseError,
        LogEntry,
        PreparedSource,
        SourceType,
        annotate_connection,
        annotate_database,
        compute_sha256,
        hash_logarchive,
        load_kb as _lk,
        prepare_source,
        query_logs,
        run_diff,
        run_export,
        run_extract,
    )

    for fn in (run_extract, prepare_source, _lk, annotate_database,
               annotate_connection, run_diff, run_export, query_logs,
               compute_sha256, hash_logarchive):
        assert callable(fn)


def test_run_extract_refuses_existing_db(tmp_path):
    """The overwrite guard fails fast (before touching the source) if db exists."""
    from forensic_aul import run_extract

    db = tmp_path / "exists.db"
    db.write_text("not empty", encoding="utf-8")
    # Source path need not exist: the guard is checked before source preparation.
    with pytest.raises(FileExistsError):
        run_extract(tmp_path / "no_such_source", db)


def test_all_names_are_resolvable():
    import forensic_aul as f
    for name in f.__all__:
        assert hasattr(f, name), f"{name} is in __all__ but not importable"


# ── annotate_database (path-based, "annotate at will") ────────────────────────

class TestAnnotateAtWill:
    def test_path_api_matches_and_extracts(self, tmp_path, kb):
        db = tmp_path / "case.db"
        _make_extracted_db(db)

        res = annotate_database(db, kb)
        assert res.counts == {"test.greeting": 1}
        assert res.total_matches == 1
        assert res.signatures_matched == 1
        assert res.db_path == db

        # Annotation persisted and re-openable without re-extracting.
        conn = sqlite3.connect(str(db))
        try:
            n = conn.execute("SELECT COUNT(*) FROM log_annotations").fetchone()[0]
            who = conn.execute(
                "SELECT value FROM extracted_values WHERE label = 'who' LIMIT 1"
            ).fetchone()
        finally:
            conn.close()
        assert n == 1
        assert who is not None and who[0] == "Hello"

    def test_rerun_after_kb_change(self, tmp_path, kb):
        db = tmp_path / "case.db"
        _make_extracted_db(db)
        assert annotate_database(db, kb).counts == {"test.greeting": 1}

        # The realistic "annotate at will" workflow: improve the KB, then
        # re-annotate the *saved* database (no re-extract). New KB content → new
        # digest, so it records as a fresh run rather than colliding.
        root = tmp_path / "kb"
        (root / "signatures" / "test.yaml").write_text(
            _KB_YAML.replace("A greeting was logged", "A greeting was logged (v2)"),
            encoding="utf-8",
        )
        kb2 = load_kb(root)
        assert kb2.sha256 != kb.sha256
        assert annotate_database(db, kb2).counts == {"test.greeting": 1}

    def test_rapid_identical_rerun_does_not_crash(self, tmp_path, kb):
        # Microsecond applied_at lets back-to-back identical runs record as
        # distinct runs instead of hitting the UNIQUE(applied_at) guard.
        db = tmp_path / "case.db"
        _make_extracted_db(db)
        assert annotate_database(db, kb).counts == {"test.greeting": 1}
        assert annotate_database(db, kb).counts == {"test.greeting": 1}

    def test_tag_selection(self, tmp_path, kb):
        db = tmp_path / "case.db"
        _make_extracted_db(db)
        # Selecting by a present tag annotates; an absent tag selects nothing.
        assert annotate_database(db, kb, only_tags={"greeting"}).counts == {"test.greeting": 1}
        assert annotate_database(db, kb, only_tags={"nope"}).counts == {}

    def test_missing_database_raises(self, tmp_path, kb):
        with pytest.raises(FileNotFoundError):
            annotate_database(tmp_path / "absent.db", kb)


# ── annotate_connection (caller-owned, in-memory) ─────────────────────────────

def test_annotate_connection_in_memory(kb):
    conn = sqlite3.connect(":memory:")
    try:
        apply_pragmas(conn)
        init_schema(conn)
        _populate(conn)
        res = annotate_connection(conn, kb)
        assert res.counts == {"test.greeting": 1}
        assert res.db_path is None  # connection variant doesn't know the path
        n = conn.execute("SELECT COUNT(*) FROM log_annotations").fetchone()[0]
        assert n == 1
    finally:
        conn.close()


# ── open_or_extract (parse once, reuse) ──────────────────────────────────────

def test_open_or_extract_reuses_existing_db(tmp_path, monkeypatch):
    from forensic_aul import open_or_extract
    from forensic_aul.ops.extraction import extract as extract_mod

    db = tmp_path / "case.db"
    db.write_bytes(b"")  # pre-existing database

    def _boom(*_a, **_k):  # pragma: no cover - must not be reached
        raise AssertionError("run_extract must not run when the DB exists")

    monkeypatch.setattr(extract_mod, "run_extract", _boom)
    assert open_or_extract(tmp_path / "src.logarchive", db) == db


def test_open_or_extract_delegates_when_absent(tmp_path, monkeypatch):
    from forensic_aul import open_or_extract
    from forensic_aul.ops.extraction import extract as extract_mod

    db = tmp_path / "case.db"
    seen: dict = {}

    class _FakeResult:
        db_path = db

    def _fake_run_extract(logarchive, db_path, **kwargs):
        seen.update(logarchive=logarchive, db_path=db_path, kwargs=kwargs)
        return _FakeResult()

    monkeypatch.setattr(extract_mod, "run_extract", _fake_run_extract)
    out = open_or_extract(tmp_path / "src.logarchive", db, fts=False, integrity="off")
    assert out == db
    assert seen["kwargs"] == {"fts": False, "integrity": "off"}


def test_public_api_surface_importable():
    """Every documented top-level name imports and is listed in __all__."""
    import forensic_aul

    for name in (
        "run_extract", "open_or_extract", "query_logs", "LogRow", "LogFilters",
        "ForensicAULError", "SourceError", "InvalidDatabaseError",
        "run_identify_workflow", "IdentifyResult", "find_loose_dirs",
        "INTEGRITY_MODES", "ProgressEvent", "ProgressSink",
        "callback_progress_sink", "logging_progress_sink", "tty_bar_sink",
    ):
        assert hasattr(forensic_aul, name), name
        assert name in forensic_aul.__all__, name


# ── run_extract with a caller-prepared source (no re-preparation) ─────────────

def test_run_extract_accepts_prepared_source(tmp_path, monkeypatch):
    """A PreparedSource is used as-is: no second prepare/hash, provenance kept,
    and cleanup stays with the caller."""
    import io
    import tarfile

    from forensic_aul import prepare_source, run_extract
    from forensic_aul.ops.extraction import extract as extract_mod

    # Minimal sysdiagnose: a wrapper folder with an (empty-content) logarchive.
    arc = tmp_path / "sd.tar.gz"
    files = {
        "sysdiagnose_DEMO/system_logs.logarchive/timesync/0.timesync": b"",
        "sysdiagnose_DEMO/system_logs.logarchive/Info.plist": b"",
    }
    with tarfile.open(arc, "w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

    with prepare_source(arc) as prepared:
        # If run_extract re-prepared, this would blow up.
        def _boom(*_a, **_k):  # pragma: no cover - must not be reached
            raise AssertionError("prepare_source must not run again")

        monkeypatch.setattr(extract_mod, "prepare_source", _boom)
        res = run_extract(prepared, tmp_path / "case.db", case_number="C1")

        # Provenance comes from the ORIGINAL container, not the extraction dir.
        assert res.source_type == "sysdiagnose"
        assert res.source_sha256 == prepared.content_sha256
        assert res.entry_count == 0  # nothing parseable in the fixture — fine
        # The caller's context manager still owns the temp extraction.
        assert prepared.logarchive_root.is_dir()
