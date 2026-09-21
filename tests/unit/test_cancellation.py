"""Cancelling a long operation, and what an interrupted run leaves behind.

Covers the four things the cancellation design rests on:

- the :class:`CancelToken` / :data:`NEVER_CANCELLED` primitive and the
  constraints ``OperationCancelled`` must satisfy (it is caught by neither
  ``except ValueError`` nor ``except KeyboardInterrupt``, and it pickles);
- **the safety property**: after a cancelled extract there is no file at the
  final name, there IS a ``.partial``, and it records ``extract_status``
  ``cancelled``;
- the run ledger (``extract_phases``) and the per-file parse completion column
  that a future resume will read;
- the readers' refusal to open an incomplete database, and the escape hatch.

Technique
---------
Cancellation is driven **from the progress sink**. ``run_extract`` already takes
one, so a sink that cancels when a chosen phase first reports fires at an exact,
reproducible point inside the real pipeline — no sleeps, no threads, no
flakiness. The fixture is the tiny synthetic sysdiagnose used elsewhere in the
suite, which runs the whole real pipeline in milliseconds.
"""

from __future__ import annotations

import io
import pickle
import sqlite3
import tarfile
from pathlib import Path

import pytest

from forensic_aul import run_extract
from forensic_aul.engine.database.access import open_analysis_database
from forensic_aul.engine.utils.cancellation import NEVER_CANCELLED, CancelToken
from forensic_aul.errors import (
    IncompleteDatabaseError,
    InvalidDatabaseError,
    OperationCancelled,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _synthetic_sysdiagnose(tmp_path: Path) -> Path:
    """A minimal sysdiagnose tarball the real pipeline accepts (0 log entries)."""
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
    return arc


def _cancel_on_phase(token: CancelToken, phase: str):
    """A ProgressSink that cancels *token* the first time *phase* reports."""
    def sink(event) -> None:
        if event.phase == phase:
            token.cancel()
    return sink


def _status(db: Path) -> str | None:
    conn = sqlite3.connect(str(db))
    try:
        row = conn.execute(
            "SELECT extract_status FROM case_metadata ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


# ── The primitive ─────────────────────────────────────────────────────────────

class TestCancelToken:
    def test_check_raises_only_once_cancelled(self):
        token = CancelToken()
        token.check()                 # no-op while un-cancelled
        assert token.cancelled is False
        token.cancel()
        assert token.cancelled is True
        with pytest.raises(OperationCancelled):
            token.check()

    def test_cancel_is_idempotent(self):
        token = CancelToken()
        token.cancel()
        token.cancel()
        assert token.cancelled is True

    def test_never_cancelled_is_inert(self):
        """The null object must stay un-cancellable — it is shared process-wide."""
        NEVER_CANCELLED.cancel()
        assert NEVER_CANCELLED.cancelled is False
        NEVER_CANCELLED.check()
        assert NEVER_CANCELLED.wait(0) is False

    def test_wraps_an_external_flag(self):
        """A token can be driven by any set/is_set/wait flag (an mp.Event)."""
        import threading

        flag = threading.Event()
        token = CancelToken(flag)
        assert token.cancelled is False
        flag.set()
        assert token.cancelled is True

    def test_module_imports_neither_qt_nor_multiprocessing(self):
        """The primitive must stay usable from a worker process and from the core."""
        source = (
            Path(__file__).resolve().parents[2]
            / "forensic_aul/engine/utils/cancellation.py"
        ).read_text(encoding="utf-8")
        code = "\n".join(
            line for line in source.splitlines() if not line.lstrip().startswith("#")
        )
        assert "import multiprocessing" not in code
        assert "PySide6" not in code


class TestOperationCancelled:
    def test_is_not_a_value_error(self):
        """Several GUI handlers catch ValueError; they must not eat a cancel."""
        assert not issubclass(OperationCancelled, ValueError)

    def test_is_not_a_keyboard_interrupt(self):
        """It must not skip past `except Exception` cleanup blocks."""
        assert not issubclass(OperationCancelled, KeyboardInterrupt)

    def test_pickles_back_from_a_worker_process(self):
        """A worker raises it; ProcessPoolExecutor pickles it to the parent."""
        restored = pickle.loads(pickle.dumps(OperationCancelled("stopped")))
        assert isinstance(restored, OperationCancelled)
        assert str(restored) == "stopped"

    def test_partial_db_path_defaults_to_none(self):
        assert OperationCancelled("x").partial_db_path is None


# ── The safety property ───────────────────────────────────────────────────────

@pytest.mark.parametrize("phase", ["parse", "ordering", "index", "stats"])
def test_cancel_leaves_a_partial_and_no_final_database(tmp_path, phase):
    """After a cancel: nothing at the final name, a .partial marked 'cancelled'.

    This is THE property everything else rests on — a file at the output path
    means a finished extract, always.
    """
    arc = _synthetic_sysdiagnose(tmp_path)
    db = tmp_path / "case.sqlite"
    token = CancelToken()

    with pytest.raises(OperationCancelled) as caught:
        run_extract(
            arc, db, case_number="C1", integrity="off",
            cancel=token, progress=_cancel_on_phase(token, phase),
        )

    partial = tmp_path / "case.sqlite.partial"
    assert not db.exists(), "a cancelled run must not produce the final artefact"
    assert partial.is_file(), "the partial database must be kept"
    assert caught.value.partial_db_path == partial
    assert _status(partial) == "cancelled"


def test_successful_run_renames_and_records_complete(tmp_path):
    """The other half of the contract: success promotes and marks complete."""
    arc = _synthetic_sysdiagnose(tmp_path)
    db = tmp_path / "case.sqlite"

    result = run_extract(arc, db, case_number="C1", integrity="off")

    assert result.db_path == db
    assert db.is_file()
    assert not (tmp_path / "case.sqlite.partial").exists()
    assert _status(db) == "complete"


def test_cancel_before_any_work_still_leaves_no_final_database(tmp_path):
    """A token already cancelled stops during preparation, before the DB exists."""
    arc = _synthetic_sysdiagnose(tmp_path)
    db = tmp_path / "case.sqlite"
    token = CancelToken()
    token.cancel()

    with pytest.raises(OperationCancelled):
        run_extract(arc, db, case_number="C1", integrity="off", cancel=token)

    assert not db.exists()


def test_overwrite_guard_covers_the_partial_name(tmp_path):
    """A leftover .partial is the previous run's evidence — never merge into it."""
    arc = _synthetic_sysdiagnose(tmp_path)
    db = tmp_path / "case.sqlite"
    (tmp_path / "case.sqlite.partial").write_text("previous run", encoding="utf-8")

    with pytest.raises(FileExistsError, match=r"\.partial"):
        run_extract(arc, db, case_number="C1", integrity="off")


def test_overwrite_clears_a_leftover_partial(tmp_path):
    arc = _synthetic_sysdiagnose(tmp_path)
    db = tmp_path / "case.sqlite"
    (tmp_path / "case.sqlite.partial").write_text("previous run", encoding="utf-8")

    run_extract(arc, db, case_number="C1", integrity="off", overwrite=True)

    assert db.is_file()
    assert not (tmp_path / "case.sqlite.partial").exists()


# ── Interrupting a running SQL statement ──────────────────────────────────────

# A statement long enough to cross the progress handler's VM-step threshold many
# times over — standing in for the finaliser's index build / FTS rebuild.
_LONG_STATEMENT = (
    "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 4000000) "
    "SELECT COUNT(*) FROM c"
)


class TestSqliteProgressHandler:
    """The only lever that reaches inside ordering / index / FTS (single statements)."""

    def test_arming_lets_a_cancel_abort_a_running_statement(self):
        from forensic_aul.ops.extraction.extract import _arm_sqlite_cancel

        conn = sqlite3.connect(":memory:")
        try:
            token = CancelToken()
            _arm_sqlite_cancel(conn, token)
            token.cancel()
            with pytest.raises(sqlite3.OperationalError):
                conn.execute(_LONG_STATEMENT).fetchone()
        finally:
            conn.close()

    def test_the_connection_survives_the_abort(self):
        """The cancel handler goes on to WRITE the run's status on this connection."""
        from forensic_aul.ops.extraction.extract import _arm_sqlite_cancel

        conn = sqlite3.connect(":memory:")
        try:
            token = CancelToken()
            _arm_sqlite_cancel(conn, token)
            token.cancel()
            with pytest.raises(sqlite3.OperationalError):
                conn.execute(_LONG_STATEMENT).fetchone()
            conn.set_progress_handler(None, 0)
            assert conn.execute("SELECT 1").fetchone() == (1,)
        finally:
            conn.close()

    def test_the_null_token_installs_no_handler(self):
        """Zero per-statement cost on the ordinary, non-cancellable path."""
        from forensic_aul.ops.extraction.extract import _arm_sqlite_cancel

        conn = sqlite3.connect(":memory:")
        try:
            _arm_sqlite_cancel(conn, NEVER_CANCELLED)
            assert conn.execute("SELECT 1").fetchone() == (1,)
        finally:
            conn.close()


def test_a_sqlite_abort_is_reported_as_a_cancellation(tmp_path):
    """An aborted statement must reach the caller as OperationCancelled…

    …not as a bare OperationalError. The translation also disarms the handler
    first — otherwise the UPDATE that records the cancellation would itself be
    interrupted by the still-armed handler, and the database would be left
    claiming to be 'running'.
    """
    from forensic_aul.engine.database.schema import init_schema
    from forensic_aul.engine.database.writer import BatchWriter
    from forensic_aul.ops.extraction.extract import (
        _arm_sqlite_cancel,
        _handle_interruption,
    )
    from forensic_aul.ops.extraction.options import CaseInfo, ExtractOptions, RunContext
    from forensic_aul.engine.utils.progress import ProgressReporter

    db = tmp_path / "aborted.sqlite.partial"
    conn = sqlite3.connect(str(db))
    init_schema(conn, enable_fts5=False)
    writer = BatchWriter(conn)
    metadata_id = writer.insert_case_metadata(case_number="C1")
    conn.commit()

    token = CancelToken()
    ctx = RunContext(
        conn=conn, db_path=db, final_db_path=tmp_path / "aborted.sqlite",
        prepared=None, case=CaseInfo(), opts=ExtractOptions(),
        reporter=ProgressReporter(None, []), t0=0.0, cancel=token,
        writer=writer, metadata_id=metadata_id,
    )
    _arm_sqlite_cancel(conn, token)
    token.cancel()
    try:
        conn.execute(_LONG_STATEMENT).fetchone()
    except sqlite3.OperationalError as exc:
        with pytest.raises(OperationCancelled) as caught:
            _handle_interruption(ctx, exc)
        assert caught.value.partial_db_path == db
    else:  # pragma: no cover — the handler must have aborted the statement
        raise AssertionError("the progress handler did not abort the statement")

    conn.close()
    assert _status(db) == "cancelled", (
        "the status UPDATE must survive — the handler is disarmed before it runs"
    )


def test_a_genuine_failure_is_not_reported_as_a_cancellation(tmp_path):
    """extract_status stays 'running' for a crash: that IS what happened."""
    from forensic_aul.engine.database.schema import init_schema
    from forensic_aul.engine.database.writer import BatchWriter
    from forensic_aul.engine.utils.progress import ProgressReporter
    from forensic_aul.ops.extraction.extract import _handle_interruption
    from forensic_aul.ops.extraction.options import CaseInfo, ExtractOptions, RunContext

    db = tmp_path / "broken.sqlite.partial"
    conn = sqlite3.connect(str(db))
    init_schema(conn, enable_fts5=False)
    writer = BatchWriter(conn)
    metadata_id = writer.insert_case_metadata(case_number="C1")
    conn.commit()

    ctx = RunContext(
        conn=conn, db_path=db, final_db_path=tmp_path / "broken.sqlite",
        prepared=None, case=CaseInfo(), opts=ExtractOptions(),
        reporter=ProgressReporter(None, []), t0=0.0, cancel=CancelToken(),
        writer=writer, metadata_id=metadata_id,
    )
    _handle_interruption(ctx, RuntimeError("disk on fire"))   # must not raise
    conn.close()
    assert _status(db) == "running"


# ── The run ledger (resume readiness) ─────────────────────────────────────────

def _phases(db: Path) -> list[tuple[str, str | None]]:
    conn = sqlite3.connect(str(db))
    try:
        return conn.execute(
            "SELECT phase, completed_at FROM extract_phases ORDER BY id"
        ).fetchall()
    finally:
        conn.close()


def test_completed_run_records_every_phase_as_finished(tmp_path):
    arc = _synthetic_sysdiagnose(tmp_path)
    db = tmp_path / "case.sqlite"
    run_extract(arc, db, case_number="C1", integrity="off")

    rows = _phases(db)
    names = [phase for phase, _ in rows]
    assert names[0] == "prepare", "preparation must be in the ledger despite running first"
    for expected in ("parse", "ordering", "index", "stats"):
        assert expected in names, expected
    assert all(completed is not None for _, completed in rows), (
        "a finished run must leave no phase open"
    )


def test_cancelled_run_leaves_the_dying_phase_open(tmp_path):
    """`completed_at IS NULL` is the record of where an interrupted run stopped."""
    arc = _synthetic_sysdiagnose(tmp_path)
    db = tmp_path / "case.sqlite"
    token = CancelToken()

    with pytest.raises(OperationCancelled):
        run_extract(
            arc, db, case_number="C1", integrity="off",
            cancel=token, progress=_cancel_on_phase(token, "ordering"),
        )

    rows = _phases(tmp_path / "case.sqlite.partial")
    open_phases = [phase for phase, completed in rows if completed is None]
    assert open_phases == ["ordering"]


def test_source_files_record_per_file_parse_completion(tmp_path):
    """The column a future mid-parse resume needs: which files are fully in.

    The synthetic fixture holds no tracev3, so the assertion is about the column
    existing with the right meaning — a registered file that was never parsed has
    NULL, which is exactly what marks it for re-parsing.
    """
    arc = _synthetic_sysdiagnose(tmp_path)
    db = tmp_path / "case.sqlite"
    run_extract(arc, db, case_number="C1", integrity="off")

    conn = sqlite3.connect(str(db))
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(source_files)")}
        assert "parse_completed_at" in cols
        unparsed = conn.execute(
            "SELECT COUNT(*) FROM source_files "
            "WHERE file_type = 'tracev3' AND parse_completed_at IS NULL"
        ).fetchone()[0]
        assert unparsed == 0, "every tracev3 the run consumed must be marked"
    finally:
        conn.close()


def test_post_parse_phases_are_rerunnable_with_identical_results(tmp_path):
    """Resume rests on ordering → index → fts → stats being idempotent.

    Running them a second time over the same rows must change nothing. This is
    cheap to guard now and is the invariant a future ``--resume`` will depend on;
    without it, restarting from a phase boundary would silently corrupt the
    ordering it re-derives.
    """
    from forensic_aul.engine.database.ordering import assign_ordering
    from forensic_aul.engine.database.schema import (
        finalize_deferred_fts,
        finalize_indexes,
        init_schema,
    )
    from forensic_aul.ops.summary.cache import refresh_summary

    db = tmp_path / "rerun.sqlite"
    conn = sqlite3.connect(str(db))
    try:
        fts_ok = init_schema(conn, enable_fts5=True, defer_fts_triggers=True,
                             create_indexes=False)
        conn.execute("INSERT INTO boots(boot_uuid, rank) VALUES ('B1', 1)")
        conn.executemany(
            "INSERT INTO logs(tracev3_file_id, timestamp_unix_ns, timestamp_mach, "
            "tracev3_chunkset_file_offset, tracev3_entry_inner_offset, message, boot_id) "
            "VALUES (?,?,?,?,?,?,1)",
            [(1, 1_000 + i, 10 + i, 0, i, f"line {i}") for i in range(25)],
        )
        conn.commit()

        def _run_tail() -> None:
            assign_ordering(conn)
            finalize_indexes(conn)
            if fts_ok:
                finalize_deferred_fts(conn)
            refresh_summary(conn)

        def _snapshot() -> list[tuple]:
            return conn.execute(
                "SELECT id, source_order, event_order FROM logs ORDER BY id"
            ).fetchall()

        _run_tail()
        first = _snapshot()
        first_count = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]

        _run_tail()   # the resume case: the whole tail runs again from scratch
        assert _snapshot() == first, "re-running the post-parse phases changed the ordering"
        assert conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0] == first_count
    finally:
        conn.close()


# ── CLI parity ────────────────────────────────────────────────────────────────

class TestCliSigint:
    """`extract`'s Ctrl+C must produce the same artefact the GUI's Cancel does."""

    def test_first_sigint_cancels_and_the_second_is_left_to_default(self):
        import signal

        from launcher.cmds.extract_cmd import _sigint_cancels

        original = signal.getsignal(signal.SIGINT)
        token = CancelToken()
        with _sigint_cancels(token):
            handler = signal.getsignal(signal.SIGINT)
            assert handler is not original, "the arm must install its own handler"
            handler(signal.SIGINT, None)          # simulate the first Ctrl+C
            assert token.cancelled is True
            assert signal.getsignal(signal.SIGINT) is original, (
                "a second Ctrl+C must fall through to the default — an operator "
                "hammering it wants out"
            )
        assert signal.getsignal(signal.SIGINT) is original, "handler must be restored"

    def test_session_reports_130_and_names_the_partial(self, tmp_path, capsys):
        """A cancelled session exits 130 and tells the analyst where the file is.

        Asserted against stderr rather than caplog: ``run_extract_session`` calls
        ``setup_logging``, which replaces the root logger's handlers — including
        the one caplog installs.
        """
        import app.extract_session as session

        db = tmp_path / "case.sqlite"
        partial = tmp_path / "case.sqlite.partial"
        partial.write_text("partial", encoding="utf-8")

        def _cancelling_run_extract(**_kwargs):
            exc = OperationCancelled("stopped")
            exc.partial_db_path = partial
            raise exc

        original = session.run_extract
        session.run_extract = _cancelling_run_extract
        try:
            code = session.run_extract_session(
                logarchive=tmp_path / "src", db_path=db,
                case_number="C1", imei="X",
            )
        finally:
            session.run_extract = original

        assert code == 130
        assert str(partial) in capsys.readouterr().err
        assert not db.exists(), (
            "sealing must never conjure a file at the final name — sqlite3.connect "
            "creates one, which would fake a completed extract"
        )


# ── Opening an incomplete database (D6) ───────────────────────────────────────

class TestOpenIncomplete:
    def _cancelled_partial(self, tmp_path: Path) -> Path:
        arc = _synthetic_sysdiagnose(tmp_path)
        token = CancelToken()
        with pytest.raises(OperationCancelled):
            run_extract(
                arc, tmp_path / "case.sqlite", case_number="C1", integrity="off",
                cancel=token, progress=_cancel_on_phase(token, "ordering"),
            )
        return tmp_path / "case.sqlite.partial"

    def test_refused_by_default(self, tmp_path):
        partial = self._cancelled_partial(tmp_path)
        with pytest.raises(IncompleteDatabaseError, match="never completed"):
            open_analysis_database(partial)

    def test_refusal_says_what_to_do(self, tmp_path):
        """The message must end on an instruction, not a dead end."""
        partial = self._cancelled_partial(tmp_path)
        with pytest.raises(IncompleteDatabaseError) as caught:
            open_analysis_database(partial)
        assert "Re-run the extract" in str(caught.value)

    def test_allow_incomplete_opens_it(self, tmp_path):
        partial = self._cancelled_partial(tmp_path)
        conn = open_analysis_database(partial, allow_incomplete=True)
        try:
            assert conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0] >= 0
        finally:
            conn.close()

    def test_incomplete_is_catchable_as_invalid(self, tmp_path):
        """Existing `except InvalidDatabaseError` handlers must keep working."""
        partial = self._cancelled_partial(tmp_path)
        with pytest.raises(InvalidDatabaseError):
            open_analysis_database(partial)

    def test_a_database_making_no_claim_is_allowed(self, tmp_path):
        """Silence is not a claim: pre-existing / hand-built stores still open.

        Databases written before extract_status existed, and fixtures assembled
        by hand, leave it NULL. Refusing those would make the flag a breaking
        change rather than an added guarantee.
        """
        from forensic_aul.engine.database.schema import init_schema

        db = tmp_path / "silent.sqlite"
        conn = sqlite3.connect(str(db))
        init_schema(conn, enable_fts5=False)
        conn.commit()
        conn.close()

        opened = open_analysis_database(db)
        opened.close()

    def test_completed_run_opens_normally(self, tmp_path):
        arc = _synthetic_sysdiagnose(tmp_path)
        db = tmp_path / "done.sqlite"
        run_extract(arc, db, case_number="C1", integrity="off")
        open_analysis_database(db).close()
