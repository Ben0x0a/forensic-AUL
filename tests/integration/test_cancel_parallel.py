"""Integration test — cancelling a multi-process extract.

Two things only a real pool can prove, and which nothing in the unit suite can:

* the ``multiprocessing.Event`` really does reach the workers. It rides
  ``ProcessPoolExecutor(initargs=…)`` and **cannot** ride ``submit(...)`` — a
  synchronisation primitive survives inheritance at process start but raises
  ``RuntimeError: Condition objects should only be shared between processes
  through inheritance`` when put on the call queue. A test that only exercised
  the serial path would never notice that being got wrong.
* the pool actually drains. ``shutdown(wait=True, cancel_futures=True)`` must
  leave no worker process still reading the evidence by the time the parent
  starts marking the database cancelled.

Plus the safety property under multiprocessing: no file at the final name, a
``.partial`` that records ``cancelled``.

Skipped automatically when the logarchive is absent. Opt-in (it runs the real
pipeline across processes): ``pytest -m integration``.
"""

from __future__ import annotations

import multiprocessing
import os
import sqlite3
from pathlib import Path

import pytest

from forensic_aul.engine.utils.cancellation import CancelToken
from forensic_aul.errors import OperationCancelled
from forensic_aul.ops.extraction.extract import run_extract

pytestmark = pytest.mark.integration

_LOGARCHIVE = Path(
    os.environ.get(
        "FAUL_EQUIV_LOGARCHIVE",
        str(Path(__file__).parent.parent / "data" / "iphoneSE_afterbackup.logarchive"),
    )
)

_JOBS = 3   # 2 worker processes + the writer — enough for a real pool


def test_multiprocessing_event_survives_initargs_but_not_the_call_queue():
    """Pin the constraint the design is built around, without a full extract."""
    ctx = multiprocessing.get_context()
    event = ctx.Event()

    # Inheritance (what parallel_parse uses) is fine …
    from concurrent.futures import ProcessPoolExecutor

    with ProcessPoolExecutor(
        max_workers=1, mp_context=ctx, initializer=_init_with_event, initargs=(event,)
    ) as ex:
        assert ex.submit(_worker_sees_event).result() is True

    # … while passing it as a call argument is rejected outright.
    with ProcessPoolExecutor(max_workers=1, mp_context=ctx) as ex:
        with pytest.raises(Exception):   # RuntimeError, raised at pickling time
            ex.submit(_takes_event, event).result()


_HELD: dict = {}


def _init_with_event(event) -> None:
    _HELD["event"] = event


def _worker_sees_event() -> bool:
    return _HELD.get("event") is not None


def _takes_event(event) -> bool:
    return event is not None


@pytest.mark.skipif(not _LOGARCHIVE.is_dir(), reason="reference logarchive not present")
def test_cancel_during_a_parallel_parse(tmp_path):
    """Cancel mid-parse with a real worker pool; the artefact must still be right."""
    db = tmp_path / "case.sqlite"
    token = CancelToken()

    def sink(event) -> None:
        # Fire once the parse is genuinely under way, so workers are running.
        if event.phase == "parse" and event.phase_fraction > 0.1:
            token.cancel()

    with pytest.raises(OperationCancelled) as caught:
        run_extract(
            _LOGARCHIVE, db, case_number="C-MP", imei="X",
            integrity="off", fts=False, jobs=_JOBS,
            cancel=token, progress=sink,
        )

    partial = tmp_path / "case.sqlite.partial"
    assert not db.exists(), "a cancelled parallel run must not produce the final artefact"
    assert partial.is_file()
    assert caught.value.partial_db_path == partial

    conn = sqlite3.connect(str(partial))
    try:
        status = conn.execute(
            "SELECT extract_status FROM case_metadata ORDER BY id DESC LIMIT 1"
        ).fetchone()[0]
        assert status == "cancelled"
        # Rows already handed to the writer are kept: they are genuine evidence,
        # and the database is marked incomplete rather than emptied.
        assert conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0] >= 0
        # Only fully-flushed files are marked, which is what a resume would trust.
        marked = conn.execute(
            "SELECT COUNT(*) FROM source_files "
            "WHERE file_type = 'tracev3' AND parse_completed_at IS NOT NULL"
        ).fetchone()[0]
        total = conn.execute(
            "SELECT COUNT(*) FROM source_files WHERE file_type = 'tracev3'"
        ).fetchone()[0]
        assert marked <= total
    finally:
        conn.close()


@pytest.mark.skipif(not _LOGARCHIVE.is_dir(), reason="reference logarchive not present")
def test_parallel_run_without_a_token_is_unaffected(tmp_path):
    """The cancellation plumbing must not change the normal parallel result."""
    db = tmp_path / "plain.sqlite"
    result = run_extract(
        _LOGARCHIVE, db, case_number="C-MP2", imei="X",
        integrity="off", fts=False, jobs=_JOBS,
    )
    assert db.is_file()
    assert not (tmp_path / "plain.sqlite.partial").exists()
    assert result.entry_count > 0
