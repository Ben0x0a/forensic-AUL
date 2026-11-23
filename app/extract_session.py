"""Shared extract-session runner for the ``extract`` and ``acquire --extract`` paths.

Wraps the full CLI-side extraction *session* — set up the forensic operational
log, log the invocation banner, run the core pipeline, then **seal** the log
(hash → store in case_metadata → close the handler) on every exit path
(success, SIGINT, failure). Centralising it here guarantees that however an
extract is launched, it always produces the same tamper-evident, sealed audit
log; previously ``acquire --extract`` ran its own copy that skipped sealing.

The core pipeline itself lives in ``forensic_aul.ops.extraction.extract``; this
module only owns the CLI session framing (logging + sealing), which is why it
sits in the ``app`` orchestration layer — above the library, below the shells —
rather than inside the library.

Used by : launcher.cmds.extract_cmd and launcher.cmds.acquire_cmd (the shells
          call ``run_extract_session``).
Uses    : forensic_aul.* (the extract pipeline, integrity sealing), app.logging_config
          (console + operational log file).
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Mapping
from pathlib import Path

from forensic_aul import __version__
from forensic_aul.engine.integrity import seal_log_file
from forensic_aul.engine.utils.cancellation import NEVER_CANCELLED, CancelToken
from forensic_aul.engine.utils.progress import ProgressSink
from forensic_aul.errors import OperationCancelled
from forensic_aul.ops.extraction.extract import run_extract
from forensic_aul.ops.extraction.options import CaseInfo, ExtractOptions

from app.logging_config import close_case_log, configure_console, open_case_log

log = logging.getLogger(__name__)


def run_extract_session(
    *,
    logarchive: Path | Mapping[str, Path],
    db_path: Path,
    case: CaseInfo,
    opts: ExtractOptions,
    verbose: bool = False,
    progress: ProgressSink | None = None,
    source_label: str | None = None,
    cancel: CancelToken = NEVER_CANCELLED,
) -> int:
    """Run one extraction session and return a process exit code (0 / 1 / 130).

    Sets up the forensic log file, runs :func:`run_extract`, and seals the log on
    every exit path. *source_label* is a short description of the input shown in
    the banner (e.g. ``"logarchive"``); the caller does any pre-flight validation.

    *cancel* is forwarded to the pipeline. A cancellation is reported like an
    interrupt (exit 130) and the operational log is sealed against the ``.partial``
    the run left behind — the interrupted database is still an audit artefact, and
    naming it here is the only way the analyst learns where it is.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    configure_console(verbose=verbose)
    log_path = open_case_log(case_number=case.case_number, imei=case.imei, db_path=db_path)

    _log_banner(log_path=log_path, case=case, opts=opts, logarchive=logarchive,
                source_label=source_label, db_path=db_path)

    metadata_id: int | None = None
    try:
        result = run_extract(logarchive, db_path, case, opts, progress=progress, cancel=cancel)
        metadata_id = result.metadata_id
    except OperationCancelled as exc:
        # An expected outcome, not a failure: no traceback, and point the analyst
        # at what the run did leave behind.
        partial = exc.partial_db_path or db_path
        log.warning("Extraction cancelled by the operator.")
        log.warning(f"Partial database kept at : {partial}")
        log.warning("It is marked incomplete (case_metadata.extract_status='cancelled') "
                    "and every reader refuses it. Re-run the extract.")
        _seal(log_path, partial, metadata_id)
        return 130
    except KeyboardInterrupt:
        log.warning("Session interrupted by user (SIGINT).")
        _seal(log_path, db_path, metadata_id)
        return 130
    except Exception:
        # Capture a crash report (all frame locals) before the traceback is lost —
        # this handler swallows the exception and returns, so sys.excepthook never
        # sees it. RunContext/options/paths are live on the stack here.
        from app.diagnostics import capture_exception
        capture_exception({"entrypoint": "cli", "op": "extract"})
        log.exception("Unhandled exception during extract")
        _seal(log_path, db_path, metadata_id)
        return 1

    log.info("=" * 72)
    log.info("Extract session completed successfully.")
    log.info("Sealing operational log file…")
    log.info("=" * 72)
    _seal(log_path, db_path, metadata_id)
    return 0


def _log_banner(
    *,
    log_path: Path,
    case: CaseInfo,
    opts: ExtractOptions,
    logarchive: Path | Mapping[str, Path],
    source_label: str | None,
    db_path: Path,
) -> None:
    if isinstance(logarchive, Mapping):
        src_path = ", ".join(f"{k}={Path(v).resolve()}" for k, v in logarchive.items())
    else:
        src_path = str(logarchive.resolve())
    src = src_path + (f"  ({source_label})" if source_label else "")
    jobs = opts.jobs
    jobs_desc = "serial" if jobs <= 1 else f"{jobs - 1} workers + 1 writer"
    log.info("=" * 72)
    log.info(f"AUL Parser {__version__} — extract session started")
    log.info(f"Log file   : {log_path}")
    log.info(f"Case       : {case.case_number}")
    log.info(f"IMEI       : {case.imei}")
    if case.exhibit_number:
        log.info(f"Exhibit    : {case.exhibit_number}")
    if case.analyst_name:
        log.info(f"Analyst    : {case.analyst_name}")
    log.info(f"Source     : {src}")
    if opts.work_dir:
        log.info(f"Work dir   : {opts.work_dir}  (kept)")
    log.info(f"Output DB  : {db_path.resolve()}")
    log.info(f"Batch size : {opts.batch_size}")
    log.info(f"Jobs       : {jobs}  ({jobs_desc})")
    log.info("=" * 72)


def _seal(log_path: Path, db_path: Path, metadata_id: int | None) -> None:
    """Close the file log handler, hash the log, and store the digest in the DB.

    Runs on every exit path. Closing the handler first flushes all bytes so the
    file is complete before it is hashed.

    WHY the existence guard: ``seal_log_file`` opens *db_path* with
    ``sqlite3.connect``, which CREATES the file when it is absent. On a failed or
    cancelled run the database is still a ``.partial``, so an unguarded call
    would conjure an empty file at the FINAL name — destroying the one property
    the whole ``.partial`` scheme rests on, that a file at the final name means a
    completed extract.
    """
    close_case_log()
    if metadata_id is not None and not db_path.exists():
        log.warning(f"Database {db_path} is absent — log hash not stored (log still hashed below)")
        metadata_id = None
    try:
        digest = seal_log_file(db_path, log_path, metadata_id)
    except OSError as exc:
        log.error(f"Could not hash log file {log_path}: {exc}")
        return
    except sqlite3.Error:
        log.exception("Failed to store log hash in DB")
        return

    log.info("Log file sealed")
    log.info(f"  Path   : {log_path}")
    log.info(f"  SHA-256: {digest}")
    if metadata_id is None:
        log.warning("metadata_id unavailable — log hash not stored in DB")
    else:
        log.info(f"Log file SHA-256 stored in case_metadata (id={metadata_id})")
