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
Uses    : forensic_aul.* (the extract pipeline, integrity sealing, logging setup).
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Mapping
from pathlib import Path

from forensic_aul import __version__
from forensic_aul.config import BATCH_SIZE
from forensic_aul.engine.integrity import seal_log_file
from forensic_aul.engine.utils.logging_setup import close_file_handler, setup_logging
from forensic_aul.engine.utils.progress import ProgressSink
from forensic_aul.ops.extraction.extract import run_extract

log = logging.getLogger(__name__)


def run_extract_session(
    *,
    logarchive: Path | Mapping[str, Path],
    db_path: Path,
    case_number: str,
    imei: str,
    exhibit_number: str | None = None,
    analyst_name: str | None = None,
    notes: str | None = None,
    batch_size: int = BATCH_SIZE,
    work_dir: Path | None = None,
    # Deferred FTS is the app default: it yields the same final database with far
    # less write amplification on large archives. The standalone `extract` command
    # passes this explicitly (with a --no-fast-fts opt-out); `acquire` inherits it.
    fast_fts: bool = True,
    fast_write: bool = False,
    fts: bool = True,
    keep_raw: bool = False,
    jobs: int = 1,
    overwrite: bool = False,
    integrity: str = "full",
    verbose: bool = False,
    progress: ProgressSink | None = None,
    source_label: str | None = None,
) -> int:
    """Run one extraction session and return a process exit code (0 / 1 / 130).

    Sets up the forensic log file, runs :func:`run_extract`, and seals the log on
    every exit path. *source_label* is a short description of the input shown in
    the banner (e.g. ``"logarchive"``); the caller does any pre-flight validation.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    log_path = setup_logging(
        verbose=verbose, case_number=case_number, imei=imei, db_path=db_path
    )

    _log_banner(
        log_path=log_path, case_number=case_number, imei=imei,
        exhibit_number=exhibit_number, analyst_name=analyst_name,
        logarchive=logarchive, source_label=source_label, work_dir=work_dir,
        db_path=db_path, batch_size=batch_size, jobs=jobs,
    )

    metadata_id: int | None = None
    try:
        result = run_extract(
            logarchive=logarchive,
            db_path=db_path,
            case_number=case_number,
            imei=imei,
            exhibit_number=exhibit_number,
            analyst_name=analyst_name,
            notes=notes,
            batch_size=batch_size,
            work_dir=work_dir,
            fast_fts=fast_fts,
            fast_write=fast_write,
            fts=fts,
            keep_raw=keep_raw,
            jobs=jobs,
            overwrite=overwrite,
            integrity=integrity,
            progress=progress,
        )
        metadata_id = result.metadata_id
    except KeyboardInterrupt:
        log.warning("Session interrupted by user (SIGINT).")
        _seal(log_path, db_path, metadata_id)
        return 130
    except Exception:
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
    case_number: str,
    imei: str,
    exhibit_number: str | None,
    analyst_name: str | None,
    logarchive: Path | Mapping[str, Path],
    source_label: str | None,
    work_dir: Path | None,
    db_path: Path,
    batch_size: int,
    jobs: int,
) -> None:
    if isinstance(logarchive, Mapping):
        src_path = ", ".join(f"{k}={Path(v).resolve()}" for k, v in logarchive.items())
    else:
        src_path = str(logarchive.resolve())
    src = src_path + (f"  ({source_label})" if source_label else "")
    jobs_desc = "serial" if jobs <= 1 else f"{jobs - 1} workers + 1 writer"
    log.info("=" * 72)
    log.info(f"AUL Parser {__version__} — extract session started")
    log.info(f"Log file   : {log_path}")
    log.info(f"Case       : {case_number}")
    log.info(f"IMEI       : {imei}")
    if exhibit_number:
        log.info(f"Exhibit    : {exhibit_number}")
    if analyst_name:
        log.info(f"Analyst    : {analyst_name}")
    log.info(f"Source     : {src}")
    if work_dir:
        log.info(f"Work dir   : {work_dir}  (kept)")
    log.info(f"Output DB  : {db_path.resolve()}")
    log.info(f"Batch size : {batch_size}")
    log.info(f"Jobs       : {jobs}  ({jobs_desc})")
    log.info("=" * 72)


def _seal(log_path: Path, db_path: Path, metadata_id: int | None) -> None:
    """Close the file log handler, hash the log, and store the digest in the DB.

    Runs on every exit path. Closing the handler first flushes all bytes so the
    file is complete before it is hashed.
    """
    close_file_handler()
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
