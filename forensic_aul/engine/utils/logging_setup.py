"""Forensic logging setup for AUL Parser.

Two handlers are configured:
  - Console : INFO by default; DEBUG if verbose=True.
               Format includes filename, line number, function name and
               process info to ease debugging.
  - File    : Always INFO.  Append mode — successive runs of the same
               case accumulate in the same file; no run is ever lost.
               Format is clean (no source location) for use as an
               operational audit trail.

File naming
-----------
    <case_number>-AUL-<imei>.log

placed in the same directory as the output SQLite database.

Special characters in case_number / imei are sanitised to underscores so
the name is valid on Windows and macOS.
"""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path

from forensic_aul.config import (
    LOG_CONSOLE_DATEFMT as _CONSOLE_DATEFMT,
    LOG_CONSOLE_FORMAT as _CONSOLE_FMT,
    LOG_FILE_DATEFMT as _FILE_DATEFMT,
    LOG_FILE_FORMAT as _FILE_FMT,
)


class _UTCFormatter(logging.Formatter):
    """Formatter that always produces UTC timestamps.

    ``logging.Formatter`` calls ``self.converter(record.created)`` to obtain
    the ``time.struct_time`` used for ``%(asctime)s``. ``time.gmtime`` has the
    matching ``(timestamp) -> struct_time`` signature and avoids the lambda's
    bug of ignoring its argument (which made every record share the format
    time, not the record time).
    """

    converter = staticmethod(time.gmtime)


# ── Filename sanitisation ─────────────────────────────────────────────────────

_UNSAFE = re.compile(r'[\\/:*?"<>|]')


def _sanitise(value: str) -> str:
    """Replace filesystem-unsafe characters with underscores."""
    return _UNSAFE.sub("_", value).strip("_ ")


# ── Public API ────────────────────────────────────────────────────────────────

def setup_logging(
    *,
    verbose: bool,
    case_number: str,
    imei: str,
    db_path: Path,
) -> Path:
    """Configure the root logger with console and file handlers.

    Must be called once, early in the process, before any log messages
    are emitted.

    Args:
        verbose:     If True the console handler shows DEBUG messages.
        case_number: Investigation / case reference (used in filename).
        imei:        Device IMEI (used in filename).
        db_path:     Path to the output SQLite database — the log file is
                     created in the same directory.

    Returns:
        Path to the log file that was opened.
    """
    root = logging.getLogger()
    # Set root to DEBUG so handlers can filter independently.
    root.setLevel(logging.DEBUG)

    # If a previous call already attached our handlers (e.g. test re-entry),
    # remove them first to avoid duplicate log lines.
    for h in list(root.handlers):
        if isinstance(h, (logging.StreamHandler, logging.FileHandler)):
            root.removeHandler(h)
            try:
                h.close()
            except Exception:
                pass

    # ── Console handler ───────────────────────────────────────────────
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(
        _UTCFormatter(fmt=_CONSOLE_FMT, datefmt=_CONSOLE_DATEFMT)
    )

    # ── File handler ──────────────────────────────────────────────────
    log_path = _build_log_path(case_number, imei, db_path)
    file_handler = logging.FileHandler(log_path, mode="a", encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(
        _UTCFormatter(fmt=_FILE_FMT, datefmt=_FILE_DATEFMT)
    )

    root.addHandler(console)
    root.addHandler(file_handler)

    # Suppress noisy third-party loggers that are not useful forensically.
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)

    return log_path


def close_file_handler() -> None:
    """Flush and remove the file handler from the root logger.

    Must be called after the last log message is emitted and before
    hashing the log file, to ensure the file is fully written and closed.
    Console logging remains active after this call.
    """
    root = logging.getLogger()
    for handler in list(root.handlers):
        if isinstance(handler, logging.FileHandler):
            handler.flush()
            handler.close()
            root.removeHandler(handler)


def _build_log_path(case_number: str, imei: str, db_path: Path) -> Path:
    """Build the log file path from case metadata."""
    safe_case = _sanitise(case_number)
    safe_imei = _sanitise(imei)
    filename = f"{safe_case}-AUL-{safe_imei}.log"
    return db_path.parent / filename
