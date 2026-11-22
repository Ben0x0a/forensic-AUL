"""Logging configuration for the frontends — the one place handlers, levels and formats are set.

Defines : configure_console (console logging via logging.config.dictConfig),
          open_case_log / close_case_log (the forensic operational log file of an
          extract session), attach_handler / set_root_level (a frontend-supplied
          handler such as the GUI log panel), and every log format.
Used by : launcher/cli.py (bootstrap), app/extract_session.py (session log),
          gui/widgets/log_panel.py (GUI log panel).
Uses    : the standard library only (logging, logging.config, re, time, pathlib).

WHY here and not in the library: a library must never configure logging — it
only names its loggers and adds a NullHandler (see forensic_aul/__init__.py), so a
host application keeps full control of its own handlers. Every frontend decision
(formats, levels, which file) lives in this one module.

Levels: the root logger follows --verbose (INFO, or DEBUG when verbose). WHY not
always DEBUG with handler filtering: the parse path logs per chunkset and per
firehose block, so a DEBUG root builds tens of millions of records that are then
dropped. A record that is never created costs nothing.
"""

from __future__ import annotations

import logging
import logging.config
import re
import time
from pathlib import Path

# ── Formats ──────────────────────────────────────────────────────────────────
# Console, default: short and readable. Consumed by: configure_console.
CONSOLE_FORMAT: str = "%(asctime)s  %(levelname)-8s — %(message)s"
# Console, --verbose: source location and process, columns aligned so records
# from different modules line up. Consumed by: configure_console.
CONSOLE_FORMAT_VERBOSE: str = (
    "%(asctime)s  "
    "%(levelname)-8s  "
    "%(filename)-28s:%(lineno)-4d  "
    "%(funcName)-30s  "
    "%(processName)s[%(process)d]"
    " — %(message)s"
)
CONSOLE_DATEFMT: str = "%H:%M:%S"
# Operational log file (audit trail): no source location — a UTC timestamp, the
# level, a fixed source label and the message. Consumed by: open_case_log.
FILE_FORMAT: str = "%(asctime)s  %(levelname)-8s  Forensic AUL — %(message)s"
FILE_DATEFMT: str = "%Y-%m-%dT%H:%M:%SZ"

# Third-party loggers that are noisy and carry nothing forensically useful.
_QUIET_LOGGERS: tuple[str, ...] = ("urllib3", "asyncio")

_UNSAFE_FILENAME_CHARS = re.compile(r'[\\/:*?"<>|]')


class UTCFormatter(logging.Formatter):
    """A formatter whose ``%(asctime)s`` is always UTC (forensic timestamps)."""

    converter = staticmethod(time.gmtime)


# The file handler this module opened, so close_case_log removes exactly it and
# never a handler some other code installed.
_case_handler: logging.FileHandler | None = None


def configure_console(*, verbose: bool = False) -> None:
    """(Re)configure the root logger with a single console handler.

    Replaces any root handlers already installed by an earlier call (dictConfig
    semantics), so calling it again — the CLI bootstrap, then a session with
    ``--verbose`` — never duplicates lines.
    """
    level = "DEBUG" if verbose else "INFO"
    logging.config.dictConfig({
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "console": {
                "()": UTCFormatter,
                "fmt": CONSOLE_FORMAT_VERBOSE if verbose else CONSOLE_FORMAT,
                "datefmt": CONSOLE_DATEFMT,
            },
        },
        "handlers": {
            "console": {"class": "logging.StreamHandler", "formatter": "console", "level": level},
        },
        "root": {"level": level, "handlers": ["console"]},
        "loggers": {name: {"level": "WARNING"} for name in _QUIET_LOGGERS},
    })


def case_log_path(case_number: str, imei: str, db_path: Path) -> Path:
    """``<case>-AUL-<imei>.log`` beside the database (unsafe characters → ``_``)."""
    safe_case = _UNSAFE_FILENAME_CHARS.sub("_", case_number).strip("_ ")
    safe_imei = _UNSAFE_FILENAME_CHARS.sub("_", imei).strip("_ ")
    return db_path.parent / f"{safe_case}-AUL-{safe_imei}.log"


def open_case_log(*, case_number: str, imei: str, db_path: Path) -> Path:
    """Start the operational log file for one case; return its path.

    Append mode: successive runs of the same case accumulate in one file, so no
    run is ever lost. Always INFO, whatever the console verbosity.
    """
    global _case_handler
    close_case_log()
    path = case_log_path(case_number, imei, db_path)
    handler = logging.FileHandler(path, mode="a", encoding="utf-8")
    handler.setLevel(logging.INFO)
    handler.setFormatter(UTCFormatter(fmt=FILE_FORMAT, datefmt=FILE_DATEFMT))
    logging.getLogger().addHandler(handler)
    _case_handler = handler
    return path


def close_case_log() -> None:
    """Flush, close and detach the case log file (before it is hashed and sealed)."""
    global _case_handler
    if _case_handler is None:
        return
    _case_handler.flush()
    _case_handler.close()
    logging.getLogger().removeHandler(_case_handler)
    _case_handler = None


def attach_handler(handler: logging.Handler, *, level: int = logging.INFO) -> None:
    """Add a frontend's own handler (e.g. the GUI log panel) to the root logger."""
    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(handler)


def set_root_level(level: int) -> None:
    """Change what the root logger lets through (e.g. the GUI's DEBUG toggle)."""
    logging.getLogger().setLevel(level)
