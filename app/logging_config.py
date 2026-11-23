"""Logging configuration for the frontends — the one place handlers, levels and formats are set.

Defines : configure_console (console logging via logging.config.dictConfig),
          attach_handler / set_root_level (a frontend-supplied handler such as the
          GUI log panel), and the console formats.
Used by : launcher/cli.py (bootstrap), app/extract_session.py (verbosity),
          gui/widgets/log_panel.py (GUI log panel).
Uses    : the standard library only (logging, logging.config, time).

The forensic operational (audit) log is NOT configured here: it is part of the
evidence an extract produces, so it lives in the library
(forensic_aul/ops/extraction/audit.py) and is opened only by run_extract.

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
import time

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

# Third-party loggers that are noisy and carry nothing forensically useful.
_QUIET_LOGGERS: tuple[str, ...] = ("urllib3", "asyncio")


class UTCFormatter(logging.Formatter):
    """A formatter whose ``%(asctime)s`` is always UTC (forensic timestamps).

    The audit log has its own (forensic_aul.ops.extraction.audit.UTCFormatter):
    the two formats are separate contracts — console vs evidence file.
    """

    converter = staticmethod(time.gmtime)


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


def attach_handler(handler: logging.Handler, *, level: int = logging.INFO) -> None:
    """Add a frontend's own handler (e.g. the GUI log panel) to the root logger."""
    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(handler)


def set_root_level(level: int) -> None:
    """Change what the root logger lets through (e.g. the GUI's DEBUG toggle)."""
    logging.getLogger().setLevel(level)
