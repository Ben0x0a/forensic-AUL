"""Forensic diagnostic reports — the public surface of the package.

Two kinds share one format: a **crash** report, written automatically when
something raises, and a **bug** report, written on demand when the tool *returns*
a wrong answer. Each holds the type + value of every variable in every stack
frame, split into ``safe`` / ``sensitive``; the local copy is full plaintext, and
``write_shared_copy`` produces the redacted copy that may leave the machine.

Defines : nothing of its own — it re-exports the names a caller needs.
Used by : launcher.cli, launcher.gui, launcher.cmds.* (incl. redact_errors_cmd),
          app.extract_session, gui.report_actions, gui.workers.base.
Uses    : its bricks, each layer importing only the layers above it (no cycle;
          standard library only):

    schema, config           the report format + vocabulary; the tunables
    capture, redact, render  build a report; redact it; render it as Markdown
    store                    report files: write, list, find, shared copy
    hooks                    the guarded entry points (excepthook, capture…)

Import a brick directly only for something not listed here (tests do).
"""

from app.diagnostics.config import CrashConfig
from app.diagnostics.hooks import (
    capture_exception,
    install_excepthook,
    write_bug_report,
    write_crash_report,
)
from app.diagnostics.redact import anonymise_path, redact_report
from app.diagnostics.render import render_markdown
from app.diagnostics.schema import KIND_BUG, KIND_CRASH, SAFE, SENSITIVE, classify
from app.diagnostics.store import (
    find_report,
    list_reports,
    report_dir,
    report_kind,
    write_shared_copy,
)

__all__ = [
    "KIND_BUG",
    "KIND_CRASH",
    "SAFE",
    "SENSITIVE",
    "CrashConfig",
    "anonymise_path",
    "capture_exception",
    "classify",
    "find_report",
    "install_excepthook",
    "list_reports",
    "redact_report",
    "render_markdown",
    "report_dir",
    "report_kind",
    "write_bug_report",
    "write_crash_report",
    "write_shared_copy",
]
