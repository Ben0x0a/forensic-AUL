"""The guarded entry points of the diagnostic reporter — they never raise.

Defines : ``install_excepthook`` (global ``sys`` / ``threading`` hooks),
          ``capture_exception`` (call from an ``except`` block that swallows and
          returns a code), ``write_crash_report`` and ``write_bug_report``.
Used by : launcher.cli / launcher.gui (install the hooks at start-up), the broad
          ``except`` handlers in app.extract_session, launcher.cmds.* and
          gui.workers.base, and gui.report_actions (files a bug report).
Uses    : app.diagnostics.capture (builds the report), .store (writes it), .config.

Design:
- A global ``sys.excepthook`` (+ ``threading.excepthook``) receives the crash;
  ``capture_exception`` covers the paths that catch-log-and-``return 1`` and so
  never reach the hook.
- Every entry point is fully guarded: any internal failure degrades to a log line
  and returns ``None`` — it never masks the original exception, whose normal
  traceback still prints.
"""

from __future__ import annotations

import logging
import sys
import threading
from pathlib import Path
from typing import Any

from app.diagnostics.capture import build_bug_report, build_crash_report
from app.diagnostics.config import CrashConfig, resolve
from app.diagnostics.store import write_report

log = logging.getLogger(__name__)


def write_crash_report(
    exc_type: type[BaseException],
    exc: BaseException,
    tb: Any,
    *,
    context: dict[str, Any] | None = None,
    cfg: CrashConfig | None = None,
) -> Path | None:
    """Write one crash report (JSON, plus a best-effort human Markdown twin) and
    return the JSON path — or ``None`` if disabled/failed.

    Guaranteed non-throwing: any internal failure is logged and swallowed so the
    original exception is never masked.
    """
    try:
        cfg = resolve(cfg)
        if not cfg.enabled:
            return None
        path = write_report(build_crash_report(exc_type, exc, tb, cfg, context), cfg)
        log.error(f"Crash report written to {path}")
        return path
    except Exception:  # noqa: BLE001 - the handler must never raise over the original error.
        log.exception("Failed to write crash report")
        return None


def write_bug_report(
    context: dict[str, Any] | None = None,
    *,
    cfg: CrashConfig | None = None,
) -> Path | None:
    """Capture the tool's CURRENT live state as a bug report and return the JSON
    path — or ``None`` if disabled/failed.

    For the failure a crash report can never catch: the tool ran to completion,
    exited cleanly, and produced a wrong answer. There is no exception and no
    traceback, so every live thread's frames are captured instead — in a GUI the
    values that explain the wrong answer are usually in a worker thread, not in the
    one that pressed the button.

    Guaranteed non-throwing, like its crash twin: an operator asking for help must
    never be punished with a second failure.
    """
    try:
        cfg = resolve(cfg)
        if not cfg.enabled:
            return None
        path = write_report(build_bug_report(cfg, context), cfg)
        log.info(f"Bug report written to {path}")
        return path
    except Exception:  # noqa: BLE001 - reporting a bug must not itself raise.
        log.exception("Failed to write bug report")
        return None


def capture_exception(
    context: dict[str, Any] | None = None,
    *,
    cfg: CrashConfig | None = None,
) -> Path | None:
    """Write a report for the exception currently being handled (``sys.exc_info``).

    For the broad ``except Exception:`` blocks that log-and-``return`` an exit
    code and so never reach ``sys.excepthook``. The active traceback still holds
    every frame down to the crash site, so all locals are captured.
    """
    exc_type, exc, tb = sys.exc_info()
    if exc is None or exc_type is None:
        return None
    return write_crash_report(exc_type, exc, tb, context=context, cfg=cfg)


_installed = False


def install_excepthook(context: dict[str, Any] | None = None) -> None:
    """Install the crash handler on ``sys.excepthook`` and ``threading.excepthook``,
    chaining the previous hooks so the normal stderr traceback still prints.
    Idempotent."""
    global _installed
    if _installed:
        return

    previous_sys_hook = sys.excepthook

    def _sys_hook(exc_type: type[BaseException], exc: BaseException, tb: Any) -> None:
        write_crash_report(exc_type, exc, tb, context=context)
        previous_sys_hook(exc_type, exc, tb)

    sys.excepthook = _sys_hook

    previous_thread_hook = threading.excepthook

    def _thread_hook(args: threading.ExceptHookArgs) -> None:
        thread_ctx = dict(context or {})
        if args.thread is not None:
            thread_ctx["thread"] = args.thread.name
        if args.exc_value is not None:
            write_crash_report(
                args.exc_type, args.exc_value, args.exc_traceback, context=thread_ctx
            )
        previous_thread_hook(args)

    threading.excepthook = _thread_hook
    _installed = True
