"""The CLI's evidence-extract session: run one audited extract, return an exit code.

Defines : ``run_extract_session`` — console logging at the requested verbosity,
          ``run_extract`` with ``ExtractOptions(audit_log=True)``, and the mapping
          of its outcome to a process exit code (0 / 1 / 130), with a crash report
          for an unexpected failure.
Used by : launcher.cmds.extract_cmd and launcher.cmds.acquire_cmd (``acquire
          --extract``), so both commands produce the same sealed audit log.
Uses    : forensic_aul (run_extract, the option types, the errors),
          app.logging_config (console), app.diagnostics (crash report).

WHY so little is left here: the audit log and its seal are part of the evidence,
so they live in the library (forensic_aul/ops/extraction/audit.py), where the GUI
and third-party callers get the same artefact. What stays is CLI-only: exit codes.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path

from forensic_aul import (
    CaseInfo,
    ExtractOptions,
    ExtractStatus,
    ForensicAULError,
    OperationCancelled,
    run_extract,
)
from forensic_aul import NEVER_CANCELLED, CancelToken
from forensic_aul import ProgressSink

from app.logging_config import configure_console

log = logging.getLogger(__name__)


def run_extract_session(
    *,
    logarchive: Path | Mapping[str, Path],
    db_path: Path,
    case: CaseInfo,
    opts: ExtractOptions,
    verbose: bool = False,
    progress: ProgressSink | None = None,
    cancel: CancelToken = NEVER_CANCELLED,
) -> int:
    """Run one evidence extract and return a process exit code (0 / 1 / 130).

    The library writes, reports and seals the audit log on every exit path; this
    only maps the outcome. A cancellation (the CLI's Ctrl+C) exits 130; an extract
    whose status is FAILED (nothing decodable) exits 1.
    """
    configure_console(verbose=verbose)
    try:
        result = run_extract(logarchive, db_path, case, replace(opts, audit_log=True),
                             progress=progress, cancel=cancel)
    except (OperationCancelled, KeyboardInterrupt):
        return 130
    except ForensicAULError:
        return 1  # already logged by the library, without a traceback
    except Exception:
        # Capture a crash report (all frame locals) before the traceback is lost —
        # this handler swallows the exception and returns, so sys.excepthook never
        # sees it. The library has already logged it into the audit log.
        from app.diagnostics import capture_exception
        capture_exception({"entrypoint": "cli", "op": "extract"})
        return 1
    # FAILED = nothing decodable: the database is kept (and its log sealed), but
    # the command did not do its job, so a script must see a non-zero code.
    return 1 if result.status is ExtractStatus.FAILED else 0
