"""The one "something is wrong" control: its caption, and what pressing it does.

Defines : ``pending_action`` (which of the two states the control is in),
          ``caption`` / ``tooltip`` (its label), and ``perform`` (open the report
          folder, or file a bug report and reveal it).
Used by : gui.views.shell (the Preferences submenu entry). Any other shell that
          grows the same control calls THIS, never a hand-copied twin.
Uses    : app.diagnostics (``list_reports``, ``write_bug_report``) and PySide6's
          ``QDesktopServices`` for the platform file-manager hand-off.

WHY one control and not two: it answers a single operator question — "something is
wrong, how do I hand it over?" — and only one answer is ever right at a given
moment. If the tool has already written error reports, the useful action is to open
them; if it has not, nothing has been captured yet and the useful action is to
capture the live state now. Two buttons would make the operator choose between an
empty folder and a redundant snapshot.

WHY this lives in its own module rather than inline in the shell: the CLI grows the
same control eventually, and a hand-copied twin drifts the moment one side learns
something the other does not.
"""

from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices

_LOG = logging.getLogger(__name__)

# The two states of the single control.
OPEN_ERRORS = "open-errors"
FILE_BUG = "file-bug"

_CAPTIONS = {
    OPEN_ERRORS: "Open error reports",
    FILE_BUG: "Report bug…",
}

_TOOLTIPS = {
    OPEN_ERRORS: "Open the folder holding this workstation's error reports. Redact "
                 "one with `faul.py redact-errors <name>` before sharing it.",
    FILE_BUG: "Capture what the tool is doing right now — every thread's variables — "
              "into a report you can redact and attach to a bug.",
}


def pending_action(report_dir: Path | None = None) -> str:
    """``OPEN_ERRORS`` when this workstation has error reports, else ``FILE_BUG``.

    Counts ERROR reports only. Counting bug reports too would be self-fulfilling:
    filing one would flip the control to "Open error reports", so the tool would
    claim it had errored purely because the operator asked a question.
    """
    from app.diagnostics import KIND_CRASH, list_reports

    return OPEN_ERRORS if list_reports(report_dir, kind=KIND_CRASH) else FILE_BUG


def caption(action: str) -> str:
    return _CAPTIONS.get(action, _CAPTIONS[FILE_BUG])


def tooltip(action: str) -> str:
    return _TOOLTIPS.get(action, _TOOLTIPS[FILE_BUG])


def _reveal(target: Path) -> None:
    """Show *target* (or its folder, for a file) in the platform file manager.

    ``QDesktopServices`` rather than a per-OS subprocess: Qt already knows how to
    hand a path to Finder / Explorer / the XDG handler, and the built-in cannot get
    the quoting wrong on a path with spaces.
    """
    folder = target if target.is_dir() else target.parent
    if not QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder))):
        _LOG.warning(f"Could not open the file manager for {folder}")


def perform(action: str | None = None, *, report_dir: Path | None = None) -> Path | None:
    """Run the control's action and return the path the operator was shown.

    *action* defaults to whatever :func:`pending_action` says right now, so a caller
    that only wants "do the right thing" need not ask twice. Never raises: the whole
    point is to help an operator who is already having a bad time.
    """
    from app.diagnostics import CrashConfig, write_bug_report

    resolved = action or pending_action(report_dir)
    directory = report_dir if report_dir is not None else CrashConfig().crash_dir

    if resolved == OPEN_ERRORS:
        if directory.is_dir():
            _reveal(directory)
            return directory
        _LOG.warning(f"No report directory at {directory}")
        return None

    path = write_bug_report({"entrypoint": "gui", "op": "manual-bug-report"})
    if path is not None:
        _reveal(path)
    return path
