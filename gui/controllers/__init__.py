"""GUI controllers — application logic that drives a view's core-op calls.

Defines : last_line() — the most informative line of a worker traceback;
          phrase_failure() — rewrites that line for the person looking at the
          form, via a small exception-type-name → phrasing map.
Used by : gui.controllers.pipeline (AcquireController, ExtractController) and
          gui.views.screens_data (ExportScreen, VerifyHashScreen — the lighter
          screens have no controller of their own; see gui.views.screen_base).
Uses    : the standard library only.

Currently holds the pipeline controllers (Acquire, Extract) in ``pipeline.py``.
The lighter data/preferences screens deliberately keep the thin view-only pattern
(see gui.views.screen_base), so they have no controller here.
"""

from __future__ import annotations

from collections.abc import Callable


def last_line(tb: str) -> str:
    """The most informative single line of a traceback string, for the UI.

    Shared by every controller: a worker failure arrives as a formatted
    traceback, and the screens show its final line. One definition so the
    screens cannot disagree about what "the error" is.
    """
    return tb.strip().splitlines()[-1] if tb.strip() else ""


# Exception type name (bare, no module prefix — see phrase_failure) → a rewrite
# of that exception's own message for the person looking at the form, not a
# Python caller. Consumed by: phrase_failure.
# WHY keyed by name rather than the class itself: the traceback crosses the
# worker thread as *text* (gui.workers.base.Worker only emits the formatted
# string), so there is no exception object left to isinstance() against.
_ERROR_PHRASING: dict[str, Callable[[str], str]] = {
    # run_extract's own message is written for a Python caller ("pass
    # overwrite=True"); recast that one sentence to point at the GUI's
    # checkbox instead. .replace() is a no-op (message shown verbatim, still
    # honest) if the upstream wording ever drifts — see phrase_failure's
    # docstring on never hiding the detail.
    "FileExistsError": lambda msg: msg.replace(
        "pass overwrite=True to replace it",
        'tick "Overwrite the output database if it exists" to replace it',
    ),
    "InvalidDatabaseError": lambda msg: f"Not a usable database — {msg}",
    "FileNotFoundError": lambda msg: f"File not found — {msg}",
    "SourceError": lambda msg: f"Unsupported source — {msg}",
}


def phrase_failure(tb: str) -> str:
    """Rewrite a worker traceback's last line for the person looking at the form.

    Parses the exception type off the last line (``ExceptionType: message``,
    stripping any module prefix such as ``forensic_aul.errors.``) and, if it is
    one of the types in ``_ERROR_PHRASING``, rewords the message for the GUI.
    Anything unmapped — or not an ``ExceptionType: message`` line at all — falls
    through to the raw last line unchanged: an unrecognised failure must still
    show its real message, never a vague placeholder that hides the detail.
    """
    line = last_line(tb)
    if not line:
        return ""
    exc_name, sep, message = line.partition(":")
    if not sep:
        return line
    phraser = _ERROR_PHRASING.get(exc_name.rsplit(".", 1)[-1].strip())
    return phraser(message.strip()) if phraser else line
