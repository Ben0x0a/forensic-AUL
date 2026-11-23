"""GUI controllers — application logic that drives a view's library calls.

Defines : phrase_failure() — a failure, as the sentence the person looking at the
          form should read, chosen by the exception's TYPE.
Used by : every controller (gui.controllers.*) and the screens' failure handlers.
Uses    : forensic_aul (the error types).

WHY by type and not by text: a failure used to cross the worker thread as a
traceback string; the GUI parsed the exception name out of it and patched the
library's own sentence with ``.replace()``, so any rewording upstream silently
broke the advice. The worker now hands over the exception object.
"""

from __future__ import annotations

from forensic_aul import InvalidDatabaseError, OutputExistsError, SourceError


def phrase_failure(exc: BaseException) -> str:
    """The sentence to show for *exc*. An unrecognised failure keeps its own
    message (with its type), never a vague placeholder that hides the detail."""
    if isinstance(exc, OutputExistsError):
        what = exc.path if exc.path is not None else "The output database"
        return (f"{what} already exists. Tick \u201cOverwrite the output database if it "
                "exists\u201d to replace it.")
    if isinstance(exc, InvalidDatabaseError):
        return f"Not a usable database — {exc}"
    if isinstance(exc, FileNotFoundError):
        return f"File not found — {exc}"
    if isinstance(exc, SourceError):
        return f"Unsupported source — {exc}"
    return f"{type(exc).__name__}: {exc}"
