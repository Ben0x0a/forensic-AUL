"""GUI controllers — application logic that drives a view's core-op calls.

Currently holds the pipeline controllers (Acquire, Extract) in ``pipeline.py``.
The lighter data/preferences screens deliberately keep the thin view-only pattern
(see gui.views.screen_base), so they have no controller here.
"""


def last_line(tb: str) -> str:
    """The most informative single line of a traceback string, for the UI.

    Shared by every controller: a worker failure arrives as a formatted
    traceback, and the screens show its final line. One definition so the
    screens cannot disagree about what "the error" is.
    """
    return tb.strip().splitlines()[-1] if tb.strip() else ""
