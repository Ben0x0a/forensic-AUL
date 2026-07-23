"""Reusable progress reporting for long-running operations.

A single, UI-agnostic standard for the whole project. Any long operation
(``extract`` today; ``export`` / ``identify`` / ``verify`` tomorrow) declares
its **weighted phases** once, then reports fractional progress within the
current phase. The reporter turns that into a single overall ``0.0 … 1.0``
fraction and forwards a :class:`ProgressEvent` to a *sink*. The core never
imports a UI — the CLI, the GUI, or a test each supply their own sink.

Design
------
- **Phases with weights** so the overall bar covers the *entire* operation, not
  just its longest loop. Steps that have no natural sub-progress (a monolithic
  SQL statement) simply jump from 0 → 1 within their phase; the weight keeps the
  overall bar moving sensibly.
- **Sink is just a callable** ``Callable[[ProgressEvent], None]``. ``None`` means
  "no progress wanted" and every reporter call becomes a cheap no-op, so callers
  never need ``if progress is not None`` guards around their work.
- **Three ready-made sinks**: :func:`tty_bar_sink` (a live one-line bar, rendered
  only on a real terminal so it never pollutes a pipe or the forensic log file),
  :func:`logging_progress_sink` (emits an INFO line every N %, which lands in
  the audit log) and :func:`callback_progress_sink` (hands formatted lines to a
  plain callable — for hosts with their own logging function). A GUI provides
  its own sink that updates a progress widget.

Example
-------
    reporter = ProgressReporter(sink, [("parse", 0.7), ("write", 0.3)])
    reporter.phase("parse")
    for i, item in enumerate(items, 1):
        ...                                   # do work
        reporter.update(i / len(items), f"{i}/{len(items)}")
    reporter.phase("write")
    ...
    reporter.finish()

Used by : forensic_aul/extract.py (run_extract) and any future long operation;
          launcher/* and gui/* supply sinks.
Uses    : the standard library only.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TextIO

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProgressEvent:
    """One progress notification handed to a sink."""

    overall: float          # 0.0 … 1.0 across all phases (monotonically rising)
    phase: str              # name of the current phase
    phase_fraction: float   # 0.0 … 1.0 within the current phase
    detail: str = ""        # short human detail, e.g. "12/56" or a file name


# A sink consumes events. ``None`` is a valid "no sink" value everywhere.
ProgressSink = Callable[[ProgressEvent], None]


class ProgressReporter:
    """Turns per-phase fractions into a single overall fraction for a sink.

    *phases* is a list of ``(name, weight)``; weights are normalised, so only
    their ratios matter (e.g. ``[("parse", 6), ("finish", 4)]``). A missing or
    ``None`` sink makes every method a no-op.
    """

    def __init__(self, sink: ProgressSink | None, phases: Sequence[tuple[str, float]]) -> None:
        self._sink = sink
        total = sum(w for _, w in phases) or 1.0
        self._weight: dict[str, float] = {name: w / total for name, w in phases}
        self._completed_weight = 0.0   # summed weight of phases already finished
        self._phase: str | None = None
        self._phase_weight = 0.0

    def phase(self, name: str, detail: str = "") -> None:
        """Begin *name*. The previous phase (if any) counts as fully complete."""
        if self._phase is not None:
            self._completed_weight += self._phase_weight
        self._phase = name
        self._phase_weight = self._weight.get(name, 0.0)
        self.update(0.0, detail)

    def update(self, phase_fraction: float, detail: str = "") -> None:
        """Report progress within the current phase (clamped to 0..1)."""
        if self._sink is None:
            return
        frac = 0.0 if phase_fraction < 0.0 else 1.0 if phase_fraction > 1.0 else phase_fraction
        overall = self._completed_weight + self._phase_weight * frac
        self._emit(ProgressEvent(min(overall, 1.0), self._phase or "", frac, detail))

    def finish(self, detail: str = "") -> None:
        """Force the overall fraction to 1.0 (covers any skipped phases)."""
        if self._sink is None:
            return
        self._emit(ProgressEvent(1.0, self._phase or "", 1.0, detail))

    def _emit(self, event: ProgressEvent) -> None:
        # A misbehaving sink must never break the operation it is observing.
        try:
            self._sink(event)  # type: ignore[misc]
        except Exception:  # noqa: BLE001 — progress is cosmetic; swallow + log
            log.debug("progress sink raised", exc_info=True)


# ── Ready-made sinks ──────────────────────────────────────────────────────────

def tty_bar_sink(stream: TextIO | None = None, width: int = 30) -> ProgressSink | None:
    """Return a live one-line bar sink, or ``None`` when *stream* is not a TTY.

    Returning ``None`` off a terminal is deliberate: a carriage-return bar would
    corrupt piped output and interleave with the forensic log file, whereas the
    per-phase INFO log lines already give a recorded trail. So callers can do
    ``ProgressReporter(tty_bar_sink(), …)`` and get a bar interactively and
    nothing at all when redirected.
    """
    out = stream or sys.stderr
    if not hasattr(out, "isatty") or not out.isatty():
        return None

    def sink(event: ProgressEvent) -> None:
        filled = int(width * event.overall)
        bar = "#" * filled + "-" * (width - filled)
        out.write(f"\r[{bar}] {event.overall * 100:5.1f}%  {event.phase:<9} {event.detail:<24}")
        out.flush()
        if event.overall >= 1.0:
            out.write("\n")
            out.flush()

    return sink


def _threshold_sink(emit: Callable[[int, ProgressEvent], None], every_percent: int) -> ProgressSink:
    """Shared crossing logic: call *emit(pct, event)* only on every_percent steps.

    Emits the very first event (start), then each time overall crosses another
    *every_percent* step, and always at 100 %.
    """
    state = {"last": -1}

    def sink(event: ProgressEvent) -> None:
        pct = int(event.overall * 100)
        if state["last"] < 0 or pct >= state["last"] + every_percent or pct >= 100:
            state["last"] = pct
            emit(pct, event)

    return sink


def logging_progress_sink(logger: logging.Logger, every_percent: int = 5) -> ProgressSink:
    """Return a sink that logs an INFO line each time overall crosses *every_percent*.

    Suitable for non-interactive / audited runs: the progress lands in the
    operational log instead of a transient bar.
    """
    return _threshold_sink(
        lambda pct, event: logger.info(f"progress {pct:3}%  {event.phase:<9} {event.detail}"),
        every_percent,
    )


def callback_progress_sink(fn: Callable[[str], None], every_percent: int = 10) -> ProgressSink:
    """Return a sink that hands formatted progress lines to a plain callable.

    Adapter for hosts with their own logging function (a GUI status setter, a
    plugin framework's ``logfunc``, …) that should not have to construct a
    ``logging.Logger`` or understand :class:`ProgressEvent`::

        run_extract(src, db, progress=callback_progress_sink(logfunc))

    *fn* receives one string per emitted step, e.g. ``"progress  40%  parse  12/56"``.
    """
    return _threshold_sink(
        lambda pct, event: fn(f"progress {pct:3}%  {event.phase:<9} {event.detail}".rstrip()),
        every_percent,
    )
