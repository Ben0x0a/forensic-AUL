"""Unit tests for the reusable progress standard (forensic_aul/engine/utils/progress.py)."""

from __future__ import annotations

import io
import logging

from forensic_aul.engine.utils.progress import (
    ProgressEvent,
    ProgressReporter,
    logging_progress_sink,
    tty_bar_sink,
)


def test_none_sink_is_noop():
    r = ProgressReporter(None, [("a", 1.0)])
    r.phase("a")
    r.update(0.5)
    r.finish()  # must not raise


def test_phase_weighting_and_overall():
    events: list[ProgressEvent] = []
    r = ProgressReporter(events.append, [("a", 3.0), ("b", 1.0)])  # weights 0.75 / 0.25
    r.phase("a")
    r.update(0.5)          # 0.75 * 0.5 = 0.375
    r.phase("b")           # phase a now fully done → 0.75
    r.update(0.5)          # 0.75 + 0.25*0.5 = 0.875
    r.finish()             # 1.0

    overalls = [round(e.overall, 3) for e in events]
    assert overalls[0] == 0.0      # phase("a") emits 0
    assert 0.375 in overalls
    assert 0.75 in overalls        # phase("b") start
    assert 0.875 in overalls
    assert overalls[-1] == 1.0
    assert all(0.0 <= e.overall <= 1.0 for e in events)


def test_update_clamps():
    events: list[ProgressEvent] = []
    r = ProgressReporter(events.append, [("a", 1.0)])
    r.phase("a")
    r.update(5.0)   # clamps to 1.0
    r.update(-3.0)  # clamps to 0.0
    assert events[-2].phase_fraction == 1.0
    assert events[-1].phase_fraction == 0.0


def test_sink_exception_is_swallowed():
    def boom(_ev):
        raise RuntimeError("sink failed")
    r = ProgressReporter(boom, [("a", 1.0)])
    r.phase("a")
    r.update(0.5)   # must not propagate — progress is cosmetic
    r.finish()


def test_tty_bar_sink_none_when_not_tty():
    assert tty_bar_sink(io.StringIO()) is None  # StringIO.isatty() is False


def test_tty_bar_sink_renders_on_fake_tty():
    class FakeTTY(io.StringIO):
        def isatty(self):
            return True
    out = FakeTTY()
    sink = tty_bar_sink(out, width=10)
    assert sink is not None
    sink(ProgressEvent(0.5, "parse", 0.5, "1/2"))
    sink(ProgressEvent(1.0, "parse", 1.0, "done"))
    text = out.getvalue()
    assert "50.0%" in text and "100.0%" in text
    assert text.endswith("\n")  # newline on completion


def test_logging_progress_sink_steps(caplog):
    logger = logging.getLogger("test.progress")
    sink = logging_progress_sink(logger, every_percent=25)
    with caplog.at_level(logging.INFO, logger="test.progress"):
        for f in (0.0, 0.1, 0.25, 0.3, 0.5, 1.0):
            sink(ProgressEvent(f, "x", f, ""))
    pcts = [r.message for r in caplog.records]
    # Emits at 0, 25, 50, 100 (not 10 or 30 — below the next 25% step).
    assert len(pcts) == 4


def test_callback_progress_sink_formats_and_thresholds():
    from forensic_aul.engine.utils.progress import ProgressEvent, callback_progress_sink

    lines: list[str] = []
    sink = callback_progress_sink(lines.append, every_percent=50)
    sink(ProgressEvent(0.0, "parse", 0.0, "start"))    # first event always emits
    sink(ProgressEvent(0.10, "parse", 0.1, ""))        # below threshold — dropped
    sink(ProgressEvent(0.55, "parse", 0.55, "12/56"))  # crosses 50 %
    sink(ProgressEvent(1.0, "index", 1.0, ""))         # 100 % always emits
    assert len(lines) == 3
    assert lines[0].startswith("progress   0%")
    assert "12/56" in lines[1] and "parse" in lines[1]
    assert lines[2].startswith("progress 100%")


def test_progress_types_are_public():
    import forensic_aul

    for name in ("ProgressEvent", "ProgressSink", "callback_progress_sink",
                 "logging_progress_sink", "tty_bar_sink"):
        assert hasattr(forensic_aul, name)
        assert name in forensic_aul.__all__
