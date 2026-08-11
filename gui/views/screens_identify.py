"""Identify wizard view: the interactive action-attribution workflow.

Defines : IdentifyScreen — a step-by-step wizard that acquires a still baseline,
          waits for the operator to perform an action, acquires again, and diffs
          the two so only lines attributable to the action remain. It is a
          **view**: widget construction, input getters and display methods only.
          The logic (validation, the async run, and the two operator pauses) lives
          in gui.controllers.identify; this module imports no ``forensic_aul.ops``.
Used by : gui.views.shell (stacked screens).
Uses    : PySide6, gui.controllers.identify, gui.views.screen_base,
          gui.widgets.components, gui.widgets.device_picker,
          gui.widgets.path_picker.

WHY a plain-enum state machine (no QStackedWidget): the wizard toggles a handful
of section panels by state, exactly as ExtractScreen shows/hides its progress and
action rows. A stacked widget would add navigation machinery for five sections
that are simpler to just show/hide in place.
"""

from __future__ import annotations

from enum import Enum, auto
from typing import Any

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QHBoxLayout, QProgressBar, QVBoxLayout

from gui.controllers.identify import IdentifyController
from gui.recent_store import RecentStore
from gui.settings_store import SettingsStore
from gui.views.screen_base import OperationScreen
from gui.widgets.components import (
    ComboBox,
    Panel,
    Pill,
    clear_layout,
    eyebrow,
    ghost_button,
    h2,
    help_label,
    mono,
    mono_input,
    primary_button,
    result_panel,
    style_combo,
    subtitle,
    field_row,
    h1,
)
from gui.widgets.device_picker import DevicePicker
from gui.widgets.path_picker import PathPicker


class _State(Enum):
    """The wizard's mutually-exclusive sections (only one is shown at a time)."""

    SETUP = auto()
    STILL = auto()
    RUNNING = auto()
    WAITING = auto()
    DONE = auto()


# The seven visible steps, in order. Consumed by _build_steps / _highlight_step.
_STEPS = ["Setup", "Still", "Baseline", "Action", "Post-action", "Extract", "Results"]

# Map a workflow ``ProgressEvent.phase`` name onto the step it belongs to, so the
# step indicator can light up as the run advances. Kept in ONE place (the engine's
# phase names come from workflow._IDENTIFY_PHASES). Unknown/absent phases leave the
# current highlight unchanged.
_PHASE_TO_STEP = {
    "connect": "Setup",
    "still": "Still",
    "baseline": "Baseline",
    "wait": "Action",
    "action": "Post-action",
    "extract-baseline": "Extract",
    "extract-action": "Extract",
    "annotate": "Extract",
    "diff": "Extract",
    "finish": "Results",
    "complete": "Results",
}

# Still-duration options offered in the setup combo: label → seconds. Default 1 min.
_STILL_CHOICES = [("Skip (no wait)", 0), ("30 seconds", 30), ("1 minute", 60),
                  ("2 minutes", 120), ("5 minutes", 300)]


class IdentifyScreen(OperationScreen):
    """The Identify wizard — setup → still → run → action → results."""

    screen_id = "identify"

    # Re-exported so the controller can reference states without importing _State.
    SETUP = _State.SETUP
    STILL = _State.STILL
    RUNNING = _State.RUNNING
    WAITING = _State.WAITING
    DONE = _State.DONE

    def __init__(self, settings: SettingsStore, recents: RecentStore) -> None:
        super().__init__()
        self._settings = settings
        self._recents = recents
        self.navigate = None  # set by the shell
        self._ctrl = IdentifyController(self, recents)
        self.progressChanged.connect(self._on_progress)

        self.content.addWidget(eyebrow("Identify"))
        self.content.addWidget(h1("Identify an action"))
        self.content.addWidget(subtitle(
            "Acquire a still baseline, perform one action on the device, then "
            "acquire again — the diff keeps only the log lines the action caused."
        ))

        self._steps = self._build_steps()
        self.content.addLayout(self._steps_row)

        self._build_setup()
        self._build_still()
        self._build_running()
        self._build_waiting()

        # Result/DONE host — filled in show_result / on the DONE state.
        self.content.addLayout(self.make_result_host())
        self._done_host = QVBoxLayout()
        self.content.addLayout(self._done_host)

        self.content.addStretch(1)
        self.set_state(_State.SETUP)

    # ── Step indicator ────────────────────────────────────────────────────────────

    def _build_steps(self) -> dict[str, Pill]:
        self._steps_row = QHBoxLayout()
        self._steps_row.setSpacing(6)
        pills: dict[str, Pill] = {}
        for name in _STEPS:
            pill = Pill(name, "neutral")
            pills[name] = pill
            self._steps_row.addWidget(pill)
        self._steps_row.addStretch(1)
        return pills

    def _highlight_step(self, step: str) -> None:
        """Give *step*'s pill the 'ok' role, all others the neutral default."""
        for name, pill in self._steps.items():
            pill.setProperty("pill", "ok" if name == step else "neutral")
            pill.style().unpolish(pill)
            pill.style().polish(pill)

    # ── Setup section ─────────────────────────────────────────────────────────────

    def _build_setup(self) -> None:
        self._setup_panel = Panel()
        self._setup_panel.add(h2("Setup"))
        self._device = DevicePicker()
        self._device.rescanRequested.connect(self._ctrl.rescan)
        self._setup_panel.add(field_row("Device", self._device, required=True))

        self._session = mono_input("identify-<UTC> when empty")
        self._setup_panel.add(field_row("Session label", self._session))

        self._still = ComboBox()
        for label, seconds in _STILL_CHOICES:
            self._still.addItem(label, seconds)
        self._still.setCurrentIndex(2)  # default: 1 minute
        style_combo(self._still)
        self._setup_panel.add(field_row("Still duration", self._still))

        self._out = PathPicker("dir", placeholder="output folder for the artefacts")
        self._setup_panel.add(field_row("Output folder", self._out, required=True))

        row = QHBoxLayout()
        row.addStretch(1)
        self._start_btn = primary_button("Start")
        self._start_btn.clicked.connect(self._ctrl.start)
        row.addWidget(self._start_btn)
        self._setup_panel.body.addLayout(row)
        self.content.addWidget(self._setup_panel)

    # ── Still section ─────────────────────────────────────────────────────────────

    def _build_still(self) -> None:
        self._still_panel = Panel(elev=True)
        self._still_panel.add(help_label(
            "Leave the device untouched while the baseline captures a quiet device."
        ))
        self._countdown = mono("")
        self._still_panel.add(self._countdown)
        row = QHBoxLayout()
        row.addStretch(1)
        skip = ghost_button("Skip wait")
        skip.clicked.connect(self._ctrl.skip_still)
        abort = ghost_button("Abort")
        abort.clicked.connect(self._ctrl.abort)
        row.addWidget(skip)
        row.addWidget(abort)
        self._still_panel.body.addLayout(row)
        self.content.addWidget(self._still_panel)

    # ── Running section (progress) ────────────────────────────────────────────────

    def _build_running(self) -> None:
        self._running_panel = Panel()
        self._running_title = h2("Working…")
        self._running_panel.add(self._running_title)
        self._bar = QProgressBar()
        self._bar.setRange(0, 100)
        self._bar.setTextVisible(False)
        self._running_panel.add(self._bar)
        self._progress_label = help_label("")
        self._running_panel.add(self._progress_label)
        self.content.addWidget(self._running_panel)

    # ── Waiting-for-action section ────────────────────────────────────────────────

    def _build_waiting(self) -> None:
        self._waiting_panel = Panel(elev=True)
        self._waiting_panel.add(h2("Perform the action on the device now."))
        self._waiting_panel.add(help_label(
            "Do the single thing you want to attribute, then continue."
        ))
        row = QHBoxLayout()
        row.addStretch(1)
        cont = primary_button("Action performed — continue", "right")
        cont.clicked.connect(self._ctrl.continue_action)
        abort = ghost_button("Abort")
        abort.clicked.connect(self._ctrl.abort)
        row.addWidget(cont)
        row.addWidget(abort)
        self._waiting_panel.body.addLayout(row)
        self.content.addWidget(self._waiting_panel)

    # ── Input getters (read by the controller) ────────────────────────────────────

    def selected_udid(self) -> str | None:
        return self._device.selected_udid()

    def session_label(self) -> str:
        return self._session.text().strip()

    def still_seconds(self) -> int:
        return self._still.currentData()

    def output_path(self) -> str:
        return self._out.path()

    # ── Device display (delegated to the picker; used by the controller) ──────────

    def set_device_scanning(self) -> None:
        self._device.set_scanning()

    def set_devices(self, devices: list[Any]) -> None:
        self._device.set_devices(devices)

    def set_device_scan_failed(self) -> None:
        self._device.set_scan_failed()

    # ── State machine (driven by the controller) ──────────────────────────────────

    def set_state(self, state: _State, result: Any = None) -> None:
        """Show only the section for *state*; on DONE, render the result summary."""
        self._setup_panel.setVisible(state is _State.SETUP)
        self._still_panel.setVisible(state is _State.STILL)
        self._running_panel.setVisible(state in (_State.RUNNING, _State.STILL, _State.WAITING))
        self._waiting_panel.setVisible(state is _State.WAITING)

        if state is _State.SETUP:
            self._highlight_step("Setup")
            clear_layout(self._done_host)
        elif state is _State.RUNNING:
            self.clear_result()
            self._bar.setValue(0)
        elif state is _State.DONE:
            self._highlight_step("Results")
            self.clear_result()
            self._show_done(result)

    def set_countdown(self, text: str) -> None:
        self._countdown.setText(text)


    # ── DONE rendering ────────────────────────────────────────────────────────────

    def _show_done(self, result: Any) -> None:
        clear_layout(self._done_host)
        diff = result.diff
        counts = None
        try:
            from forensic_aul import IdentifyResults

            with IdentifyResults(diff.sqlite_path) as res:
                counts = res.counts()
        except Exception:  # noqa: BLE001 — the summary falls back to diff counts
            counts = None
        if counts is not None:
            summary = (
                f"{counts.retained} retained · {counts.noise} background noise · "
                f"{counts.kb_known} KB-known"
            )
        else:
            summary = f"{diff.retained} retained · {diff.excluded} background noise"
        panel = result_panel(
            True,
            f"Identify complete — {summary}"
            f"<br><span style='color:#545a68'>{diff.sqlite_path}</span>",
        )
        self._done_host.addWidget(panel)

        row = QHBoxLayout()
        row.addStretch(1)
        view_btn = primary_button("View results", "right")
        view_btn.clicked.connect(lambda: self._open_results(diff.sqlite_path))
        reveal_btn = ghost_button("Reveal in folder", "folder")
        reveal_btn.clicked.connect(self._reveal_output)
        new_btn = ghost_button("New run", "plus")
        new_btn.clicked.connect(lambda: self.set_state(_State.SETUP))
        for btn in (view_btn, reveal_btn, new_btn):
            row.addWidget(btn)
        self._done_host.addLayout(row)

    def _open_results(self, db_path: Any) -> None:
        if self.navigate:
            self.navigate("identify", prefill={"tab": "results", "db": str(db_path)})

    def _reveal_output(self) -> None:
        out = self.output_path()
        if out:
            QDesktopServices.openUrl(QUrl.fromLocalFile(out))

    # ── Progress relay (GUI thread; countdown rides the detail label) ─────────────

    def _on_progress(self, fraction: float, label: str) -> None:
        # The still countdown is carried on the detail label as ``still:<n>`` with
        # a -1 fraction (see IdentifyController.wait_still). A -1 fraction means
        # "leave the bar" — only the countdown QLabel updates.
        if label.startswith("still:"):
            self.set_state(_State.STILL)
            remaining = label.split(":", 1)[1]
            self.set_countdown(f"Hold still — {remaining}s remaining")
            self._highlight_step("Still")
            return
        if fraction < 0:
            return
        step = _PHASE_TO_STEP.get(label)
        if step is not None:
            self._highlight_step(step)
        # The engine fires the "wait" phase just before blocking for the action,
        # so switch to the WAITING panel as soon as we see it.
        if label == "wait":
            self.set_state(_State.WAITING)
        elif self._waiting_panel.isVisible() and label not in ("wait",):
            # A later phase (post-action acquisition) means the operator continued.
            self.set_state(_State.RUNNING)
        self._bar.setValue(int(fraction * 100))
        self._progress_label.setText(f"{fraction * 100:.1f}% · {label}")
