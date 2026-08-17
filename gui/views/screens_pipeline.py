"""Pipeline views: Acquire (step 1) and Extract (step 2).

Defines : AcquireScreen — collects a ``.logarchive`` from a connected device;
          ExtractScreen — parses an archive into SQLite with inline progress and
          terminal actions. Both are **views**: widget construction, input getters
          and display methods only. The application logic (validation, core-op
          invocation, results, device scan, acquisition-sidecar auto-fill) lives in
          gui.controllers.pipeline; these views import no ``forensic_aul.ops``.
Used by : gui.views.shell (stacked screens).
Uses    : PySide6, gui.controllers.pipeline, gui.views.screen_base,
          gui.widgets.components, gui.widgets.path_picker,
          forensic_aul.engine.utils.system (host core count for the jobs dropdown).

Note on case metadata: the mockup gathers case identity in Acquire and treats
later steps as independent. ``run_extract`` nonetheless *requires* a case number
and IMEI, so Extract carries a compact "Case metadata" panel — the functional
price of keeping each step independently runnable.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QWidget,
)

from forensic_aul.engine.utils.system import physical_cpu_count
from gui.controllers.pipeline import AcquireController, ExtractController
from gui.recent_store import RecentStore
from gui.settings_store import SettingsStore
from gui.views.screen_base import OperationScreen, RecentList
from gui.widgets.components import (
    ComboBox,
    Divider,
    Panel,
    _repolish,
    clear_layout,
    eyebrow,
    ghost_button,
    mono_input,
    primary_button,
    field_row,
    h1,
    h2,
    help_label,
    style_combo,
    subtitle,
)
from gui.widgets.device_picker import DevicePicker
from gui.widgets.path_picker import PathPicker

_DB_FILTER = "SQLite database (*.db *.sqlite *.sqlite3);;All files (*)"

# Candidate parser-job counts offered in the Extract dropdown. WHY this subset
# (not a free 0-256 spinbox): benchmarking showed parse throughput plateaus at ~6
# and regresses past 8, so exposing arbitrary values invites slower, memory-hungry
# choices. The list is filtered to the host's physical core count at build time,
# and "Auto" (data=0) defers to resolve_auto_jobs() in the controller.
_JOB_CHOICES = (1, 2, 4, 6, 8)


def _job_options() -> list[int]:
    """Return the offered job counts, capped at the host's physical cores.

    Always includes 1 (serial) so the dropdown is never empty on a single-core
    host; values above the core count are dropped because spawning more workers
    than cores only adds memory pressure without parse speed.
    """
    cores = physical_cpu_count()
    options = [n for n in _JOB_CHOICES if n <= cores]
    return options or [1]


# ── Acquire ───────────────────────────────────────────────────────────────────

class AcquireScreen(OperationScreen):
    """Step 1 view — collect a .logarchive from a connected iOS device."""

    screen_id = "acquire"

    def __init__(self, settings: SettingsStore, recents: RecentStore) -> None:
        super().__init__()
        self._settings = settings
        self._recents = recents
        self.navigate = None  # set by the shell
        self._ctrl = AcquireController(self, recents)

        self.content.addWidget(eyebrow("Acquire"))
        self.content.addWidget(h1("New acquisition"))
        self.content.addWidget(subtitle(
            "Connect a device and collect a .faul container — the logarchive plus its "
            "chain-of-custody sidecar in one portable, timestamped, hashed file."
        ))

        if self._settings.get("recentDb"):
            recent_panel = Panel()
            recent_panel.add(h2("Recent acquisitions"))
            recent_panel.add(RecentList(
                self._recents.get("acquire"), on_pick=self._pick_output))
            self.content.addWidget(recent_panel)

        form = Panel()
        form.add(h2("Case information"))
        self._case = mono_input("CASE-2026-0001")
        self._exhibit = mono_input("EX-001-A")
        self._analyst = QLineEdit()
        self._notes = QLineEdit()
        self._notes.setPlaceholderText("Context, collection conditions…")
        form.add(field_row("Case no.", self._case, required=True))
        form.add(field_row("Exhibit", self._exhibit))
        form.add(field_row("Analyst", self._analyst, required=True))
        form.add(field_row("Notes", self._notes))
        form.add(Divider())

        form.add(h2("Source"))
        # Device enumeration extracted to a shared DevicePicker (reused by the
        # Identify wizard). The picker only announces a rescan request; the
        # controller runs the async scan and drives the picker's setters.
        self._device = DevicePicker()
        self._device.rescanRequested.connect(self._ctrl.rescan)
        form.add(field_row("Device", self._device, required=True))

        self._out = PathPicker("dir", placeholder="output folder for the .faul")
        form.add(field_row("Output folder", self._out, required=True))
        self.content.addWidget(form)

        self.content.addLayout(self.make_result_host())

        actions = QHBoxLayout()
        actions.addStretch(1)
        self._reset_btn = ghost_button("Clear")
        self._reset_btn.clicked.connect(self._ctrl.reset)
        self._start_btn = primary_button("Start acquisition")
        self._start_btn.clicked.connect(self._ctrl.start)
        # Accent shortcut shown only after a successful run: jumps to Extract with
        # the case metadata and the just-collected logarchive path pre-filled.
        self._continue_btn = primary_button("Continue to Extract", "right")
        self._continue_btn.setVisible(False)
        self._continue_btn.clicked.connect(self._ctrl.continue_to_extract)
        actions.addWidget(self._reset_btn)
        actions.addWidget(self._start_btn)
        actions.addWidget(self._continue_btn)
        self.content.addLayout(actions)
        self.content.addStretch(1)

    # ── Input getters (read by the controller) ───────────────────────────────────

    def case_text(self) -> str:
        return self._case.text().strip()

    def exhibit_text(self) -> str:
        return self._exhibit.text().strip()

    def analyst_text(self) -> str:
        return self._analyst.text().strip()

    def notes_text(self) -> str:
        return self._notes.text().strip()

    def output_path(self) -> str:
        return self._out.path()

    def device_udid(self) -> Any:
        return self._device.selected_udid()

    # ── Display methods (driven by the controller) ───────────────────────────────

    def _pick_output(self, path: str) -> None:
        self._out.set_path(path)

    def set_device_scanning(self) -> None:
        self._device.set_scanning()

    def set_devices(self, devices: list[Any]) -> None:
        self._device.set_devices(devices)

    def set_device_scan_failed(self) -> None:
        self._device.set_scan_failed()

    def set_running(self, running: bool) -> None:
        self._start_btn.setEnabled(not running)
        self._start_btn.setText("Acquiring…" if running else "Start acquisition")

    def set_continue_visible(self, visible: bool) -> None:
        self._continue_btn.setVisible(visible)
        # One button language: only the row's forward action may be primary
        # (violet). Once "Continue to Extract" appears as that forward action,
        # demote "Start acquisition" to ghost so the two don't compete; restore
        # it to primary when the shortcut is hidden again (a fresh run or a
        # form reset — see AcquireController.reset()).
        self._start_btn.setProperty("variant", "ghost" if visible else "primary")
        _repolish(self._start_btn)

    def clear_form(self) -> None:
        for edit in (self._case, self._exhibit, self._analyst, self._notes):
            edit.clear()
        self._out.set_path("")


# ── Extract ───────────────────────────────────────────────────────────────────

class ExtractScreen(OperationScreen):
    """Step 2 view — parse an archive into a normalised SQLite database."""

    screen_id = "extract"

    def __init__(self, settings: SettingsStore, recents: RecentStore) -> None:
        super().__init__()
        # This screen deliberately has no "Recent databases" list — see the
        # Output section below. It reads *settings* for the default parser-job
        # count only.
        self._settings = settings
        self.navigate = None
        self._ctrl = ExtractController(self, recents)
        self.progressChanged.connect(self._on_progress)

        self.content.addWidget(eyebrow("Extract"))
        self.content.addWidget(h1("Extract to SQLite"))
        self.content.addWidget(subtitle(
            "Parse a .logarchive folder, a sysdiagnose .tar.gz, a .faul container, or a "
            "full-file-system .zip into a normalised SQLite database. The source is "
            "picked explicitly; a .faul auto-fills the case fields from its sidecar."
        ))

        form = Panel()
        form.add(h2("Archive to extract"))
        self._src = PathPicker("file", placeholder="logarchive folder / .tar.gz / .faul / .zip")
        form.add(field_row("Source", self._src, required=True))
        form.add(_indented_help(
            "Drag a .logarchive folder onto the field, or Browse for a .tar.gz / .faul / .zip."))
        # Note shown when a matching acquisition sidecar is found and case fields
        # are auto-filled; hidden otherwise. Driven by the controller via set_sidecar_note.
        self._sidecar_note = help_label("")
        self._sidecar_note.setVisible(False)
        form.add(_indent_widget(self._sidecar_note))
        # Any source change (typed, dropped, or Browsed) → controller sidecar scan.
        self._src.edit.textChanged.connect(self._ctrl.on_source_changed)
        form.add(Divider())

        form.add(h2("Output"))
        # WHY no "Recent databases" picker here (review item G8): the Acquire
        # and Export screens' recents list an existing path to *reopen*; on this
        # screen a recent entry is a finished case.sqlite, which is never a
        # sensible autofill for a *destination* path — one Overwrite tick away
        # from clobbering a previous case. It is not a sensible Source pick
        # either (a finished SQLite DB, not a raw logarchive/.tar.gz/.zip).
        # Least-surprising fix: this screen has no recents list at all.
        self._out = PathPicker("save", placeholder="case.sqlite", name_filter=_DB_FILTER)
        form.add(field_row("SQLite DB", self._out, required=True))
        form.add(Divider())

        form.add(h2("Case metadata"))
        self._case = mono_input("CASE-2026-0001")
        self._imei = mono_input("device IMEI")
        self._exhibit = mono_input()
        self._analyst = QLineEdit()
        self._notes = QLineEdit()
        self._notes.setPlaceholderText("Context, collection conditions…")
        form.add(field_row("Case no.", self._case, required=True))
        form.add(field_row("IMEI", self._imei, required=True))
        form.add(field_row("Exhibit", self._exhibit))
        form.add(field_row("Analyst", self._analyst))
        form.add(field_row("Notes", self._notes))
        form.add(Divider())

        form.add(h2("Options"))
        # A curated dropdown rather than a free number box: "Auto" (data=0) lets the
        # controller pick a memory-aware default; explicit choices are capped at the
        # physical core count (see _job_options).
        self._jobs = ComboBox()
        self._jobs.addItem("Auto (recommended)", 0)
        for n in _job_options():
            self._jobs.addItem("1 core (serial)" if n == 1 else f"{n} cores", n)
        # Pre-select the analyst's default (0 = Auto). A configured value the
        # host cannot offer — a settings file carried from a bigger machine —
        # simply leaves Auto selected rather than inventing a core count.
        preferred = self._settings.get_int("extractJobs")
        if preferred:
            index = self._jobs.findData(preferred)
            if index >= 0:
                self._jobs.setCurrentIndex(index)
        style_combo(self._jobs)
        form.add(field_row("Parser jobs", self._jobs))
        self._fast_fts = QCheckBox("Defer full-text index (faster, builds on first search)")
        # On by default: same final database, far less write amplification on big archives.
        self._fast_fts.setChecked(True)
        self._fast_write = QCheckBox("Relax durability for speed (--fast-write)")
        self._overwrite = QCheckBox("Overwrite the output database if it exists")
        for box in (self._fast_fts, self._fast_write, self._overwrite):
            form.add(box)

        # KB annotation — present but disabled (ROADMAP: lands in v3).
        annotate = QCheckBox("Annotate with Knowledge Base")
        annotate.setEnabled(False)
        annotate.setToolTip("Available in v3")
        kb_row = QWidget()
        kb_layout = QHBoxLayout(kb_row)
        kb_layout.setContentsMargins(0, 0, 0, 0)
        kb_layout.setSpacing(8)
        kb_layout.addWidget(annotate)
        # Plain muted text rather than a Pill badge: the boxed pill's border +
        # padding bumped the row's line height out of line with the other options.
        kb_layout.addWidget(help_label("v3"))
        kb_layout.addStretch(1)
        form.add(kb_row)
        self.content.addWidget(form)

        # Inline progress (hidden until a run starts).
        self._progress_panel = Panel()
        self._progress_title = h2("Extracting…")
        self._progress_panel.add(self._progress_title)
        self._bar = QProgressBar()
        self._bar.setRange(0, 100)
        self._bar.setTextVisible(False)
        self._progress_panel.add(self._bar)
        self._progress_label = help_label("")
        self._progress_panel.add(self._progress_label)
        self._progress_panel.setVisible(False)
        self.content.addWidget(self._progress_panel)

        self.content.addLayout(self.make_result_host())

        self._actions = QHBoxLayout()
        self._actions.addStretch(1)
        self.content.addLayout(self._actions)
        self.content.addStretch(1)
        self.show_idle_actions()

    # ── Input getters (read by the controller) ───────────────────────────────────

    def source_path(self) -> str:
        return self._src.path()

    def output_path(self) -> str:
        return self._out.path()

    def case_text(self) -> str:
        return self._case.text().strip()

    def imei_text(self) -> str:
        return self._imei.text().strip()

    def exhibit_text(self) -> str:
        return self._exhibit.text().strip()

    def analyst_text(self) -> str:
        return self._analyst.text().strip()

    def notes_text(self) -> str:
        return self._notes.text().strip()

    def jobs_value(self) -> int:
        return self._jobs.currentData()

    def fast_fts(self) -> bool:
        return self._fast_fts.isChecked()

    def fast_write(self) -> bool:
        return self._fast_write.isChecked()

    def overwrite(self) -> bool:
        return self._overwrite.isChecked()

    # ── Terminal-state action rows ────────────────────────────────────────────────

    def show_idle_actions(self) -> None:
        clear_layout(self._actions)
        self._actions.addStretch(1)
        start = primary_button("Start extraction")
        start.clicked.connect(self._ctrl.start)
        self._actions.addWidget(start)

    def show_running_actions(self) -> None:
        clear_layout(self._actions)
        self._actions.addStretch(1)
        # One button language: keep the row's forward action primary (violet)
        # and just relabel + disable it while running, mirroring how
        # AcquireScreen.set_running treats its own primary button — not a swap
        # to a disabled ghost, which reads as unstyled.
        running = primary_button("Extracting…")
        running.setEnabled(False)
        self._actions.addWidget(running)

    def show_done_actions(self) -> None:
        clear_layout(self._actions)
        self._actions.addStretch(1)
        new = ghost_button("Extract new", "plus")
        new.clicked.connect(self._reset)
        export = ghost_button("Export", "export")
        export.clicked.connect(lambda: self.navigate and self.navigate("export"))
        # The row's forward action — the natural next step after a successful
        # extract — is primary; "Extract new" and "Export" stay ghost.
        exploit = primary_button("Open in Exploit", "right")
        exploit.clicked.connect(
            lambda: self.navigate and self.navigate(
                "exploit", prefill={"db": self.output_path()}
            )
        )
        for btn in (new, export, exploit):
            self._actions.addWidget(btn)

    # ── Display methods ───────────────────────────────────────────────────────────

    def prefill(self, data: dict[str, Any]) -> None:
        """Populate the form from an upstream step (e.g. a finished acquisition).

        Called by the shell when navigating in with a payload. Existing values are
        overwritten because the caller is the authoritative source for this run.
        Setting the source path also triggers the controller's sidecar scan, which
        is harmless here (it would only re-confirm the same values).
        """
        self.fill_fields(
            source=data.get("logarchive"),
            case=data.get("case"),
            imei=data.get("imei"),
            exhibit=data.get("exhibit_number"),
            analyst=data.get("analyst"),
            only_empty=False,
        )

    def fill_fields(
        self,
        *,
        case: str | None = None,
        imei: str | None = None,
        exhibit: str | None = None,
        analyst: str | None = None,
        source: str | None = None,
        only_empty: bool,
    ) -> int:
        """Set the case-metadata fields, returning how many were actually filled.

        With *only_empty* True, a field already holding text is left untouched.
        *source* (when given) is applied last so its textChanged sidecar scan runs
        after the other fields are in place.
        """
        count = 0
        for widget, value in (
            (self._case, case),
            (self._imei, imei),
            (self._exhibit, exhibit),
            (self._analyst, analyst),
        ):
            if not value:
                continue
            if only_empty and widget.text().strip():
                continue
            widget.setText(value)
            count += 1
        if source:
            self._src.set_path(source)
        return count

    def set_sidecar_note(self, text: str | None) -> None:
        """Show *text* under the source field, or hide the note when None/empty."""
        if text:
            self._sidecar_note.setText(text)
            self._sidecar_note.setVisible(True)
        else:
            self._sidecar_note.setVisible(False)

    def begin_progress(self) -> None:
        self.clear_result()
        self._progress_panel.setVisible(True)
        self._progress_title.setText("Extracting…")
        self._bar.setValue(0)

    def mark_progress_complete(self) -> None:
        self._bar.setValue(100)
        self._progress_title.setText("Extraction complete")

    def hide_progress(self) -> None:
        self._progress_panel.setVisible(False)

    def _on_progress(self, fraction: float, label: str) -> None:
        self._bar.setValue(int(fraction * 100))
        self._progress_label.setText(f"{fraction * 100:.1f}% · {label}")


    def _reset(self) -> None:
        self._src.set_path("")
        self._out.set_path("")
        self._progress_panel.setVisible(False)
        self.clear_result()
        self.show_idle_actions()


# ── Shared helpers ──────────────────────────────────────────────────────────────

def _indent_widget(widget: QWidget) -> QWidget:
    """Wrap *widget* so it aligns under the field column (matches ``.field-help``)."""
    row = QWidget()
    layout = QHBoxLayout(row)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(12)
    spacer = QLabel("")
    spacer.setFixedWidth(130)
    layout.addWidget(spacer)
    layout.addWidget(widget, 1)
    return row


def _indented_help(text: str) -> QWidget:
    """A help line aligned under the field column (matches ``.field-help``)."""
    return _indent_widget(help_label(text))


