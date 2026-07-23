"""Controller for the Identify wizard (gui.views.screens_identify).

Defines : IdentifyController — the application logic behind the interactive
          action-attribution wizard: validate the setup form, load an optional
          knowledge base, drive ``run_identify_workflow`` off the GUI thread, and
          bridge the two interactive pauses (the "keep still" countdown and the
          "perform the action" wait) between the worker thread and the GUI. The
          view (gui.views.screens_identify) holds only widgets + display methods.
Used by : gui.views.screens_identify (IdentifyScreen constructs its controller).
Uses    : PySide6 only indirectly (through the view's run_task host),
          forensic_aul.run_identify_workflow / load_kb / AcquisitionAborted,
          forensic_aul.engine.utils.system.resolve_auto_jobs, threading,
          gui.recent_store.

WHY a controller (mirroring gui.controllers.pipeline): identify runs a real async
core op with validation, weighted progress, and two operator pauses worth
isolating from the widgets. Like AcquireController/ExtractController this is a
plain object, not a QObject — the callbacks it hands to ``view.run_task`` are
re-emitted from the view (a main-thread OperationScreen), so Qt delivers them on
the GUI thread.

THREADING INVARIANT: widgets are NEVER touched from the worker thread. Worker→GUI
progress goes through the view's queued ``emit_progress`` signal only (the
countdown ticks ride the progress detail label — see wait_still). GUI→worker
control uses two ``threading.Event`` objects only (Skip / Continue) plus a plain
``_aborted`` flag; no widget is read or written off-thread.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any

from forensic_aul import AcquisitionAborted, load_kb, run_identify_workflow
from forensic_aul.engine.utils.system import resolve_auto_jobs
from gui.recent_store import RecentStore

log = logging.getLogger(__name__)

# Directory holding the shipped knowledge base; annotation is enrichment only, so
# a missing/unloadable KB never blocks the run (see start()). Resolved relative
# to the project root (three levels above this file), NOT the working directory:
# a GUI launched from the Dock/Finder has cwd "/" and a cwd-relative path would
# silently skip annotation on every run.
_KB_DIR = Path(__file__).resolve().parents[2] / "knowledge_base"


def _last_line(tb: str) -> str:
    """The most informative single line of a traceback string, for the UI."""
    return tb.strip().splitlines()[-1] if tb.strip() else ""


def _is_aborted(tb: str) -> bool:
    """True when the traceback's FINAL exception is an AcquisitionAborted.

    Parses the exception type from the traceback's last line
    (``pkg.module.AcquisitionAborted: message``) rather than substring-matching
    the whole text — an unrelated error whose message merely mentions the word
    must not be misreported as an operator abort.
    """
    exc_type = _last_line(tb).split(":", 1)[0].strip()
    return exc_type.rsplit(".", 1)[-1] == "AcquisitionAborted"


class IdentifyController:
    """Logic for the Identify wizard: setup validation, run, and the two pauses.

    *view* is the IdentifyScreen (accessed for its input getters, display methods,
    ``run_task`` host and ``navigate`` callback). *recents* records completed runs.
    """

    def __init__(self, view: Any, recents: RecentStore) -> None:
        self._view = view
        self._recents = recents
        # GUI→worker control channels (set from the GUI thread, waited on in the
        # worker thread). Fresh objects are created per run in start().
        self._skip_event = threading.Event()
        self._continue_event = threading.Event()
        self._aborted = False
        # Set when the knowledge base failed to load for the current run, so the
        # DONE state can tell the analyst the results are unannotated.
        self._kb_warning: str | None = None

    # ── Device enumeration ──────────────────────────────────────────────────────

    def rescan(self) -> None:
        import asyncio

        from forensic_aul.ops.acquisition.device import list_connected_devices

        self._view.set_device_scanning()
        # list_connected_devices is a coroutine — run it in its own loop on the
        # worker thread, mirroring AcquireController.rescan.
        self._view.run_task(
            lambda: asyncio.run(list_connected_devices()),
            self.on_devices, self.on_scan_failed,
        )

    def on_devices(self, devices: list[Any]) -> None:
        self._view.set_devices(devices)

    def on_scan_failed(self, tb: str) -> None:
        self._view.set_device_scan_failed()
        self._view.show_result(False, _last_line(tb) or "scan failed")

    # ── Run ─────────────────────────────────────────────────────────────────────

    def start(self) -> None:
        if not self._view.selected_udid():
            self._view.show_result(False, "Select a device (click ⟳ to enumerate).")
            return
        if not self._view.output_path():
            self._view.show_result(False, "Choose an output folder.")
            return

        # KB annotation is pure enrichment: a missing or unreadable knowledge base
        # must never sink the run, so a failure is warned and we proceed with none.
        # The failure is remembered and surfaced on DONE (see on_done) — an
        # analyst must know the results are unannotated, not discover it later.
        self._kb_warning = None
        try:
            kb = load_kb(_KB_DIR)
        except Exception as exc:  # noqa: BLE001 — annotation is optional enrichment
            self._kb_warning = (
                f"Knowledge base not loaded ({exc}) — results are unannotated."
            )
            log.warning(f"Could not load knowledge base ({exc}); continuing without annotation.")
            kb = None

        # Fresh control channels + flag per run so a prior run's state never leaks.
        self._skip_event = threading.Event()
        self._continue_event = threading.Event()
        self._aborted = False

        self._view.set_state(self._view.RUNNING)
        kwargs = dict(
            udid=self._view.selected_udid(),
            output_dir=Path(self._view.output_path()),
            still_seconds=self._view.still_seconds(),
            case_number=self._view.session_label() or None,
            integrity="off",
            fts=False,
            jobs=resolve_auto_jobs(),
            kb=kb,
            write_csv=False,
            # The GUI already chose the device in the setup form, so auto-confirm.
            confirm=lambda _device: True,
            progress=lambda ev: self._view.emit_progress(ev.overall, ev.phase),
            status=log.info,
            wait_still=self.wait_still,
            wait_for_action=self.wait_for_action,
        )
        self._view.run_task(
            lambda: run_identify_workflow(**kwargs), self.on_done, self.on_failed,
        )

    # ── Interactive pauses (run on the WORKER thread) ────────────────────────────

    def wait_still(self, seconds: int) -> None:
        """Hold for *seconds*, ticking a countdown to the GUI via progress detail.

        Runs on the worker thread. The countdown text is carried on the progress
        detail label (``still:<n>``) rather than a direct widget write — the view's
        _on_progress recognises it and updates the QLabel on the GUI thread. A
        fraction of -1.0 tells the view to leave the progress bar untouched.
        """
        for remaining in range(seconds, 0, -1):
            self._view.emit_progress(-1.0, f"still:{remaining}")  # countdown tick
            # Skip wakes early (analyst chose not to wait the full duration).
            if self._skip_event.wait(1.0):
                break
        if self._aborted:
            raise AcquisitionAborted("aborted during still phase")

    def wait_for_action(self) -> None:
        """Block until the operator signals the action is done (worker thread)."""
        self._continue_event.wait()
        if self._aborted:
            raise AcquisitionAborted("aborted during action wait")

    # ── GUI-thread control buttons ───────────────────────────────────────────────

    def skip_still(self) -> None:
        self._skip_event.set()

    def continue_action(self) -> None:
        self._continue_event.set()

    def abort(self) -> None:
        # Set the flag first, then wake BOTH pauses: whichever the worker is
        # currently blocked on unblocks, sees _aborted, and raises AcquisitionAborted.
        self._aborted = True
        self._skip_event.set()
        self._continue_event.set()

    # ── Completion / failure (GUI thread) ────────────────────────────────────────

    def on_done(self, result: Any) -> None:
        self._recents.add(
            "identify", str(result.diff.sqlite_path), f"{result.diff.retained} retained"
        )
        self._view.set_state(self._view.DONE, result)
        if self._kb_warning:
            # After set_state: DONE clears the result host, so the warning must
            # land afterwards to stay visible next to the summary.
            self._view.show_result(False, self._kb_warning)

    def on_failed(self, tb: str) -> None:
        # An operator abort is an expected, informational outcome — not an error:
        # nothing is written beyond the archives already collected. Anything else
        # is a genuine failure surfaced with its most informative traceback line.
        self._view.set_state(self._view.SETUP)
        if _is_aborted(tb):
            self._view.show_result(
                False, "Aborted — nothing was written beyond the collected archives."
            )
        else:
            self._view.show_result(False, _last_line(tb) or "identify failed")
