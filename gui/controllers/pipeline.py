"""Controllers for the pipeline views (Acquire, Extract).

Defines : AcquireController, ExtractController — the application logic behind the
          two pipeline screens: validate the view's inputs, invoke the core ops
          (``forensic_aul.ops.*``) off the GUI thread via the view's ``run_task``
          host, and route results / errors back to the view. The views
          (gui.views.screens_pipeline) hold only widgets and pure display methods
          and import no core ops.
Used by : gui.views.screens_pipeline (each pipeline view constructs its controller).
Uses    : PySide6 (asyncio bridge only), forensic_aul.ops.acquisition / .extraction,
          forensic_aul.engine.utils.system, gui.recent_store, and — by attribute —
          its view (a gui.views.screens_pipeline screen).

WHY controllers only for the pipeline: Acquire and Extract run real asynchronous
core ops with validation, progress, prefill and acquisition-sidecar logic worth
isolating from the widgets. The lighter data/preferences screens keep the thin
view-only convention documented in gui.views.screen_base — adding controllers
there would be indirection without payoff.

These controllers are plain objects, not QObjects: the off-thread callbacks they
pass to ``view.run_task`` are re-emitted from the view (an OperationScreen, a
main-thread QObject), so Qt already delivers them on the GUI thread.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

from forensic_aul.engine.utils.system import resolve_auto_jobs
from forensic_aul.ops.acquisition.acquire import acquire
from forensic_aul.ops.acquisition.device import list_connected_devices
from forensic_aul.ops.acquisition.report import load_sidecar_for
from forensic_aul.ops.extraction.extract import run_extract
from gui.recent_store import RecentStore

log = logging.getLogger(__name__)


def _last_line(tb: str) -> str:
    """The most informative single line of a traceback string, for the UI."""
    return tb.strip().splitlines()[-1] if tb.strip() else ""


class AcquireController:
    """Logic for the Acquire view: device scan + collection, results, hand-off.

    *view* is the AcquireScreen (accessed for its input widgets, display methods,
    ``run_task`` host and ``navigate`` callback). *recents* records completed runs.
    """

    def __init__(self, view: Any, recents: RecentStore) -> None:
        self._view = view
        self._recents = recents
        # Payload handed to the Extract view by the post-run "Continue" shortcut.
        self._prefill_payload: dict[str, Any] | None = None

    # ── Device enumeration ──────────────────────────────────────────────────────

    def rescan(self) -> None:
        self._view.set_device_scanning()
        # list_connected_devices is a coroutine — run it in its own loop on the
        # worker thread (acquire() uses asyncio.run internally; mirror that here).
        self._view.run_task(
            lambda: asyncio.run(list_connected_devices()),
            self.on_devices, self.on_scan_failed,
        )

    def on_devices(self, devices: list[Any]) -> None:
        self._view.set_devices(devices)

    def on_scan_failed(self, tb: str) -> None:
        self._view.set_device_scan_failed()
        self._view.show_result(False, _last_line(tb) or "scan failed")

    # ── Collection ──────────────────────────────────────────────────────────────

    def start(self) -> None:
        case = self._view.case_text()
        if not case:
            self._view.show_result(False, "Case number is required.")
            return
        if not self._view.output_path():
            self._view.show_result(False, "Choose an output folder.")
            return
        kwargs = dict(
            case_number=case,
            output_dir=Path(self._view.output_path()),
            udid=self._view.device_udid(),
            exhibit=self._view.exhibit_text() or None,
            analyst=self._view.analyst_text() or None,
            notes=self._view.notes_text() or None,
            confirm=lambda _device: True,  # the GUI already chose to start
        )
        self._view.set_continue_visible(False)  # hide any stale shortcut
        self._view.set_running(True)
        self._view.run_task(lambda: acquire(**kwargs), self.on_done, self.on_failed)

    def on_done(self, result: Any) -> None:
        self._view.set_running(False)
        path = str(getattr(result, "logarchive_path", ""))
        sha = getattr(result, "logarchive_sha256", "") or ""
        # Capture everything Extract needs so the operator does not retype it: the
        # collected archive path, the device IMEI, and the case fields entered here.
        device = getattr(result, "device", None)
        self._prefill_payload = {
            "logarchive": path or None,
            "imei": getattr(device, "imei", None) if device is not None else None,
            "case": self._view.case_text() or None,
            "exhibit": self._view.exhibit_text() or None,
            "analyst": self._view.analyst_text() or None,
        }
        self._recents.add("acquire", self._view.output_path(), Path(path).name if path else "")
        self._view.show_result(
            True,
            f"Collected {Path(path).name}<br><span style='color:#545a68'>"
            f"{path}<br>SHA-256 {sha[:16]}…</span>" if path else "Acquisition complete.",
        )
        self._view.set_continue_visible(True)

    def on_failed(self, tb: str) -> None:
        self._view.set_running(False)
        self._view.show_result(False, _last_line(tb) or "acquisition failed")

    def continue_to_extract(self) -> None:
        """Open Extract pre-filled with this acquisition's path and case metadata."""
        if self._view.navigate and self._prefill_payload:
            self._view.navigate("extract", prefill=self._prefill_payload)

    def reset(self) -> None:
        self._prefill_payload = None
        self._view.set_continue_visible(False)
        self._view.clear_form()
        self._view.clear_result()


class ExtractController:
    """Logic for the Extract view: validation, parse run, results, sidecar fill.

    *view* is the ExtractScreen; *recents* records completed extractions.
    """

    def __init__(self, view: Any, recents: RecentStore) -> None:
        self._view = view
        self._recents = recents
        # De-dupes the per-keystroke textChanged storm on the source field.
        self._last_sidecar_src = ""

    # ── Acquisition-sidecar auto-fill ─────────────────────────────────────────────

    def on_source_changed(self, text: str) -> None:
        """Look for a ``<source>.acquisition.json`` sidecar and auto-fill from it."""
        src = text.strip()
        if src == self._last_sidecar_src:
            return
        self._last_sidecar_src = src
        self._view.set_sidecar_note(None)
        if not src:
            return

        report = load_sidecar_for(Path(src))  # None if absent or unreadable
        if report is None:
            return

        case = report.get("case") or {}
        device = report.get("device") or {}
        # only_empty: never clobber a value the analyst already typed.
        filled = self._view.fill_fields(
            case=case.get("case_number"),
            imei=device.get("imei"),
            exhibit=case.get("exhibit"),
            analyst=case.get("analyst"),
            only_empty=True,
        )
        if filled:
            self._view.set_sidecar_note(
                f"Auto-filled {filled} case field(s) from the acquisition sidecar."
            )

    # ── Extraction run ────────────────────────────────────────────────────────────

    def start(self) -> None:
        if not self._view.source_path():
            self._view.show_result(False, "Choose a source (logarchive folder / .tar.gz / .zip).")
            return
        if not self._view.output_path():
            self._view.show_result(False, "Choose an output database path.")
            return
        if not self._view.case_text():
            self._view.show_result(False, "Case number is required.")
            return
        if not self._view.imei_text():
            self._view.show_result(False, "IMEI is required.")
            return

        # Auto (data 0) defers to the memory-aware resolver; any other entry is an
        # explicit core count chosen from the curated dropdown.
        jobs = self._view.jobs_value() or resolve_auto_jobs()
        kwargs = dict(
            logarchive=Path(self._view.source_path()),
            db_path=Path(self._view.output_path()),
            case_number=self._view.case_text(),
            imei=self._view.imei_text(),
            exhibit_number=self._view.exhibit_text() or None,
            analyst_name=self._view.analyst_text() or None,
            jobs=jobs,
            fast_fts=self._view.fast_fts(),
            fast_write=self._view.fast_write(),
            overwrite=self._view.overwrite(),
            progress=lambda ev: self._view.emit_progress(ev.overall, ev.phase),
        )
        self._view.begin_progress()
        self._view.show_running_actions()
        self._view.run_task(lambda: run_extract(**kwargs), self.on_done, self.on_failed)

    def on_done(self, result: Any) -> None:
        self._view.mark_progress_complete()
        ios = getattr(result, "ios_version", None) or getattr(result, "ios_build", None) or "?"
        count = getattr(result, "entry_count", 0)
        db_path = str(getattr(result, "db_path", self._view.output_path()))
        self._recents.add("database", db_path, f"{count:,} entries")
        self._view.show_result(
            True,
            f"Extracted {count:,} entries → {Path(db_path).name}<br>"
            f"<span style='color:#545a68'>{getattr(result, 'device_model', '?') or '?'} · "
            f"iOS {ios} · {getattr(result, 'parse_errors', 0)} parse errors</span>",
        )
        self._view.show_done_actions()

    def on_failed(self, tb: str) -> None:
        self._view.hide_progress()
        self._view.show_result(False, _last_line(tb) or "extraction failed")
        self._view.show_idle_actions()
