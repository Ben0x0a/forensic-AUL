"""Controllers for the data screens: Export and Verify hash.

Defines : ExportController (validate the form, build the LogFilter, run the
          export off-thread, report) and VerifyHashController (the expected
          digest from an acquisition sidecar, the hashing off-thread, the
          verdict).
Used by : gui.views.screens_data (each screen builds its controller).
Uses    : forensic_aul (run_export, LogFilter, load_sidecar_for),
          gui.controllers (phrase_failure), gui.navigation (ExportFrom), hashlib.

WHY controllers here too (G6): the screens used to run the export and the hash
from their widget code; every screen now follows one pattern — the view holds
widgets and forwards the user's input, the controller decides and calls the
library.
"""

from __future__ import annotations

import hashlib
from dataclasses import fields, replace
from pathlib import Path
from typing import Any

from forensic_aul import LogFilter, load_sidecar_for, run_export
from gui.controllers import phrase_failure
from gui.navigation import ExportFrom

# Read files in chunks so hashing a multi-GB image never loads it whole.
_HASH_CHUNK = 1 << 20  # 1 MiB


# The LogFilter fields the Export form shows as its own inputs. Consumed by:
# ExportController.receive (fills them) and start (the form wins for them).
_FORM_FIELDS = ("process", "subsystem", "level", "like", "last")


class ExportController:
    """Logic for the Export view (``run_task``, ``show_result``, ``set_exporting``,
    ``fill_form``, ``show_carried``)."""

    def __init__(self, view: Any) -> None:
        self._view = view
        # Filters handed over by another screen that the form has no input for
        # (time bounds, keyword, category…). Applied on export and always shown
        # to the analyst (show_carried), never applied invisibly.
        self._carried = LogFilter()

    def receive(self, payload: ExportFrom) -> None:
        """Take a hand-off: the database, the form's filters, and the rest."""
        f = payload.filters
        self._view.fill_form(
            db=str(payload.db),
            process=", ".join(f.process or ()), subsystem=", ".join(f.subsystem or ()),
            level=", ".join(f.level or ()), like=f.like or "", last=f.last or "",
        )
        self._carried = replace(f, **{name: None for name in _FORM_FIELDS})
        self._view.show_carried(describe_filters(self._carried))

    def clear_carried(self) -> None:
        self._carried = LogFilter()
        self._view.show_carried("")

    def start(self, *, db: str, out: str, fmt: str, process: str, subsystem: str,
              level: str, like: str, last: str) -> None:
        if not db:
            self._view.show_result(False, "Choose a database to export.")
            return
        if not out:
            self._view.show_result(False, "Choose an output file.")
            return
        filters = replace(
            self._carried,
            process=_csv_list(process), subsystem=_csv_list(subsystem),
            level=_csv_list(level), like=like.strip() or None, last=last.strip() or None,
        )
        db_path, out_path = Path(db), Path(out)
        self._view.set_exporting(True)
        self._view.run_task(
            lambda: run_export(db_path, out_path, filters, fmt=fmt),
            lambda result: self._on_done(result, fmt, out_path),
            self._on_failed,
        )

    def _on_done(self, result: Any, fmt: str, out: Path) -> None:
        self._view.set_exporting(False)
        rows = getattr(result, "rows", 0)
        fmt = getattr(result, "fmt", "") or fmt
        out = Path(getattr(result, "output_path", out))
        self._view.show_result(True, f"Exported {rows:,} row(s) as {fmt.upper()} → {out.name}")

    def _on_failed(self, exc: BaseException) -> None:
        self._view.set_exporting(False)
        self._view.show_result(False, phrase_failure(exc))


class VerifyHashController:
    """Logic for the Verify hash view (``run_task``, ``set_hashing``, ``add_row``)."""

    def __init__(self, view: Any) -> None:
        self._view = view

    @staticmethod
    def expected_from_sidecar(path: str) -> str | None:
        """The SHA-256 an acquisition sidecar recorded for *path*, if any."""
        report = load_sidecar_for(Path(path)) if path else None
        if report is None:
            return None
        return (report.get("acquisition") or {}).get("logarchive_sha256") or None

    def start(self, *, path: str, algo: str, expected: str) -> None:
        if not path:
            return
        # Captured now, not re-read from the widgets once the hash finishes: a
        # large file can take a while to hash, and the analyst is free to edit
        # File / Expected hash while it runs. Reading them afterwards would label
        # the result with whatever is in the field *then* — silently attributing
        # the just-computed digest to a different file.
        name = Path(path).name
        expected = normalise_hash(expected)
        self._view.set_hashing(True)
        self._view.run_task(
            lambda: hash_file(Path(path), algo),
            lambda computed: self._on_done(name, expected, computed),
            lambda exc: self._on_failed(name, exc),
        )

    def _on_done(self, name: str, expected: str, computed: str) -> None:
        self._view.set_hashing(False, computed=computed)
        if not expected:
            status = ("INFO", "info")
        elif expected == computed.lower():
            status = ("OK", "ok")
        else:
            status = ("MISMATCH", "err")
        self._view.add_row(name, computed, expected, status)

    def _on_failed(self, name: str, exc: BaseException) -> None:
        self._view.set_hashing(False)
        # WHY a tooltip, not a discarded reason: a bare ERROR pill gives the
        # analyst nothing to act on — permission denied, file vanished mid-run and
        # a read error all look identical. The traceback is also in the log panel.
        self._view.add_row(name, "—", "—", ("ERROR", "err"), tooltip=phrase_failure(exc))


def hash_file(path: Path, algo: str) -> str:
    """Stream *path* through *algo* (sha256/sha1/md5) and return the hex digest."""
    digest = hashlib.new(algo)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_HASH_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalise_hash(text: str) -> str:
    return text.strip().lower().replace(" ", "")


def _csv_list(text: str) -> list[str] | None:
    items = [token.strip() for token in text.split(",") if token.strip()]
    return items or None


def describe_filters(filters: LogFilter) -> str:
    """*filters* as ``name: value`` pairs, set fields only ("" when none is set).

    Generic over the dataclass fields so a filter added to LogFilter later is
    shown here too, rather than silently applied without being displayed.
    """
    parts = []
    for spec in fields(filters):
        value = getattr(filters, spec.name)
        if value in (None, False, [], ""):
            continue
        shown = ", ".join(value) if isinstance(value, list) else ("yes" if value is True else value)
        parts.append(f"{spec.name.replace('_', ' ')}: {shown}")
    return " · ".join(parts)
