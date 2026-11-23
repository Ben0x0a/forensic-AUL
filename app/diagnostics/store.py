"""Diagnostic reports on disk: naming, writing, listing, and the shareable copy.

Defines : ``report_dir`` (where reports go), ``write_report`` (JSON + best-effort
          Markdown twin), ``list_reports`` / ``report_kind`` (find and tell the kinds
          apart), ``find_report`` (a path, a file name or a stem → the report), and
          ``write_shared_copy`` (the redacted ``*.shared.json`` + ``*.shared.md``).
Used by : app.diagnostics.hooks (writes), launcher.cmds.redact_errors_cmd (lists,
          shares) and gui.report_actions (counts, reveals the folder).
Uses    : app.diagnostics.schema (kinds), .config (the folder), .redact and .render,
          and the standard library.

WHY one module owns every file rule: the file-name prefix decides which kind a
report is, the ``.shared`` suffix keeps the redacted copies out of the listing, and
both kinds go through one writer — so a rule changed here cannot drift between the
writer, the lister and the sharer.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
from pathlib import Path
from typing import Any

from app.diagnostics.config import CrashConfig, resolve
from app.diagnostics.redact import redact_report
from app.diagnostics.render import render_markdown
from app.diagnostics.schema import KIND_BUG, KIND_CRASH

log = logging.getLogger(__name__)

# Filename prefix per kind. They differ so a shell can COUNT one kind without the
# other: a control that decides between "open error reports" and "report bug…" must
# count crashes only — counting bug reports is self-fulfilling, since filing one
# would make the tool claim it had errored.
_FILENAME_PREFIX = {KIND_CRASH: "faul_crash_", KIND_BUG: "faul_bug_"}

# Marks the redacted copy of a report: <stem>.shared.json / <stem>.shared.md.
_SHARED_TAG = ".shared"


def report_dir(cfg: CrashConfig | None = None) -> Path:
    """The folder holding the reports (not created here)."""
    return resolve(cfg).crash_dir


def _dump(report: dict[str, Any], path: Path) -> None:
    # utf-8-sig so Windows tooling auto-detects the encoding (house rule).
    path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8-sig",
    )


def _report_path(directory: Path, kind: str) -> Path:
    """A filesystem-safe, collision-free path: kind-specific prefix (so one kind can
    be counted without the other); no colons in the timestamp; pid suffix; a numeric
    suffix only if a same-second same-pid file already exists (never overwrite an
    existing report)."""
    directory.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
    base = f"{_FILENAME_PREFIX[kind]}{stamp}_p{os.getpid()}"
    path = directory / f"{base}.json"
    counter = 1
    while path.exists():
        path = directory / f"{base}_{counter}.json"
        counter += 1
    return path


def _write_markdown_twin(report: dict[str, Any], json_path: Path) -> None:
    """Best-effort human-readable ``.md`` beside the JSON. Guarded: the JSON is the
    authoritative artefact, so a Markdown failure must not sink the report."""
    try:
        json_path.with_suffix(".md").write_text(render_markdown(report), encoding="utf-8-sig")
    except Exception:  # noqa: BLE001 - the JSON already succeeded; the twin is a convenience.
        log.debug("Could not render Markdown twin", exc_info=True)


def write_report(report: dict[str, Any], cfg: CrashConfig | None = None) -> Path:
    """Write one report (JSON + best-effort Markdown twin); return the JSON path.

    The single writer for both kinds: whatever the JSON gains — an encoding, a
    naming rule, a twin — both kinds gain together and cannot drift apart.
    """
    path = _report_path(report_dir(cfg), report["kind"])
    _dump(report, path)
    _write_markdown_twin(report, path)
    return path


def list_reports(crash_dir: Path | None = None, *, kind: str | None = None) -> list[Path]:
    """Saved reports, newest first. *kind* selects ``KIND_CRASH`` or ``KIND_BUG``;
    ``None`` returns both. The redacted ``*.shared.json`` copies are excluded.

    WHY the kind filter: a shell offering one control for "something is wrong" picks
    its caption from the number of ERROR reports. Counting bug reports there would
    be self-fulfilling — filing one would make the tool claim it had errored.
    """
    directory = crash_dir if crash_dir is not None else report_dir()
    if not directory.is_dir():
        return []
    prefixes = [_FILENAME_PREFIX[kind]] if kind else list(_FILENAME_PREFIX.values())
    found: list[tuple[float, Path]] = []
    for prefix in prefixes:
        for path in directory.glob(f"{prefix}*.json"):
            if path.name.endswith(f"{_SHARED_TAG}.json"):
                continue
            try:
                found.append((path.stat().st_mtime, path))
            except OSError:  # noqa: PERF203 - a report deleted mid-scan is simply skipped.
                continue
    return [p for _, p in sorted(found, reverse=True)]


def report_kind(path: Path) -> str:
    """``KIND_CRASH`` or ``KIND_BUG`` for a saved report, from its filename prefix."""
    return KIND_BUG if path.name.startswith(_FILENAME_PREFIX[KIND_BUG]) else KIND_CRASH


def find_report(target: str | Path, crash_dir: Path | None = None) -> Path | None:
    """Accept a full path, a bare file name, or a report stem (``.json`` appended)."""
    directory = crash_dir if crash_dir is not None else report_dir()
    target = str(target)
    for candidate in (Path(target), directory / target, directory / f"{target}.json"):
        if candidate.is_file():
            return candidate
    return None


def write_shared_copy(source: Path) -> tuple[Path, Path]:
    """Write the redacted, shareable pair beside *source*; return (JSON, Markdown).

    Raises ``OSError`` / ``ValueError`` when *source* cannot be read as a report —
    the caller decides how to tell the operator.
    """
    report = json.loads(source.read_text(encoding="utf-8-sig"))
    redacted = redact_report(report)
    # Strip the trailing ``.json`` so a *.json source yields *.shared.json.
    stem = source.name[:-5] if source.name.endswith(".json") else source.name
    shared_json = source.with_name(f"{stem}{_SHARED_TAG}.json")
    shared_md = source.with_name(f"{stem}{_SHARED_TAG}.md")
    _dump(redacted, shared_json)
    shared_md.write_text(render_markdown(redacted), encoding="utf-8-sig")
    return shared_json, shared_md
