"""AUL Parser — ``redact-errors`` subcommand.

Defines : the ``redact-errors`` command — list the local diagnostic reports (both
          the automatic *error* reports and the operator-filed *bug* reports), or
          turn one into a redacted, shareable pair (``*.shared.json`` +
          ``*.shared.md``) safe to attach to a bug report. Argument parsing + file
          I/O only; the redaction and Markdown rendering live in ``app.sanitize``.
Used by : launcher/cli.py (registers the parser, dispatches to ``run``).
Uses    : app.diagnostics (report directory, ``list_reports``, ``report_kind``) and
          app.sanitize (``redact_report``, ``render_markdown``).
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

log = logging.getLogger(__name__)


def add_subcommand(sub) -> None:  # type: ignore[type-arg]
    p = sub.add_parser(
        "redact-errors",
        help="List local error/bug reports, or redact one into a shareable copy.",
        description=(
            "With no argument, lists the reports saved under the FAUL report "
            "directory — both the error reports written automatically on a failure "
            "and the bug reports filed from the GUI. Given a report ID or path, "
            "writes a redacted, shareable copy (<name>.shared.json + "
            "<name>.shared.md) with every sensitive value replaced by a type + "
            "hash — review it before filing a bug."
        ),
    )
    p.add_argument(
        "target", nargs="?", metavar="ID_OR_PATH",
        help="A report file (or its name) to redact for sharing. "
             "Omit to list the available reports.",
    )
    p.add_argument(
        "--dir", type=Path, default=None, metavar="DIR",
        help="Report directory (default: ~/.config/faul/crash_reports).",
    )


# ── Entry point ───────────────────────────────────────────────────────────────

def run(args: argparse.Namespace) -> int:
    from app.diagnostics import CrashConfig

    crash_dir: Path = args.dir or CrashConfig().crash_dir
    if args.target is None:
        return _list_reports(crash_dir)
    return _share(args.target, crash_dir)


def _list_reports(crash_dir: Path) -> int:
    """List both kinds — an operator redacting one to file a bug does not care
    whether it came from a crash or from the "report bug" control."""
    from app.diagnostics import list_reports, report_kind

    reports = list_reports(crash_dir)
    if not reports:
        log.info(f"No reports found in {crash_dir}")
        return 0
    log.info(f"Reports in {crash_dir}:")
    for path in reports:
        size_kib = path.stat().st_size / 1024
        log.info(f"  [{report_kind(path):<5}] {path.name}  ({size_kib:.1f} KiB)")
    log.info("Run `faul.py redact-errors <name>` to produce a redacted, shareable copy.")
    return 0


def _resolve(target: str, crash_dir: Path) -> Path | None:
    """Accept a full path, a bare filename, or a report stem (``.json`` appended)."""
    for candidate in (Path(target), crash_dir / target, crash_dir / f"{target}.json"):
        if candidate.is_file():
            return candidate
    return None


def _share(target: str, crash_dir: Path) -> int:
    from app.sanitize import redact_report, render_markdown

    source = _resolve(target, crash_dir)
    if source is None:
        log.error(f"error: crash report not found: {target}")
        return 1
    try:
        report = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        log.error(f"error: could not read crash report {source}: {exc}")
        return 1

    redacted = redact_report(report)
    # Strip the trailing ``.json`` so a *.json source yields *.shared.json.
    stem = source.name[:-5] if source.name.endswith(".json") else source.name
    shared_json = source.with_name(f"{stem}.shared.json")
    shared_md = source.with_name(f"{stem}.shared.md")

    shared_json.write_text(
        json.dumps(redacted, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8-sig",
    )
    shared_md.write_text(render_markdown(redacted), encoding="utf-8-sig")

    log.info("Redacted, shareable crash report written:")
    log.info(f"  JSON     : {shared_json}")
    log.info(f"  Markdown : {shared_md}")
    log.info("Review the ⚠ Sensitive sections before attaching either file to a bug report.")
    return 0
