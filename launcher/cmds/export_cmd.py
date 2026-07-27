"""AUL Parser — ``export`` subcommand (CLI glue).

Defines : the argparse wiring for ``export`` and a thin ``run(args)`` that maps
          parsed arguments onto ``ExportFilters`` and delegates to the library
          ``forensic_aul.ops.export.exporter.run_export``. All export logic lives in
          the library; this module only handles CLI concerns (flags, error → exit
          code, the final stdout summary line).
Used by : launcher/cli.py (subcommand registration + dispatch).
Uses    : forensic_aul.ops.export.exporter (run_export, ExportFilters).
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

log = logging.getLogger(__name__)


# ── Argument parser ───────────────────────────────────────────────────────────

def add_subcommand(sub) -> None:  # type: ignore[type-arg]
    p = sub.add_parser(
        "export",
        help="Export an analysis database to CSV / JSON / JSONL with filters.",
        description=(
            "Exports rows from `logs` (joined with annotations when present) "
            "to a flat file. Filters can target log columns (process, "
            "subsystem, time range, …) or annotations (signature id, action "
            "substring, tag).\n\n"
            "Extracted fields are included by default as `<signature_id>.<field>` "
            "columns. Pass --no-fields to omit them."
        ),
    )
    p.add_argument("database", type=Path, metavar="DATABASE",
                   help="SQLite database produced by `extract`.")
    p.add_argument(
        "-o", "--output",
        type=Path,
        metavar="FILE",
        required=True,
        help="Output file path. Format inferred from suffix unless --format given.",
    )
    # Choices come from the writer registry so a newly registered format is
    # automatically accepted here.
    from forensic_aul.ops.export.exporter import export_formats

    p.add_argument(
        "--format",
        choices=export_formats(),
        default=None,
        help="Output format (default: inferred from --output suffix).",
    )

    timef = p.add_argument_group("time filters")
    timef.add_argument("--from", dest="time_from", metavar="ISO",
                       help="Lower bound (inclusive). ISO 8601 datetime.")
    timef.add_argument("--to",   dest="time_to",   metavar="ISO",
                       help="Upper bound (exclusive). ISO 8601 datetime.")
    timef.add_argument("--last", metavar="DURATION",
                       help="Shortcut for --from now-DURATION. Accepts 10m/1h/24h/7d.")

    logf = p.add_argument_group("log-column filters")
    logf.add_argument("--process",   metavar="P", action="append", default=None,
                      help="Restrict to this process name (repeatable; OR).")
    logf.add_argument("--subsystem", metavar="S", action="append", default=None,
                      help="Restrict to this subsystem (repeatable; OR).")
    logf.add_argument("--level",     metavar="LVL", action="append", default=None,
                      help="Restrict to this log level (Default/Info/Debug/Error/Fault, repeatable).")
    logf.add_argument("--like",      metavar="PATTERN", default=None, dest="like",
                      help="SQL LIKE pattern on the message column — %% and _ "
                           "wildcards, NOT a regular expression.")

    kbf = p.add_argument_group("knowledge-base filters")
    kbf.add_argument("--signature",       metavar="ID", action="append", default=None,
                     help="Only logs carrying this signature annotation (repeatable; OR).")
    kbf.add_argument("--action",          metavar="SUBSTR", default=None,
                     help="Only logs whose annotation action contains this substring (case-insensitive).")
    kbf.add_argument("--tag",             metavar="TAG", action="append", default=None,
                     help="Only logs whose annotation carries this tag (repeatable; OR).")
    kbf.add_argument("--annotated-only",  action="store_true",
                     help="Skip every log without at least one annotation.")

    out = p.add_argument_group("output options")
    out.add_argument("--no-fields", dest="include_fields", action="store_false",
                     help="Do not include extracted-value columns (one per label) in the output.")
    out.set_defaults(include_fields=True)


# ── Entry point ───────────────────────────────────────────────────────────────

def run(args: argparse.Namespace) -> int:
    from forensic_aul.ops.export.exporter import ExportFilters, run_export
    from forensic_aul.ops.export.report import format_export_result

    filters = ExportFilters(
        fmt=args.format,
        time_from=args.time_from,
        time_to=args.time_to,
        last=args.last,
        process=args.process,
        subsystem=args.subsystem,
        level=args.level,
        like=args.like,
        signature=args.signature,
        action=args.action,
        tag=args.tag,
        annotated_only=args.annotated_only,
        include_fields=args.include_fields,
    )

    try:
        res = run_export(args.database, args.output, filters)
    except (FileNotFoundError, ValueError) as exc:
        log.error(f"error: {exc}")
        return 1

    print(format_export_result(res))
    return 0
