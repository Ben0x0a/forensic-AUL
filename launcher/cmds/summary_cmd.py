"""AUL Parser — ``summary`` subcommand (dispatch only).

Parses args, calls ``forensic_aul.ops.summary.summary.summarise`` (all the
read-only querying), then prints the report rendered by
``forensic_aul.ops.summary.report.format_summary``. No data or presentation
logic lives here.
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

log = logging.getLogger(__name__)


def add_subcommand(sub) -> None:  # type: ignore[type-arg]
    p = sub.add_parser(
        "summary",
        help="Print a high-level summary of an analysis database.",
        description=(
            "Prints case metadata, top processes/subsystems/levels, "
            "annotated-action counts, and a temporal distribution of log "
            "entries over the covered window.\n\n"
            "Use this before `export` to know what's in the DB and decide "
            "what to filter on."
        ),
    )
    p.add_argument("database", type=Path, metavar="DATABASE",
                   help="SQLite database produced by `extract`.")
    p.add_argument("--top", type=int, default=10, metavar="N",
                   help="How many entries per top-N section (default: 10).")
    p.add_argument("--buckets", type=int, default=40, metavar="N",
                   help="Approximate number of buckets in the temporal histogram (default: 40).")


# ── Entry point ───────────────────────────────────────────────────────────────

def run(args: argparse.Namespace) -> int:
    from forensic_aul.ops.summary.summary import summarise
    from forensic_aul.ops.summary.report import format_summary

    try:
        s = summarise(args.database, top=args.top, buckets=args.buckets)
    except (FileNotFoundError, ValueError) as exc:
        log.error(f"error: {exc}")
        return 1

    print(format_summary(s))
    return 0
