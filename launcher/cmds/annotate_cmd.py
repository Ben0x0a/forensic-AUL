"""AUL Parser — ``annotate`` subcommand.

Apply the YAML knowledge base to an extracted SQLite database. Inserts
rows into ``kb_signatures`` and ``log_annotations``; never modifies
existing log rows. Multi-match is supported (one log can have multiple
annotations from different signatures).
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

log = logging.getLogger(__name__)

_DEFAULT_KB_DIR = "knowledge_base"


def add_subcommand(sub) -> None:  # type: ignore[type-arg]
    p = sub.add_parser(
        "annotate",
        help="Apply the YAML knowledge base to an extracted SQLite database.",
        description=(
            "Runs every selected signature against the logs table, writing "
            "one row per match into log_annotations and one row per signature "
            "(that produced ≥1 hit) into kb_signatures.\n\n"
            "The kb_sha256 + kb_version pair is stored on every annotation "
            "run for traceability."
        ),
    )
    p.add_argument("database", type=Path, metavar="DATABASE",
                   help="SQLite database produced by `extract`.")
    p.add_argument(
        "--kb",
        type=Path,
        metavar="PATH",
        default=Path(_DEFAULT_KB_DIR),
        help=f"Knowledge-base root directory (default: ./{_DEFAULT_KB_DIR}).",
    )
    p.add_argument(
        "--signature",
        action="append",
        metavar="ID",
        default=None,
        help="Restrict to this signature id (repeatable). Default: all.",
    )
    p.add_argument(
        "--tag",
        action="append",
        metavar="TAG",
        default=None,
        help="Restrict to signatures carrying this tag (repeatable).",
    )


def run(args: argparse.Namespace) -> int:
    from forensic_aul.ops.knowledge_base.loader import KnowledgeBaseError, load_kb
    from forensic_aul.ops.annotation.matcher import annotate_database
    from forensic_aul.ops.annotation import report

    if not args.database.is_file():
        log.error(f"error: {args.database} is not a file")
        return 1

    try:
        kb = load_kb(args.kb)
    except KnowledgeBaseError as exc:
        log.error(f"error: KB invalid: {exc}")
        return 1

    only_ids  = set(args.signature) if args.signature else None
    only_tags = set(args.tag)       if args.tag       else None

    print(report.format_header(args.database, kb))
    print("")

    # The library opens the DB, sets the forensic pragma, commits and closes.
    try:
        result = annotate_database(args.database, kb, only_ids=only_ids, only_tags=only_tags)
    except Exception as exc:
        log.exception(f"error: annotate failed — {exc}")
        return 1

    print("")
    print(report.format_annotate_result(result))
    return 0
