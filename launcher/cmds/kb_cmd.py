"""AUL Parser — ``kb`` subcommand (knowledge-base management).

Read-only operations on the YAML knowledge base. Does not touch any
analysis database — for that, see ``annotate``. This handler is dispatch +
trivial filtering only; all rendering lives in
``forensic_aul.ops.knowledge_base.report``.

Subcommands:
    list      List signatures, optionally filtered by tag/process.
    show      Print one signature's full definition.
    validate  Load all YAMLs, report structural errors, and warn about extracted
              labels not in the labels.yaml vocabulary.
    labels    Print the controlled label vocabulary (labels.yaml).
    stats     Counts: total, by tag, by confidence, by source file.
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

log = logging.getLogger(__name__)

_DEFAULT_KB_DIR = "knowledge_base"


# ── Argument parser ───────────────────────────────────────────────────────────

def add_subcommand(sub) -> None:  # type: ignore[type-arg]
    p = sub.add_parser(
        "kb",
        help="Inspect / validate the YAML knowledge base.",
        description="Read-only operations on the YAML knowledge base.",
    )
    p.add_argument(
        "--kb",
        type=Path,
        metavar="PATH",
        default=Path(_DEFAULT_KB_DIR),
        help=f"Knowledge-base root directory (default: ./{_DEFAULT_KB_DIR}).",
    )

    sp = p.add_subparsers(dest="kb_action", metavar="ACTION")
    sp.required = True

    p_list = sp.add_parser("list", help="List signatures.")
    p_list.add_argument("--tag",     metavar="TAG", default=None,
                        help="Only signatures carrying this tag.")
    p_list.add_argument("--process", metavar="P",   default=None,
                        help="Only signatures that match this process name.")
    p_list.add_argument("--json",    action="store_true",
                        help="Emit machine-readable JSON.")

    p_show = sp.add_parser("show", help="Show one signature in full.")
    p_show.add_argument("signature_id", metavar="ID")

    sp.add_parser("validate", help="Load + validate all YAMLs; warn on unknown labels.")
    sp.add_parser("labels",   help="Print the controlled label vocabulary.")
    sp.add_parser("stats",    help="Print KB-wide counts.")


# ── Entry point ───────────────────────────────────────────────────────────────

def run(args: argparse.Namespace) -> int:
    from forensic_aul.ops.knowledge_base.loader import KnowledgeBaseError, load_kb
    from forensic_aul.ops.knowledge_base import report

    try:
        kb = load_kb(args.kb)
    except KnowledgeBaseError as exc:
        log.error(f"error: {exc}")
        return 1

    action = args.kb_action
    if action == "list":
        selected = [
            s for s in kb.signatures
            if (not args.tag or args.tag in s.tags)
            and (not args.process or s.match.process == args.process)
        ]
        print(report.format_signature_list_json(selected) if args.json
              else report.format_signature_list(kb, selected))
        return 0

    if action == "show":
        target = next((s for s in kb.signatures if s.id == args.signature_id), None)
        if target is None:
            log.error(f"error: no signature with id {args.signature_id!r}")
            return 1
        print(report.format_signature(target))
        return 0

    if action == "validate":
        from forensic_aul.ops.knowledge_base.lint import lint_labels
        print(report.format_validation(kb, lint_labels(kb)))
        return 0

    if action == "labels":
        print(report.format_labels(kb))
        return 0

    if action == "stats":
        print(report.format_stats(kb))
        return 0

    raise AssertionError(f"unknown kb action: {action}")
