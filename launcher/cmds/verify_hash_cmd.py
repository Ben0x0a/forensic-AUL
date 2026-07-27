"""AUL Parser — ``verify`` subcommand (dispatch + rendering only).

Parses args, calls ``forensic_aul.ops.verify.verify.verify_database`` (which does the
re-hashing and comparisons), and renders the :class:`VerifyResult`. No
chain-of-custody logic lives here.

Exit code:
  0  all checks passed
  1  at least one mismatch / missing file
  2  invocation error (DB unreadable, schema invalid, …)
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

log = logging.getLogger(__name__)


# ── Argument parser ───────────────────────────────────────────────────────────

def add_subcommand(sub) -> None:  # type: ignore[type-arg]
    p = sub.add_parser(
        "verify-hash",
        help="Re-hash the evidence and check it against the digests stored at extract time.",
        description=(
            "Re-hashes the logarchive (global + per-file) and the operational "
            "log file, comparing the digests against those stored at extract "
            "time in case_metadata and source_files.\n\n"
            "Use this before disclosure / handover to prove that the evidence "
            "has not been altered since extraction."
        ),
    )
    p.add_argument("database", type=Path, metavar="DATABASE",
                   help="Path to the SQLite database produced by `extract`.")
    p.add_argument("--logarchive", type=Path, metavar="DIR", default=None,
                   help="Override path to the .logarchive (default: read from case_metadata).")
    p.add_argument("--log-file", type=Path, metavar="FILE", default=None,
                   help="Override path to the operational log file (default: read from case_metadata).")
    p.add_argument("--skip-files", action="store_true",
                   help="Skip per-file verification (only do the global logarchive hash).")


# ── Entry point ───────────────────────────────────────────────────────────────

def run(args: argparse.Namespace) -> int:
    from forensic_aul.ops.verify.verify import verify_database
    from forensic_aul.ops.verify.report import format_verify

    try:
        result = verify_database(
            args.database,
            logarchive=args.logarchive,
            log_file=args.log_file,
            skip_files=args.skip_files,
        )
    except (FileNotFoundError, ValueError) as exc:
        log.error(f"error: {exc}")
        return 2

    print(format_verify(result))
    return 0 if result.ok else 1
