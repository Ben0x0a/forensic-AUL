"""AUL Parser — ``validate`` subcommand.

Compares the output of ``forensic-aul extract`` against the ground-truth
``log show --style ndjson`` produced by Apple. Designed to operate as
autonomously as possible: on macOS, a single ``.logarchive`` argument is
enough; on a Mac with a phone connected, a single ``--from-device``
flag triggers the whole pipeline (collect → show → extract → diff).

(Named ``validate`` — not ``test`` — so it never reads as the project's pytest
suite in ``tests/``; the runtime validation tooling lives in ``forensic_aul/testing/``.)

Source forms (auto-detected by file shape):

  forensic-aul validate                                 # mac: list devices, refuse otherwise
  forensic-aul validate --from-device                   # mac: 1 device → auto
  forensic-aul validate --from-device <NAME_OR_UDID>    # mac: explicit device
  forensic-aul validate <logarchive>                    # mac: auto-generate ref
  forensic-aul validate <logarchive> <ref.ndjson>       # cross-platform
  forensic-aul validate <db.sqlite>   <ref.ndjson>      # cross-platform
  forensic-aul validate <db.sqlite>   --regen-ref <logarchive>   # mac: re-generate ref

Pass criterion
--------------
Default: every reference record must be found in the DB. Override with
``--allow-missing N`` (the count, not the percentage).
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

log = logging.getLogger(__name__)

_VALIDATE_CASE_NUMBER = "VALIDATE"
# Synthetic placeholder IMEI — all-zero, NOT a Luhn-valid identifier.
_VALIDATE_IMEI = "000000000000000"


def add_subcommand(sub) -> None:  # type: ignore[type-arg]
    p = sub.add_parser(
        "validate",
        help="Validate extract output against an Apple 'log show' ndjson reference.",
        description=(
            "Validates the output of `forensic-aul extract` against Apple's "
            "`log show --style ndjson` ground truth.\n\n"
            "On macOS, the reference can be generated automatically from a "
            "logarchive on disk, or even acquired straight from a connected "
            "iOS device with --from-device.\n\n"
            "Pass criterion: every reference record must be present in the DB."
        ),
    )
    p.add_argument(
        "source",
        type=Path,
        nargs="?",
        metavar="SOURCE",
        help=(
            "A logarchive directory, a SQLite database produced by `extract`, "
            "or omitted when --from-device is used."
        ),
    )
    p.add_argument(
        "reference",
        type=Path,
        nargs="?",
        metavar="REFERENCE_NDJSON",
        help="Apple `log show --style ndjson` reference; auto-generated on macOS if omitted.",
    )

    src_group = p.add_argument_group("acquisition")
    src_group.add_argument(
        "--from-device",
        nargs="?",
        const="",  # bare flag → auto-pick if a single device is connected
        metavar="NAME_OR_UDID",
        help=(
            "macOS only: run `log collect` first, against the named device. "
            "Pass nothing to auto-pick when one device is connected."
        ),
    )
    src_group.add_argument(
        "--regen-ref",
        type=Path,
        metavar="LOGARCHIVE",
        help=(
            "Force re-generation of the reference ndjson from this logarchive "
            "(macOS only). Useful when SOURCE is an existing DB."
        ),
    )
    src_group.add_argument(
        "--acquisition",
        nargs=2,
        type=Path,
        metavar=("ARCHIVE_A", "ARCHIVE_B"),
        help=(
            "L2 acquisition check: compare two logarchives file-by-file "
            "(SHA-256 + append-check), parser-free — proves two acquisition "
            "methods (e.g. pymobiledevice3 vs `log collect`) copied identical "
            "device files. Cross-platform; needs no reference and no root."
        ),
    )

    p.add_argument(
        "--report",
        type=Path,
        metavar="REPORT_FILE",
        default=None,
        help="Write the comparison report to this text file (in addition to stdout).",
    )
    p.add_argument(
        "--ndjson-output",
        type=Path,
        metavar="NDJSON_FILE",
        default=None,
        help=(
            "Export the DB records as ndjson (Apple field names) to this file, "
            "sorted by machTimestamp — useful for side-by-side diff with the reference."
        ),
    )
    p.add_argument(
        "--samples",
        type=int,
        default=20,
        metavar="N",
        help="Maximum number of mismatch samples per category (default: 20).",
    )
    p.add_argument(
        "--allow-missing",
        type=int,
        default=0,
        metavar="N",
        help=(
            "Maximum number of reference records allowed to be missing from "
            "the DB while still passing (default: 0)."
        ),
    )
    p.add_argument(
        "--log-show-args",
        type=str,
        metavar="ARGS",
        default=None,
        help=(
            "Override the flags passed to `log show` (default: --info --debug --signpost). "
            "Pass them as a single quoted string."
        ),
    )
    p.add_argument(
        "--collect-last",
        type=str,
        metavar="DURATION",
        default=None,
        help=(
            "For --from-device (L3): bound both device collections to this window "
            "(e.g. '1h', '30m') — keeps the capture small/fast and drift minimal."
        ),
    )

    p.add_argument(
        "--db-output",
        type=Path,
        metavar="DB_PATH",
        default=None,
        help="When extracting, write the DB here (default: persistent file next to the source).",
    )
    p.add_argument(
        "--keep-db",
        dest="keep_db",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Keep the extracted database after the test (default: keep).",
    )
    p.add_argument(
        "--keep-ref",
        dest="keep_ref",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Keep the auto-generated reference ndjson after the test (default: discard).",
    )

    # Case identifiers used when auto-extracting (optional — defaults work for testing)
    p.add_argument(
        "--case-number",
        metavar="CASE",
        default=_VALIDATE_CASE_NUMBER,
        help=f"Case number used for auto-extract (default: {_VALIDATE_CASE_NUMBER!r}).",
    )
    p.add_argument(
        "--imei",
        metavar="IMEI",
        default=_VALIDATE_IMEI,
        help=f"IMEI used for auto-extract (default: {_VALIDATE_IMEI!r}).",
    )


# ── Entry point ───────────────────────────────────────────────────────────────

def run(args: argparse.Namespace) -> int:
    """Delegate to the self-check pipeline (QA tooling lives in the library)."""
    from forensic_aul.testing.pipeline import run as run_pipeline
    return run_pipeline(args)
