"""AUL Parser — ``identify`` and ``identify-diff`` subcommands (CLI glue).

Defines : the argparse wiring for both commands and thin ``run`` handlers. The
          actual action-attribution workflow (acquire baseline → operator acts →
          acquire again → extract ×2 → diff) lives in
          ``forensic_aul.ops.identify.workflow``; this module only supplies the
          terminal front-end (prompts, banners, exception → exit code).
Used by : launcher/cli.py (subcommand registration + dispatch).
Uses    : forensic_aul.ops.identify.workflow / .diff / .report,
          forensic_aul.ops.extraction.extract (open_or_extract).
"""

from __future__ import annotations

import argparse
import logging
import time
from pathlib import Path

log = logging.getLogger(__name__)

_DEFAULT_KB_DIR = "knowledge_base"


# ── Argument parsers ──────────────────────────────────────────────────────────

def add_subcommand(sub) -> None:  # type: ignore[type-arg]
    _add_identify(sub)
    _add_identify_diff(sub)


def _add_identify(sub) -> None:  # type: ignore[type-arg]
    p = sub.add_parser(
        "identify",
        help="Identify log lines produced by a user action (interactive).",
        description=(
            "Acquires a baseline logarchive, prompts the operator to perform "
            "an action, acquires a second logarchive, then diffs the two so "
            "only lines attributable to the action remain.\n\n"
            "Two outputs are written:\n"
            "  * <prefix>.csv  — retained lines only\n"
            "  * <prefix>.db   — every post-baseline line, with `excluded` flag\n"
            "\n"
            "Cross-OS: the acquisition is iOS via pymobiledevice3; the diff "
            "is pure SQLite."
        ),
    )

    dev = p.add_argument_group("device selection")
    dev.add_argument("--udid", metavar="UDID", default=None,
                     help="UDID of the device (default: first connected device).")

    case = p.add_argument_group("case identifiers")
    case.add_argument("--case-number", default=None, metavar="CASE",
                      help="Investigation / case reference number "
                           "(default: 'identify-<UTC timestamp>').")
    case.add_argument("--exhibit",  metavar="EXHIBIT", help="Exhibit / item reference.")
    case.add_argument("--analyst",  metavar="NAME",    help="Analyst name.")
    case.add_argument("--notes",    metavar="TEXT",    help="Free-text notes.")

    acq = p.add_argument_group("acquisition options")
    acq.add_argument(
        "--still",
        type=int,
        default=60,
        metavar="SECONDS",
        help=(
            "Seconds to keep the device untouched before the baseline "
            "acquisition, so idle/connection noise lands in the baseline "
            "(default: 60; 0 skips the pause)."
        ),
    )
    acq.add_argument(
        "--output-dir", "-o",
        type=Path,
        metavar="DIR",
        default=Path("."),
        help="Directory for archives, DBs, and the diff outputs (default: cwd).",
    )
    acq.add_argument("--yes", "-y", action="store_true",
                     help="Skip device confirmation prompt before baseline acquire.")

    kb = p.add_argument_group("knowledge base")
    kb.add_argument(
        "--kb",
        type=Path,
        metavar="PATH",
        default=None,
        help=(
            f"Knowledge-base root directory to annotate the action DB with "
            f"(default: ./{_DEFAULT_KB_DIR} if it exists; otherwise runs "
            "unannotated)."
        ),
    )

    out = p.add_argument_group("output")
    out.add_argument("--no-csv", action="store_true",
                     help="Skip writing the retained-lines CSV (SQLite output only).")

    perf = p.add_argument_group("performance")
    perf.add_argument("--batch-size", type=int, default=1_000, metavar="N",
                      help="Batch size for the extract pipeline (default: 1000).")


def _add_identify_diff(sub) -> None:  # type: ignore[type-arg]
    p = sub.add_parser(
        "identify-diff",
        help="Run only the diff step on two existing archives or DBs.",
        description=(
            "Diff a baseline against a post-action capture. Each argument "
            "may be a .logarchive directory (will be extracted to a sibling "
            ".db) or a pre-built SQLite database.\n\n"
            "Outputs:\n"
            "  * <prefix>.csv  — retained lines only\n"
            "  * <prefix>.db   — every post-baseline line, with `excluded` flag\n"
        ),
    )
    p.add_argument("baseline", type=Path, metavar="BASELINE",
                   help="Baseline .logarchive directory or .db file.")
    p.add_argument("action", type=Path, metavar="ACTION",
                   help="Post-action .logarchive directory or .db file.")
    p.add_argument(
        "--output-prefix",
        type=Path,
        metavar="PREFIX",
        default=None,
        help="Path prefix for outputs (default: alongside ACTION as <stem>-identified).",
    )
    p.add_argument("--case-number", metavar="CASE", default=None,
                   help="Case number recorded if a .logarchive must be extracted.")
    p.add_argument("--imei", metavar="IMEI", default=None,
                   help="IMEI recorded if a .logarchive must be extracted.")
    p.add_argument("--batch-size", type=int, default=1_000, metavar="N",
                   help="Batch size for the extract pipeline (default: 1000).")


# ── Entry points ──────────────────────────────────────────────────────────────

def run(args: argparse.Namespace) -> int:
    if args.command == "identify":
        return _run_identify(args)
    if args.command == "identify-diff":
        return _run_identify_diff(args)
    raise AssertionError(f"unexpected command: {args.command}")


# ── identify (terminal front-end for the workflow) ────────────────────────────

def _run_identify(args: argparse.Namespace) -> int:
    from forensic_aul.ops.acquisition.acquire import AcquisitionAborted, AcquisitionError
    from forensic_aul.ops.identify.report import format_diff_result
    from forensic_aul.ops.identify.workflow import run_identify_workflow
    from forensic_aul.ops.knowledge_base.loader import KnowledgeBaseError, load_kb

    # Terminal callbacks for the library workflow: the CLI owns every prompt and
    # print; the workflow owns the sequence (see ops/identify/workflow.py).
    def confirm(device) -> bool:
        print("")
        print("  Connected device")
        print("  " + "─" * 50)
        print(device.display_table())
        print("")
        if args.yes:
            return True
        try:
            answer = input("  Proceed with identify workflow? [y/N] ").strip().lower()
        except EOFError:
            # No interactive stdin — treat as a decline rather than hanging.
            raise AcquisitionAborted("no interactive stdin for confirmation") from None
        return answer in ("y", "yes")

    def wait_still(seconds: int) -> None:
        print(f"  Keep the device untouched for {seconds} s (Ctrl-C aborts)…")
        time.sleep(seconds)

    def wait_for_action() -> None:
        print("")
        print("  ──────────────────────────────────────────────────────────")
        print("  Baseline collected. Perform the action on the device now.")
        print("  Press Enter when the action is complete (Ctrl-C to abort).")
        print("  ──────────────────────────────────────────────────────────")
        try:
            input("  > ")
        except EOFError:
            raise AcquisitionAborted("no interactive stdin during action wait") from None

    def status(line: str) -> None:
        print(f"  {line}")

    # Knowledge base: an explicit --kb is a hard requirement (load failure is an
    # error, exit 1); the implicit default directory is best-effort (missing or
    # unloadable → warn and run unannotated, since most users have no KB set up).
    kb = None
    if args.kb is not None:
        try:
            kb = load_kb(args.kb)
        except KnowledgeBaseError as exc:
            log.error(f"error: could not load knowledge base {args.kb}: {exc}")
            return 1
    else:
        default_kb_dir = Path(_DEFAULT_KB_DIR)
        if default_kb_dir.is_dir():
            try:
                kb = load_kb(default_kb_dir)
            except KnowledgeBaseError as exc:
                log.warning(f"could not load default knowledge base {default_kb_dir}: {exc}")

    try:
        res = run_identify_workflow(
            args.case_number,
            output_dir=args.output_dir,
            udid=args.udid,
            still_seconds=args.still,
            exhibit=args.exhibit,
            analyst=args.analyst,
            notes=args.notes,
            batch_size=args.batch_size,
            kb=kb,
            write_csv=not args.no_csv,
            confirm=confirm,
            wait_still=wait_still,
            wait_for_action=wait_for_action,
            status=status,
        )
    except KeyboardInterrupt:
        print("\nAborted.")
        return 130
    except AcquisitionAborted:
        print("Aborted.")
        return 0
    except (ImportError, ValueError, AcquisitionError) as exc:
        log.error(f"error: {exc}")
        return 1
    except Exception as exc:
        from app.diagnostics import capture_exception
        capture_exception({"entrypoint": "cli", "op": "identify"})
        log.exception(f"error: identify workflow failed — {exc}")
        return 1

    print("")
    print(format_diff_result(res.diff))
    return 0


# ── identify-diff (standalone) ────────────────────────────────────────────────

def _run_identify_diff(args: argparse.Namespace) -> int:
    baseline_db = _resolve_to_db(args.baseline, args.case_number, args.imei, args.batch_size)
    if baseline_db is None:
        return 1
    action_db = _resolve_to_db(args.action, args.case_number, args.imei, args.batch_size)
    if action_db is None:
        return 1

    if args.output_prefix is not None:
        prefix_path = args.output_prefix
        csv_out    = prefix_path.with_suffix(".csv")
        sqlite_out = prefix_path.with_suffix(".db")
    else:
        stem = action_db.stem + "-identified"
        csv_out    = action_db.with_name(stem + ".csv")
        sqlite_out = action_db.with_name(stem + ".db")

    print(f"  Diffing → {csv_out}")
    print(f"           {sqlite_out}")

    from forensic_aul.ops.identify.diff import run_diff
    from forensic_aul.ops.identify.report import format_diff_result
    try:
        res = run_diff(baseline_db, action_db, csv_out, sqlite_out)
    except Exception as exc:
        from app.diagnostics import capture_exception
        capture_exception({"entrypoint": "cli", "op": "identify-diff"})
        log.exception(f"error: diff failed — {exc}")
        return 1

    print("")
    print(format_diff_result(res))
    return 0


def _resolve_to_db(
    path: Path,
    case_number: str | None,
    imei: str | None,
    batch_size: int,
) -> Path | None:
    """Return *path* if it's a SQLite DB, otherwise extract it first.

    A sibling ``.db`` from a previous run is reused (see ``open_or_extract``).
    """
    if path.is_file() and path.suffix.lower() == ".db":
        return path
    if path.is_dir() and path.suffix.lower() == ".logarchive":
        from forensic_aul.ops.extraction.extract import open_or_extract

        db_path = path.with_suffix(".db")
        try:
            return open_or_extract(
                path, db_path,
                case_number=case_number or "IDENTIFY",
                imei=imei or "UNKNOWN",
                notes="identify-diff",
                batch_size=batch_size,
            )
        except Exception as exc:
            log.exception(f"error: extract failed — {exc}")
            return None
    log.error(f"error: {path} is neither a .db file nor a .logarchive directory")
    return None
