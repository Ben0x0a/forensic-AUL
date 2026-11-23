"""AUL Parser — ``identify`` subcommand (CLI glue).

Defines : the argparse wiring for ``identify`` and its thin ``run`` handler. The
          command has two modes: the default interactive workflow, and the
          offline ``--diff BASELINE ACTION`` mode that runs only the diff step
          on captures the analyst already has. The actual action-attribution
          workflow (acquire baseline → operator acts →
          acquire again → extract ×2 → diff) lives in
          ``forensic_aul.ops.workflows.identify``; this module only supplies the
          terminal front-end (prompts, banners, exception → exit code).
Used by : launcher/cli.py (subcommand registration + dispatch).
Uses    : forensic_aul.ops.workflows.identify / .diff / .report,
          forensic_aul.ops.extraction.extract (open_or_extract).
"""

from __future__ import annotations

import argparse
import logging
import time
from pathlib import Path

from dataclasses import replace

from forensic_aul import ExtractOptions, IdentifyOptions
from forensic_aul import IDENTIFY_EXTRACT

log = logging.getLogger(__name__)



# ── Argument parsers ──────────────────────────────────────────────────────────

def add_subcommand(sub) -> None:  # type: ignore[type-arg]
    p = _add_identify(sub)
    _add_diff_options(p)


def _add_identify(sub):  # type: ignore[type-arg,no-untyped-def]
    p = sub.add_parser(
        "identify",
        help="Identify log lines produced by a user action.",
        description=(
            "Default (interactive, needs a connected iOS device): acquires a "
            "baseline logarchive, prompts the operator to perform an action, "
            "acquires a second logarchive, then diffs the two so only lines "
            "attributable to the action remain.\n\n"
            "With --diff BASELINE ACTION: skips the acquisition entirely and "
            "runs only the diff step on two captures you already have. Each "
            "may be a .logarchive directory (extracted to a sibling .db) or a "
            "pre-built SQLite database. No device and no `acquire` extra "
            "needed.\n\n"
            "Two outputs are written either way:\n"
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
    case.add_argument("--exhibit-number", "-e", metavar="EXHIBIT",
                      help="Exhibit / item reference.")
    case.add_argument("--analyst",  metavar="NAME",    help="Analyst name.")
    case.add_argument("--notes",    metavar="TEXT",    help="Free-text notes.")

    acq = p.add_argument_group("acquisition options")
    acq.add_argument(
        "--still",
        type=int,
        default=None,
        metavar="SECONDS",
        help=(
            "Seconds to keep the device untouched before the baseline "
            "acquisition, so idle/connection noise lands in the baseline "
            f"(default: {IdentifyOptions.still_seconds}, or the [identify] "
            "settings; 0 skips the pause)."
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
            "Knowledge-base root directory to annotate the action DB with "
            "(default: the knowledge base shipped with fAUL; if it cannot be "
            "loaded the run continues unannotated)."
        ),
    )

    out = p.add_argument_group("output")
    out.add_argument("--no-csv", action="store_true",
                     help="Skip writing the retained-lines CSV (SQLite output only).")

    perf = p.add_argument_group("performance")
    perf.add_argument("--batch-size", type=int, default=None, metavar="N",
                      help=f"Batch size for the extract pipeline "
                           f"(default: {IDENTIFY_EXTRACT.batch_size}, or the "
                           "[identify.extract] settings).")
    return p


def _add_diff_options(p) -> None:  # type: ignore[type-arg,no-untyped-def]
    """Add the diff-only mode (`--diff BASELINE ACTION`) to the identify parser."""
    diff = p.add_argument_group(
        "diff-only mode",
        "Skip the acquisition and diff two captures you already have.",
    )
    diff.add_argument(
        "--diff",
        nargs=2,
        type=Path,
        metavar=("BASELINE", "ACTION"),
        default=None,
        help="Diff BASELINE against ACTION and exit. Each may be a .logarchive "
             "directory (extracted to a sibling .db) or a .db file. No device "
             "is used.",
    )
    diff.add_argument(
        "--output-prefix",
        type=Path,
        metavar="PREFIX",
        default=None,
        help="--diff only: path prefix for outputs "
             "(default: alongside ACTION as <stem>-identified).",
    )
    diff.add_argument("--imei", metavar="IMEI", default=None,
                      help="--diff only: IMEI recorded if a .logarchive must be extracted.")


# ── Entry points ──────────────────────────────────────────────────────────────

def run(args: argparse.Namespace) -> int:
    # --diff selects the offline mode; without it we drive the full interactive
    # acquire → act → acquire → diff workflow.
    if args.diff is not None:
        return _run_identify_diff(args)
    return _run_identify(args)


# ── identify (terminal front-end for the workflow) ────────────────────────────

def _run_identify(args: argparse.Namespace) -> int:
    from forensic_aul import AcquisitionAborted, AcquisitionError
    from forensic_aul.reports import format_diff_result

    from forensic_aul import CaseInfo
    from forensic_aul import run_identify_workflow
    from forensic_aul import KnowledgeBaseError, load_kb

    # Terminal callbacks for the library workflow: the CLI owns every prompt and
    # print; the workflow owns the sequence (see ops/workflows/identify.py).
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
    # error, exit 1); the shipped default is best-effort (unloadable → warn and
    # run unannotated — annotation enriches the diff, it never gates it).
    kb = None
    if args.kb is not None:
        try:
            kb = load_kb(args.kb)
        except KnowledgeBaseError as exc:
            log.error(f"error: could not load knowledge base {args.kb}: {exc}")
            return 1
    else:
        try:
            kb = load_kb()
        except KnowledgeBaseError as exc:
            log.warning(f"could not load the shipped knowledge base: {exc}")

    try:
        res = run_identify_workflow(
            args.output_dir,
            CaseInfo(case_number=args.case_number, exhibit_number=args.exhibit_number,
                     analyst_name=args.analyst, notes=args.notes),
            IdentifyOptions(
                udid=args.udid,
                # A flag left out means "the settings decide".
                still_seconds=args.still if args.still is not None else args.settings.identify.still_seconds,
                write_csv=False if args.no_csv else args.settings.identify.write_csv,
                extract=_identify_extract(args),
            ),
            kb=kb,
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


# ── identify --diff (offline mode) ────────────────────────────────────────────────

def _run_identify_diff(args: argparse.Namespace) -> int:
    baseline, action = args.diff
    baseline_db = _resolve_to_db(baseline, args.case_number, args.imei, _identify_extract(args))
    if baseline_db is None:
        return 1
    action_db = _resolve_to_db(action, args.case_number, args.imei, _identify_extract(args))
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

    from forensic_aul import run_diff
    from forensic_aul.reports import format_diff_result
    try:
        res = run_diff(baseline_db, action_db, csv_out, sqlite_out)
    except Exception as exc:
        from app.diagnostics import capture_exception
        capture_exception({"entrypoint": "cli", "op": "identify --diff"})
        log.exception(f"error: diff failed — {exc}")
        return 1

    print("")
    print(format_diff_result(res))
    return 0


def _identify_extract(args) -> ExtractOptions:  # type: ignore[no-untyped-def]
    """The [identify.extract] settings, with --batch-size on top when given."""
    opts = args.settings.identify.extract
    return opts if args.batch_size is None else replace(opts, batch_size=args.batch_size)


def _resolve_to_db(
    path: Path,
    case_number: str | None,
    imei: str | None,
    opts: ExtractOptions,
) -> Path | None:
    """Return *path* if it's a SQLite DB, otherwise extract it first.

    A sibling ``.db`` from a previous run is reused (see ``open_or_extract``).
    """
    if path.is_file() and path.suffix.lower() == ".db":
        return path
    if path.is_dir() and path.suffix.lower() == ".logarchive":
        from forensic_aul import CaseInfo
        from forensic_aul import open_or_extract

        db_path = path.with_suffix(".db")
        try:
            return open_or_extract(
                path, db_path,
                CaseInfo(case_number=case_number or "IDENTIFY", imei=imei or "UNKNOWN",
                         notes="identify --diff"),
                opts,
            )
        except Exception as exc:
            log.exception(f"error: extract failed — {exc}")
            return None
    log.error(f"error: {path} is neither a .db file nor a .logarchive directory")
    return None
