"""AUL Parser — ``extract`` subcommand.

Defines : the ``extract`` command's argument parser (``add_subcommand``) and its
          handler (``run``) — source-type pre-flight validation, then delegation
          to ``app.extract_session.run_extract_session`` which owns the logging
          setup, the pipeline call, and sealing the operational log. The same
          helper backs ``acquire --extract`` so both produce a sealed log.
Used by : launcher/cli.py (registers the parser, dispatches to ``run``).
Uses    : app.extract_session, forensic_aul.ops.extraction.source,
          forensic_aul.engine.utils.progress.
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from forensic_aul.config import BATCH_SIZE

log = logging.getLogger(__name__)


# ── Argument parser ───────────────────────────────────────────────────────────

def add_subcommand(sub) -> None:  # type: ignore[type-arg]
    p = sub.add_parser(
        "extract",
        help="Parse a logarchive / sysdiagnose / .faul / FFS acquisition into a SQLite database.",
        description=(
            "Reads a unified-log source and writes all Firehose log entries to a "
            "normalised SQLite database. The source is auto-detected (by content, not "
            "extension) and may be:\n"
            "  - a .logarchive directory (from 'log collect' or pymobiledevice3),\n"
            "  - a sysdiagnose .tar.gz (its system_logs.logarchive is used),\n"
            "  - a .faul portable container (from 'acquire'; its embedded sidecar "
            "auto-fills the case fields), or\n"
            "  - a full-file-system .zip (private/var/db/diagnostics + uuidtext are used).\n\n"
            "Alternatively, when the two unified-log folders are already uncompressed "
            "on disk, give them directly with --diagnostics and --uuidtext (the "
            "positional INPUT is then omitted); they are merged into a logarchive "
            "layout by hard link (zero-copy, or a copy on filesystems without hard "
            "links such as exFAT / some network drives).\n\n"
            "The output database is the required -o/--output. Examples:\n"
            "  faul.py extract INPUT -o case.db --case-number C1 --imei 35…\n"
            "  faul.py extract -o case.db --diagnostics DIAG --uuidtext UUID "
            "--case-number C1 --imei 35…\n\n"
            "Archives / loose dirs are materialised into a temp dir (auto-cleaned) "
            "unless --work-dir is given.\n\n"
            "--case-number and --imei are required: they identify the log file on disk."
        ),
    )
    p.add_argument(
        "logarchive",
        type=Path,
        nargs="?",
        default=None,
        metavar="INPUT",
        help=(
            "Path to a .logarchive directory, a sysdiagnose .tar.gz, a .faul "
            "container, or an FFS .zip. Omit when using --diagnostics / --uuidtext."
        ),
    )
    p.add_argument(
        "-o", "--output",
        type=Path,
        required=True,
        metavar="OUTPUT_DB",
        help="Path for the output SQLite database (created or overwritten).",
    )

    # Case identifiers (drive the log filename). Required — but a .faul source
    # carries them in its embedded sidecar, so they may be omitted for a .faul
    # (an explicit flag still overrides the sidecar value).
    required = p.add_argument_group("case identifiers  (required unless supplied by a .faul sidecar)")
    required.add_argument(
        "--case-number",
        default=None,
        metavar="CASE",
        help="Investigation / case reference number (e.g. CASE-2024-001). "
             "Auto-filled from a .faul's sidecar when omitted.",
    )
    required.add_argument(
        "--imei",
        default=None,
        metavar="IMEI",
        help="Device IMEI — used to name the log file. "
             "Auto-filled from a .faul's sidecar when omitted.",
    )

    # Optional case metadata
    meta = p.add_argument_group("optional case metadata")
    meta.add_argument("--exhibit-number", "-e", metavar="EXHIBIT",
                      help="Exhibit / item reference.")
    meta.add_argument("--analyst",  metavar="NAME",    help="Analyst name.")
    meta.add_argument("--notes",    metavar="TEXT",    help="Free-text notes.")

    # Source handling
    src = p.add_argument_group("source handling")
    src.add_argument(
        "--diagnostics",
        type=Path,
        default=None,
        metavar="DIR",
        help=(
            "Loose-dirs source: the uncompressed private/var/db/diagnostics/ folder "
            "(Persist/Special/Signpost/timesync). Use together with --uuidtext "
            "instead of the positional INPUT."
        ),
    )
    src.add_argument(
        "--uuidtext",
        type=Path,
        default=None,
        metavar="DIR",
        help=(
            "Loose-dirs source: the uncompressed private/var/db/uuidtext/ folder "
            "(the 2-char dirs + dsc/). Use together with --diagnostics."
        ),
    )
    src.add_argument(
        "--work-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help=(
            "For archive sources (sysdiagnose / FFS): extract the logarchive into "
            "this directory and keep it, instead of an auto-cleaned temp dir."
        ),
    )
    src.add_argument(
        "--reset-work-dir",
        action="store_true",
        help=(
            "Delete the work root inside --work-dir before extracting. Without "
            "this, a work root left by a previous run is refused rather than "
            "reused: its files would be hashed and parsed as part of this "
            "acquisition."
        ),
    )
    src.add_argument(
        "--integrity",
        choices=("full", "fingerprint", "off"),
        default="full",
        help=(
            "Source hashing mode (default: full). 'full' takes the complete "
            "chain-of-custody attestation (per-file SHA-256 + end-of-run "
            "re-verification); 'fingerprint' keeps only a cheap archive "
            "fingerprint; 'off' skips all hashing. Non-full modes are for "
            "triage only — the database records NO evidence hashes."
        ),
    )
    src.add_argument(
        "--overwrite",
        action="store_true",
        help=(
            "Replace OUTPUT if it already exists. Without this, extracting into an "
            "existing database is refused (it would merge two acquisitions)."
        ),
    )

    # Performance
    perf = p.add_argument_group("performance")
    perf.add_argument(
        "--batch-size",
        type=int,
        default=BATCH_SIZE,
        metavar="N",
        help=(
            f"Number of log entries per DB commit batch (default: {BATCH_SIZE}). "
            "Higher → fewer commit syncs, more RAM; lower it on small machines."
        ),
    )
    perf.add_argument(
        "--jobs", "-j",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Total process budget for parsing (N-1 parser workers + 1 writer). "
            "Default: auto — capped at the physical core count (max 8, where parse "
            "throughput plateaus) and reduced further on low-memory hosts. Use 1 "
            "to disable multiprocessing. Each worker holds its own ~150-250 MB "
            "string cache. The result is identical regardless of N."
        ),
    )
    perf.add_argument(
        "--fast-fts",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Build the full-text-search index once at the end instead of "
            "maintaining it per row. Default: on — it produces the same final "
            "database with far less disk I/O on large acquisitions. The only "
            "trade-off is that an interrupted run leaves full-text search empty "
            "until rebuilt, and the final rebuild has a higher memory peak. Use "
            "--no-fast-fts to maintain the index incrementally during the load "
            "(so a partial run is still searchable)."
        ),
    )
    perf.add_argument(
        "--fast-write",
        action="store_true",
        help=(
            "Relax write durability (PRAGMA synchronous=OFF) for speed. The "
            "default (synchronous=NORMAL + WAL) never corrupts the database; "
            "--fast-write is faster but CAN corrupt it on an OS crash / power "
            "loss, so use it only on disposable, re-runnable extractions."
        ),
    )
    perf.add_argument(
        "--fts",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Build the FTS5 full-text-search index over the message column. "
            "Default: on. The inverted index is the single largest addition to "
            "the database; pass --no-fts to skip it entirely (message search then "
            "falls back to a LIKE scan) for a markedly smaller, faster extract."
        ),
    )
    perf.add_argument(
        "--keep-raw",
        action="store_true",
        help=(
            "Store the per-entry raw_data JSON (the decoded FirehoseItemInfo list) "
            "for byte-level traceability. Default: off — it is often the fattest "
            "column and building it costs CPU on every entry. Enable only when the "
            "raw item breakdown is needed; all resolved fields are kept regardless."
        ),
    )
    perf.add_argument(
        "--fast",
        action="store_true",
        help=(
            "Shortcut for --fast-fts and --fast-write together (fastest, least "
            "safe). Implies both of their caveats: interrupted full-text search "
            "and possible corruption on power loss — disposable runs only."
        ),
    )


# ── Case-field resolution ───────────────────────────────────────────────────--

def _resolve_case_fields(
    args: argparse.Namespace, source: Path | dict[str, Path]
) -> tuple[str | None, str | None, str | None, str | None, str | None]:
    """Merge explicit --case-* flags with a ``.faul``'s embedded sidecar.

    Precedence: an explicit CLI flag always wins; any field left unset falls back
    to the acquisition sidecar carried inside a ``.faul`` source (case number,
    exhibit, analyst, notes come from ``sidecar["case"]``; IMEI from
    ``sidecar["device"]``). Non-``.faul`` sources have no embedded sidecar, so the
    flags are returned unchanged. Returns
    ``(case_number, imei, exhibit, analyst, notes)``.
    """
    case_number, imei = args.case_number, args.imei
    exhibit, analyst, notes = args.exhibit_number, args.analyst, args.notes
    if isinstance(source, dict):
        return case_number, imei, exhibit, analyst, notes

    from forensic_aul.ops.acquisition.report import load_sidecar_for

    sidecar = load_sidecar_for(Path(source))
    if not sidecar:
        return case_number, imei, exhibit, analyst, notes

    case = sidecar.get("case") or {}
    device = sidecar.get("device") or {}
    case_number = case_number or (case.get("case_number") or None)
    imei = imei or (device.get("imei") or None)
    exhibit = exhibit or (case.get("exhibit_number") or None)
    analyst = analyst or (case.get("analyst") or None)
    notes = notes or (case.get("notes") or None)
    if any((case_number, imei, exhibit, analyst, notes)):
        log.info("Case fields auto-filled from the .faul acquisition sidecar (explicit flags override).")
    return case_number, imei, exhibit, analyst, notes


# ── Entry point ───────────────────────────────────────────────────────────────

def run(args: argparse.Namespace) -> int:
    from forensic_aul.ops.extraction.source import (
        LOOSE_DIAGNOSTICS_KEY,
        LOOSE_UUIDTEXT_KEY,
        SourceType,
        detect_source_type,
    )
    from forensic_aul.engine.utils.progress import tty_bar_sink
    from forensic_aul.engine.utils.system import resolve_auto_jobs
    from app.extract_session import run_extract_session

    output: Path = args.output

    # Resolve the parallelism budget. An explicit --jobs is honoured verbatim;
    # otherwise auto-derive from physical cores and free RAM (see
    # engine/utils/system.py — capped at the throughput knee, narrowed when memory
    # is tight so a small host does not over-subscribe workers and swap).
    jobs: int = args.jobs if args.jobs and args.jobs > 0 else resolve_auto_jobs()

    # ── Resolve the source mode + pre-flight validation ──────────────────────
    # (full file logging not yet set up; bootstrap console logging from main()
    # routes these diagnostics to stderr.)
    # Two mutually exclusive ways to name the evidence:
    #   - a single positional INPUT (.logarchive dir / sysdiagnose / FFS), or
    #   - the two loose folders via --diagnostics + --uuidtext.
    source: Path | dict[str, Path]
    source_label: str
    loose = args.diagnostics is not None or args.uuidtext is not None

    if loose:
        if args.logarchive is not None:
            log.error("error: give either INPUT or --diagnostics/--uuidtext, not both.")
            return 1
        if args.diagnostics is None or args.uuidtext is None:
            log.error("error: --diagnostics and --uuidtext must be given together.")
            return 1
        for label, d in (("--diagnostics", args.diagnostics), ("--uuidtext", args.uuidtext)):
            if not d.is_dir():
                log.error(f"error: {label} is not a directory: {d}")
                return 1
        source = {LOOSE_DIAGNOSTICS_KEY: args.diagnostics, LOOSE_UUIDTEXT_KEY: args.uuidtext}
        source_label = SourceType.LOOSE_DIRS.value
    else:
        if args.logarchive is None:
            log.error("error: provide INPUT, or both --diagnostics and --uuidtext.")
            return 1
        # Accept a .logarchive dir, sysdiagnose .tar.gz, .faul, or FFS .zip — the
        # type is detected by content, so reject anything unrecognised up front
        # with a clear message rather than failing deep in the pipeline.
        try:
            source = args.logarchive
            source_label = detect_source_type(args.logarchive).value
        except ValueError as exc:
            log.error(f"error: {exc}")
            return 1

    # ── Resolve case fields (explicit flags override a .faul's embedded sidecar) ─
    case_number, imei, exhibit, analyst, notes = _resolve_case_fields(args, source)
    for label, value in (("--case-number", case_number), ("--imei", imei)):
        if not value:
            log.error(
                f"error: {label} is required (or provide a .faul source whose "
                "sidecar carries it)."
            )
            return 1

    if output.exists() and not output.is_file():
        log.error(f"error: {output} exists and is not a regular file")
        return 1

    # The session helper owns logging setup, the pipeline call, and sealing the
    # operational log on every exit path (shared with `acquire --extract`).
    return run_extract_session(
        logarchive=source,
        db_path=output,
        case_number=case_number,
        imei=imei,
        exhibit_number=exhibit,
        analyst_name=analyst,
        notes=notes,
        batch_size=args.batch_size,
        work_dir=args.work_dir,
        reset_work_dir=args.reset_work_dir,
        # --fast is a CLI-only shortcut for both fast-fts and fast-write.
        fast_fts=args.fast_fts or args.fast,
        fast_write=args.fast_write or args.fast,
        fts=args.fts,
        keep_raw=args.keep_raw,
        jobs=jobs,
        overwrite=args.overwrite,
        integrity=args.integrity,
        verbose=args.verbose,
        # Live bar on an interactive terminal; no-op when piped/redirected
        # (the per-phase INFO log lines remain the recorded trail).
        progress=tty_bar_sink(),
        source_label=source_label,
    )
