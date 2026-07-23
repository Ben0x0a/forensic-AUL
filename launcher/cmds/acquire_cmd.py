"""AUL Parser — ``acquire`` subcommand (CLI glue).

Connects to an iOS device via USB and collects a ``.faul`` (the logarchive plus
its embedded traceability sidecar), then optionally runs ``extract``. ``--raw``
produces the legacy loose ``.logarchive`` + ``.acquisition.json`` layout instead.

The collection logic lives in the library (``forensic_aul.ops.acquisition``); this module
only handles CLI concerns: argument parsing, the device summary / confirmation
prompt (supplied to the library as a *confirm* callback), and exit codes.
Device-sourced fields (IMEI, serial, …) are always read from the device.

pymobiledevice3 is an *optional* dependency — a clear error is shown if it is not
installed.

Usage examples
--------------
List connected devices:
    forensic-aul acquire --list

Acquire logs (IMEI read automatically from device):
    forensic-aul acquire --case-number CASE-2024-001

Acquire with explicit UDID and output directory:
    forensic-aul acquire --case-number CASE-2024-001 --udid <UDID> --output-dir ./evidence

Acquire and immediately extract to SQLite:
    forensic-aul acquire --case-number CASE-2024-001 --extract --db ./evidence/out.db
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Callable

log = logging.getLogger(__name__)


# ── Argument parser ───────────────────────────────────────────────────────────

def add_subcommand(sub) -> None:  # type: ignore[type-arg]
    p = sub.add_parser(
        "acquire",
        help="Acquire a .faul (logarchive + sidecar) from a connected iOS device via USB.",
        description=(
            "Connects to an iOS device via USB using pymobiledevice3, retrieves "
            "device metadata (IMEI, serial, SIM cards, …) from the device itself, "
            "and collects a .logarchive.\n\n"
            "The logarchive and its traceability sidecar are packed into a single "
            "portable .faul container (the sidecar travels inside it, so the two "
            "never separate). Use --raw for the legacy loose layout instead: a "
            ".logarchive directory plus a separate .acquisition.json file.\n\n"
            "Device-sourced fields (IMEI, serial number, …) cannot be overridden — "
            "they are always read directly from the device.\n\n"
            "Use --list to enumerate connected devices without acquiring.\n\n"
            "pymobiledevice3 must be installed separately:  pip install pymobiledevice3"
        ),
    )

    device_grp = p.add_argument_group("device selection")
    device_grp.add_argument(
        "--list", "-l",
        action="store_true",
        dest="list_devices",
        help="List connected devices and exit (no acquisition).",
    )
    device_grp.add_argument(
        "--udid",
        metavar="UDID",
        default=None,
        help="Connect to this specific device UDID (default: first connected device).",
    )

    case_grp = p.add_argument_group("case identifiers  (recorded in acquisition report)")
    case_grp.add_argument(
        "--case-number",
        metavar="CASE",
        default=None,
        help="Investigation / case reference number (required unless --list).",
    )
    case_grp.add_argument("--exhibit",  metavar="EXHIBIT", help="Exhibit / item reference.")
    case_grp.add_argument("--analyst",  metavar="NAME",    help="Analyst name.")
    case_grp.add_argument("--notes",    metavar="TEXT",    help="Free-text notes.")

    acq_grp = p.add_argument_group("acquisition options")
    acq_grp.add_argument(
        "--output-dir", "-o",
        type=Path,
        metavar="DIR",
        default=Path("."),
        help="Directory where the .logarchive and report will be saved (default: current directory).",
    )
    acq_grp.add_argument(
        "--start-time",
        metavar="TIME",
        default=None,
        help=(
            "Collect logs from this point in time. "
            "Accepts an ISO 8601 datetime (e.g. '2024-01-15T12:00:00') "
            "or a relative offset (e.g. '1h', '24h', '7d'). "
            "Default: collect all available logs."
        ),
    )
    acq_grp.add_argument(
        "--size-limit",
        type=int,
        metavar="BYTES",
        default=None,
        help="Maximum logarchive size in bytes.",
    )
    acq_grp.add_argument(
        "--age-limit",
        type=int,
        metavar="DAYS",
        default=None,
        help="Maximum log age in days.",
    )
    acq_grp.add_argument(
        "--yes", "-y",
        action="store_true",
        help="Skip the confirmation prompt before acquiring.",
    )
    acq_grp.add_argument(
        "--raw",
        action="store_true",
        help=(
            "Produce the legacy loose layout — a .logarchive directory plus a "
            "separate .acquisition.json sidecar file — instead of a single .faul "
            "container. Use when a downstream tool needs a plain logarchive."
        ),
    )

    post_grp = p.add_argument_group("post-acquisition")
    post_grp.add_argument(
        "--extract",
        action="store_true",
        help="Immediately run 'extract' on the acquired logarchive after acquisition.",
    )
    post_grp.add_argument(
        "--db",
        type=Path,
        metavar="DB_PATH",
        default=None,
        help="SQLite database path for --extract (default: <logarchive>.db next to the archive).",
    )
    post_grp.add_argument(
        "--batch-size",
        type=int,
        default=1_000,
        metavar="N",
        help="Batch size for --extract (default: 1000).",
    )


# ── Entry point ───────────────────────────────────────────────────────────────

def run(args) -> int:  # type: ignore[type-arg]
    # --list is a pure enumeration (its own short-lived event loop).
    if args.list_devices:
        return asyncio.run(_cmd_list())

    if not args.case_number:
        log.error("error: --case-number is required for acquisition")
        log.error("       (use --list to enumerate connected devices)")
        return 1

    from forensic_aul.ops.acquisition.acquire import (
        AcquisitionAborted,
        AcquisitionError,
        acquire,
    )

    log.info(f'Connecting to device{f" {args.udid}" if args.udid else ""}…')
    try:
        # extract=False: the CLI runs its own extract below (via _run_extract →
        # run_extract_session) so that step gets a sealed operational log.
        result = acquire(
            case_number=args.case_number,
            output_dir=args.output_dir,
            udid=args.udid,
            start_time=args.start_time,
            size_limit=args.size_limit,
            age_limit=args.age_limit,
            exhibit=args.exhibit,
            analyst=args.analyst,
            notes=args.notes,
            extract=False,
            pack=not args.raw,   # --raw → legacy loose .logarchive + sidecar
            confirm=_make_confirm(args.yes),
        )
    except AcquisitionAborted:
        print("Aborted.")
        return 0
    except ImportError as exc:
        log.error(f"error: {exc}")
        return 1
    except AcquisitionError as exc:
        log.error(f"Acquisition failed: {exc}")
        log.error(f"error: acquisition failed — {exc}")
        return 1
    except Exception as exc:  # noqa: BLE001 — surface any unexpected failure cleanly
        log.exception(f"error: acquisition failed — {exc}")
        return 1

    from forensic_aul.ops.acquisition.report import format_acquire_result
    print(format_acquire_result(result))

    # ── Optional immediate extract (CLI-driven, with its own operational log) ──
    if args.extract:
        imei = result.device.imei or "UNKNOWN"
        db_path = args.db or result.logarchive_path.with_suffix(".db")
        print("")
        print(f"  Running extract → {db_path}")
        rc = _run_extract(
            logarchive=result.logarchive_path,
            db_path=db_path,
            case_number=args.case_number,
            imei=imei,
            exhibit_number=args.exhibit,
            analyst_name=args.analyst,
            notes=args.notes,
            batch_size=args.batch_size,
        )
        if rc != 0:
            return rc

    print("")
    print("  Acquisition complete.")
    return 0


def _make_confirm(skip_prompt: bool) -> Callable[[object], bool]:
    """Build the *confirm* callback the library calls after connecting.

    Prints the device summary, warns on a missing IMEI, and (unless --yes) prompts
    the operator. Returns False to abort. The library performs no I/O itself.
    """
    def confirm(device) -> bool:  # type: ignore[no-untyped-def]
        print("")
        print("  Connected device")
        print("  " + "─" * 50)
        print(device.display_table())
        print("")
        if not device.imei:
            log.warning("IMEI could not be read from the device")
            print("  Warning: IMEI could not be read from device.")
            print("           This may happen on Wi-Fi-only devices or with restricted profiles.")
            print("")
        if not skip_prompt:
            try:
                answer = input("  Proceed with log acquisition? [y/N] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\nAborted.")
                return False
            if answer not in ("y", "yes"):
                return False
        print("  Collecting logs… (this may take several minutes for large archives)")
        print("")
        return True

    return confirm


# ── --list handler ────────────────────────────────────────────────────────────

async def _cmd_list() -> int:
    from forensic_aul.ops.acquisition.device import list_connected_devices
    try:
        devices = await list_connected_devices()
    except ImportError as exc:
        log.error(f"error: {exc}")
        return 1
    except Exception as exc:
        log.error(f"Device enumeration failed: {exc}")
        log.error(f"error: could not list devices — {exc}")
        return 1

    if not devices:
        print("No iOS devices detected via USB.")
        return 0

    print(f"\n  {len(devices)} device(s) connected:\n")
    for i, dev in enumerate(devices, 1):
        print(f"  [{i}] {'─' * 50}")
        print(dev.display_table())
    print("")
    return 0


# ── Post-acquisition extract (CLI-side, to seal an operational log) ───────────

def _run_extract(
    logarchive: Path,
    db_path: Path,
    case_number: str,
    imei: str,
    exhibit_number: str | None,
    analyst_name: str | None,
    notes: str | None,
    batch_size: int,
) -> int:
    # Same sealed-log extraction session as the standalone `extract` command:
    # one shared helper so an acquired-then-extracted DB gets an identically
    # sealed, tamper-evident operational log.
    from app.extract_session import run_extract_session

    return run_extract_session(
        logarchive=logarchive,
        db_path=db_path,
        case_number=case_number,
        imei=imei,
        exhibit_number=exhibit_number,
        analyst_name=analyst_name,
        notes=notes,
        batch_size=batch_size,
        overwrite=True,
    )
