"""Device acquisition — collect a .logarchive from a connected iOS device.

Defines : the library-level ``acquire`` operation. It connects to an iOS device
          over USB (via the optional ``pymobiledevice3`` dependency), collects a
          ``.logarchive``, hashes it, writes a traceability report, and optionally
          runs ``run_extract`` — returning an :class:`~forensic_aul.outcomes.AcquireResult`.
Used by : launcher/cmds/acquire_cmd.py (CLI glue) and external callers.
Uses    : forensic_aul.ops.acquisition.device (connect/list), forensic_aul.engine.integrity (hashing),
          .acquisition_report (report), forensic_aul.ops.extraction.extract (optional
          follow-on extract), forensic_aul.outcomes.

``pymobiledevice3`` is imported lazily; if it is missing the relevant call raises
``ImportError`` with installation guidance (surfaced from acquisition.device).

This module is I/O-agnostic: it never prompts or prints. Interactive concerns
(device summary, confirmation prompt) are supplied by the caller through the
*confirm* callback, so the same operation drives the CLI and any other front-end.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from forensic_aul.errors import ForensicAULError
from forensic_aul.engine.utils.time import parse_duration_seconds
from forensic_aul.engine.faul_format import FAUL_SUFFIX, pack_faul
from forensic_aul.ops.acquisition.report import build_report_dict, write_acquisition_report
from forensic_aul.ops.acquisition.device import DeviceInfo, close_lockdown, connect_device
from forensic_aul.engine.integrity import hash_logarchive
from forensic_aul.outcomes import AcquireResult

log = logging.getLogger(__name__)


# ── Errors ────────────────────────────────────────────────────────────────────

class AcquisitionError(ForensicAULError):
    """A device acquisition failed (connection, collection, or output)."""


class AcquisitionAborted(AcquisitionError):
    """The *confirm* callback declined the acquisition (not an error condition)."""


# ── Public entry point ────────────────────────────────────────────────────────

def acquire(
    case_number: str,
    *,
    output_dir: Path = Path("."),
    udid: str | None = None,
    start_time: str | int | None = None,
    size_limit: int | None = None,
    age_limit: int | None = None,
    exhibit: str | None = None,
    analyst: str | None = None,
    notes: str | None = None,
    extract: bool = False,
    db_path: Path | None = None,
    batch_size: int = 1_000,
    pack: bool = True,
    confirm: Callable[[DeviceInfo], bool] | None = None,
) -> AcquireResult:
    """Collect a ``.logarchive`` from a connected iOS device into a ``.faul``.

    Connects to the device (the first one, or *udid*), collects a logarchive to a
    temp dir, hashes it, and packs it together with its acquisition sidecar into a
    single portable ``.faul`` container written to *output_dir* under a
    chain-of-custody filename (``<case>-<imei|udid>-<UTC>.faul``). When *extract*
    is True it then runs ``run_extract`` on that container into *db_path* (default:
    the output path with a ``.db`` suffix).

    The sidecar (case + device provenance) travels **inside** the ``.faul``, so it
    can never be separated from the evidence and is auto-loaded by ``extract``.

    *pack* (default True) selects the output layout. With ``pack=False`` the legacy
    **loose** layout is produced instead: the ``<name>.logarchive`` directory is
    written directly into *output_dir* alongside a separate
    ``<name>.logarchive.acquisition.json`` sidecar file (``AcquireResult.
    report_path`` then points at it). Use it when a downstream tool needs a plain
    logarchive rather than the ``.faul`` bundle.

    *start_time* selects how far back to collect: an ISO 8601 datetime, a relative
    offset (``"1h"`` / ``"24h"`` / ``"7d"``), a Unix timestamp (int), or None for
    everything available.

    *confirm*, if given, is called with the connected :class:`DeviceInfo` after
    connection and **before** collection; returning False aborts (raising
    :class:`AcquisitionAborted`). Use it to show a summary / prompt the operator.
    The library itself performs no I/O beyond logging.

    Returns:
        An :class:`~forensic_aul.outcomes.AcquireResult` (logarchive path, SHA-256,
        device metadata, report path, and the optional ``extract_result``).

    Raises:
        ImportError: ``pymobiledevice3`` is not installed.
        AcquisitionAborted: *confirm* returned False.
        AcquisitionError: connection, collection, or output failed.
    """
    return asyncio.run(_acquire_async(
        case_number=case_number,
        output_dir=output_dir,
        udid=udid,
        start_time=start_time,
        size_limit=size_limit,
        age_limit=age_limit,
        exhibit=exhibit,
        analyst=analyst,
        notes=notes,
        extract=extract,
        db_path=db_path,
        batch_size=batch_size,
        pack=pack,
        confirm=confirm,
    ))


# ── Async implementation ──────────────────────────────────────────────────────

async def _acquire_async(
    *,
    case_number: str,
    output_dir: Path,
    udid: str | None,
    start_time: str | int | None,
    size_limit: int | None,
    age_limit: int | None,
    exhibit: str | None,
    analyst: str | None,
    notes: str | None,
    extract: bool,
    db_path: Path | None,
    batch_size: int,
    pack: bool,
    confirm: Callable[[DeviceInfo], bool] | None,
) -> AcquireResult:
    if not case_number:
        raise AcquisitionError("case_number is required")

    # ── Connect (ImportError if pymobiledevice3 is missing) ───────────────────
    log.info(f'Connecting to device{f" {udid}" if udid else ""}…')
    lockdown, device = await connect_device(udid)

    # ── Build a chain-of-custody output path under output_dir ─────────────────
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_case = sanitise_filename_token(case_number)
    if not safe_case:
        await close_lockdown(lockdown)
        raise AcquisitionError(
            f"case_number {case_number!r} contains no usable filename characters"
        )
    # UTC keeps the filename consistent with the timestamps written to the DB.
    timestamp_str = datetime.now(tz=timezone.utc).strftime("%Y_%m_%d_%H_%M_%SZ")
    id_token = sanitise_filename_token(device.imei) if device.imei else device.udid[:8]
    stem = f"{safe_case}-{id_token}-{timestamp_str}"
    # pack=True → one portable .faul; pack=False → legacy loose .logarchive dir.
    output = output_dir / (f"{stem}{FAUL_SUFFIX}" if pack else f"{stem}.logarchive")

    # Defence in depth: the resolved output must stay under output_dir.
    try:
        output.resolve().relative_to(output_dir.resolve())
    except ValueError as exc:
        await close_lockdown(lockdown)
        raise AcquisitionError(
            f"refusing to write outside output directory: {output}"
        ) from exc

    # When packing, collect into a local temp dir and then pack (with the
    # acquisition sidecar) into a single .faul so the two never travel apart —
    # the temp dir is local + auto-cleaned; packing is one sequential copy into
    # the (possibly network) output_dir. When NOT packing, collect the logarchive
    # straight into output_dir and write a neighbouring sidecar file (old layout).
    report_path: Path | None = None
    with contextlib.ExitStack() as stack:
        if pack:
            tmp = stack.enter_context(tempfile.TemporaryDirectory(prefix="faul_acquire_"))
            logarchive_path = Path(tmp) / f"{stem}.logarchive"
        else:
            logarchive_path = output

        try:
            # ── Operator confirmation hook (front-end supplies the interaction) ─
            if confirm is not None and not confirm(device):
                raise AcquisitionAborted("acquisition declined by confirm callback")

            # ── Collect ─────────────────────────────────────────────────────────
            start_unix = _parse_start_time(start_time)
            log.info(f"Collecting logs → {logarchive_path}")
            await collect_logarchive(
                lockdown, str(logarchive_path),
                size_limit=size_limit, age_limit=age_limit, start_unix=start_unix,
            )
        finally:
            await close_lockdown(lockdown)

        if not logarchive_path.exists():
            raise AcquisitionError(
                f"collection reported success but {logarchive_path} was not created"
            )
        log.info(f"Log collection complete: {logarchive_path}")

        # ── Hash ────────────────────────────────────────────────────────────────
        file_hashes: dict[str, str] = {}
        try:
            logarchive_sha256, file_hashes = hash_logarchive(logarchive_path)
            file_count = len(file_hashes)
        except Exception as exc:  # noqa: BLE001 — hashing must not lose the collected evidence
            log.warning(f"Could not hash logarchive: {exc}")
            logarchive_sha256, file_count = "", 0

        # ── Write the output: pack a .faul, or write the loose sidecar file ──────
        if pack:
            sidecar = build_report_dict(
                logarchive_path, device,
                case_number=case_number, exhibit=exhibit, analyst=analyst, notes=notes,
                logarchive_sha256=logarchive_sha256, file_count=file_count,
                file_hashes=file_hashes,
            )
            try:
                pack_faul(
                    logarchive_path, output,
                    sidecar=sidecar, logarchive_arcname=logarchive_path.name,
                )
            except OSError as exc:
                raise AcquisitionError(
                    f"collection succeeded but the .faul could not be written: {exc}"
                ) from exc
        else:
            try:
                report_path = write_acquisition_report(
                    logarchive_path, device,
                    case_number=case_number, exhibit=exhibit, analyst=analyst, notes=notes,
                    logarchive_sha256=logarchive_sha256, file_count=file_count,
                    file_hashes=file_hashes,
                )
            except Exception as exc:  # noqa: BLE001 — a report failure must not lose the archive
                log.warning(f"Could not write acquisition report: {exc}")
    # (a temp logarchive, if any, is freed here — the follow-on extract reads
    #  the packed .faul / the loose logarchive left in output_dir)

    # ── Optional follow-on extract (reads the output we just wrote) ───────────
    extract_result = None
    if extract:
        from forensic_aul.ops.extraction.extract import run_extract
        target_db = db_path or output.with_suffix(".db")
        log.info(f"Running extract → {target_db}")
        extract_result = run_extract(
            output, target_db,
            case_number=case_number, imei=device.imei or "UNKNOWN",
            exhibit_number=exhibit, analyst_name=analyst, notes=notes,
            batch_size=batch_size, overwrite=True,
        )

    return AcquireResult(
        logarchive_path=output,
        logarchive_sha256=logarchive_sha256,
        file_count=file_count,
        device=device,
        report_path=report_path,   # None when the sidecar is embedded in the .faul
        extract_result=extract_result,
    )


async def collect_logarchive(
    lockdown: object,
    out: str,
    *,
    size_limit: int | None,
    age_limit: int | None,
    start_unix: int | None,
) -> None:
    """Collect the logarchive via pymobiledevice3's OsTraceService.

    Isolated so the (hardware-bound) collection can be substituted in tests and so
    the optional ``pymobiledevice3`` import is confined to one place.
    """
    from pymobiledevice3.services.os_trace import OsTraceService

    svc = OsTraceService(lockdown)
    await svc.collect(out=out, size_limit=size_limit, age_limit=age_limit, start_time=start_unix)


# ── Helpers ───────────────────────────────────────────────────────────────────

# ASCII-only allowlist — deliberately not `\w` (which is Unicode-aware and would
# admit homoglyphs into filenames written during a forensic acquisition).
_FILENAME_FORBIDDEN_RE = re.compile(r"[^A-Za-z0-9_-]")


def sanitise_filename_token(value: str) -> str:
    """Reduce *value* to a safe ASCII filename token (no path traversal)."""
    cleaned = _FILENAME_FORBIDDEN_RE.sub("_", value).strip(".")
    while ".." in cleaned:
        cleaned = cleaned.replace("..", "_")
    return cleaned


def _parse_start_time(value: str | int | None) -> int | None:
    """Resolve *value* to a Unix timestamp (seconds), or None."""
    if value is None:
        return None
    if isinstance(value, int):
        return value

    seconds = parse_duration_seconds(value)
    if seconds is not None:
        return int(datetime.now(tz=timezone.utc).timestamp()) - seconds

    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return int(datetime.strptime(value, fmt).replace(tzinfo=timezone.utc).timestamp())
        except ValueError:
            continue

    log.warning(f"Could not parse start_time {value!r} — ignoring")
    return None
