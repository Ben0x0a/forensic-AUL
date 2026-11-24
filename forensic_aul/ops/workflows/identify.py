"""Action-attribution workflow: still-pause baseline → action → acquire → diff.

Defines : ``run_identify_workflow`` (sync wrapper) and its async body — the full
          interactive identify sequence: acquire a baseline logarchive whose
          window starts BEFORE an optional operator "keep the device still"
          pause (so the pause and any USB/lockdown connection chatter both land
          in the baseline noise set), wait for the operator to perform the
          action, acquire a post-action logarchive, extract both to SQLite,
          optionally annotate the action DB against a knowledge base, and diff
          the two so only the lines attributable to the action remain. All
          user interaction is injected through callbacks (``confirm`` /
          ``wait_still`` / ``prepare`` / ``wait_for_action`` / ``describe_action`` /
          ``status``) so the CLI, the
          GUI and tests each supply their own front-end — the workflow itself
          performs no I/O beyond logging. This is a research tool, not a
          chain-of-custody acquisition: by default (``integrity="off"``) it
          skips the hashing / acquisition-report machinery to keep the
          interactive loop fast; pass ``integrity="full"``/``"fingerprint"``
          to restore the evidentiary paperwork.
Used by : launcher/cmds/identify_cmd.py and gui/controllers/identify.py (via
          forensic_aul.run_identify_workflow).
Uses    : forensic_aul.ops.acquisition (device connection, collection, report,
          AcquisitionError/-Aborted), forensic_aul.ops.extraction.extract
          (run_extract), forensic_aul.ops.identify.diff (run_diff),
          forensic_aul.ops.identify.run_info (run facts in the identified DB),
          forensic_aul.ops.annotation.matcher (annotate_database),
          .identify_options (IdentifyOptions), forensic_aul.engine.integrity
          (hash_logarchive), forensic_aul.engine.utils.progress.

WHY in ops/workflows and not in ops/identify: this is orchestration — it chains
the acquisition, extraction, annotation and diff bricks. A workflow may import
bricks; a brick never imports another brick's operations (review finding S4),
so each stays usable and testable on its own.

Errors are raised, never turned into exit codes: ``AcquisitionAborted`` when the
operator declines, ``OperationCancelled`` when they stop a run already under way,
``AcquisitionError`` / ``ValueError`` for failures — the front-end maps them to
exit status and user messages. Declining and cancelling are separate types on
purpose: the first means the run never legitimately started, the second that the
operator interrupted one that had.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from forensic_aul.engine.integrity import hash_logarchive
from forensic_aul.engine.utils.progress import ProgressReporter, ProgressSink
from forensic_aul.ops.acquisition.acquire import (
    AcquisitionAborted,
    AcquisitionError,
    collect_logarchive,
    sanitise_filename_token,
)
from forensic_aul.device_info import DeviceInfo
from forensic_aul.ops.acquisition.device import close_lockdown, connect_device
from forensic_aul.ops.acquisition.report import write_acquisition_report
from forensic_aul.case_info import CaseInfo
from forensic_aul.ops.identify.diff import run_diff, write_identified_csv
from forensic_aul.ops.identify.repeat import merge_repetitions, rank_repeated
from forensic_aul.ops.identify.run_info import ACTION_DESCRIPTION_KEY, write_run_info
from forensic_aul.ops.workflows.identify_options import IdentifyOptions
from forensic_aul.errors import ExtractFailedError
from forensic_aul.ops.annotation.matcher import annotate_database
from forensic_aul.ops.extraction.extract import run_extract
from forensic_aul.outcomes import ExtractStatus, IdentifyCycle, IdentifyResult

if TYPE_CHECKING:
    from forensic_aul.ops.knowledge_base.models import KnowledgeBase

log = logging.getLogger(__name__)

# Weighted phases for ProgressReporter (see engine/utils/progress.py). Weights
# are ratios, not percentages — the extract phases dominate because parsing is
# the slowest step by far. "wait" and "annotate" get minimal but non-zero
# weight since they can legitimately take a moment (operator pause / KB run).
_IDENTIFY_PHASES = [
    ("connect", 0.02), ("still", 0.04), ("prepare", 0.02), ("settle", 0.02), ("baseline", 0.12),
    ("wait", 0.02), ("action", 0.12), ("extract-baseline", 0.26),
    ("extract-action", 0.26), ("annotate", 0.04), ("diff", 0.12),
]


def _identify_phases(repeat: int) -> list[tuple[str, float]]:
    """The phases for *repeat* repetitions: every phase but ``connect`` runs
    once per repetition, so its weight is shared out — the reporter adds a
    phase's weight each time it is entered. Pair with ``total=`` the sum of
    ``_IDENTIFY_PHASES``: normalising by these shared-out weights would undo it."""
    n = max(1, repeat)
    return [(name, weight if name == "connect" else weight / n)
            for name, weight in _IDENTIFY_PHASES]

# Subfolder of the run folder for everything but the results (archives,
# extracts, each repetition's diff). Consumed by: _run_identify_async.
INTERMEDIATE_DIR_NAME = "intermediate"

# Seconds between "still collecting" progress updates during a capture.
_COLLECT_TICK_S = 1.0


def run_identify_workflow(
    output_dir: Path,
    case: CaseInfo | None = None,
    opts: IdentifyOptions | None = None,
    *,
    kb: "KnowledgeBase | None" = None,
    confirm: Callable[[DeviceInfo], bool] | None = None,
    wait_still: Callable[[int], None] | None = None,
    prepare: Callable[[], None] | None = None,
    wait_for_action: Callable[[], None] | None = None,
    describe_action: Callable[[], str] | None = None,
    status: Callable[[str], None] | None = None,
    progress: ProgressSink | None = None,
) -> IdentifyResult:
    """Run the full identify workflow and return the produced artefacts.

    Sequence: connect → confirm → set up chain-of-custody paths → capture
    ``t0`` → optional still pause (*wait_still*) → optional preparation
    (*prepare*, then a settle pause) → acquire a baseline covering *from t0* → wait for the operator to perform the action (*wait_for_action*)
    → acquire the post-action logarchive → extract both to SQLite → optionally
    annotate the action DB against *kb* → diff the two (see
    ``ops/identify/diff.py``).

    The baseline window starts at ``t0`` — captured BEFORE the still pause —
    so both the idle wait and the USB/lockdown connection chatter land in the
    baseline noise set rather than leaking into the diff as false positives.
    The baseline acquisition itself is never skipped even when *still_seconds*
    is 0: the diff needs its cutoff regardless.

    Front-end callbacks (each optional; all are invoked off the event loop so a
    blocking ``input()`` is fine):

    - *confirm(device)* — shown the connected :class:`DeviceInfo` before the
      baseline acquisition; returning False aborts (``AcquisitionAborted``).
    - *wait_still(seconds)* — asked to hold for *still_seconds* while the
      baseline captures a quiet device; raise
      :class:`~forensic_aul.errors.OperationCancelled` to abort (the GUI does so
      through a ``CancelToken``), or return early to skip the remaining wait (the
      callback owns the timing, not this function). Only invoked when *wait_still*
      is given AND *still_seconds* > 0.
    - *prepare()* — returns once the operator has done what must happen but is
      not of interest (unlock, open the app, reach the right screen), or at once
      when there is nothing to do; either way the baseline is handled the same.
      Those lines then land in the baseline instead of the result. *wait_still*
      is then asked for ``opts.settle_seconds``, so the work a preparation set
      off ends before the baseline is collected. Raise ``OperationCancelled`` to
      abort.
    - *wait_for_action()* — blocks until the operator has performed the action;
      raise :class:`~forensic_aul.errors.OperationCancelled` to abort. ``None``
      proceeds immediately (useful only in tests — a real run needs the pause).
    - *describe_action()* — asked once both captures are done for the operator's
      description of the action (front-ends let it be typed during the still
      pause and edited here). Stored in the identified database and the result.
    - *status(line)* — human progress lines ("[1/2] Acquiring baseline …");
      defaults to the module logger at INFO.
    - *progress* — a :class:`~forensic_aul.engine.utils.progress.ProgressSink`
      receiving weighted overall-fraction events across the whole run (see
      ``_IDENTIFY_PHASES``); each inner ``run_extract`` call's own 0..1
      progress advances the current phase.

    Every artefact of one run is written into a single **session directory**,
    ``output_dir/<prefix>/``, where *prefix* is
    ``<case>-<imei|udid>-<YYYY_MM_DD_HH_MM_SSZ>`` (UTC). The prefix is repeated
    on each file inside it, so a file stays self-identifying if it is copied
    out::

        <output_dir>/<prefix>/
            <prefix>-baseline.logarchive   <prefix>-baseline.db
            <prefix>-action.logarchive     <prefix>-action.db
            <prefix>-identified.csv        <prefix>-identified.db

    Args:
        output_dir: Where the session directory is created (required: evidence
            never lands in an implicit current directory).
        case: The case identifiers (none required: identify is not an evidence
            extract). When ``case.case_number`` is falsy, the session directory
            and its artefacts are named ``identify-<YYYY_MM_DD_HH_MM_SSZ>`` (UTC).
        opts: See :class:`IdentifyOptions`. ``opts.extract`` is forwarded to both
            ``run_extract`` calls; when its ``integrity`` is ``"off"`` (the
            default) the post-acquisition hashing + acquisition-report writing is
            skipped entirely — identify is a research tool, and that
            chain-of-custody machinery is pure latency/paperwork here.
        kb: When given, ``annotate_database`` runs on the ACTION db only
            (the baseline is diffed away and never needs annotations). A
            failure is logged and swallowed — annotation is an enrichment,
            not a requirement for the diff to succeed.

    Returns:
        An :class:`~forensic_aul.outcomes.IdentifyResult` with the four artefact
        paths (two archives, two databases) and the nested
        :class:`~forensic_aul.outcomes.DiffResult`.

    Raises:
        ValueError: ``case.case_number`` yields no usable filename characters
            after sanitising.
        ExtractFailedError: a capture's extract decoded nothing (status FAILED).
        ImportError: ``pymobiledevice3`` is not installed.
        AcquisitionAborted: the operator declined before the run started.
        OperationCancelled: a front-end callback stopped a run under way.
        AcquisitionError: connection, collection, or output-path safety failed.
    """
    return asyncio.run(_run_identify_async(
        output_dir,
        case if case is not None else CaseInfo(),
        opts if opts is not None else IdentifyOptions(),
        kb=kb, confirm=confirm, wait_still=wait_still, prepare=prepare,
        wait_for_action=wait_for_action, describe_action=describe_action,
        status=status, progress=progress,
    ))


async def _run_identify_async(
    output_dir: Path,
    case: CaseInfo,
    opts: IdentifyOptions,
    *,
    kb: "KnowledgeBase | None",
    confirm: Callable[[DeviceInfo], bool] | None,
    wait_still: Callable[[int], None] | None,
    prepare: Callable[[], None] | None,
    wait_for_action: Callable[[], None] | None,
    describe_action: Callable[[], str] | None,
    status: Callable[[str], None] | None,
    progress: ProgressSink | None,
) -> IdentifyResult:
    # Unpacked once, so the steps below read as plain names.
    case_number, exhibit_number = case.case_number, case.exhibit_number
    analyst, notes = case.analyst_name, case.notes
    udid, write_csv = opts.udid, opts.write_csv
    integrity = opts.extract.integrity
    say = status or (lambda line: log.info(line))
    # Normalised by one full run's total: the per-cycle phases carry 1/N of
    # their weight and are entered N times, so together they add up to it.
    reporter = ProgressReporter(progress, _identify_phases(opts.repeat),
                                total=sum(w for _, w in _IDENTIFY_PHASES))

    # ── Connect ───────────────────────────────────────────────────────────────
    reporter.phase("connect")
    log.info(f'Connecting to device{f" {udid}" if udid else ""}…')
    lockdown, device = await connect_device(udid)

    try:
        # Callbacks run via to_thread: a front-end confirm/wait typically blocks
        # on input(), which must not stall the event loop owning the connection.
        if confirm is not None and not await asyncio.to_thread(confirm, device):
            raise AcquisitionAborted("identify declined by confirm callback")

        # ── Chain-of-custody output paths ─────────────────────────────────────
        output_dir.mkdir(parents=True, exist_ok=True)
        if case_number:
            safe_case = sanitise_filename_token(case_number)
            if not safe_case:
                raise ValueError(
                    f"case_number {case_number!r} contains no usable filename characters"
                )
            id_token = sanitise_filename_token(device.imei) if device.imei else device.udid[:8]
            timestamp_str = datetime.now(tz=timezone.utc).strftime("%Y_%m_%d_%H_%M_%SZ")
            prefix = f"{safe_case}-{id_token}-{timestamp_str}"
        else:
            # No case number: a bare, timestamped prefix (same strftime as the
            # case-number branch) so runs stay chronologically sortable.
            timestamp_str = datetime.now(tz=timezone.utc).strftime("%Y_%m_%d_%H_%M_%SZ")
            prefix = f"identify-{timestamp_str}"

        # Every artefact of a run lives in one session directory named after the
        # prefix, so a run is a single self-contained folder to archive, move or
        # hand over — never six files scattered among other runs' output.
        session_dir = output_dir / prefix
        session_dir.mkdir(parents=True, exist_ok=True)

        # The run folder holds the results only — the identified database and
        # its CSV(s); everything they were made from (archives, extracts, each
        # repetition's diff) goes to intermediate/, for whoever needs it.
        result_db = session_dir / f"{prefix}-identified.db"
        (session_dir / INTERMEDIATE_DIR_NAME).mkdir(exist_ok=True)
        cycles = _cycle_paths(session_dir / INTERMEDIATE_DIR_NAME, prefix, opts.repeat,
                              result_db)

        # Defence in depth: ensure resolved paths still live under output_dir.
        out_resolved = output_dir.resolve()
        for cycle in cycles:
            for p in (cycle.baseline_archive, cycle.action_archive):
                try:
                    p.resolve().relative_to(out_resolved)
                except ValueError as exc:
                    raise AcquisitionError(
                        f"refusing to write outside output directory: {p}"
                    ) from exc

        for number, cycle in enumerate(cycles, 1):
            label = f"[{number}/{len(cycles)}] " if len(cycles) > 1 else ""
            if len(cycles) > 1:
                say(f"Repetition {number} of {len(cycles)}")
            await _capture_cycle(
                lockdown, cycle, opts, reporter, say, label,
                wait_still=wait_still, prepare=prepare, wait_for_action=wait_for_action,
            )
    finally:
        await close_lockdown(lockdown)

    description = ""
    if describe_action is not None:
        description = (await asyncio.to_thread(describe_action) or "").strip()

    # ── Hash + acquisition reports (skipped when integrity="off": identify is
    # a research tool, and this chain-of-custody machinery is pure latency /
    # evidence paperwork that a quick attribution run does not need) ──────────
    if integrity != "off":
        for cycle in cycles:
            for label, archive in (("baseline", cycle.baseline_archive),
                                   ("action", cycle.action_archive)):
                _hash_and_report(archive, label, device, case)

    # ── Per cycle: extract both, annotate the action, diff ──────────────────────
    imei = device.imei or "UNKNOWN"
    diffs = []
    say("Processing the captures (extract, compare)…")
    for cycle in cycles:
        for label, phase, archive, db in (
            ("baseline", "extract-baseline", cycle.baseline_archive, cycle.baseline_db),
            ("post-action", "extract-action", cycle.action_archive, cycle.action_db),
        ):
            reporter.phase(phase)
            # Paths in the log, not the status lines: the status says what is
            # happening, the log (--verbose) says where.
            log.info(f"Extracting {label} → {db}")
            capture_case = CaseInfo(
                case_number=case_number, imei=imei,
                exhibit_number=exhibit_number, analyst_name=analyst,
                notes=f"identify/{label}" + (f" — {notes}" if notes else ""),
            )
            result = run_extract(archive, db, capture_case, opts.extract,
                                 progress=lambda ev: reporter.update(ev.overall, ev.detail))
            # Stop here rather than diff two empty databases (B4): a FAILED
            # extract means this tool cannot decode the device's logs at all.
            if getattr(result, "status", None) is ExtractStatus.FAILED:
                raise ExtractFailedError(label, result)

        # Annotate: enrichment, not a requirement — never abort the run.
        if kb is not None:
            reporter.phase("annotate")
            try:
                annotate_database(cycle.action_db, kb)
            except Exception as exc:  # noqa: BLE001 — annotation must not sink the diff
                log.warning(f"Could not annotate action database: {exc}")

        reporter.phase("diff")
        log.info(f"Diffing → {cycle.identified_db}")
        # No CSV here: the run's one CSV is written from the result database.
        diffs.append(run_diff(cycle.baseline_db, cycle.action_db, None, cycle.identified_db))

    # ── Repeated runs: one result database, ranked ──────────────────────────────
    ranking = None
    if len(cycles) > 1:
        say(f"Merging the {len(cycles)} repetitions and ranking the templates…")
        log.info(f"Merging → {result_db}")
        merge_repetitions([c.identified_db for c in cycles], result_db)
        # Always with its CSV, whatever write_csv says: the CSV is how the
        # ranking is read (no viewer for it), in any spreadsheet or script.
        ranking = rank_repeated(result_db, session_dir / f"{prefix}-repeat.csv")
    write_run_info(result_db, {ACTION_DESCRIPTION_KEY: description})
    csv_path = None
    if write_csv:
        csv_path = session_dir / f"{prefix}-identified.csv"
        write_identified_csv(result_db, csv_path)
    reporter.finish("complete")

    first = cycles[0]
    return IdentifyResult(
        baseline_archive=first.baseline_archive,
        action_archive=first.action_archive,
        baseline_db=first.baseline_db,
        action_db=first.action_db,
        diff=diffs[0],
        action_description=description,
        cycles=tuple(
            IdentifyCycle(c.baseline_archive, c.action_archive, c.baseline_db, c.action_db, d)
            for c, d in zip(cycles, diffs)
        ),
        ranking=ranking,
        identified_db=result_db,
        csv_path=csv_path,
    )


@dataclass(frozen=True)
class _CyclePaths:
    """Where one repetition's artefacts go (see _cycle_paths)."""

    baseline_archive: Path
    action_archive: Path
    baseline_db: Path
    action_db: Path
    identified_db: Path


def _cycle_paths(
    intermediate_dir: Path, prefix: str, repeat: int, result_db: Path,
) -> list[_CyclePaths]:
    """One set of paths per repetition, in *intermediate_dir*: ``<prefix>-…``
    for a single run, ``<prefix>-<n>-…`` when repeated. A single run diffs
    straight into *result_db*; repetitions diff into their own databases, merged
    into it afterwards."""
    paths = []
    for number in range(1, max(1, repeat) + 1):
        stem = intermediate_dir / (prefix if repeat <= 1 else f"{prefix}-{number}")
        paths.append(_CyclePaths(
            Path(f"{stem}-baseline.logarchive"), Path(f"{stem}-action.logarchive"),
            Path(f"{stem}-baseline.db"), Path(f"{stem}-action.db"),
            result_db if repeat <= 1 else Path(f"{stem}-identified.db"),
        ))
    return paths


async def _capture_cycle(
    lockdown: object, cycle: _CyclePaths, opts: IdentifyOptions,
    reporter: ProgressReporter, say: Callable[[str], None], label: str, *,
    wait_still: Callable[[int], None] | None,
    prepare: Callable[[], None] | None,
    wait_for_action: Callable[[], None] | None,
) -> None:
    """One repetition's captures: still → prepare/settle → baseline → action."""
    # ── t0: captured BEFORE the still wait ──────────────────────────────────
    # The baseline window starts here, not after the pause, so the idle wait
    # itself (and any USB/lockdown connection chatter preceding it) lands inside
    # the baseline noise set instead of leaking into the diff.
    t0 = int(datetime.now(tz=timezone.utc).timestamp())

    # ── Optional still pause ─────────────────────────────────────────────────
    if wait_still is not None and opts.still_seconds > 0:
        reporter.phase("still")
        # Logged, not said: the wait_still callback shows the pause itself
        # (it was printed twice before — I3).
        log.info(f"{label}Still pause: {opts.still_seconds} s")
        # Raising aborts the whole run (same contract as wait_for_action);
        # returning early is a deliberate skip — the callback owns timing.
        await asyncio.to_thread(wait_still, opts.still_seconds)

    # ── Optional preparation, then a settle pause ───────────────────────────
    # Inside the baseline window (it started at t0): the preparation's lines
    # become baseline keys, so the result keeps the action of interest only.
    if prepare is not None:
        reporter.phase("prepare")
        await asyncio.to_thread(prepare)
        # Always, not only "if something was done": the run cannot tell, and a
        # few idle seconds cost nothing.
        if wait_still is not None and opts.settle_seconds > 0:
            # Its own phase: re-entering "still" would add that weight twice
            # and push the bar to 100 % before the run ends.
            reporter.phase("settle")
            log.info(f"{label}Settle pause: {opts.settle_seconds} s")
            await asyncio.to_thread(wait_still, opts.settle_seconds)

    # ── Baseline (never skipped: the diff needs its cutoff) ────────────────────
    reporter.phase("baseline")
    say("Capturing the baseline…")
    log.info(f"{label}Baseline → {cycle.baseline_archive}")
    await _collect(lockdown, cycle.baseline_archive, t0, reporter)

    # Cutoff for the action capture: now (post-baseline). Anything after this
    # point is what the analyst is hunting for.
    action_start_unix = int(datetime.now(tz=timezone.utc).timestamp())

    # ── Operator performs the action ─────────────────────────────────────────
    # Phase fires BEFORE wait_for_action runs — the front-end uses it to show
    # the pause panel ahead of blocking on the callback.
    reporter.phase("wait")
    if wait_for_action is not None:
        await asyncio.to_thread(wait_for_action)

    # ── Post-action ──────────────────────────────────────────────────────────
    reporter.phase("action")
    say("Capturing the action…")
    log.info(f"{label}Action → {cycle.action_archive}")
    await _collect(lockdown, cycle.action_archive, action_start_unix, reporter)


def _hash_and_report(archive: Path, label: str, device: DeviceInfo, case: CaseInfo) -> None:
    """Hash *archive* and write its acquisition report (failures only logged)."""
    try:
        sha, hashes = hash_logarchive(archive)
    except Exception as exc:  # noqa: BLE001
        log.warning(f"Could not hash {label} archive: {exc}")
        sha, hashes = "", {}
    try:
        write_acquisition_report(
            logarchive_path=archive,
            device=device,
            case_number=case.case_number,
            exhibit_number=case.exhibit_number,
            analyst=case.analyst_name,
            notes=f"identify/{label}" + (f" — {case.notes}" if case.notes else ""),
            logarchive_sha256=sha,
            file_count=len(hashes),
        )
    except Exception as exc:  # noqa: BLE001
        log.warning(f"Could not write {label} acquisition report: {exc}")


async def _collect(
    lockdown: object, archive_path: Path, start_unix: int, reporter: ProgressReporter,
) -> None:
    """One windowed collection into *archive_path* (missing output = error).

    The collection reports nothing until it ends (pymobiledevice3's ``collect``
    has no progress hook), so a ticker reports the elapsed time meanwhile — an
    honest "still working", not an invented fraction (I3).
    """
    async def tick() -> None:
        started = asyncio.get_running_loop().time()
        while True:
            await asyncio.sleep(_COLLECT_TICK_S)
            elapsed = asyncio.get_running_loop().time() - started
            reporter.update(0.0, f"collecting… {elapsed:.0f} s")

    ticker = asyncio.create_task(tick())
    try:
        await collect_logarchive(
            lockdown, str(archive_path),
            size_limit=None, age_limit=None, start_unix=start_unix,
        )
    finally:
        ticker.cancel()
    if not archive_path.exists():
        raise AcquisitionError(
            f"collection reported success but {archive_path} was not created"
        )
