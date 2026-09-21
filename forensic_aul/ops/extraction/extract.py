"""AUL Parser — extract pipeline.

Converts a .logarchive directory into a normalised SQLite database.

Pipeline steps
--------------
1. Forensic hashing of the whole logarchive
2. Schema initialisation (WAL, tables, indexes, FTS5)
3. Insert case_metadata placeholder
4. Parse all *.timesync files (ops/extraction/timesync_setup.py)
5. Build lazy StringCacheProvider (UUIDText + DSC)
6. Pass 1 — collect Oversize entries from all tracev3 files
7. Pass 2 — parse all tracev3 in order, produce LogEntry rows, write to DB
8. Finalise case_metadata (timestamps, ios_model, ios_build_version)

The stages share one :class:`~forensic_aul.ops.extraction.options.RunContext`
(connection, prepared source, options, reporter, cancellation token) instead of
long parameter lists; the user-tunable knobs live in ``ExtractOptions`` (same
module).

Interruption
------------
The pipeline is cancellable and, more importantly, **always says whether it
finished**. Two independent markers carry that, deliberately:

* out of band — the output is written as ``<name>.partial`` and only renamed to
  ``<name>`` on success, so an interrupted run is obvious from the filename with
  no code having had to run (see :data:`PARTIAL_SUFFIX`);
* in band — ``case_metadata.extract_status`` goes ``running`` → ``complete`` /
  ``cancelled``, which is what ``open_analysis_database`` checks before letting a
  reader treat the store as a full parse.

``extract_phases`` records each phase's start and end as the run progresses, so
an interrupted database can say which phase it died in — and a future resume can
read the same ledger (together with ``source_files.parse_completed_at``) to know
where to restart.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from forensic_aul import __version__
from forensic_aul.config import BATCH_SIZE, PARTIAL_SUFFIX
from forensic_aul.engine.database.ordering import assign_ordering
from forensic_aul.engine.database.schema import (
    EXTRACT_STATUS_CANCELLED,
    EXTRACT_STATUS_COMPLETE,
    apply_pragmas,
    finalize_deferred_fts,
    finalize_indexes,
    init_schema,
)
from forensic_aul.engine.database.writer import (
    BatchWriter,
    now_iso,
    register_source_file,
)
from forensic_aul.engine.integrity import verify_source_files
from forensic_aul.engine.ios_builds import ios_version_for_build
from forensic_aul.engine.parser.string_cache import StringCacheProvider
from forensic_aul.engine.utils.cancellation import NEVER_CANCELLED, CancelToken
from forensic_aul.engine.utils.progress import ProgressReporter, ProgressSink
from forensic_aul.engine.utils.time import iso8601_from_unix_ns
from forensic_aul.errors import OperationCancelled
from forensic_aul.ops.extraction.discovery import find_tracev3_files
from forensic_aul.ops.extraction.options import CaseInfo, ExtractOptions, RunContext
from forensic_aul.ops.extraction.oversize_pass import OversizeCache, collect_oversize
from forensic_aul.ops.extraction.source import PreparedSource, prepare_source
from forensic_aul.ops.extraction.timesync_setup import setup_timesync
from forensic_aul.ops.extraction.tracev3_parse import process_tracev3
from forensic_aul.ops.extraction.workers import parallel_parse
from forensic_aul.ops.summary.cache import refresh_summary
from forensic_aul.outcomes import ExtractResult

# Relative phase weights for the extract progress bar (ratios, normalised by the
# reporter). Tuned to the observed split on a large extract; finish() covers any
# phase that is skipped (e.g. the FTS rebuild when FTS is incremental).
_EXTRACT_PHASES = [
    ("prepare", 0.08),   # source prep + hashing + timesync + string cache + oversize scan
    ("parse", 0.55),     # pass 2, weighted by tracev3 bytes
    ("ordering", 0.17),  # assign_ordering
    ("index", 0.13),     # finalize_indexes
    ("fts", 0.07),       # deferred FTS rebuild (--fast-fts only)
    ("stats", 0.05),     # summary statistics, cached into the database
]

# How often SQLite asks the cancellation handler whether to abort, measured in
# virtual-machine steps. It is the ONLY way to interrupt the three monolithic
# statements in the finaliser (ordering phase 1, the index builds, the FTS
# rebuild), each of which can run for minutes with no Python code executing in
# between. Measured: an abort lands in well under a millisecond, and the
# connection stays usable afterwards — which is what lets the cancel handler go
# on to record the run's status in the very database it just interrupted.
_CANCEL_VM_STEPS = 50_000

log = logging.getLogger(__name__)


def partial_path_for(db_path: Path) -> Path:
    """Return the ``.partial`` working path ``run_extract`` writes for *db_path*.

    One definition so the pipeline, the overwrite guard and any caller inspecting
    an interrupted run cannot disagree about the name.
    """
    return db_path.with_name(db_path.name + PARTIAL_SUFFIX)


def _db_sidecars(path: Path) -> tuple[Path, ...]:
    """The SQLite file *path* plus its WAL/SHM sidecars, in delete-safe order."""
    return (
        path,
        path.with_name(path.name + "-wal"),
        path.with_name(path.name + "-shm"),
    )


@dataclass
class _ParseStats:
    """What the parse pass (steps 3-7) hands to the finaliser."""

    total_entries: int = 0
    total_errors: int = 0
    ios_model: str = ""
    ios_build_version: str = ""
    boot_uuid: str = ""
    metadata_id: int = 0

    def absorb(self, file_stats: tuple[str, str, str, int, int]) -> None:
        """Fold one tracev3 file's (boot_uuid, model, build, written, errors) in."""
        b_uuid, model, build, n_written, n_err = file_stats
        self.total_entries += n_written
        self.total_errors += n_err
        if b_uuid and not self.boot_uuid:
            self.boot_uuid = b_uuid
        if model and not self.ios_model:
            self.ios_model = model
        if build and not self.ios_build_version:
            self.ios_build_version = build


def _ingest_shutdown_log(
    writer: BatchWriter,
    logarchive_root: Path,
    file_hashes: dict[str, str],
) -> int:
    """Parse ``shutdown.log`` (if present) into the shutdown_events tables.

    These are wall-clock-anchored power-off events with no mach time/boot, so they
    live outside the logs/event_order timeline (see extraction/shutdown_log.py).
    Returns the number of shutdown events ingested.
    """
    from forensic_aul.ops.extraction.shutdown_log import (
        find_shutdown_log,
        parse_shutdown_log,
    )

    path = find_shutdown_log(logarchive_root)
    if path is None:
        log.debug("No shutdown.log found — skipping shutdown events")
        return 0
    try:
        events = parse_shutdown_log(path)
    except Exception as exc:  # noqa: BLE001 — a malformed sidecar must not fail the extract
        log.warning(f"shutdown.log parse error in {path.name}: {exc}")
        return 0
    if not events:
        log.info(f"shutdown.log found ({path.name}) but no shutdown events parsed")
        return 0

    sf_id = register_source_file(writer, logarchive_root, path, "shutdown_log", file_hashes)
    for ev in events:
        ev_id = writer.insert_shutdown_event(
            sf_id, ev.unix_ns, ev.iso, ev.delay_seconds, len(ev.clients)
        )
        if ev.clients:
            writer.insert_shutdown_clients(
                ev_id, [(c.pid, c.process_path, c.lingered_seconds) for c in ev.clients]
            )
    return len(events)


# ── Public entry point ────────────────────────────────────────────────────────

def run_extract(
    logarchive: Path | Mapping[str, Path] | PreparedSource,
    db_path: Path,
    *,
    case_number: str | None = None,
    imei: str | None = None,
    exhibit_number: str | None = None,
    analyst_name: str | None = None,
    notes: str | None = None,
    batch_size: int = BATCH_SIZE,
    work_dir: Path | None = None,
    reset_work_dir: bool = False,
    fast_fts: bool = True,
    fast_write: bool = False,
    fts: bool = True,
    keep_raw: bool = False,
    jobs: int = 1,
    overwrite: bool = False,
    integrity: str = "full",
    progress: ProgressSink | None = None,
    cancel: CancelToken = NEVER_CANCELLED,
) -> ExtractResult:
    """Full extract pipeline: source → SQLite.

    This is the main entry point called by the CLI. *logarchive* may be a
    ``.logarchive`` directory, a sysdiagnose ``.tar.gz``, a full-file-system
    ``.zip``, or a mapping of two already-uncompressed folders
    ``{"diagnostics": dir, "uuidtext": dir}`` — the source-preparation layer
    normalises all of them to a logarchive layout before parsing (see
    forensic_aul/ops/extraction/source.py). Archives / loose dirs are materialised
    into *work_dir* (kept) or an auto-cleaned temp dir. A kept work root that
    already holds files is **refused** — reusing it would parse the previous run's
    evidence into this case; pass *reset_work_dir* to delete it first.

    Alternatively pass an already-built :class:`PreparedSource` (from
    ``prepare_source``, e.g. to inspect the type/hashes before committing to a
    long extract). Preparation then does **not** run again — the source is not
    re-hashed and its full provenance (source type, archive fingerprint, iOS
    version) is recorded as prepared. In that case *work_dir* and *integrity*
    are ignored (both were decided at preparation time) and cleanup stays with
    the caller (use ``with prepare_source(...) as src:``).

    *jobs* is the total process budget for parsing: ``1`` (default) parses
    in-process; ``N`` uses ``N-1`` worker processes plus the writer (this main
    process), so total processes ≈ one per CPU core. The result is identical
    regardless of *jobs* (ordering is assigned post-load; see database/ordering.py).

    .. warning::
        ``jobs > 1`` uses **spawn-based multiprocessing**: the calling entry
        point must be import-safe (guarded by ``if __name__ == "__main__":`` or
        equivalent — always true for a plugin/module that only runs code inside
        functions). An entry script that starts the extract at import time would
        be re-executed by every spawned worker, which typically surfaces as a
        run that "succeeds" with 0 entries.

    *integrity* selects the source-hashing mode (see
    ``ops/extraction/source.INTEGRITY_MODES``): ``"full"`` (default) takes the
    complete chain-of-custody attestation (per-file SHA-256, content hash,
    end-of-run re-verification); ``"fingerprint"`` keeps only the cheap archive
    fingerprint; ``"off"`` skips all hashing. Non-full modes trade the forensic
    attestation for start-up speed — the database then records NULL hashes and
    the end-of-run integrity re-check is skipped.

    *fts* (default True) builds an FTS5 full-text index over every message —
    valuable for interactive analyst search, but a large cost on multi-million
    row extracts. Programmatic consumers that filter on structured columns
    (process / subsystem / format string / message prefix — see ``query_logs``)
    should pass ``fts=False``.

    If *db_path* (or the ``.partial`` of a previous interrupted run) already
    exists the call refuses to proceed unless *overwrite* is True — extracting
    into an existing database would silently merge two acquisitions into one
    file. With *overwrite* both (and their ``-wal`` / ``-shm`` sidecars) are
    removed first so the run starts clean.

    **The output is written to ``<db_path>.partial`` and renamed to *db_path*
    only once the run has succeeded.** So a file at *db_path* means a complete
    extract, and a ``.partial`` beside it means an interrupted one — a
    cancellation, a crash, a ``SIGKILL`` and a power cut all leave the same
    unambiguous artefact, because no code has to run for the name to say so. The
    rename is atomic within a filesystem. The same fact is recorded *in band* as
    ``case_metadata.extract_status`` (``running`` → ``complete`` / ``cancelled``),
    which is what the readers check (see ``open_analysis_database``).

    *cancel* makes the run interruptible: pass a
    :class:`~forensic_aul.engine.utils.cancellation.CancelToken` and call
    ``cancel()`` on it from another thread. The pipeline stops at its next check
    point (per archive member / per source file / per tracev3 chunk, and inside
    the finaliser's long SQL statements via SQLite's progress handler), records
    ``cancelled`` in the database, leaves the ``.partial`` in place and raises
    :class:`~forensic_aul.errors.OperationCancelled` with ``partial_db_path``
    set. Rows already parsed are kept — they are genuine evidence; the database
    is simply marked as not being the complete parse of its source.

    Returns:
        An :class:`~forensic_aul.outcomes.ExtractResult` bundling the output
        ``db_path``, the ``metadata_id`` (to seal the log-file hash later), and
        the run facts (entry/error counts, device model, iOS build/version, boot
        UUID, time range, source type and SHA-256).

    Raises:
        FileExistsError: *db_path* (or its ``.partial``) exists and *overwrite*
            is False.
        OperationCancelled: *cancel* was cancelled during the run.
    """
    # For a caller-supplied PreparedSource the integrity mode was decided at
    # preparation time; derive it from the prepared state so the finaliser's
    # re-hash decision matches reality (there is no baseline to re-check when
    # preparation did not hash).
    if isinstance(logarchive, PreparedSource):
        integrity = "full" if logarchive.file_hashes else "off"

    opts = ExtractOptions(
        batch_size=batch_size,
        fast_fts=fast_fts,
        fast_write=fast_write,
        fts=fts,
        keep_raw=keep_raw,
        jobs=jobs,
        overwrite=overwrite,
        integrity=integrity,
    )
    case = CaseInfo(
        case_number=case_number,
        imei=imei,
        exhibit_number=exhibit_number,
        analyst_name=analyst_name,
        notes=notes,
    )

    # Fail fast (before the expensive source hashing) and never silently append
    # a second acquisition into an existing database. The actual removal is
    # deferred until just before we open the connection (see below), so a failure
    # during source preparation cannot destroy a pre-existing database.
    # BOTH names are guarded: a leftover `.partial` is the previous run's
    # evidence, and writing this acquisition into it would merge two cases just
    # as surely as writing into a finished database would.
    work_path = partial_path_for(db_path)
    for existing in (db_path, work_path):
        if existing.exists() and not opts.overwrite:
            raise FileExistsError(
                f"{existing} already exists; pass overwrite=True to replace it "
                "(extracting into an existing database would merge two acquisitions)"
            )

    _t0 = time.monotonic()
    # Wall-clock start of preparation, kept so the phase can be entered into the
    # extract_phases ledger later — the database it belongs in does not exist yet.
    _prepare_started_at = now_iso()
    reporter = ProgressReporter(progress, _EXTRACT_PHASES)
    reporter.phase("prepare", "hashing source")
    cancel.check()

    # ── Step 1: Source preparation + forensic hashing ─────────────────────
    log.info("─── Step 1/7 : Source preparation + hashing ──────────────────")
    _t_hash = time.monotonic()
    # A caller-supplied PreparedSource is used as-is: preparation (and its
    # integrity mode) already happened, so re-preparing would re-hash the whole
    # source and — worse — replace the real provenance (source type, archive
    # fingerprint, iOS version) with that of the intermediate directory.
    caller_prepared = isinstance(logarchive, PreparedSource)
    if caller_prepared:
        prepared = logarchive
        log.info("Source already prepared by the caller — reusing (no re-hash)")
        log.debug("Prepared root : %s", prepared.logarchive_root.resolve())
    else:
        log.info("Preparing source (extracting archives may take a moment)…")
        if isinstance(logarchive, Mapping):
            log.debug("Source dirs : %s", {k: str(v) for k, v in logarchive.items()})
        else:
            log.debug("Source path : %s", Path(logarchive).resolve())
        prepared = prepare_source(
            logarchive, work_dir=work_dir, integrity=opts.integrity,
            reset_work_dir=reset_work_dir, cancel=cancel,
        )
    log.info(f"Source type        : {prepared.source_type.value}")
    if prepared.archive_fingerprint is not None:
        log.info(f"Archive fingerprint: {prepared.archive_fingerprint}  (pre-run snapshot)")
        if prepared.is_temporary:
            log.info("Work dir           : temporary (auto-cleaned after run)")
        else:
            log.info(f"Work dir (kept)    : {prepared.logarchive_root}")
    if prepared.content_sha256 is not None:
        timing = "pre-computed by caller" if caller_prepared else f"{len(prepared.file_hashes)} files hashed in {time.monotonic() - _t_hash:.1f} s"
        log.info(f"Content SHA-256    : {prepared.content_sha256}  ({timing})")
    elif caller_prepared:
        log.info("Content SHA-256    : (not taken at preparation time)")
    else:
        log.info(f"Content SHA-256    : (not taken — integrity={opts.integrity!r})")
    log.debug("Per-file hashes:")
    for rel_path, digest in sorted(prepared.file_hashes.items()):
        log.debug("  %s  %s", digest, rel_path)

    # ── Step 2: Database setup ────────────────────────────────────────────
    log.info("─── Step 2/7 : Database initialisation ─────────────────────────")
    log.debug("Output database : %s  (written as %s)", db_path.resolve(), work_path.name)
    # Source preparation succeeded, so it is now safe to clear any existing DB
    # (and its WAL/SHM sidecars) and start clean — deferred from the entry guard
    # so a prep failure could not have destroyed a pre-existing database. Both
    # names go, for the same reason the guard above checks both.
    if opts.overwrite:
        for stale in (*_db_sidecars(db_path), *_db_sidecars(work_path)):
            stale.unlink(missing_ok=True)
    conn = sqlite3.connect(str(work_path))
    ctx = RunContext(
        conn=conn,
        db_path=work_path,
        final_db_path=db_path,
        prepared=prepared,
        case=case,
        opts=opts,
        reporter=reporter,
        t0=_t0,
        cancel=cancel,
        prepare_started_at=_prepare_started_at,
    )
    # Arm the only interrupt that reaches inside a running SQL statement. Done
    # once, here, so it covers every statement the pipeline issues on this
    # connection — including the finaliser's three monolithic ones.
    _arm_sqlite_cancel(conn, cancel)
    try:
        result = _run_extract_inner(ctx)
        reporter.finish("complete")
        # ── Integrity attestation (after) ─────────────────────────────────
        # Re-check the archive fingerprint now the run is complete: we only ever
        # opened the evidence read-only, so a mismatch means it was modified
        # externally during the run and the result must be treated with caution.
        if prepared.archive_fingerprint is not None:
            if prepared.verify_unchanged():
                log.info("Archive integrity re-check : PASS — unchanged since pre-run snapshot")
            else:
                log.warning(f"Archive integrity re-check : FAIL — {prepared.original_path} changed during the run!")
    except BaseException as exc:
        _handle_interruption(ctx, exc)
        raise
    finally:
        conn.close()
        # A caller-supplied PreparedSource is cleaned up by its owner (typically
        # a `with prepare_source(...)` block); cleaning it here would tear down
        # a temp extraction the caller may still want to inspect or reuse.
        if not caller_prepared:
            prepared.cleanup()

    # ── Promote the artefact to its final name ────────────────────────────
    # Only reached on success, and only after the connection is closed (so WAL
    # is checkpointed and the file on disk is self-contained). From this instant
    # the presence of db_path is the proof that the extract finished.
    _promote_partial(work_path, db_path)
    return result


# ── Phase ledger (extract_phases) ─────────────────────────────────────────────

def _enter_phase(ctx: RunContext, name: str, detail: str = "") -> None:
    """Advance the progress bar to *name*, open its ledger row, and check *cancel*.

    Progress and ledger are driven from one call so the bar an operator watches
    and the record a future resume reads can never disagree about which phase is
    running. The previous phase is closed first; a phase left open in the table is
    therefore exactly the phase an interrupted run died in.

    WHY the cancel check comes LAST — after the row is opened: a phase boundary
    is the cheapest possible check point, and stopping here (rather than one
    statement into the phase) is the difference between an operator's Cancel
    landing at once and it waiting out a whole index build. Opening the row first
    means the ledger still names the phase the run was entering, which is what
    resume needs to know.
    """
    _leave_phase(ctx)
    ctx.reporter.phase(name, detail)
    if ctx.writer is not None:
        ctx.phase_id = ctx.writer.begin_phase(name)
    ctx.cancel.check()


def _leave_phase(ctx: RunContext) -> None:
    """Close the currently-open ``extract_phases`` row, if any."""
    if ctx.writer is not None and ctx.phase_id is not None:
        ctx.writer.complete_phase(ctx.phase_id)
    ctx.phase_id = None


def _record_prepare_phase(ctx: RunContext) -> None:
    """Enter the already-finished source-preparation phase into the ledger.

    Source preparation runs before the database it would be recorded in exists,
    so it is the one phase written after the fact — with the time it really
    started, captured by ``run_extract``. Without this the ledger would begin
    mid-run and could not account for the minutes a large archive spends being
    extracted and hashed.
    """
    if ctx.writer is None or not ctx.prepare_started_at:
        return
    ctx.writer.complete_phase(ctx.writer.begin_phase("prepare", ctx.prepare_started_at))


# ── Cancellation plumbing ─────────────────────────────────────────────────────

def _arm_sqlite_cancel(conn: sqlite3.Connection, cancel: CancelToken) -> None:
    """Let *cancel* abort a statement already running on *conn*.

    HOW: SQLite calls the registered handler every ``_CANCEL_VM_STEPS`` virtual
    machine instructions and aborts the current statement (raising
    ``sqlite3.OperationalError``) when it returns a non-zero value.

    WHY this is not optional: three of the pipeline's steps — ``assign_ordering``
    phase 1, ``finalize_indexes`` and ``finalize_deferred_fts`` — are *single*
    statements that can run for minutes on a large extract. No Python executes
    while they do, so a token check between phases would leave Cancel doing
    nothing at all for the whole of the finaliser.

    Installed only for a real token: with the null token the handler could never
    fire, so registering it would be pure per-statement overhead.
    """
    if cancel is NEVER_CANCELLED:
        return
    conn.set_progress_handler(lambda: 1 if cancel.cancelled else 0, _CANCEL_VM_STEPS)


def _mark_cancelled(ctx: RunContext) -> None:
    """Record ``extract_status='cancelled'`` in the interrupted database.

    Best-effort by design: the ``.partial`` filename already marks the artefact,
    so failing to write the in-band flag must never replace the operator's
    cancellation with a confusing secondary error.
    """
    if ctx.writer is None or ctx.metadata_id is None:
        # The run never got as far as inserting case_metadata — there is no row
        # to flag. The `.partial` name carries the whole message on its own.
        return
    try:
        # An aborted statement can leave a transaction open; drop it first so the
        # status UPDATE is not rolled back with it.
        ctx.conn.rollback()
        ctx.writer.set_extract_status(ctx.metadata_id, EXTRACT_STATUS_CANCELLED)
        log.info(f"Run marked cancelled in {ctx.db_path.name} (extract_status=cancelled)")
    except Exception:  # noqa: BLE001 — never mask the cancellation itself
        log.warning("Could not record the cancelled status in the database", exc_info=True)


def _handle_interruption(ctx: RunContext, exc: BaseException) -> None:
    """React to whatever ended the run early; translate a cancel-driven abort.

    Returns normally for a genuine failure (leaving ``extract_status='running'``,
    which is the truth: the run died). Raises
    :class:`~forensic_aul.errors.OperationCancelled` — carrying
    ``partial_db_path`` — when the operator cancelled, including the case where
    the cancellation surfaced as SQLite aborting a statement rather than as a
    token check.
    """
    # FIRST, before anything else touches the connection: the progress handler is
    # still armed and still sees a cancelled token, so it would abort the very
    # UPDATE that records the cancellation.
    try:
        ctx.conn.set_progress_handler(None, 0)
    except Exception:  # noqa: BLE001 — a dead connection is not worth a new error
        log.debug("could not disarm the sqlite cancel handler", exc_info=True)

    if isinstance(exc, OperationCancelled):
        _mark_cancelled(ctx)
        exc.partial_db_path = ctx.db_path
        return
    # A statement aborted by our own progress handler arrives as a bare
    # OperationalError; only the token can say whether that was us.
    if ctx.cancel.cancelled and isinstance(exc, sqlite3.OperationalError):
        _mark_cancelled(ctx)
        cancelled = OperationCancelled(
            "operation cancelled by the operator (SQLite statement aborted)"
        )
        cancelled.partial_db_path = ctx.db_path
        raise cancelled from exc


def _promote_partial(work_path: Path, db_path: Path) -> None:
    """Rename the finished ``.partial`` to its final name (the success marker).

    Any WAL/SHM sidecar that outlived the close is moved with it: leaving one
    behind under the old stem would orphan it next to a database it no longer
    belongs to. A clean close normally removes both, so this is defence in depth.
    """
    for suffix in ("-wal", "-shm"):
        sidecar = work_path.with_name(work_path.name + suffix)
        if sidecar.exists():
            sidecar.replace(db_path.with_name(db_path.name + suffix))
    work_path.replace(db_path)


def open_or_extract(
    logarchive: Path | Mapping[str, Path],
    db_path: Path,
    **run_extract_kwargs,
) -> Path:
    """Return *db_path*, extracting *logarchive* into it first if it is absent.

    The standard "parse once, reuse" pattern for programmatic consumers: several
    features (or several runs) share one analysis database without each
    re-implementing the exists-check. When *db_path* already exists it is
    returned as-is — its content is trusted to be a previous extract of the same
    source (this helper does not verify that; delete the file to force a fresh
    extract). Otherwise :func:`run_extract` runs with the given keyword options
    and the resulting path is returned.
    """
    if db_path.exists():
        log.info(f"Reusing existing analysis database: {db_path}")
        return db_path
    return run_extract(logarchive, db_path, **run_extract_kwargs).db_path


def _run_extract_inner(ctx: RunContext) -> ExtractResult:
    """Body of run_extract — connection lifetime is owned by the caller."""
    opts = ctx.opts
    # Durability: NORMAL (default) never corrupts the DB; --fast-write uses OFF
    # for speed at the cost of power-loss safety. sort_threads parallelises the
    # finaliser sorts (index builds + ordering) across the same core budget.
    apply_pragmas(
        ctx.conn,
        synchronous="OFF" if opts.fast_write else "NORMAL",
        sort_threads=max(0, opts.jobs),
    )
    # Indexes are always deferred to the end of the run (built by finalize_indexes):
    # cheap on a finished table, and an interrupted run still has complete, correct
    # (just unindexed) data. FTS is on by default (--no-fts opts out); when on it
    # stays incremental unless --fast-fts defers the rebuild.
    ctx.fts5_ok = init_schema(
        ctx.conn, enable_fts5=opts.fts, defer_fts_triggers=opts.fast_fts, create_indexes=False
    )
    log.info(f'Schema created  : WAL mode (sync={"OFF" if opts.fast_write else "NORMAL"}), indexes deferred, FTS5={"enabled" if ctx.fts5_ok else ("disabled" if not opts.fts else "unavailable")}{" (deferred rebuild)" if opts.fast_fts and ctx.fts5_ok else ""}, raw_data={"kept" if opts.keep_raw else "dropped"}, batch_size={opts.batch_size}')

    ctx.writer = BatchWriter(ctx.conn, batch_size=opts.batch_size)
    _record_prepare_phase(ctx)

    stats = _run_parse(ctx)
    result = _finalise(ctx, stats)
    _leave_phase(ctx)
    return result


def _run_parse(ctx: RunContext) -> _ParseStats:
    """Steps 3-7: metadata placeholder, timesync, string cache, oversize, parse loop."""
    conn, writer, opts = ctx.conn, ctx.writer, ctx.opts
    assert writer is not None, "Invariant violated: _run_extract_inner must create the writer"
    logarchive = ctx.prepared.logarchive_root
    file_hashes = ctx.prepared.file_hashes

    # ── Step 3: Case metadata ─────────────────────────────────────────────
    log.info("─── Step 3/7 : Case metadata ────────────────────────────────────")
    stats = _ParseStats()
    stats.metadata_id = writer.insert_case_metadata(
        case_number=ctx.case.case_number,
        imei=ctx.case.imei,
        exhibit_number=ctx.case.exhibit_number,
        analyst_name=ctx.case.analyst_name,
        notes=ctx.case.notes,
        source_path=str(ctx.prepared.original_path),
        logarchive_path=ctx.prepared.recorded_logarchive_path,
        logarchive_sha256=ctx.prepared.content_sha256,
        source_type=ctx.prepared.source_type.value,
        archive_fingerprint=ctx.prepared.archive_fingerprint,
        tool_version=__version__,
    )
    conn.commit()
    # Publish the id at once: from here on the cancel path can flag this exact
    # row, and it must not depend on _run_parse returning normally to learn it.
    ctx.metadata_id = stats.metadata_id
    log.info(f"Case metadata inserted  : id={stats.metadata_id}  case={ctx.case.case_number}  imei={ctx.case.imei}")
    if ctx.case.exhibit_number:
        log.info(f"  Exhibit  : {ctx.case.exhibit_number}")
    if ctx.case.analyst_name:
        log.info(f"  Analyst  : {ctx.case.analyst_name}")

    # ── Step 4: Timesync ──────────────────────────────────────────────────
    log.info("─── Step 4/7 : Timesync files ───────────────────────────────────")
    ctx.cancel.check()
    ts = setup_timesync(writer, logarchive, file_hashes)

    # ── Step 5: String cache (UUIDText + DSC) ─────────────────────────────
    log.info("─── Step 5/7 : String cache (UUIDText + DSC) ───────────────────")
    ctx.cancel.check()
    strings = StringCacheProvider(logarchive)
    strings.load(writer, logarchive, file_hashes)
    # StringCacheProvider already logs its summary at INFO

    # ── Step 6: Pass 1 — Oversize entries ────────────────────────────────
    log.info("─── Step 6/7 : Pass 1 — Oversize scan ──────────────────────────")
    tracev3_files = find_tracev3_files(logarchive)
    log.info(f"Found {len(tracev3_files)} tracev3 file(s)  (Persist / Special / Signpost order)")
    for f in tracev3_files:
        log.debug("  %s  (%d B)", f.relative_to(logarchive), f.stat().st_size)

    # Pre-register every tracev3 file now, in canonical order, so tracev3_file_id
    # is fixed before parsing (workers receive it; source_order/event_order rely on
    # the canonical id order). Keyed by posix relpath so it is picklable + stable.
    tracev3_file_ids: dict[str, int] = {}
    for path in tracev3_files:
        rel = path.relative_to(logarchive).as_posix()
        tracev3_file_ids[rel] = register_source_file(
            writer, logarchive, path, "tracev3", file_hashes
        )
    # Persist source_files + anchors before parsing (workers read no DB, but this
    # keeps the on-disk state consistent and the WAL small).
    conn.commit()

    oversize_cache: OversizeCache = collect_oversize(
        tracev3_files, strings, cancel=ctx.cancel
    )
    log.info(f"Oversize cache  : {len(oversize_cache)} entry(ies) collected")

    # ── Step 7: Pass 2 — Main parse ───────────────────────────────────────
    log.info("─── Step 7/7 : Pass 2 — Main parse ─────────────────────────────")
    rels = [p.relative_to(logarchive).as_posix() for p in tracev3_files]

    # Progress: weight the parse by tracev3 byte size (files vary ~1000x in entry
    # count, so byte size advances the bar far more smoothly than file count).
    _enter_phase(ctx, "parse")
    _sizes = {rel: max(1, p.stat().st_size) for p, rel in zip(tracev3_files, rels)}
    _total_bytes = sum(_sizes.values()) or 1
    _done_bytes = 0

    if opts.jobs <= 1:
        # Serial in-process path: parse → writer.add directly.
        for i, (path, rel) in enumerate(zip(tracev3_files, rels), 1):
            log.info(f"[{i}/{len(tracev3_files)}] {rel}")
            stats.absorb(process_tracev3(
                path, logarchive, strings, oversize_cache,
                ts.timesync_data, ts.boot_uuid_to_timesync_file_id,
                tracev3_file_ids[rel], ts.anchor_id_map, writer.add,
                keep_raw=opts.keep_raw, cancel=ctx.cancel,
            ))
            # Flush BEFORE marking: parse_completed_at asserts that every row of
            # this file is in the database, and rows still in the batch buffer
            # would make that assertion false (see BatchWriter.mark_file_parsed).
            writer.flush()
            writer.mark_file_parsed(tracev3_file_ids[rel])
            _done_bytes += _sizes[rel]
            ctx.reporter.update(_done_bytes / _total_bytes, f"{i}/{len(tracev3_files)}")
    else:
        n_workers = max(1, opts.jobs - 1)
        log.info(f"Parsing in parallel : {n_workers} worker process(es) + 1 writer (jobs={opts.jobs})")
        done = 0

        def _handle_result(rel: str, file_stats: tuple, entries: list) -> None:
            nonlocal done, _done_bytes
            # Single writer (this process) — one DB connection, no contention.
            writer.add_batch(entries)
            writer.flush()                              # see the serial path
            writer.mark_file_parsed(tracev3_file_ids[rel])
            stats.absorb(file_stats)
            done += 1
            _done_bytes += _sizes[rel]
            ctx.reporter.update(_done_bytes / _total_bytes, f"{done}/{len(rels)}")
            log.info(f"[{done}/{len(rels)}] {rel}  ({file_stats[3]} entries)")

        parallel_parse(
            rels,
            n_workers,
            init_args=(
                logarchive, ts.timesync_data, oversize_cache,
                ts.boot_uuid_to_timesync_file_id, ts.anchor_id_map,
                tracev3_file_ids, strings.uuid_file_ids(), opts.keep_raw,
            ),
            handle_result=_handle_result,
            cancel=ctx.cancel,
        )

    writer.flush()
    log.info(f"Parse complete  : {stats.total_entries} total entries written  {stats.total_errors} parse error(s)")
    if stats.total_errors:
        log.warning(f"{stats.total_errors} parse error(s) encountered — run with --verbose for details")
    if writer.write_errors:
        # Loud and explicit: the store is knowingly incomplete. Each dropped row
        # was already logged at ERROR with its source provenance.
        log.warning(f"{writer.write_errors} log row(s) could NOT be stored by the database and were dropped — the database is incomplete; see the ERROR lines above for the affected records.")
    if opts.jobs > 1 and tracev3_files and stats.total_entries == 0 and stats.total_errors == 0:
        # The classic missing-__main__-guard failure: spawn-based workers
        # re-import the caller's entry point, misbehave, and every file comes
        # back empty without a single error. Never let that end silently.
        log.error(
            f"Parallel parse wrote 0 entries from {len(tracev3_files)} tracev3 "
            "file(s) with no parse errors. This usually means the calling entry "
            'point is not import-safe (missing `if __name__ == "__main__":` '
            "guard), which breaks spawn-based multiprocessing. Re-run with "
            "jobs=1, or guard the entry point."
        )

    # ── Shutdown events (shutdown.log → shutdown_events/_clients) ───────────
    # Wall-clock-anchored power-off events; kept out of the logs/event_order
    # timeline and correlated to logs by wall-clock time.
    n_shutdowns = _ingest_shutdown_log(writer, logarchive, file_hashes)
    if n_shutdowns:
        log.info(f"Shutdown events : {n_shutdowns} parsed from shutdown.log")
    conn.commit()

    return stats


def _finalise(ctx: RunContext, stats: _ParseStats) -> ExtractResult:
    """Ordering, indexes, FTS, integrity re-check, metadata update; returns ExtractResult."""
    conn, writer, opts = ctx.conn, ctx.writer, ctx.opts
    assert writer is not None, "Invariant violated: _run_extract_inner must create the writer"

    # ── Forensic ordering ──────────────────────────────────────────────────
    # Assign source_order (per-file physical) + event_order (boot, monotonic mach)
    # now that every row is loaded — independent of insertion order, so it is
    # identical whether the parse ran serially or across worker processes.
    _enter_phase(ctx, "ordering", "merging timeline")
    log.info("Assigning forensic ordering (source_order + event_order)…")
    assign_ordering(conn)

    # ── Build secondary indexes (deferred from schema setup) ───────────────
    # One sorted build per index over the finished table — far cheaper than
    # maintaining every index on each INSERT during the load. Runs after ordering
    # so the event_order / source_order indexes build on their final values.
    _enter_phase(ctx, "index", "building indexes")
    log.info("Building secondary indexes…")
    _t_idx = time.monotonic()
    finalize_indexes(conn)
    conn.commit()
    log.info(f"Secondary indexes built in {time.monotonic() - _t_idx:.1f} s")

    # ── Deferred FTS5 build (--fast-fts) ───────────────────────────────────
    # The bulk load ran without FTS maintenance triggers; build the index once
    # now and install the triggers for subsequent mutations.
    if opts.fast_fts and ctx.fts5_ok:
        _enter_phase(ctx, "fts", "full-text index")
        log.info("Building FTS5 index (deferred rebuild)…")
        _t_fts = time.monotonic()
        finalize_deferred_fts(conn)
        log.info(f"FTS5 index built in {time.monotonic() - _t_fts:.1f} s")

    # ── Per-file integrity re-verification ─────────────────────────────────
    # Re-hash every registered source file now the run is complete and store the
    # result per file (source_files.sha256_after / integrity_ok). This is the
    # "after" half of the per-file chain of custody: a file that changed under us
    # is flagged individually, while every other file's parsed data stays usable.
    # Non-full integrity modes took no "before" baseline, so the re-hash could
    # only ever record NULLs — skip the whole pass.
    files_ok = files_changed = files_unverifiable = 0
    if opts.integrity == "full":
        log.info("Re-verifying per-file integrity (end-of-run re-hash)…")
        _t_intg = time.monotonic()
        files_ok, files_changed, files_unverifiable = verify_source_files(
            conn, ctx.prepared.logarchive_root, cancel=ctx.cancel
        )
        log.info(f"Integrity re-check : {files_ok} unchanged, {files_changed} changed, {files_unverifiable} unverifiable  ({time.monotonic() - _t_intg:.1f} s)")
        if files_changed:
            log.warning(f"{files_changed} source file(s) CHANGED during the run — their parsed data is suspect (see source_files.integrity_ok = 0); other files are unaffected")
    else:
        log.info(f"Per-file integrity re-check : skipped (integrity={opts.integrity!r} — no baseline hashes)")

    # ── Compute log time bounds ────────────────────────────────────────────
    # The displayed range is the wall-clock span, so take MIN/MAX of the indexed
    # timestamp_unix_ns (one index-aided pass each) and format to ISO on read.
    # The ISO string is no longer stored (see schema.py / iso8601_from_unix_ns).
    # WHY ``WHERE timestamp_unix_ns > 0``: a failed resolution is persisted as the
    # sentinel 0 (visible by design). Without the guard, a single unresolved entry
    # makes MIN read 1970-01-01 and corrupts the reported log_start_time. The
    # sentinel rows stay in the DB; only this summary read excludes them.
    first_ts: str | None = None
    last_ts: str | None = None
    bounds = conn.execute(
        "SELECT MIN(timestamp_unix_ns), MAX(timestamp_unix_ns) FROM logs "
        "WHERE timestamp_unix_ns > 0"
    ).fetchone()
    if bounds and bounds[0] is not None:
        first_ts = iso8601_from_unix_ns(bounds[0])
    if bounds and bounds[1] is not None:
        last_ts = iso8601_from_unix_ns(bounds[1])
    unresolved = conn.execute(
        "SELECT COUNT(*) FROM logs WHERE timestamp_unix_ns = 0"
    ).fetchone()[0]
    if unresolved:
        log.warning(f'Unresolved timestamps : {unresolved} entr{"y" if unresolved == 1 else "ies"} have timestamp_unix_ns=0 (excluded from the reported time range; rows kept in the DB)')
    log.info(f"Log time range  : {first_ts}  →  {last_ts}")

    # ── Resolve iOS version ────────────────────────────────────────────────
    # Priority: authoritative SystemVersion.plist (FFS/sysdiagnose) → best-effort
    # build-code table (bare logarchive dir) → None (keep just the build code).
    ios_version = ctx.prepared.ios_product_version or ios_version_for_build(stats.ios_build_version)
    if ios_version:
        log.info(f'iOS version     : {ios_version}  (build {stats.ios_build_version or "?"})')

    # ── Finalise case_metadata ─────────────────────────────────────────────
    writer.update_case_metadata(
        stats.metadata_id,
        ios_model=stats.ios_model,
        ios_build_version=stats.ios_build_version,
        ios_version=ios_version,
        log_start_time=first_ts,
        log_end_time=last_ts,
    )
    conn.commit()

    # ── Summary statistics, cached into the database ───────────────────────
    # WHY here and not on demand: summarising costs six-plus full passes over
    # ``logs``. Paying that once, at the end of a run that has already read every
    # byte and while the page cache is still warm, means every later reader — the
    # GUI's Exploit overview above all — gets the statistics for free instead of
    # freezing for tens of seconds on open. A failure is logged and swallowed: the
    # extraction itself succeeded, and a missing cache degrades to "not evaluated",
    # never to a lost database.
    _enter_phase(ctx, "stats", "summary statistics")
    refresh_summary(conn)
    _leave_phase(ctx)

    # ── Declare the run complete ───────────────────────────────────────────
    # The LAST thing written, so no ordering of failures can leave a store
    # claiming to be finished when it is not. Its counterpart is the rename of
    # the .partial file, done by run_extract once the connection is closed.
    assert stats.metadata_id, "Invariant violated: _run_parse must insert case_metadata"
    writer.set_extract_status(stats.metadata_id, EXTRACT_STATUS_COMPLETE)

    elapsed = time.monotonic() - ctx.t0
    log.info("═" * 72)
    log.info("Extract complete")
    log.info(f'  Device model      : {stats.ios_model or "(unknown)"}')
    log.info(f'  Build version     : {stats.ios_build_version or "(unknown)"}')
    log.info(f'  Boot UUID         : {stats.boot_uuid or "(unknown)"}')
    log.info(f"  Log entries       : {stats.total_entries}")
    log.info(f"  Time range        : {first_ts}  →  {last_ts}")
    log.info(f"  Parse errors      : {stats.total_errors}")
    log.info(f"  Elapsed           : {elapsed:.1f} s")
    log.info(f"  Output database   : {ctx.final_db_path.resolve()}")
    log.info(f"  Logarchive SHA-256: {ctx.prepared.content_sha256}")
    log.info("  Log file SHA-256  : (computed after log is closed)")
    log.info("═" * 72)

    return ExtractResult(
        # The FINAL name: this is only reached on success, and run_extract
        # promotes the .partial to it moments later.
        db_path=ctx.final_db_path,
        metadata_id=stats.metadata_id,
        entry_count=stats.total_entries,
        parse_errors=stats.total_errors,
        write_errors=writer.write_errors,
        source_type=ctx.prepared.source_type.value,
        source_sha256=ctx.prepared.content_sha256,
        device_model=stats.ios_model or None,
        ios_build=stats.ios_build_version or None,
        ios_version=ios_version,
        boot_uuid=stats.boot_uuid or None,
        time_range=(first_ts, last_ts),
        source_files_verified=files_ok,
        source_files_changed=files_changed,
        source_files_unverifiable=files_unverifiable,
    )
