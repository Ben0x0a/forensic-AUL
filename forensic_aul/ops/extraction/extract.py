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
(connection, prepared source, options, reporter) instead of long parameter
lists; the user-tunable knobs live in ``ExtractOptions`` (same module).
"""

from __future__ import annotations

import logging
import sqlite3
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from forensic_aul import __version__
from forensic_aul.config import BATCH_SIZE
from forensic_aul.engine.database.ordering import assign_ordering
from forensic_aul.engine.database.schema import (
    apply_pragmas,
    finalize_deferred_fts,
    finalize_indexes,
    init_schema,
)
from forensic_aul.engine.database.writer import BatchWriter, register_source_file
from forensic_aul.engine.integrity import verify_source_files
from forensic_aul.engine.ios_builds import ios_version_for_build
from forensic_aul.engine.parser.string_cache import StringCacheProvider
from forensic_aul.engine.utils.progress import ProgressReporter, ProgressSink
from forensic_aul.engine.utils.time import iso8601_from_unix_ns
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

log = logging.getLogger(__name__)


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
    from forensic_aul.ops.extraction.shutdown_log import find_shutdown_log, parse_shutdown_log

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
    fast_fts: bool = False,
    fast_write: bool = False,
    fts: bool = True,
    keep_raw: bool = False,
    jobs: int = 1,
    overwrite: bool = False,
    integrity: str = "full",
    progress: ProgressSink | None = None,
) -> ExtractResult:
    """Full extract pipeline: source → SQLite.

    This is the main entry point called by the CLI. *logarchive* may be a
    ``.logarchive`` directory, a sysdiagnose ``.tar.gz``, a full-file-system
    ``.zip``, or a mapping of two already-uncompressed folders
    ``{"diagnostics": dir, "uuidtext": dir}`` — the source-preparation layer
    normalises all of them to a logarchive layout before parsing (see
    forensic_aul/ops/extraction/source.py). Archives / loose dirs are materialised
    into *work_dir* (kept) or an auto-cleaned temp dir.

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

    If *db_path* already exists the call refuses to proceed unless *overwrite* is
    True — extracting into an existing database would silently merge two
    acquisitions into one file. With *overwrite* the existing database (and its
    ``-wal`` / ``-shm`` sidecars) is removed first so the run starts clean.

    Returns:
        An :class:`~forensic_aul.outcomes.ExtractResult` bundling the output
        ``db_path``, the ``metadata_id`` (to seal the log-file hash later), and
        the run facts (entry/error counts, device model, iOS build/version, boot
        UUID, time range, source type and SHA-256).

    Raises:
        FileExistsError: *db_path* exists and *overwrite* is False.
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
    if db_path.exists() and not opts.overwrite:
        raise FileExistsError(
            f"{db_path} already exists; pass overwrite=True to replace it "
            "(extracting into an existing database would merge two acquisitions)"
        )

    _t0 = time.monotonic()
    reporter = ProgressReporter(progress, _EXTRACT_PHASES)
    reporter.phase("prepare", "hashing source")

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
        prepared = prepare_source(logarchive, work_dir=work_dir, integrity=opts.integrity)
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
    log.debug("Output database : %s", db_path.resolve())
    # Source preparation succeeded, so it is now safe to clear any existing DB
    # (and its WAL/SHM sidecars) and start clean — deferred from the entry guard
    # so a prep failure could not have destroyed a pre-existing database.
    if opts.overwrite:
        for sidecar in (db_path, db_path.with_name(db_path.name + "-wal"),
                        db_path.with_name(db_path.name + "-shm")):
            sidecar.unlink(missing_ok=True)
    conn = sqlite3.connect(str(db_path))
    try:
        ctx = RunContext(
            conn=conn,
            db_path=db_path,
            prepared=prepared,
            case=case,
            opts=opts,
            reporter=reporter,
            t0=_t0,
        )
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
        return result
    finally:
        conn.close()
        # A caller-supplied PreparedSource is cleaned up by its owner (typically
        # a `with prepare_source(...)` block); cleaning it here would tear down
        # a temp extraction the caller may still want to inspect or reuse.
        if not caller_prepared:
            prepared.cleanup()


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

    stats = _run_parse(ctx)
    return _finalise(ctx, stats)


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
    log.info(f"Case metadata inserted  : id={stats.metadata_id}  case={ctx.case.case_number}  imei={ctx.case.imei}")
    if ctx.case.exhibit_number:
        log.info(f"  Exhibit  : {ctx.case.exhibit_number}")
    if ctx.case.analyst_name:
        log.info(f"  Analyst  : {ctx.case.analyst_name}")

    # ── Step 4: Timesync ──────────────────────────────────────────────────
    log.info("─── Step 4/7 : Timesync files ───────────────────────────────────")
    ts = setup_timesync(writer, logarchive, file_hashes)

    # ── Step 5: String cache (UUIDText + DSC) ─────────────────────────────
    log.info("─── Step 5/7 : String cache (UUIDText + DSC) ───────────────────")
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

    oversize_cache: OversizeCache = collect_oversize(tracev3_files, strings)
    log.info(f"Oversize cache  : {len(oversize_cache)} entry(ies) collected")

    # ── Step 7: Pass 2 — Main parse ───────────────────────────────────────
    log.info("─── Step 7/7 : Pass 2 — Main parse ─────────────────────────────")
    rels = [p.relative_to(logarchive).as_posix() for p in tracev3_files]

    # Progress: weight the parse by tracev3 byte size (files vary ~1000x in entry
    # count, so byte size advances the bar far more smoothly than file count).
    ctx.reporter.phase("parse")
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
                keep_raw=opts.keep_raw,
            ))
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
    ctx.reporter.phase("ordering", "merging timeline")
    log.info("Assigning forensic ordering (source_order + event_order)…")
    assign_ordering(conn)

    # ── Build secondary indexes (deferred from schema setup) ───────────────
    # One sorted build per index over the finished table — far cheaper than
    # maintaining every index on each INSERT during the load. Runs after ordering
    # so the event_order / source_order indexes build on their final values.
    ctx.reporter.phase("index", "building indexes")
    log.info("Building secondary indexes…")
    _t_idx = time.monotonic()
    finalize_indexes(conn)
    conn.commit()
    log.info(f"Secondary indexes built in {time.monotonic() - _t_idx:.1f} s")

    # ── Deferred FTS5 build (--fast-fts) ───────────────────────────────────
    # The bulk load ran without FTS maintenance triggers; build the index once
    # now and install the triggers for subsequent mutations.
    if opts.fast_fts and ctx.fts5_ok:
        ctx.reporter.phase("fts", "full-text index")
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
            conn, ctx.prepared.logarchive_root
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
    ctx.reporter.phase("stats", "summary statistics")
    refresh_summary(conn)

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
    log.info(f"  Output database   : {ctx.db_path.resolve()}")
    log.info(f"  Logarchive SHA-256: {ctx.prepared.content_sha256}")
    log.info("  Log file SHA-256  : (computed after log is closed)")
    log.info("═" * 72)

    return ExtractResult(
        db_path=ctx.db_path,
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
