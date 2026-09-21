"""Worker-process parsing for multiprocessing (ProcessPoolExecutor) path.

Defines : parallel_parse (the bounded-window scheduler), _WORKER, worker_init,
          worker_parse
Used by : forensic_aul.ops.extraction.extract (_run_parse, parallel path)
Uses    : forensic_aul.ops.extraction.tracev3_parse (process_tracev3),
          forensic_aul.ops.extraction.oversize_pass (OversizeCache),
          forensic_aul.engine.models (TimesyncBoot, LogEntry),
          forensic_aul.engine.parser.string_cache (StringCacheProvider),
          forensic_aul.engine.utils.cancellation (CancelToken)

Pickling note
-------------
ProcessPoolExecutor pickles *worker_init* and *worker_parse* by their
**qualified name** — both must remain module-level in this file and must not be
nested inside another function or turned into closures.  The extract pipeline
references them as ``workers.worker_init`` / ``workers.worker_parse`` (or via
a direct import that resolves to the same qualified name).

Worker processes parse tracev3 files in parallel and return resolved LogEntry
batches to the single writer (the main process). All DB ids a row needs are
resolved from maps prepared in the main process, so a worker never opens the
database. The read-only string cache is loaded from disk in each worker
(cross-platform: works under spawn and fork) rather than pickled across.

Cancellation across the process boundary
----------------------------------------
The parent's :class:`CancelToken` cannot be handed to a worker directly, so this
module owns the bridge — which is what keeps ``cancellation.py`` free of any
``multiprocessing`` import:

1. a ``multiprocessing.Event`` is created here and passed via the pool's
   ``initargs``. **It must ride ``initargs`` and nothing else**: a synchronisation
   primitive survives inheritance at process start, but putting one through
   ``ex.submit(...)`` (i.e. through the call queue) raises ``RuntimeError:
   Condition objects should only be shared between processes through
   inheritance``;
2. a daemon thread mirrors the parent token into that event, so setting the
   token propagates without the parent having to poll from its result loop;
3. each worker wraps the inherited event in an ordinary :class:`CancelToken`
   (both expose ``set`` / ``is_set`` / ``wait``) and hands it to
   ``process_tracev3``, which checks it per chunk.
"""

from __future__ import annotations

import multiprocessing
import threading
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from itertools import islice
from pathlib import Path
from typing import Callable

from forensic_aul.engine.models import LogEntry, TimesyncBoot
from forensic_aul.engine.parser.string_cache import StringCacheProvider
from forensic_aul.engine.utils.cancellation import NEVER_CANCELLED, CancelToken
from forensic_aul.errors import OperationCancelled
from forensic_aul.ops.extraction.oversize_pass import OversizeCache
from forensic_aul.ops.extraction.tracev3_parse import process_tracev3

# How often the mirror thread copies the parent token into the workers'
# multiprocessing.Event. Small enough that it adds nothing measurable to the
# observed cancel latency (which is dominated by one chunkset), large enough
# that the thread is invisible in a profile.
_CANCEL_MIRROR_INTERVAL_S = 0.1


# ── Bounded-window scheduler (runs in the main / writer process) ──────────────

def parallel_parse(
    rels: list[str],
    n_workers: int,
    init_args: tuple,
    handle_result: Callable[[str, tuple[str, str, str, int, int], list[LogEntry]], None],
    *,
    cancel: CancelToken = NEVER_CANCELLED,
) -> None:
    """Parse *rels* across *n_workers* processes, streaming results to one writer.

    *handle_result(rel, stats, entries)* is called in this (the sole writer)
    process for each completed file — it writes the entries, aggregates the
    stats and advances progress. *init_args* are forwarded to ``worker_init``.

    Bound the number of in-flight files so completed-but-unwritten results
    cannot pile up in the writer process. WHY: each worker returns its file's
    *entire* list of LogEntry objects back here to be written. If we submit
    every file at once, the workers race ahead of the single writer and their
    returned lists accumulate in this process — observed at 38 GB of resident
    memory on a 2.5 GB archive, which then thrashes swap. Keeping at most ~2x
    workers' worth of files in flight keeps every core fed while capping
    resident results to a handful of files' entries. The output is identical
    regardless of the window size.

    On cancellation the pool is drained with ``shutdown(wait=True,
    cancel_futures=True)`` before propagating: queued files are dropped, running
    workers stop at their next chunk boundary, and every process has exited by
    the time the caller regains control — so the caller can safely finish
    writing to the database it shares with nobody.

    Raises:
        OperationCancelled: *cancel* was cancelled during the parse.
    """
    # One context for both the event and the pool: an Event built by a different
    # start method than the pool uses would not be the primitive the children
    # inherit. get_context() (no argument) keeps the platform default this
    # module has always used.
    ctx = multiprocessing.get_context()
    cancel_event = ctx.Event()
    mirror_stop = threading.Event()
    mirror = threading.Thread(
        target=_mirror_cancel,
        args=(cancel, cancel_event, mirror_stop),
        name="faul-cancel-mirror",
        daemon=True,
    )
    mirror.start()
    try:
        with ProcessPoolExecutor(
            max_workers=n_workers,
            mp_context=ctx,
            initializer=worker_init,
            initargs=(*init_args, cancel_event),
        ) as ex:
            max_in_flight = max(2, n_workers * 2)
            rel_iter = iter(rels)
            in_flight: dict[object, str] = {
                ex.submit(worker_parse, rel): rel
                for rel in islice(rel_iter, max_in_flight)
            }
            try:
                while in_flight:
                    finished, _ = wait(in_flight, return_when=FIRST_COMPLETED)
                    for fut in finished:
                        rel = in_flight.pop(fut)
                        stats, entries = fut.result()
                        handle_result(rel, stats, entries)
                        cancel.check()
                        # Refill: keep the in-flight window full until files run out.
                        nxt = next(rel_iter, None)
                        if nxt is not None:
                            in_flight[ex.submit(worker_parse, nxt)] = nxt
            except OperationCancelled:
                # Drop everything still queued and wait for the running workers to
                # notice the event and return. WHY wait: the `with` block would
                # join them anyway, and doing it explicitly makes the contract
                # visible — no worker is still touching the evidence when the
                # caller starts marking the database cancelled.
                ex.shutdown(wait=True, cancel_futures=True)
                raise
    finally:
        mirror_stop.set()


def _mirror_cancel(
    cancel: CancelToken, cancel_event, stop: threading.Event
) -> None:
    """Copy *cancel* into the workers' event until cancelled or *stop* is set.

    Runs on a daemon thread in the parent. WHY a thread rather than a check in
    the result loop: that loop blocks in ``wait(...)`` until a worker finishes a
    whole file, which on a large tracev3 is tens of seconds — the workers would
    only learn of the cancellation after the very thing the operator is waiting
    to stop had finished.
    """
    while not stop.is_set():
        if cancel.wait(_CANCEL_MIRROR_INTERVAL_S):
            cancel_event.set()
            return


# ── Worker-process parsing (multiprocessing) ──────────────────────────────────

_WORKER: dict[str, object] = {}


def worker_init(
    logarchive_root: Path,
    timesync_data: dict[str, TimesyncBoot],
    oversize_cache: OversizeCache,
    boot_uuid_to_timesync_file_id: dict[str, int],
    anchor_id_map: dict[tuple[int, int], int],
    tracev3_file_ids: dict[str, int],
    uuid_file_ids: dict[str, int],
    keep_raw: bool,
    cancel_event,
) -> None:
    """Initialise one worker: load the read-only string cache from disk once.

    *cancel_event* is the ``multiprocessing.Event`` inherited from the parent
    (see the module docstring); it is wrapped in a plain :class:`CancelToken`
    here so the parsing code below the boundary is identical to the serial path.
    """
    strings = StringCacheProvider(logarchive_root)
    strings.load_content()
    strings.set_uuid_file_ids(uuid_file_ids)
    _WORKER.clear()
    _WORKER.update(
        root=logarchive_root,
        strings=strings,
        timesync_data=timesync_data,
        oversize_cache=oversize_cache,
        boot_map=boot_uuid_to_timesync_file_id,
        anchor_id_map=anchor_id_map,
        tracev3_file_ids=tracev3_file_ids,
        keep_raw=keep_raw,
        cancel=CancelToken(cancel_event),
    )


def worker_parse(rel_path: str) -> tuple[tuple[str, str, str, int, int], list[LogEntry]]:
    """Parse one tracev3 (path relative to the logarchive root) → (stats, entries)."""
    root: Path = _WORKER["root"]  # type: ignore[assignment]
    entries: list[LogEntry] = []
    stats = process_tracev3(
        root / rel_path,
        root,
        _WORKER["strings"],                        # type: ignore[arg-type]
        _WORKER["oversize_cache"],                 # type: ignore[arg-type]
        _WORKER["timesync_data"],                  # type: ignore[arg-type]
        _WORKER["boot_map"],                       # type: ignore[arg-type]
        _WORKER["tracev3_file_ids"][rel_path],     # type: ignore[index]
        _WORKER["anchor_id_map"],                  # type: ignore[arg-type]
        entries.append,
        keep_raw=bool(_WORKER["keep_raw"]),
        cancel=_WORKER["cancel"],                  # type: ignore[arg-type]
    )
    return stats, entries
