"""Process-pool helpers shared by the parse passes.

Defines : ``parallel_map`` (an ordered map over a process pool, with the caller's
          cancel token mirrored into the workers) and ``mirror_cancel`` (the
          thread that does the mirroring; also used by the pass-2 scheduler).
Used by : forensic_aul.ops.extraction.oversize_pass (pass 1) and
          forensic_aul.ops.extraction.workers (pass 2).
Uses    : forensic_aul.engine.utils.cancellation and the standard library.
"""

from __future__ import annotations

import multiprocessing
import threading
from concurrent.futures import ProcessPoolExecutor
from typing import Callable, TypeVar

from forensic_aul.engine.utils.cancellation import NEVER_CANCELLED, CancelToken
from forensic_aul.errors import OperationCancelled

T = TypeVar("T")

# How often the mirror thread copies the parent token into the workers'
# multiprocessing.Event: small enough to add nothing to the cancel latency,
# large enough to be invisible in a profile.
_CANCEL_MIRROR_INTERVAL_S = 0.1


def parallel_map(
    fn: Callable[[str, CancelToken], T],
    items: list[str],
    n_workers: int,
    *,
    cancel: CancelToken = NEVER_CANCELLED,
) -> list[T]:
    """``[fn(item, token) for item in items]`` across *n_workers* processes.

    Results come back in the order of *items*, whatever order they finish in.
    *fn* must be a module-level function (it is pickled under spawn); it receives
    a token mirroring *cancel*. For small results only: every result is held
    until all are done (pass 2 streams its entries with its own scheduler).

    Raises:
        OperationCancelled: *cancel* was cancelled; every worker has exited.
    """
    ctx = multiprocessing.get_context()
    cancel_event = ctx.Event()
    mirror_stop = threading.Event()
    mirror = threading.Thread(
        target=mirror_cancel, args=(cancel, cancel_event, mirror_stop),
        name="faul-cancel-mirror", daemon=True,
    )
    mirror.start()
    try:
        with ProcessPoolExecutor(
            max_workers=n_workers, mp_context=ctx,
            initializer=_map_init, initargs=(cancel_event,),
        ) as ex:
            futures = [ex.submit(_map_call, fn, item) for item in items]
            try:
                results = []
                for fut in futures:
                    results.append(fut.result())
                    cancel.check()
                return results
            except OperationCancelled:
                ex.shutdown(wait=True, cancel_futures=True)
                raise
    finally:
        mirror_stop.set()


# The worker's token, set once per process by the pool initializer.
_MAP_CANCEL: list[CancelToken] = []


def _map_init(cancel_event) -> None:  # type: ignore[no-untyped-def]
    _MAP_CANCEL[:] = [CancelToken(cancel_event)]


def _map_call(fn, item):  # type: ignore[no-untyped-def]
    return fn(item, _MAP_CANCEL[0])


def mirror_cancel(
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
