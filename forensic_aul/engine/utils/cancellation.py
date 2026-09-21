"""Cooperative cancellation for long-running operations.

Defines : :class:`CancelToken` — a flag one thread (or process) sets and the
          working code polls — and :data:`NEVER_CANCELLED`, the null object a
          caller that never cancels can pass. Together they are the cancellation
          counterpart of :mod:`forensic_aul.engine.utils.progress`.
Used by : forensic_aul.ops.extraction.* (the extract pipeline and its workers),
          forensic_aul.ops.acquisition.acquire, forensic_aul.engine.integrity,
          launcher/* and gui/* (which own a token and cancel it).
Uses    : the standard library only — deliberately no Qt and no
          ``multiprocessing`` (see "Driving a token from another process").

Design
------
- **A null object, not ``None``.** ``progress.py`` argues the same case for its
  sink: hot loops must be able to write ``cancel.check()`` unconditionally,
  never ``if cancel is not None and cancel.cancelled``. So the default value of
  every ``cancel`` parameter in the library is :data:`NEVER_CANCELLED`, whose
  ``check()`` is a no-op and whose ``cancelled`` is always ``False``.
- **Polled, never pre-emptive.** Cancelling sets a flag; the working code
  notices at its next check point. That is the only safe shape for a forensic
  pipeline — a thread killed mid-write would leave a torn database, whereas a
  cooperative stop happens at a known boundary and can record where it stopped.
- **``check()`` raises, ``cancelled`` asks.** ``check()`` raises
  :class:`~forensic_aul.errors.OperationCancelled` so a deep call stack unwinds
  to whoever owns the artefact; ``cancelled`` is the non-raising form for the
  places that must not unwind (a sqlite progress handler, a poll loop).
- **Built on ``threading.Event``**, the standard library's own
  set-once/read-many flag: already thread-safe and already provides the timed
  ``wait()`` a poll loop needs, so there is nothing to hand-roll.

Driving a token from another process
------------------------------------
:class:`CancelToken` accepts any object exposing ``set()`` / ``is_set()`` /
``wait()``. A ``multiprocessing.Event`` satisfies that interface, so a worker
process can wrap the event it inherited and use the ordinary token API — which
is why this module needs no ``multiprocessing`` import of its own (see
``ops/extraction/workers.py``, where the event rides ``initargs``).

Example
-------
    cancel = CancelToken()
    ...                                       # another thread: cancel.cancel()
    for item in items:
        cancel.check()                        # raises OperationCancelled
        ...
"""

from __future__ import annotations

import threading
from typing import Protocol, runtime_checkable

from forensic_aul.errors import OperationCancelled


@runtime_checkable
class CancelFlag(Protocol):
    """The set-once flag a :class:`CancelToken` wraps.

    Both ``threading.Event`` and ``multiprocessing.Event`` satisfy it, which is
    what lets one token type serve the in-process and cross-process cases
    without this module importing ``multiprocessing``.
    """

    def set(self) -> None: ...

    def is_set(self) -> bool: ...

    def wait(self, timeout: float | None = None) -> bool: ...


class CancelToken:
    """A cancellation flag: set it from anywhere, poll it from the working code.

    *flag* defaults to a fresh ``threading.Event``. Pass an existing flag — most
    usefully a ``multiprocessing.Event`` inherited by a worker process — to have
    this token reflect it.
    """

    def __init__(self, flag: CancelFlag | None = None) -> None:
        self._flag: CancelFlag = flag if flag is not None else threading.Event()

    def cancel(self) -> None:
        """Request cancellation. Idempotent; safe from any thread."""
        self._flag.set()

    @property
    def cancelled(self) -> bool:
        """True once :meth:`cancel` has been called (never raises)."""
        return self._flag.is_set()

    def check(self) -> None:
        """Raise :class:`OperationCancelled` if cancellation has been requested.

        The check point of a cooperative cancel: sprinkle it at loop boundaries
        that are frequent enough to be responsive and coarse enough to leave the
        artefact in a state the caller can describe.
        """
        if self._flag.is_set():
            raise OperationCancelled("operation cancelled by the operator")

    def wait(self, timeout: float | None = None) -> bool:
        """Block until cancelled or *timeout* elapses; True if cancelled.

        Used by pollers that would otherwise busy-loop (the thread mirroring this
        token into a worker pool's ``multiprocessing.Event``).
        """
        return self._flag.wait(timeout)


class _NeverCancelled(CancelToken):
    """The null token: never cancelled, and cancelling it does nothing.

    WHY ``cancel()`` is a silent no-op rather than an error: this is a single
    shared instance used as the default of every ``cancel`` parameter in the
    library, so honouring a ``cancel()`` on it would cancel every unrelated
    operation in the process. Refusing loudly would instead break the
    substitutability the null object exists to provide. A caller that means to
    cancel something owns a real :class:`CancelToken`.
    """

    def __init__(self) -> None:
        super().__init__()

    def cancel(self) -> None:
        return None

    @property
    def cancelled(self) -> bool:
        return False

    def check(self) -> None:
        return None

    def wait(self, timeout: float | None = None) -> bool:
        # Honour the timeout so a poll loop handed the null token still paces
        # itself instead of spinning; it simply never reports a cancellation.
        if timeout:
            threading.Event().wait(timeout)
        return False


# The "no cancellation wanted" value. Every library ``cancel`` parameter
# defaults to it, so working code never needs an ``is not None`` guard.
NEVER_CANCELLED: CancelToken = _NeverCancelled()
