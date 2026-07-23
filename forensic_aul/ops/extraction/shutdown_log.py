"""Parser for the unified-log ``shutdown.log`` sidecar.

``shutdown.log`` records each power-off/reboot. During shutdown ``logd`` polls who
is still alive and writes blocks like::

    After 0.63s, these clients are still here:
        remaining client pid: 215 (/System/.../destinationd/<uuid>)
        remaining client pid: 0 (/kernel/<uuid>)
    After 2.62s, these clients are still here:
        remaining client pid: 0 (/kernel/<uuid>)
    SIGTERM: [1774602168] All buffers flushed

The ``SIGTERM: [<epoch>]`` line carries the **Unix epoch (seconds)** of the
power-off. A file may contain several such events (several boots).

WHY this is NOT merged into ``logs``: a shutdown is **wall-clock anchored** (an
epoch) with no mach continuous time and no boot UUID, so it cannot be placed in
the ``(boot, mach)`` ``event_order`` timeline without misrepresenting it. It is
therefore stored in its own tables (``shutdown_events`` / ``shutdown_clients``)
and correlated to logs by wall-clock time.

For each event we capture every process that lingered (the union across the
"After Xs" checks) and how long it lingered (the largest check it appeared in),
so an analyst can ask "which process blocked shutdown most / longest".

Used by : forensic_aul/ops/extraction/extract.py (shutdown-event ingestion step).
Uses    : the standard library only.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

_AFTER_RE = re.compile(r"After\s+([0-9.]+)s,\s+these clients are still here", re.IGNORECASE)
_CLIENT_RE = re.compile(r"remaining client pid:\s*(\d+)\s*\((.*)\)\s*$")
_SIGTERM_RE = re.compile(r"SIGTERM:\s*\[(\d+)\]")


@dataclass
class ShutdownClient:
    """A process still alive during a shutdown, and how long it lingered."""

    pid: int | None
    process_path: str
    lingered_seconds: float | None


@dataclass
class ShutdownEvent:
    """One power-off, with the processes that delayed it."""

    unix_ns: int            # SIGTERM epoch × 1e9
    iso: str                # ISO 8601 UTC
    delay_seconds: float | None   # largest "After Xs" check = total shutdown delay
    clients: list[ShutdownClient] = field(default_factory=list)


def find_shutdown_log(root: Path) -> Path | None:
    """Locate ``shutdown.log`` in a prepared logarchive root.

    Logarchive / sysdiagnose keep it under ``Extra/``; an FFS flattens the
    ``diagnostics/`` loose files to the root, so check both, then fall back to a
    recursive search.
    """
    for rel in ("Extra/shutdown.log", "shutdown.log"):
        candidate = root / rel
        if candidate.is_file():
            return candidate
    matches = sorted(root.rglob("shutdown.log"))
    return matches[0] if matches else None


def parse_shutdown_log(path: Path) -> list[ShutdownEvent]:
    """Parse *path* into a list of :class:`ShutdownEvent` (one per SIGTERM line).

    Unrecognised lines are ignored, so format drift across iOS versions degrades
    gracefully rather than raising.
    """
    events: list[ShutdownEvent] = []
    # (pid, path) → largest "After Xs" check the process was still seen at.
    lingered: dict[tuple[int | None, str], float] = {}
    current_after: float = 0.0   # the current block's elapsed-seconds
    delay: float = 0.0           # largest check seen this event = total delay

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        after_match = _AFTER_RE.search(line)
        if after_match:
            current_after = float(after_match.group(1))
            delay = max(delay, current_after)
            continue

        client_match = _CLIENT_RE.search(line)
        if client_match:
            key = (int(client_match.group(1)), client_match.group(2))
            lingered[key] = max(lingered.get(key, 0.0), current_after)
            continue

        sigterm_match = _SIGTERM_RE.search(line)
        if sigterm_match:
            epoch = int(sigterm_match.group(1))
            clients = [
                ShutdownClient(pid=pid, process_path=proc, lingered_seconds=secs)
                for (pid, proc), secs in lingered.items()
            ]
            events.append(ShutdownEvent(
                unix_ns=epoch * 1_000_000_000,
                iso=datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                delay_seconds=delay or None,
                clients=clients,
            ))
            lingered = {}
            current_after = 0.0
            delay = 0.0

    return events
