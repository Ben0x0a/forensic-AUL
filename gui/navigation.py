"""Typed navigation between screens: where to go, and what to carry there.

Defines : the navigation payloads (OpenDatabase, ExtractFrom, ExportFrom,
          ShowIdentifyResults),
          Destination (a bare screen id or one payload), Navigate (the callback a
          screen is given), target_of (the screen a destination lands on), and
          the Screen protocol every stacked screen satisfies.
Used by : gui.views.shell (dispatch), gui.views.* (screens that navigate or
          receive), gui.controllers.pipeline / identify (build payloads).
Uses    : forensic_aul (CaseInfo — the case metadata Acquire hands to Extract;
          LogFilter — the rows Exploit hands to Export).

WHY typed payloads instead of ``navigate(screen_id, prefill={...})``: the dict
was a contract only by convention — a renamed key ("exhibit" vs
"exhibit_number") made the receiver silently ignore it. A payload names its own
target screen, so the sender cannot route it to a screen that does not
understand it, and the receiver reads attributes a type checker verifies.

WHY a Protocol for screens instead of ``hasattr`` probes: the shell used to
patch a ``navigate`` attribute onto any screen that happened to have one, and
look up ``prefill`` with ``getattr``. A screen that forgot the attribute was
skipped without a word. With the protocol, every stacked screen is bound and
asked the same way, and a payload sent to a screen that cannot take it fails
loudly (see ``receive`` in gui.views.screen_base).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar, Protocol, runtime_checkable

from forensic_aul import CaseInfo, LogFilter


@dataclass(frozen=True)
class OpenDatabase:
    """Open *db* in the Exploit workbench (e.g. Extract's "Open in Exploit")."""

    screen_id: ClassVar[str] = "exploit"
    db: Path


@dataclass(frozen=True)
class ExtractFrom:
    """Pre-fill Extract from an upstream step (a finished acquisition).

    *source* is the collected archive; *case* carries the metadata the analyst
    already typed, so it is not retyped.
    """

    screen_id: ClassVar[str] = "extract"
    source: Path | None = None
    case: CaseInfo = field(default_factory=CaseInfo)


@dataclass(frozen=True)
class ExportFrom:
    """Open Export on *db*, narrowed by *filters* (e.g. Exploit's current view).

    WHY a payload rather than a shared "current database / filters" object that
    Export observes: Export then changes only when the analyst asks for it, never
    behind their back because another screen opened a database.
    """

    screen_id: ClassVar[str] = "export"
    db: Path
    filters: LogFilter = field(default_factory=LogFilter)


@dataclass(frozen=True)
class ShowIdentifyResults:
    """Open *db* (an identify database) on the Identify hub's Results tab."""

    screen_id: ClassVar[str] = "identify"
    db: Path


# A payload: something a screen can receive. Consumed by: Screen.receive and
# the receiving screens' isinstance dispatch.
Payload = OpenDatabase | ExtractFrom | ExportFrom | ShowIdentifyResults

# Where to go: a bare screen id switches screens; a payload switches AND
# delivers. Consumed by: MainWindow.navigate.
Destination = str | Payload

# The callback a screen is bound to (the shell's MainWindow.navigate).
Navigate = Callable[[Destination], None]


def target_of(destination: Destination) -> str:
    """The id of the screen *destination* lands on."""
    return destination if isinstance(destination, str) else destination.screen_id


@runtime_checkable
class Screen(Protocol):
    """What the shell needs from every screen in its stack.

    ``bind_navigator`` hands the screen the shell's navigate callback;
    ``receive`` delivers a payload addressed to this screen.
    """

    screen_id: str

    def bind_navigator(self, navigate: Navigate) -> None: ...

    def receive(self, payload: Payload) -> None: ...


__all__ = [
    "Destination",
    "ExportFrom",
    "ExtractFrom",
    "Navigate",
    "OpenDatabase",
    "Payload",
    "Screen",
    "ShowIdentifyResults",
    "target_of",
]
