"""Option container for a device acquisition.

Defines : ``AcquireOptions`` — which device, how much to collect, and the output
          layout. Built once by a frontend and passed through untouched.
Used by : forensic_aul.ops.acquisition.acquire (``acquire``), the CLI ``acquire``
          command and the GUI Acquire screen (re-exported from forensic_aul).
Uses    : the standard library only.

The case identifiers travel separately, as a ``CaseInfo`` (the same object an
extract takes); the device's own IMEI is read from the device, not from it.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AcquireOptions:
    """The tunable behaviour of one ``acquire`` call (see its docstring)."""

    # The device to collect from. None = the only connected one; with several
    # connected, a frontend must make the operator choose (see the GUI's guard).
    udid: str | None = None
    # How far back: ISO 8601 datetime, relative ("1h" / "24h" / "7d"), a Unix
    # timestamp, or None for everything available.
    start_time: str | int | None = None
    size_limit: int | None = None   # bytes; None = no limit
    age_limit: int | None = None    # days; None = no limit
    # True: one portable .faul (archive + sidecar). False: the legacy loose layout
    # (<name>.logarchive + <name>.logarchive.acquisition.json).
    pack: bool = True
