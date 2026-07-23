"""File-system discovery helpers for tracev3 and timesync files.

Defines : find_tracev3_files, find_timesync_files
Used by : forensic_aul.ops.extraction.extract (_run_parse)
Uses    : forensic_aul.engine.utils.files (is_appledouble)
"""

from __future__ import annotations

from pathlib import Path

from forensic_aul.engine.utils.files import is_appledouble


def find_tracev3_files(logarchive: Path) -> list[Path]:
    """Return tracev3 files in canonical processing order: Persist/ → Special/ → Signpost/.

    AppleDouble ``._*`` sidecars are skipped — they are not real tracev3 payloads
    and parsing them is wasted work (see engine/utils/files.is_appledouble).
    """
    order = ["Persist", "Special", "Signpost"]
    result: list[Path] = []
    for subdir in order:
        d = logarchive / subdir
        if d.is_dir():
            result.extend(p for p in sorted(d.glob("*.tracev3")) if not is_appledouble(p))
    # Any remaining .tracev3 at other locations
    seen = set(result)
    for p in sorted(logarchive.rglob("*.tracev3")):
        if p not in seen and not is_appledouble(p):
            result.append(p)
    return result


def find_timesync_files(logarchive: Path) -> list[Path]:
    # Skip AppleDouble ``._*`` sidecars: a ``._*.timesync`` stub otherwise triggers
    # a spurious "Invalid timesync boot signature" error (see is_appledouble).
    return [
        p for p in sorted((logarchive / "timesync").glob("*.timesync"))
        if not is_appledouble(p)
    ]
