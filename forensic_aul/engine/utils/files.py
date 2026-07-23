"""Filesystem helpers shared across the extract pipeline.

Defines : :func:`is_appledouble` — the single source of truth for recognising
          macOS AppleDouble ``._*`` sidecar files.
Used by : forensic_aul.ops.extraction.extract (tracev3 / timesync discovery),
          forensic_aul.engine.parser.string_cache (DSC discovery).
Uses    : pathlib (typing only).
"""

from __future__ import annotations

from pathlib import Path


def is_appledouble(path: Path) -> bool:
    """Return True if *path* is a macOS AppleDouble ``._*`` sidecar file.

    WHY: when a logarchive is copied or zipped through a non-Apple filesystem,
    macOS writes a ``._<name>`` companion for every file to carry the resource
    fork / extended attributes. These are not real tracev3 / timesync / dsc
    payloads — on the test archive exactly half of the 2 207 ``*.tracev3``
    matches were ``._`` stubs, and a ``._*.timesync`` stub triggered a spurious
    "Invalid timesync boot signature" parse error. Skipping them at discovery
    removes that wasted I/O and the misleading error, and never drops real data
    (the real file sits beside its ``._`` twin).

    The AppleDouble convention is a literal ``._`` filename prefix, so a name
    check is authoritative — no need to read the file.
    """
    return path.name.startswith("._")
