"""The format watch: what a parse saw that this version does not fully understand.

Defines : ``FormatWatch`` (per-file counts of observations, picklable), the
          observation kinds, ``ALERT_KINDS`` (those that mean the format may
          have changed) and ``log_summary``.
Used by : forensic_aul.ops.extraction.tracev3_parse (records), .extract (merges,
          logs, stores them in the ``format_observations`` table).
Uses    : the standard library only.

WHY: the iOS 27 change went unnoticed because the parser read new fields as
"padding" or "unknown" and threw them away — the first sign was zero entries.
Recording what does not match the known format (a section that does not fill
its declared space, a flag bit never documented, an unknown chunk tag) turns the
next change into a WARNING with a name, on the first archive that carries it.
The codecs seen are recorded too: with the OS build in case_metadata, they are
the format fingerprint of that build.
"""

from __future__ import annotations

import logging
from collections import Counter

log = logging.getLogger(__name__)

# Observation kinds.
CODEC = "codec"                     # informational: which chunkset codec was seen
CATALOG_DRIFT = "catalog_drift"     # a catalog section did not match its records
FIREHOSE_FLAG = "firehose_flag"     # an undocumented firehose flag bit was set
CHUNK_TAG = "chunk_tag"             # an unknown top-level tracev3 chunk
SUBCHUNK_TAG = "subchunk_tag"       # an unknown sub-chunk inside a chunkset

# The kinds that mean "this OS may have changed the log format".
ALERT_KINDS = frozenset({CATALOG_DRIFT, FIREHOSE_FLAG, CHUNK_TAG, SUBCHUNK_TAG})

# Distinct details kept per kind and file: a field that varies freely must not
# grow the table without bound; the count of what was dropped is kept.
_MAX_DETAILS_PER_KIND = 50


class FormatWatch:
    """Observations of one file: ``(kind, detail) → count``."""

    def __init__(self) -> None:
        self.counts: Counter[tuple[str, str]] = Counter()
        self._per_kind: Counter[str] = Counter()

    def note(self, kind: str, detail: str, n: int = 1) -> None:
        key = (kind, detail)
        if key not in self.counts:
            if self._per_kind[kind] >= _MAX_DETAILS_PER_KIND:
                key = (kind, "(other values)")
            else:
                self._per_kind[kind] += 1
        self.counts[key] += n

    def rows(self) -> tuple[tuple[str, str, int], ...]:
        """The observations as plain tuples (what crosses the process boundary)."""
        return tuple((kind, detail, n) for (kind, detail), n in sorted(self.counts.items()))


def log_summary(rows: list[tuple[str, str, int]]) -> None:
    """One line per distinct observation over the run: WARNING for the alert kinds."""
    totals: Counter[tuple[str, str]] = Counter()
    for kind, detail, n in rows:
        totals[(kind, detail)] += n
    for (kind, detail), n in sorted(totals.items()):
        if kind in ALERT_KINDS:
            log.warning(f"Format watch: {kind} {detail} (×{n}) — this OS version may have "
                        "changed the log format; see the format_observations table")
        else:
            log.info(f"Format watch: {kind} {detail} (×{n})")
