"""Flat-memory sort-merge comparison of a FAUL database against an Apple ndjson.

Defines : ``merge_compare(db_path, ndjson_path) -> ComparisonReport`` — the
          streaming twin of ``comparator.compare``. Where ``compare`` loads BOTH
          sides fully into RAM (fine for a bounded window, OOM on a multi-day
          `log show --debug` store), this walks two **sorted** streams in lockstep
          and never holds more than one record per side plus bounded samples.
Used by : forensic_aul.testing.pipeline (the ``validate`` command).
Uses    : forensic_aul.testing.comparator (report + matched-pair comparison +
          DB row builder), forensic_aul.testing.ndjson_loader (record builder),
          and the system ``sort`` for the external sort of the reference ndjson.

Both sides are ordered by the match key ``(bootUUID_norm, machTimestamp, threadID)``:
- the DB via ``ORDER BY`` (SQLite sorts on disk via its temp store);
- the ndjson by projecting each record to a ``boot⇥mach⇥tid⇥payload`` TSV line and
  running ``sort`` (which spills to disk) — this is what "compare line by line on
  disk" means, and why a whole store fits in flat memory.

SORT-ORDER INVARIANT (must hold for the merge to be correct): SQLite ``ORDER BY``
on the boot expression uses BINARY collation, so ``sort`` runs under ``LC_ALL=C``
(byte order); the boot UUID is normalised identically (upper-case, de-dashed) on
both sides; machTimestamp and threadID are compared numerically. A Python tuple
``(boot_uuid, mach, tid)`` of ASCII-hex + ints reproduces exactly that order, so
the two-pointer walk stays in step.
"""

from __future__ import annotations

import heapq
import json
import logging
import os
import sqlite3
import subprocess
import tempfile
from collections import Counter
from collections.abc import Iterator
from pathlib import Path

from forensic_aul.testing.comparator import (
    _MAX_SAMPLES,
    ComparisonReport,
    DbRecord,
    _DB_QUERY,
    _missing_sample,
    _process_label,
    compare_matched_pair,
    db_record_from_row,
    new_field_stats,
)
from forensic_aul.testing.ndjson_loader import RefKey, RefRecord, build_record

log = logging.getLogger(__name__)

# Append the match-key ordering to the shared projection query. UPPER(REPLACE(…))
# reproduces the boot-UUID normalisation the RefKey uses, so the DB order equals
# the ndjson order. Numeric columns sort numerically; the boot expression sorts
# BINARY (matched by LC_ALL=C on the ndjson side).
_DB_ORDER_BY = (
    " ORDER BY UPPER(REPLACE(COALESCE(b.boot_uuid, ''), '-', '')), "
    "l.timestamp_mach, l.tid"
)

# Cap for the external `sort` in-memory buffer (see _ndjson_sorted_stream). Keeps
# peak RSS bounded regardless of reference size; the rest spills to on-disk temp.
_SORT_BUFFER = "256M"


def _ordkey(rec: RefRecord | DbRecord) -> tuple[str, int, int]:
    """The orderable match key. ASCII-hex boot compares byte-wise (== LC_ALL=C ==
    SQLite BINARY); mach/tid compare numerically — so this matches both streams."""
    k: RefKey = rec.key
    return (k.boot_uuid, k.mach_timestamp, k.thread_id)


def _dedup(stream: Iterator[RefRecord] | Iterator[DbRecord]):
    """Collapse adjacent equal-key records (first wins), matching the in-RAM path's
    dict-dedup. Safe because the stream is sorted, so duplicates are contiguous."""
    prev: tuple[str, int, int] | None = None
    for rec in stream:
        key = _ordkey(rec)
        if key == prev:
            continue
        prev = key
        yield rec


# ── sorted source streams ──────────────────────────────────────────────────────

def _db_stream(db_path: Path) -> Iterator[DbRecord]:
    conn = sqlite3.connect(str(db_path))
    try:
        conn.row_factory = sqlite3.Row
        for row in conn.execute(_DB_QUERY + _DB_ORDER_BY):
            yield db_record_from_row(row)
    finally:
        conn.close()


def _ndjson_sorted_stream(ndjson_path: Path, tmp_dir: Path) -> Iterator[RefRecord]:
    """External-sort the reference ndjson, then stream it back as ``RefRecord``s.

    Pass 1 projects each comparable record to ``boot⇥mach⇥tid⇥<json>`` (JSON escapes
    all tabs/newlines, so the payload never breaks the TSV). ``sort`` (LC_ALL=C)
    orders it on disk. Pass 2 reparses the payload with the shared ``build_record``.
    """
    unsorted = tmp_dir / "ref_unsorted.tsv"
    with unsorted.open("w", encoding="utf-8") as out, ndjson_path.open("rb") as fh:
        for raw_line in fh:
            raw_line = raw_line.strip()
            if not raw_line or not raw_line.startswith(b"{"):
                continue
            try:
                obj = json.loads(raw_line)
            except json.JSONDecodeError:
                continue
            rec = build_record(obj)
            if rec is None:
                continue
            payload = json.dumps(obj, ensure_ascii=False)
            out.write(f"{rec.key.boot_uuid}\t{rec.key.mach_timestamp}\t{rec.key.thread_id}\t{payload}\n")

    ordered = tmp_dir / "ref_sorted.tsv"
    env = {**os.environ, "LC_ALL": "C"}
    # -S caps the in-memory buffer so `sort` spills to on-disk temp files (-T) for
    # a large reference instead of buffering the whole file in RAM — WITHOUT it,
    # BSD/Apple sort holds the entire input in memory (~1.8 GB on a 1 GB ndjson),
    # which would defeat the whole point of streaming.
    subprocess.run(  # noqa: S603,S607 — fixed argv, no shell
        ["sort", "-S", _SORT_BUFFER, "-t", "\t", "-k1,1", "-k2,2n", "-k3,3n",
         "-T", str(tmp_dir), "-o", str(ordered), str(unsorted)],
        env=env, check=True,
    )

    def _gen() -> Iterator[RefRecord]:
        with ordered.open("r", encoding="utf-8") as fh:
            for line in fh:
                parts = line.rstrip("\n").split("\t", 3)
                if len(parts) < 4:
                    continue
                rec = build_record(json.loads(parts[3]))
                if rec is not None:
                    yield rec

    return _gen()


# ── bounded top-N samples (smallest mach) ──────────────────────────────────────

def _push_top(heap: list, mach: int, seq: int, item, limit: int) -> None:
    """Keep the *limit* items with the smallest ``mach`` in a size-bounded max-heap
    (stored as ``(-mach, seq, item)`` so ``heap[0]`` is the current largest mach)."""
    if limit <= 0:
        return
    entry = (-mach, seq, item)
    if len(heap) < limit:
        heapq.heappush(heap, entry)
    elif entry[0] > heap[0][0]:  # -mach bigger ⇒ mach smaller ⇒ belongs in the set
        heapq.heapreplace(heap, entry)


def _drain_top(heap: list) -> list:
    """Return the kept items ordered by ascending mach (then insertion order)."""
    return [item for _, _, item in sorted(heap, key=lambda e: (-e[0], e[1]))]


# ── the merge ──────────────────────────────────────────────────────────────────

def merge_compare(
    db_path: Path | str,
    ndjson_path: Path | str,
    *,
    max_samples: int = _MAX_SAMPLES,
) -> ComparisonReport:
    """Compare a FAUL DB against an Apple ndjson in flat memory, returning the same
    :class:`ComparisonReport` as :func:`comparator.compare`."""
    db_path = Path(db_path)
    ndjson_path = Path(ndjson_path)
    with tempfile.TemporaryDirectory(prefix="faul_merge_") as td:
        left = _dedup(_ndjson_sorted_stream(ndjson_path, Path(td)))   # reference
        right = _dedup(_db_stream(db_path))                            # our DB
        return _walk(left, right, max_samples=max_samples)


def _walk(
    ref_stream: Iterator[RefRecord],
    db_stream: Iterator[DbRecord],
    *,
    max_samples: int,
) -> ComparisonReport:
    report = ComparisonReport()
    fstats = new_field_stats()
    proc_counter: Counter[str] = Counter()
    fmt_counter: Counter[str] = Counter()
    missing_heap: list = []
    extra_heap: list = []
    ts_max_abs = 0
    seq = 0

    def on_missing(r: RefRecord) -> None:
        nonlocal seq
        report.missing += 1
        report.ref_total += 1
        if r.is_user_action:
            report.ref_user_action_count += 1
        proc_counter[_process_label(r)] += 1
        fmt_counter[r.format_string or "(no format string)"] += 1
        _push_top(missing_heap, r.mach_timestamp, seq, _missing_sample(r), max_samples)
        seq += 1

    def on_extra(d: DbRecord) -> None:
        nonlocal seq
        report.extra += 1
        report.db_total += 1
        _push_top(extra_heap, d.key.mach_timestamp, seq, d.key, max_samples)
        seq += 1

    r = next(ref_stream, None)
    d = next(db_stream, None)
    while r is not None and d is not None:
        rk, dk = _ordkey(r), _ordkey(d)
        if rk == dk:
            report.matched += 1
            report.ref_total += 1
            report.db_total += 1
            if r.is_user_action:
                report.ref_user_action_count += 1
            abs_delta = compare_matched_pair(r, d, report, fstats, max_samples=max_samples)
            ts_max_abs = max(ts_max_abs, abs_delta)
            r = next(ref_stream, None)
            d = next(db_stream, None)
        elif dk < rk:
            on_extra(d)
            d = next(db_stream, None)
        else:
            on_missing(r)
            r = next(ref_stream, None)

    while r is not None:
        on_missing(r)
        r = next(ref_stream, None)
    while d is not None:
        on_extra(d)
        d = next(db_stream, None)

    report.field_stats = list(fstats.values())
    report.ts_max_abs_us_delta = ts_max_abs
    report.missing_by_process = proc_counter.most_common(10)
    report.missing_by_format_string = fmt_counter.most_common(10)
    report.missing_samples = _drain_top(missing_heap)
    report.extra_samples = _drain_top(extra_heap)
    return report
