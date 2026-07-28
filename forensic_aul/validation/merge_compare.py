"""Flat-memory sort-merge comparison of a FAUL database against an Apple ndjson.

Defines : ``merge_compare(db_path, ndjson_path) -> ComparisonReport`` — the
          streaming twin of ``comparator.compare``. Where ``compare`` loads BOTH
          sides fully into RAM (fine for a bounded window, OOM on a multi-day
          `log show --debug` store), this walks two **sorted** streams in lockstep
          and never holds more than one record per side plus bounded samples.
Used by : forensic_aul.validation.pipeline (the ``validate-tool`` command).
Uses    : forensic_aul.validation.comparator (report + matched-pair comparison +
          DB row builder), forensic_aul.validation.ndjson_loader (line iterator +
          record builder), and the STANDARD LIBRARY only — the external sort of the
          reference ndjson is implemented here, so this module runs unchanged on
          macOS, Linux and Windows.

Both sides are ordered by the match key ``(bootUUID_norm, machTimestamp, threadID)``:
- the DB via ``ORDER BY`` (SQLite sorts on disk via its temp store);
- the ndjson by projecting each record to a ``boot⇥mach⇥tid⇥payload`` TSV line,
  spilling RAM-sized sorted chunks to disk and merging them back with
  ``heapq.merge`` — this is what "compare line by line on disk" means, and why a
  whole store fits in flat memory.

SORT-ORDER INVARIANT (must hold for the merge to be correct): SQLite ``ORDER BY``
on the boot expression uses BINARY collation, i.e. byte order; the boot UUID is
normalised identically (upper-case, de-dashed) on both sides; machTimestamp and
threadID are compared numerically. The ndjson side sorts on the very same Python
tuple ``(boot_uuid, mach, tid)`` of ASCII-hex + ints that :func:`_ordkey` hands the
two-pointer walk, so the two streams stay in step by construction.

WHY not the system ``sort``: it is not portable (Windows' ``sort.exe`` rejects
``-S``/``-T``/``-k``, and the spill flags differ between GNU and BSD), it forced
the byte-order invariant to be re-established through ``LC_ALL=C``, and BSD sort
buffers the whole input in RAM unless capped — the exact failure this module
exists to avoid.
"""

from __future__ import annotations

import heapq
import json
import logging
import sqlite3
import tempfile
from collections import Counter
from collections.abc import Iterator
from pathlib import Path

from forensic_aul.validation.comparator import (
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
from forensic_aul.validation.ndjson_loader import (
    RefKey,
    RefRecord,
    build_record,
    iter_ndjson_objs,
)

log = logging.getLogger(__name__)

# Append the match-key ordering to the shared projection query. UPPER(REPLACE(…))
# reproduces the boot-UUID normalisation the RefKey uses, so the DB order equals
# the ndjson order. Numeric columns sort numerically; the boot expression sorts
# BINARY. COALESCE on the nullable `tid` mirrors the same coercion in
# db_record_from_row, so the SQL order still equals the key order (SQLite would
# otherwise sort NULL ahead of every negative tid). The trailing `l.id` breaks ties
# among duplicate match keys in rowid order — the same order the in-RAM
# `load_db_records` scan sees — so both paths keep the SAME record for a duplicate.
_DB_ORDER_BY = (
    " ORDER BY UPPER(REPLACE(COALESCE(b.boot_uuid, ''), '-', '')), "
    "l.timestamp_mach, COALESCE(l.tid, 0), l.id"
)

# Bytes of reference payload held in RAM before a chunk is sorted and spilled to
# disk. This — NOT the reference size — is what bounds peak memory: a 40 GB ndjson
# costs the same as a 40 MB one. Measured overhead is ~6x the payload bytes once
# the per-record tuple/str objects are counted, so 64 MiB peaks around 400 MB.
# Lower it on a small machine; the only cost is more (smaller) chunks to merge.
_CHUNK_BYTES = 64 * 1024 * 1024

# Chunks merged in one pass. Bounds the simultaneously open files (macOS defaults
# to a 256-descriptor limit); a spill that produced more chunks than this is
# reduced in successive passes first.
_MERGE_FANIN = 32


def _ordkey(rec: RefRecord | DbRecord) -> tuple[str, int, int]:
    """The orderable match key, and the sort key of BOTH streams. The ASCII-hex
    boot compares byte-wise (== SQLite BINARY); mach/tid compare numerically."""
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


# ── external sort of the reference ndjson (pure Python, cross-platform) ────────
# One spilled line is ``boot⇥mach⇥tid⇥<json payload>``. JSON escapes every tab and
# newline, so the payload can never break the TSV framing.

def _chunk_line(key: tuple[str, int, int], payload: str) -> str:
    boot, mach, tid = key
    return f"{boot}\t{mach}\t{tid}\t{payload}\n"


def _read_chunk(path: Path) -> Iterator[tuple[tuple[str, int, int], str]]:
    """Stream one spilled chunk back as ``(key, payload)`` pairs, in stored order."""
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t", 3)
            if len(parts) < 4:
                # We wrote these lines ourselves with exactly four fields, so a
                # short one means the spill was truncated (a full disk). Skipping
                # it would silently under-count the reference and turn a write
                # failure into a bogus "missing entries" verdict.
                raise ValueError(f"corrupt sort chunk {path}: {line[:80]!r}")
            boot, mach, tid, payload = parts
            yield (boot, int(mach), int(tid)), payload


def _merge_chunks(chunks: list[Path]) -> Iterator[tuple[tuple[str, int, int], str]]:
    """Merge already-sorted chunks into one ascending stream, holding a single line
    per chunk in RAM. ``heapq.merge`` is stable across its inputs, so passing the
    chunks in spill order keeps equal keys in the reference's FILE order."""
    return heapq.merge(*(_read_chunk(p) for p in chunks), key=lambda item: item[0])


def _spill_sorted_chunks(ndjson_path: Path, tmp_dir: Path) -> list[Path]:
    """Pass 1: project every comparable record to a keyed TSV line and spill it in
    RAM-sized, individually sorted chunks."""
    chunks: list[Path] = []
    buffer: list[tuple[tuple[str, int, int], str]] = []
    buffered = 0

    def flush() -> None:
        nonlocal buffer, buffered
        if not buffer:
            return
        # Stable sort: records with an equal match key keep their file order, so
        # the _dedup below keeps the same one the in-RAM loader's dict would.
        buffer.sort(key=lambda item: item[0])
        path = tmp_dir / f"chunk_{len(chunks):05d}.tsv"
        with path.open("w", encoding="utf-8") as out:
            out.writelines(_chunk_line(key, payload) for key, payload in buffer)
        chunks.append(path)
        buffer = []
        buffered = 0

    for obj in iter_ndjson_objs(ndjson_path):
        rec = build_record(obj)
        if rec is None:
            continue
        payload = json.dumps(obj, ensure_ascii=False)
        buffer.append((_ordkey(rec), payload))
        buffered += len(payload)
        if buffered >= _CHUNK_BYTES:
            flush()
    flush()
    return chunks


def _reduce_chunks(chunks: list[Path], tmp_dir: Path) -> list[Path]:
    """Merge chunks in passes until at most ``_MERGE_FANIN`` remain.

    WHY: the final streaming merge holds every remaining chunk open at once, and a
    multi-GB reference spills far more chunks than the process file-descriptor
    limit allows. Each pass is stable and consumes its inputs, so peak disk stays
    ~2x the spill and the key order is preserved.
    """
    round_no = 0
    while len(chunks) > _MERGE_FANIN:
        merged: list[Path] = []
        for start in range(0, len(chunks), _MERGE_FANIN):
            group = chunks[start:start + _MERGE_FANIN]
            if len(group) == 1:
                merged.append(group[0])
                continue
            out_path = tmp_dir / f"merge{round_no}_{len(merged):05d}.tsv"
            with out_path.open("w", encoding="utf-8") as out:
                out.writelines(_chunk_line(k, p) for k, p in _merge_chunks(group))
            for spent in group:
                spent.unlink(missing_ok=True)
            merged.append(out_path)
        chunks = merged
        round_no += 1
    return chunks


def _ndjson_sorted_stream(ndjson_path: Path, tmp_dir: Path) -> Iterator[RefRecord]:
    """External-sort the reference ndjson on disk, then stream it back as
    ``RefRecord``s in match-key order.

    Pass 1 spills RAM-sized sorted chunks; intermediate passes reduce them to a
    mergeable number; the returned generator merges what is left and reparses each
    payload with the shared ``build_record``. Nothing larger than one chunk is ever
    resident, so a 40 GB reference costs the same RAM as a small one.
    """
    chunks = _reduce_chunks(_spill_sorted_chunks(ndjson_path, tmp_dir), tmp_dir)

    def _gen() -> Iterator[RefRecord]:
        for _key, payload in _merge_chunks(chunks):
            rec = build_record(json.loads(payload))
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
