"""Three-level comparison engine between our SQLite output and Apple's ndjson.

Level 1 — Entry count
    Are the total number of comparable entries the same?

Level 2 — Timestamp matching
    For every reference record, is there a row in our DB with the same
    (boot_uuid, mach_timestamp, thread_id) triple?

Level 3 — Message comparison  (on matched records only)
    a) Exact match of the formatted message
    b) Normalised match  (strip, lowercase, collapse whitespace)
    c) Format string match (raw printf template)
    d) Structural fields (pid, tid, euid, subsystem, category, …)

Results are written both to the logger (INFO level) and returned as a
:class:`ComparisonReport` dataclass for programmatic use.
"""

from __future__ import annotations

import logging
import re
import sqlite3
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from forensic_aul.testing.ndjson_loader import LoadResult, RefKey, RefRecord

log = logging.getLogger(__name__)

# Number of mismatch samples to include in the report
_MAX_SAMPLES = 20

_WS_RE = re.compile(r"\s+")


def _normalise_msg(s: str) -> str:
    """Lowercase + collapse all whitespace runs to a single space."""
    return _WS_RE.sub(" ", s.strip().lower())


# ── DB record ─────────────────────────────────────────────────────────────────

@dataclass
class DbRecord:
    """Minimal projection of a logs row needed for comparison."""
    key: RefKey
    mach_timestamp: int
    timestamp_unix_ns: int
    boot_uuid: str
    event_type: str
    log_level: str
    pid: int
    tid: int
    euid: int
    subsystem: str
    category: str
    activity_id: int
    parent_activity_id: int
    message: str
    message_format_string: str
    process_uuid: str
    library_uuid: str


_DB_QUERY = """
SELECT
    l.timestamp_mach,
    l.timestamp_unix_ns,
    COALESCE(b.boot_uuid, '')  AS boot_uuid,
    COALESCE(et.name, '')      AS event_type,
    COALESCE(ll.name, '')      AS log_level,
    l.pid,
    l.tid,
    l.euid,
    COALESCE(s.name, '')  AS subsystem,
    COALESCE(c.name, '')  AS category,
    l.activity_id,
    l.parent_activity_id,
    COALESCE(l.message, '')               AS message,
    COALESCE(fs.value, '')                AS message_format_string,
    COALESCE(pu.uuid, '')                 AS process_uuid,
    COALESCE(lib.uuid, '')                AS library_uuid
FROM logs l
LEFT JOIN subsystems    s   ON l.subsystem_id    = s.id
LEFT JOIN categories    c   ON l.category_id     = c.id
LEFT JOIN libraries     lib ON l.library_id      = lib.id
LEFT JOIN format_strs   fs  ON l.format_str_id   = fs.id
LEFT JOIN boots         b   ON l.boot_id         = b.id
LEFT JOIN event_types   et  ON l.event_type_id   = et.id
LEFT JOIN log_levels    ll  ON l.log_level_id    = ll.id
LEFT JOIN process_uuids pu  ON l.process_uuid_id = pu.id
"""


def load_db_records(db_path: Path | str) -> dict[RefKey, DbRecord]:
    """Load all rows from the logs table into a RefKey-indexed dict.

    Iterates the cursor instead of `fetchall()` so we never materialise
    a multi-million-row resultset in RAM.
    """
    db_path = Path(db_path)
    records: dict[RefKey, DbRecord] = {}
    collisions = 0

    # `with sqlite3.connect(...)` only commits/rollbacks the txn — it does
    # NOT close the connection, so close it explicitly in `finally`.
    conn = sqlite3.connect(str(db_path))
    try:
        conn.row_factory = sqlite3.Row
        for row in conn.execute(_DB_QUERY):
            boot_uuid_norm = (row["boot_uuid"] or "").upper().replace("-", "")
            key = RefKey(
                boot_uuid=boot_uuid_norm,
                mach_timestamp=row["timestamp_mach"],
                thread_id=row["tid"],
            )
            if key in records:
                collisions += 1
                continue
            records[key] = DbRecord(
                key=key,
                mach_timestamp=row["timestamp_mach"],
                timestamp_unix_ns=row["timestamp_unix_ns"] or 0,
                boot_uuid=row["boot_uuid"] or "",
                event_type=row["event_type"] or "",
                log_level=row["log_level"] or "",
                pid=row["pid"] or 0,
                tid=row["tid"] or 0,
                euid=row["euid"] or 0,
                subsystem=row["subsystem"],
                category=row["category"],
                activity_id=row["activity_id"] or 0,
                parent_activity_id=row["parent_activity_id"] or 0,
                message=row["message"],
                message_format_string=row["message_format_string"],
                process_uuid=row["process_uuid"],
                library_uuid=row["library_uuid"],
            )
    finally:
        conn.close()

    if collisions:
        log.warning(f"load_db_records: {collisions} duplicate keys in DB (first wins)")

    log.info(f"load_db_records: {len(records)} rows loaded from {db_path.name}")
    return records


# ── Field-level comparison helpers ───────────────────────────────────────────

@dataclass
class FieldStats:
    name: str
    total: int = 0
    match: int = 0

    @property
    def pct(self) -> float:
        return 100.0 * self.match / self.total if self.total else 0.0

    def __str__(self) -> str:
        return f"{self.name}: {self.match}/{self.total} ({self.pct:.1f}%)"


@dataclass
class MessageMismatch:
    key: RefKey
    expected: str
    got: str
    format_str_expected: str
    format_str_got: str


@dataclass
class TimestampMismatch:
    """A matched-key entry whose unix-microsecond timestamp differs.

    ``delta_us`` is signed (db − ref) so the report can show whether we are
    consistently early or late.
    """
    key: RefKey
    ref_unix_us: int
    db_unix_us: int
    delta_us: int


@dataclass
class MissingSample:
    """A reference record absent from the DB, with enough context to debug.

    Carries the process image, the format string and the event message so a
    pattern can be spotted (one process, one format string, one time window?).
    """
    key: RefKey
    process_image: str
    format_string: str
    event_message: str
    subsystem: str
    category: str


# ── Report ────────────────────────────────────────────────────────────────────

@dataclass
class ComparisonReport:
    # ── Level 1 : counts ──────────────────────────────────────────────────────
    ref_total: int = 0
    ref_user_action_count: int = 0
    db_total: int = 0

    # ── Level 2 : timestamp matching ─────────────────────────────────────────
    matched: int = 0         # keys present in both
    missing: int = 0         # in ref but not in DB
    extra: int = 0           # in DB but not in ref
    missing_samples: list[MissingSample] = field(default_factory=list)
    extra_samples: list[RefKey] = field(default_factory=list)

    # ── Level 2 — aggregations over the missing set ──────────────────────────
    # Two angles: which processes lose entries, and which format strings do.
    missing_by_process: list[tuple[str, int]] = field(default_factory=list)
    missing_by_format_string: list[tuple[str, int]] = field(default_factory=list)

    # ── Level 3 : message comparison (on matched only) ────────────────────────
    msg_exact: int = 0
    msg_normalised: int = 0
    msg_format_match: int = 0
    msg_mismatches: list[MessageMismatch] = field(default_factory=list)

    # ── Level 3 : structural field accuracy (on matched only) ─────────────────
    field_stats: list[FieldStats] = field(default_factory=list)

    # ── Level 3c : timestamp accuracy (on matched only) ───────────────────────
    # Computed at microsecond precision because Apple's ndjson ``timestamp``
    # field is microsecond-resolved.
    ts_us_match: int = 0       # |db_us − ref_us| == 0
    ts_us_within_1: int = 0    # |db_us − ref_us| <= 1   (rounding tolerance)
    ts_max_abs_us_delta: int = 0  # worst-case absolute delta seen
    ts_total: int = 0
    ts_samples: list["TimestampMismatch"] = field(default_factory=list)


# ── Main comparison function ──────────────────────────────────────────────────

def compare(
    ref: LoadResult,
    db_records: dict[RefKey, DbRecord],
    *,
    max_samples: int = _MAX_SAMPLES,
) -> ComparisonReport:
    """Run all three comparison levels and return a :class:`ComparisonReport`."""
    report = ComparisonReport(
        ref_total=ref.count,
        ref_user_action_count=ref.user_action_count,
        db_total=len(db_records),
    )

    # Initialise field-level counters
    field_names = [
        "event_type", "log_level", "pid", "euid",
        "subsystem", "category", "activity_id", "parent_activity_id",
    ]
    fstats: dict[str, FieldStats] = {n: FieldStats(name=n) for n in field_names}

    ref_keys = set(ref.records.keys())
    db_keys  = set(db_records.keys())

    # ── Level 2 : key matching ────────────────────────────────────────────────
    matched_keys = ref_keys & db_keys
    missing_keys = ref_keys - db_keys
    extra_keys   = db_keys  - ref_keys

    report.matched = len(matched_keys)
    report.missing = len(missing_keys)
    report.extra   = len(extra_keys)

    # Build the rich missing samples (key + process + format + message snippet)
    sorted_missing = sorted(missing_keys, key=lambda k: k.mach_timestamp)
    report.missing_samples = [
        _missing_sample(ref.records[k]) for k in sorted_missing[:max_samples]
    ]
    report.extra_samples = sorted(
        extra_keys, key=lambda k: k.mach_timestamp
    )[:max_samples]

    # Aggregations over the *full* missing set (not just the samples).
    proc_counter: Counter[str] = Counter()
    fmt_counter: Counter[str] = Counter()
    for k in missing_keys:
        rec = ref.records[k]
        proc_counter[_process_label(rec)] += 1
        fmt_counter[rec.format_string or "(no format string)"] += 1
    report.missing_by_process = proc_counter.most_common(10)
    report.missing_by_format_string = fmt_counter.most_common(10)

    # ── Level 3 : message + timestamp + field comparison on matched keys ────
    ts_max_abs = 0
    for key in matched_keys:
        ref_rec = ref.records[key]
        db_rec  = db_records[key]

        # Timestamp comparison at microsecond precision (Apple's resolution).
        # We tolerate exact equality ("us_match") and ±1 µs ("within_1") to
        # absorb the harmless half-up rounding when both sides round
        # independently around a sub-µs boundary.
        if ref_rec.timestamp_unix_us is not None and db_rec.timestamp_unix_ns:
            db_us = db_rec.timestamp_unix_ns // 1_000
            delta = db_us - ref_rec.timestamp_unix_us
            abs_delta = abs(delta)
            report.ts_total += 1
            if delta == 0:
                report.ts_us_match += 1
                report.ts_us_within_1 += 1
            elif abs_delta <= 1:
                report.ts_us_within_1 += 1
            elif len(report.ts_samples) < max_samples:
                report.ts_samples.append(TimestampMismatch(
                    key=key,
                    ref_unix_us=ref_rec.timestamp_unix_us,
                    db_unix_us=db_us,
                    delta_us=delta,
                ))
            if abs_delta > ts_max_abs:
                ts_max_abs = abs_delta

        # Message exact
        if ref_rec.event_message == db_rec.message:
            report.msg_exact += 1
            report.msg_normalised += 1
        elif _normalise_msg(ref_rec.event_message) == _normalise_msg(db_rec.message):
            report.msg_normalised += 1
        else:
            if len(report.msg_mismatches) < max_samples:
                report.msg_mismatches.append(MessageMismatch(
                    key=key,
                    expected=ref_rec.event_message,
                    got=db_rec.message,
                    format_str_expected=ref_rec.format_string,
                    format_str_got=db_rec.message_format_string,
                ))

        # Format string match
        if ref_rec.format_string == db_rec.message_format_string:
            report.msg_format_match += 1

        # Structural fields
        comparisons: list[tuple[str, object, object]] = [
            ("event_type",           ref_rec.event_type,          db_rec.event_type),
            ("log_level",            ref_rec.log_level,           db_rec.log_level),
            ("pid",                  ref_rec.pid,                 db_rec.pid),
            ("euid",                 ref_rec.euid,                db_rec.euid),
            ("subsystem",            ref_rec.subsystem,           db_rec.subsystem),
            ("category",             ref_rec.category,            db_rec.category),
            ("activity_id",          ref_rec.activity_id,         db_rec.activity_id),
            ("parent_activity_id",   ref_rec.parent_activity_id,  db_rec.parent_activity_id),
        ]
        for fname, ref_val, db_val in comparisons:
            fs = fstats[fname]
            fs.total += 1
            if ref_val == db_val:
                fs.match += 1
            else:
                log.debug(
                    "field mismatch [%s] key=(%s, %d, %d)  ref=%r  db=%r",
                    fname, key.boot_uuid[:8], key.mach_timestamp, key.thread_id,
                    ref_val, db_val,
                )

    report.field_stats = list(fstats.values())
    report.ts_max_abs_us_delta = ts_max_abs
    return report


# ── Missing-sample helpers ────────────────────────────────────────────────────

def _process_label(rec: RefRecord) -> str:
    """Pick the most useful process identifier available in the ref record.

    Apple's ndjson stores ``processImagePath`` (full path); fall back to the
    UUID and finally to ``"(unknown)"`` so the bucket is never empty.
    """
    if rec.process_image_path:
        return rec.process_image_path
    if rec.process_image_uuid:
        return f"uuid:{rec.process_image_uuid}"
    return "(unknown)"


def _missing_sample(rec: RefRecord) -> MissingSample:
    return MissingSample(
        key=rec.key,
        process_image=_process_label(rec),
        format_string=rec.format_string or "",
        event_message=rec.event_message or "",
        subsystem=rec.subsystem or "",
        category=rec.category or "",
    )


# ── Unicode table helpers ─────────────────────────────────────────────────────

def _table(
    headers: list[str],
    rows: list[list[str]],
    *,
    aligns: list[str] | None = None,   # "l" | "r" | "c" per column
) -> list[str]:
    """Render a Unicode box-drawing table and return lines (no trailing newline)."""
    ncols = len(headers)
    if aligns is None:
        aligns = ["l"] * ncols

    # Column widths
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def _fmt(cell: str, width: int, align: str) -> str:
        if align == "r":
            return cell.rjust(width)
        if align == "c":
            return cell.center(width)
        return cell.ljust(width)

    def _sep(left: str, mid: str, right: str, fill: str) -> str:
        return left + mid.join(fill * (w + 2) for w in widths) + right

    lines: list[str] = []
    lines.append(_sep("╔", "╦", "╗", "═"))
    lines.append(
        "║ "
        + " ║ ".join(_fmt(h, widths[i], "c") for i, h in enumerate(headers))
        + " ║"
    )
    lines.append(_sep("╠", "╬", "╣", "═"))
    for row in rows:
        lines.append(
            "║ "
            + " ║ ".join(_fmt(row[i], widths[i], aligns[i]) for i in range(ncols))
            + " ║"
        )
    lines.append(_sep("╚", "╩", "╝", "═"))
    return lines


def _truncate(value: str, max_len: int) -> str:
    """Truncate *value* to *max_len* chars with an explicit ellipsis marker.

    Slicing at a fixed byte/character offset can split a multi-codepoint
    grapheme cluster mid-way; here we accept that risk on the textual side
    but flag the truncation so a downstream reader doesn't believe the
    string ended naturally.
    """
    if len(value) <= max_len:
        return value
    return value[:max_len] + "…"


def _pct_bar(pct_val: float, width: int = 20) -> str:
    """Return a compact ASCII progress bar, e.g. '████████░░░░ 68.5%'.

    Clamps to [0, width] so an out-of-range percentage never produces a
    negative-length string.
    """
    filled = max(0, min(width, round(pct_val / 100 * width)))
    return "█" * filled + "░" * (width - filled)


# ── Human-readable report renderer ───────────────────────────────────────────

def render_report(report: ComparisonReport, *, log_fn=None) -> str:
    """Render a ComparisonReport as a human-readable string with Unicode tables.

    Also emits each line via *log_fn* (defaults to ``log.info``).
    """
    if log_fn is None:
        log_fn = log.info

    W = 80
    lines: list[str] = []

    def emit(line: str = "") -> None:
        lines.append(line)
        log_fn("%s", line)

    def pct(num: int, den: int) -> str:
        return "n/a" if den == 0 else f"{100.0 * num / den:.2f}%"

    def pct_f(num: int, den: int) -> float:
        return 0.0 if den == 0 else 100.0 * num / den

    emit("═" * W)
    emit("  forensic-aul — Comparison Report")
    emit("═" * W)

    # ── Level 1 : Entry count ─────────────────────────────────────────────────
    emit()
    emit("  Level 1 — Entry count")
    emit()
    delta = report.db_total - report.ref_total
    sign = "+" if delta >= 0 else ""
    for line in _table(
        ["Source", "Count", "Note"],
        [
            ["Reference (ndjson)", f"{report.ref_total:,}", ""],
            ["  of which userAction", f"{report.ref_user_action_count:,}", "treated as Log (conservative)"],
            ["Database", f"{report.db_total:,}", ""],
            ["Delta (DB − ref)", f"{sign}{delta:,}", f"{pct(abs(delta), report.ref_total)} off"],
        ],
        aligns=["l", "r", "l"],
    ):
        emit("  " + line)

    # ── Level 2 : Timestamp matching ──────────────────────────────────────────
    emit()
    emit("  Level 2 — Timestamp matching  (bootUUID + machTimestamp + threadID)")
    emit()
    match_pct = pct_f(report.matched, report.ref_total)
    for line in _table(
        ["Metric", "Count", "%", "Bar (20 chars)"],
        [
            ["Matched", f"{report.matched:,}", pct(report.matched, report.ref_total),
             _pct_bar(match_pct)],
            ["Missing (ref → DB)", f"{report.missing:,}", pct(report.missing, report.ref_total),
             _pct_bar(pct_f(report.missing, report.ref_total))],
            ["Extra (DB → ref)", f"{report.extra:,}", pct(report.extra, report.ref_total),
             _pct_bar(pct_f(report.extra, report.ref_total))],
        ],
        aligns=["l", "r", "r", "l"],
    ):
        emit("  " + line)

    if report.missing_samples:
        emit()
        emit(f"  First {len(report.missing_samples)} missing entries (sorted by mach_timestamp):")
        for s in report.missing_samples:
            k = s.key
            proc = _truncate(s.process_image, 50)
            emit(f"    mach={k.mach_timestamp:<14d} tid={k.thread_id:<6d} boot={k.boot_uuid[:8]}…  proc={proc}")
            if s.subsystem or s.category:
                emit(f"        subsystem={s.subsystem!r}  category={s.category!r}")
            if s.format_string:
                emit(f"        fmt   : {_truncate(s.format_string, 100)!r}")
            if s.event_message:
                emit(f"        msg   : {_truncate(s.event_message, 100)!r}")

    if report.missing_by_process:
        emit()
        emit("  Missing — top processes:")
        total_missing = report.missing or 1
        for proc, count in report.missing_by_process:
            share = 100.0 * count / total_missing
            emit(f"    {count:>10,}  ({share:5.1f}%)  {_truncate(proc, 70)}")

    if report.missing_by_format_string:
        emit()
        emit("  Missing — top format strings:")
        total_missing = report.missing or 1
        for fmt, count in report.missing_by_format_string:
            share = 100.0 * count / total_missing
            emit(f"    {count:>10,}  ({share:5.1f}%)  {_truncate(fmt, 70)!r}")

    if report.extra_samples:
        emit()
        emit(f"  First {len(report.extra_samples)} extra keys (mach_timestamp / boot_uuid / tid):")
        for k in report.extra_samples:
            emit(f"    {k.mach_timestamp:>14d}  {k.boot_uuid[:8]}…  tid={k.thread_id}")

    # ── Level 3a : Message comparison ────────────────────────────────────────
    emit()
    emit("  Level 3a — Message comparison  (on matched entries only)")
    emit()
    base = report.matched
    for line in _table(
        ["Match type", "Count", f"/ {base:,}", "%", "Bar (20 chars)"],
        [
            ["Exact",
             f"{report.msg_exact:,}", f"{base:,}",
             pct(report.msg_exact, base),
             _pct_bar(pct_f(report.msg_exact, base))],
            ["Normalised (lower+strip)",
             f"{report.msg_normalised:,}", f"{base:,}",
             pct(report.msg_normalised, base),
             _pct_bar(pct_f(report.msg_normalised, base))],
            ["Format string",
             f"{report.msg_format_match:,}", f"{base:,}",
             pct(report.msg_format_match, base),
             _pct_bar(pct_f(report.msg_format_match, base))],
        ],
        aligns=["l", "r", "r", "r", "l"],
    ):
        emit("  " + line)

    if report.msg_mismatches:
        emit()
        emit(f"  Sample message mismatches ({len(report.msg_mismatches)} shown):")
        for mm in report.msg_mismatches:
            emit(f"    mach={mm.key.mach_timestamp}  tid={mm.key.thread_id}")
            emit(f"      expected : {_truncate(mm.expected, 120)!r}")
            emit(f"      got      : {_truncate(mm.got, 120)!r}")
            if mm.format_str_expected or mm.format_str_got:
                emit(f"      fmt_ref  : {_truncate(mm.format_str_expected, 80)!r}")
                emit(f"      fmt_db   : {mm.format_str_got[:80]!r}")

    # ── Level 3c : Timestamp accuracy (microsecond) ──────────────────────────
    if report.ts_total:
        emit()
        emit("  Level 3c — Wall-clock timestamp accuracy  (matched entries; µs precision)")
        emit()
        for line in _table(
            ["Match type", "Count", f"/ {report.ts_total:,}", "%", "Bar (20 chars)"],
            [
                ["Exact (Δ = 0 µs)",
                 f"{report.ts_us_match:,}", f"{report.ts_total:,}",
                 pct(report.ts_us_match, report.ts_total),
                 _pct_bar(pct_f(report.ts_us_match, report.ts_total))],
                ["Within ±1 µs",
                 f"{report.ts_us_within_1:,}", f"{report.ts_total:,}",
                 pct(report.ts_us_within_1, report.ts_total),
                 _pct_bar(pct_f(report.ts_us_within_1, report.ts_total))],
            ],
            aligns=["l", "r", "r", "r", "l"],
        ):
            emit("  " + line)
        emit()
        emit(f"  Worst-case absolute Δ: {report.ts_max_abs_us_delta:,} µs")
        if report.ts_samples:
            emit()
            emit(f"  First {len(report.ts_samples)} timestamp mismatches (>1 µs):")
            for ts in report.ts_samples:
                emit(
                    f"    mach={ts.key.mach_timestamp:<14d} tid={ts.key.thread_id:<6d}  "
                    f"Δ={ts.delta_us:+d} µs  "
                    f"ref={ts.ref_unix_us}  db={ts.db_unix_us}"
                )

    # ── Level 3b : Structural field accuracy ─────────────────────────────────
    emit()
    emit("  Level 3b — Structural field accuracy  (on matched entries only)")
    emit()
    field_rows = []
    for fs in report.field_stats:
        field_rows.append([
            fs.name,
            f"{fs.match:,}",
            f"{fs.total:,}",
            f"{fs.pct:.2f}%",
            _pct_bar(fs.pct),
        ])
    for line in _table(
        ["Field", "Matched", "Total", "%", "Bar (20 chars)"],
        field_rows,
        aligns=["l", "r", "r", "r", "l"],
    ):
        emit("  " + line)

    emit()
    emit("═" * W)

    return "\n".join(lines)
