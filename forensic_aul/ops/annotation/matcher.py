"""Apply a knowledge base to an extracted log database.

Hot path: every signature pre-filters candidates via indexed columns
(format_str_id, process_id, subsystem_id, category_id) before any regex
evaluation, with log_level_id as a non-indexed residual refinement on the
already-narrow candidate set. The worst-case scan is O(N_logs) once per
signature on the indexed lead columns — orders of magnitude faster than
running every regex over the full table.

For dynamic-format signatures (no anchor format string) the candidate
set is restricted via the indexed refinements only and falls back to a
sequential message_regex scan over what remains.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from forensic_aul.engine.database.access import open_analysis_database
from forensic_aul.ops.knowledge_base.models import KnowledgeBase, Signature
from forensic_aul.ops.summary.cache import clear_summary, store_summary
from forensic_aul.ops.summary.summary import (
    DEFAULT_BUCKETS,
    DEFAULT_TOP,
    summarise_connection,
)
from forensic_aul.outcomes import AnnotateResult

log = logging.getLogger(__name__)


# ── Schema for annotation tables ──────────────────────────────────────────────

_DDL = """
CREATE TABLE IF NOT EXISTS kb_signatures (
    id                  INTEGER PRIMARY KEY,
    signature_id        TEXT NOT NULL,        -- e.g. "sb.app_foreground"
    action              TEXT NOT NULL,
    description         TEXT,
    confidence          TEXT,
    tags                TEXT,                 -- JSON list
    source_file         TEXT,                 -- KB-relative YAML path
    kb_version          TEXT NOT NULL,        -- semver from VERSION
    kb_sha256           TEXT NOT NULL,        -- digest of KB tree
    applied_at          TEXT NOT NULL,        -- ISO 8601 UTC
    match_count         INTEGER NOT NULL DEFAULT 0,
    UNIQUE (signature_id, kb_sha256, applied_at)
);

CREATE TABLE IF NOT EXISTS log_annotations (
    id                  INTEGER PRIMARY KEY,
    log_id              INTEGER NOT NULL REFERENCES logs(id),
    kb_signature_id     INTEGER NOT NULL REFERENCES kb_signatures(id)
);

CREATE INDEX IF NOT EXISTS idx_log_annotations_log_id   ON log_annotations(log_id);
CREATE INDEX IF NOT EXISTS idx_log_annotations_kb_id    ON log_annotations(kb_signature_id);

-- One row per (label, value) extracted from a matched message by a signature's
-- extract_regex / extract_fields. Normalised (not a JSON blob) so values are
-- directly SQL-queryable, e.g. SELECT DISTINCT value FROM extracted_values
-- WHERE label = 'ssid'. The export pivots these into one column per label.
CREATE TABLE IF NOT EXISTS extracted_values (
    id                  INTEGER PRIMARY KEY,
    log_annotation_id   INTEGER NOT NULL REFERENCES log_annotations(id),
    label               TEXT NOT NULL,
    value               TEXT
);

CREATE INDEX IF NOT EXISTS idx_extracted_values_annot   ON extracted_values(log_annotation_id);
CREATE INDEX IF NOT EXISTS idx_extracted_values_label   ON extracted_values(label);
"""


def init_annotation_schema(conn: sqlite3.Connection) -> None:
    with conn:
        conn.executescript(_DDL)


# ── Public entry point ────────────────────────────────────────────────────────

def annotate_database(
    db: Path | str,
    kb: KnowledgeBase,
    *,
    only_ids: set[str] | None = None,
    only_tags: set[str] | None = None,
) -> AnnotateResult:
    """Annotate the analysis database at *db* against *kb* (path-based, primary API).

    Opens the SQLite database at *db* (produced by ``run_extract``), enables
    foreign keys, runs every selected signature, commits, and closes the
    connection. This is the convenient way to (re-)annotate a database **at will**
    — e.g. after improving the knowledge base — without re-extracting.

    For an in-memory database, or when the caller wants to manage the connection
    and transaction itself, use :func:`annotate_connection` instead.

    Args:
        db: Path to a SQLite database created by ``run_extract``.
        kb: A loaded :class:`KnowledgeBase` (see ``load_kb``).
        only_ids: If given, restrict to these signature ids.
        only_tags: If given, restrict to signatures carrying any of these tags.

    Returns:
        An :class:`~forensic_aul.outcomes.AnnotateResult` (with ``db_path`` set).
        The per-signature ``signature_id → match_count`` mapping is on ``.counts``.

    Raises:
        FileNotFoundError: *db* does not exist.
        InvalidDatabaseError: *db* is not an analysis database.
    """
    path = Path(db)
    conn = open_analysis_database(path)
    try:
        # Same forensic pragma as the extract pipeline so FK constraints hold.
        conn.execute("PRAGMA foreign_keys = ON")
        result = annotate_connection(conn, kb, only_ids=only_ids, only_tags=only_tags)
        return replace(result, db_path=path)
    finally:
        conn.close()


def annotate_connection(
    conn: sqlite3.Connection,
    kb: KnowledgeBase,
    *,
    only_ids: set[str] | None = None,
    only_tags: set[str] | None = None,
) -> AnnotateResult:
    """Run every selected signature against ``logs`` on an open connection.

    Lower-level counterpart to :func:`annotate_database`: the caller owns the
    connection (opening, pragmas, and closing). The annotation tables are created
    if absent and the work is committed before returning. Useful for in-memory
    databases or caller-managed transactions.

    Returns an :class:`~forensic_aul.outcomes.AnnotateResult` (``db_path`` is None
    here; ``annotate_database`` fills it in). The per-signature mapping is on
    ``.counts``.
    """
    init_annotation_schema(conn)

    selected = _select_signatures(kb.signatures, only_ids, only_tags)
    log.info(f"Annotating with {len(selected)} signature(s)")

    # Microsecond precision (not seconds): the UNIQUE(signature_id, kb_sha256,
    # applied_at) guard would otherwise reject a rapid identical re-run (the
    # "annotate at will" workflow) within the same wall-clock second.
    applied_at = datetime.now(tz=timezone.utc).isoformat(timespec="microseconds")
    counts: dict[str, int] = {}

    for sig in selected:
        t0 = time.monotonic()
        n = _annotate_one(conn, sig, kb, applied_at)
        counts[sig.id] = n
        log.info(f"  {sig.id:<30}  {n:6} match(es)  ({time.monotonic() - t0:.2f}s)")

    conn.commit()
    refresh_summary_cache(conn)
    return AnnotateResult(
        counts=counts,
        total_matches=sum(counts.values()),
        signatures_run=len(counts),
        signatures_matched=sum(1 for v in counts.values() if v),
    )


def refresh_summary_cache(conn: sqlite3.Connection) -> None:
    """Recompute the cached summary after annotations changed (best-effort).

    Annotating moves ``annotated_count``, ``signature_count``, the per-action
    rollup and the histogram's annotated series, so a summary cached at extract
    time is stale the moment this runs. WHY recompute rather than clear it: the
    connection is already open and the tables are hot, and the alternative —
    leaving the analyst with "not evaluated" after every annotate — would make
    the statistics useless exactly when they became interesting.

    Never raises: statistics are a convenience, and a failure here must not undo
    a successful annotation.
    """
    try:
        summary = summarise_connection(conn, top=DEFAULT_TOP, buckets=DEFAULT_BUCKETS)
        store_summary(conn, summary, top=DEFAULT_TOP, buckets=DEFAULT_BUCKETS)
    except Exception as exc:  # noqa: BLE001 — never fail an annotation over its statistics
        log.warning(f"Could not refresh summary statistics: {exc}")
        clear_summary(conn)


def _select_signatures(
    sigs: tuple[Signature, ...],
    only_ids: set[str] | None,
    only_tags: set[str] | None,
) -> list[Signature]:
    if only_ids is None and only_tags is None:
        return list(sigs)
    out: list[Signature] = []
    for s in sigs:
        if only_ids is not None and s.id in only_ids:
            out.append(s)
            continue
        if only_tags is not None and (set(s.tags) & only_tags):
            out.append(s)
    return out


# ── Per-signature implementation ──────────────────────────────────────────────

def _annotate_one(
    conn: sqlite3.Connection,
    sig: Signature,
    kb: KnowledgeBase,
    applied_at: str,
) -> int:
    """Apply *sig* to logs and write annotations. Returns match count."""
    # ── Resolve indexed lookup ids (one query each, all hits indexed) ────────
    fmt_ids = _resolve_format_str_ids(conn, sig)
    if fmt_ids is _NO_MATCH:
        return 0  # signature references format strings absent from this DB

    proc_id = _resolve_lookup_id(conn, "processes",  sig.match.process)
    subs_id = _resolve_lookup_id(conn, "subsystems", sig.match.subsystem)
    cat_id  = _resolve_lookup_id(conn, "categories", sig.match.category)
    if any(x is _NO_MATCH for x in (proc_id, subs_id, cat_id)):
        return 0

    # ── Build the candidate query ────────────────────────────────────────────
    where: list[str] = []
    params: list = []
    if fmt_ids is not None:
        if len(fmt_ids) == 1:
            where.append("format_str_id = ?")
            params.append(fmt_ids[0])
        else:
            where.append(f"format_str_id IN ({','.join('?' * len(fmt_ids))})")
            params.extend(fmt_ids)
    if proc_id is not None:
        where.append("process_id = ?"); params.append(proc_id)
    if subs_id is not None:
        where.append("subsystem_id = ?"); params.append(subs_id)
    if cat_id is not None:
        where.append("category_id = ?"); params.append(cat_id)
    if sig.match.log_level is not None:
        # log_level is normalised — translate the signature's level name to its
        # log_levels.id once. _NO_MATCH means the DB has no such level → no hits.
        lvl_id = _resolve_lookup_id(conn, "log_levels", sig.match.log_level)
        if lvl_id is _NO_MATCH:
            return 0
        where.append("log_level_id = ?"); params.append(lvl_id)

    # Dynamic signatures with no indexed refinement at all would scan every
    # row — refuse rather than silently melt the disk.
    if not where:
        log.warning(f"Signature {sig.id} has no indexed pre-filter — refusing full-table scan")
        return 0

    sql = f"SELECT id, message FROM logs WHERE {' AND '.join(where)}"
    cur = conn.execute(sql, params)

    # ── Insert kb_signatures row (one per annotate run that produced ≥1 hit) ─
    kb_sig_rowid: int | None = None
    annot_batch: list[tuple[int, int]] = []
    n_match = 0

    msg_re = sig._compiled_message_regex
    # When a signature extracts values we must know each annotation's rowid to
    # attach its extracted_values, so those rows are inserted one at a time;
    # signatures with no extraction keep the fast batched path.
    has_extract = sig._compiled_extract_regex is not None or bool(sig._compiled_extract_fields)

    for log_id, message in cur:
        if msg_re is not None:
            if message is None or not msg_re.search(message):
                continue

        if kb_sig_rowid is None:
            kb_sig_rowid = _insert_kb_signature(conn, sig, kb, applied_at)

        if has_extract:
            annot_id = _insert_annotation(conn, log_id, kb_sig_rowid)
            values = _extract_values(sig, message)
            if values:
                _insert_extracted_values(conn, annot_id, values)
        else:
            annot_batch.append((log_id, kb_sig_rowid))
            if len(annot_batch) >= 1_000:
                _flush_annotations(conn, annot_batch)
                annot_batch.clear()

        n_match += 1

    if annot_batch:
        _flush_annotations(conn, annot_batch)

    if kb_sig_rowid is not None:
        conn.execute(
            "UPDATE kb_signatures SET match_count = ? WHERE id = ?",
            (n_match, kb_sig_rowid),
        )

    return n_match


# ── Lookup helpers ────────────────────────────────────────────────────────────

# Sentinel: signature references a value that doesn't exist in this DB
# (e.g. a format string never produced by the device under analysis).
_NO_MATCH = object()


def _resolve_format_str_ids(conn: sqlite3.Connection, sig: Signature):
    """Return list[int] of format_str_ids, None for dynamic, or _NO_MATCH."""
    if sig.match.dynamic:
        return None  # don't filter on format_str_id

    candidates: list[str] = []
    if sig.match.format_str:
        candidates.append(sig.match.format_str)
    if sig.match.format_str_any:
        candidates.extend(sig.match.format_str_any)

    placeholders = ",".join("?" * len(candidates))
    rows = conn.execute(
        f"SELECT id FROM format_strs WHERE value IN ({placeholders})",
        candidates,
    ).fetchall()
    if not rows:
        return _NO_MATCH
    return [r[0] for r in rows]


def _resolve_lookup_id(conn: sqlite3.Connection, table: str, name: str | None):
    """None → no constraint; _NO_MATCH → name absent from DB; else the int id."""
    if name is None:
        return None
    row = conn.execute(f"SELECT id FROM {table} WHERE name = ?", (name,)).fetchone()
    if row is None:
        return _NO_MATCH
    return row[0]


# ── Insert helpers ────────────────────────────────────────────────────────────

def _insert_kb_signature(
    conn: sqlite3.Connection,
    sig: Signature,
    kb: KnowledgeBase,
    applied_at: str,
) -> int:
    cur = conn.execute(
        """
        INSERT INTO kb_signatures
            (signature_id, action, description, confidence, tags,
             source_file, kb_version, kb_sha256, applied_at, match_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
        """,
        (
            sig.id, sig.action, sig.description, sig.confidence,
            json.dumps(list(sig.tags)),
            sig.source_file, kb.version, kb.sha256, applied_at,
        ),
    )
    rid = cur.lastrowid
    if rid is None:
        raise RuntimeError("kb_signatures insert returned no rowid")
    return rid


def _flush_annotations(
    conn: sqlite3.Connection,
    batch: list[tuple[int, int]],
) -> None:
    conn.executemany(
        "INSERT INTO log_annotations (log_id, kb_signature_id) VALUES (?, ?)",
        batch,
    )


def _insert_annotation(conn: sqlite3.Connection, log_id: int, kb_signature_id: int) -> int:
    cur = conn.execute(
        "INSERT INTO log_annotations (log_id, kb_signature_id) VALUES (?, ?)",
        (log_id, kb_signature_id),
    )
    rid = cur.lastrowid
    if rid is None:
        raise RuntimeError("log_annotations insert returned no rowid")
    return rid


def _insert_extracted_values(
    conn: sqlite3.Connection,
    annotation_id: int,
    values: list[tuple[str, str]],
) -> None:
    conn.executemany(
        "INSERT INTO extracted_values (log_annotation_id, label, value) VALUES (?, ?, ?)",
        [(annotation_id, label, value) for label, value in values],
    )


def _extract_values(sig: Signature, message: str | None) -> list[tuple[str, str]]:
    """Return (label, value) pairs from a signature's extract_regex + extract_fields.

    Named groups of ``extract_regex`` and each ``extract_fields`` entry that match
    contribute a pair; groups/regexes that don't match (value is None) are omitted
    rather than stored as empty rows. Order: extract_regex groups, then fields.
    """
    out: list[tuple[str, str]] = []
    target = message or ""

    if sig._compiled_extract_regex is not None:
        m = sig._compiled_extract_regex.search(target)
        if m is not None:
            for label, value in m.groupdict().items():
                if value is not None:
                    out.append((label, value))

    for name, pat in sig._compiled_extract_fields:
        m = pat.search(target)
        if m is None:
            continue
        # Prefer the named group matching the field name, else group 1, else all.
        if name in m.groupdict():
            value = m.group(name)
        elif m.groups():
            value = m.group(1)
        else:
            value = m.group(0)
        if value is not None:
            out.append((name, value))

    return out
