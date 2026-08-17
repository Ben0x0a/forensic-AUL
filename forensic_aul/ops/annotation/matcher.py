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
from typing import Any

from forensic_aul.engine.database.access import open_analysis_database
from forensic_aul.ops.knowledge_base.models import KnowledgeBase, Signature
from forensic_aul.ops.summary.cache import refresh_summary
from forensic_aul.outcomes import AnnotateResult

log = logging.getLogger(__name__)


# ── Schema for annotation tables ──────────────────────────────────────────────

_DDL = """
-- The signature AS APPLIED, not merely a reference to one. WHY the whole rule
-- and not just its id: an annotated database is the artefact an analyst reports
-- from, and "why is this line flagged?" must be answerable from the database
-- alone — after the knowledge base has moved on, or on a machine that never had
-- it. Every column below is a copy taken at annotate time; the KB's own version
-- + digest identify which knowledge base it was copied from.
CREATE TABLE IF NOT EXISTS kb_signatures (
    id                  INTEGER PRIMARY KEY,
    signature_id        TEXT NOT NULL,        -- e.g. "sb.app_foreground"
    action              TEXT NOT NULL,
    description         TEXT,
    interpretation      TEXT,                 -- what one may conclude
    caveats             TEXT,                 -- when that conclusion does not hold
    confidence          TEXT,
    tags                TEXT,                 -- JSON list
    references_json     TEXT,                 -- JSON list of sources/evidence
    platform            TEXT,
    ios_min             TEXT,
    ios_max             TEXT,
    match_json          TEXT,                 -- JSON of the match rule that fired
    extract_json        TEXT,                 -- JSON of the extraction spec
    author              TEXT,
    created             TEXT,                 -- ISO date the rule was written
    sig_version         TEXT,                 -- per-signature semver
    status              TEXT,                 -- draft | validated | deprecated
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
    # Version gating: a signature declaring ios_min/ios_max/platform is a claim
    # about which OS it was reverse-engineered against, and applying it outside
    # that range would attach a conclusion the author never supported.
    case = _case_platform(conn)
    selected, skipped = _apply_version_gates(selected, case)
    if skipped:
        log.info(
            f"Skipped {len(skipped)} signature(s) not applicable to "
            f"{case[0]} {case[1] or '(unknown version)'}: {', '.join(skipped)}"
        )
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
    refresh_summary(conn)
    return AnnotateResult(
        counts=counts,
        total_matches=sum(counts.values()),
        signatures_run=len(counts),
        signatures_matched=sum(1 for v in counts.values() if v),
    )


def clear_annotations(db: Path | str | sqlite3.Connection) -> int:
    """Remove every annotation from *db*; return how many were removed.

    Deletes ``extracted_values`` → ``log_annotations`` → ``kb_signatures`` in
    foreign-key order, then refreshes the cached statistics so the counts an
    analyst sees match the database again.

    WHY this exists: ``annotate`` is append-only by design (running two KB
    versions side by side is a legitimate comparison), which means re-running it
    over the same database silently duplicates every annotation and inflates the
    statistics and exports. Removing first is the way to genuinely re-annotate,
    and it is a deliberate act rather than a hidden side effect of the second run.

    Returns 0 when the database has never been annotated (no tables to clear).
    """
    if isinstance(db, sqlite3.Connection):
        return _clear_annotations(db)
    conn = open_analysis_database(db)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        return _clear_annotations(conn)
    finally:
        conn.close()


def _clear_annotations(conn: sqlite3.Connection) -> int:
    if not _has_annotation_tables(conn):
        return 0
    removed = conn.execute("SELECT COUNT(*) FROM log_annotations").fetchone()[0]
    with conn:
        # FK order: values reference annotations, annotations reference signatures.
        conn.execute("DELETE FROM extracted_values")
        conn.execute("DELETE FROM log_annotations")
        conn.execute("DELETE FROM kb_signatures")
    refresh_summary(conn)
    log.info(f"Removed {removed} annotation(s)")
    return removed


def _has_annotation_tables(conn: sqlite3.Connection) -> bool:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name IN ('log_annotations', 'kb_signatures', 'extracted_values')"
    ).fetchall()
    return len(rows) == 3


def annotation_state(db: Path | str | sqlite3.Connection) -> dict[str, Any]:
    """Describe the annotations already on *db*, for a UI to decide what to offer.

    Returns ``{"annotated": int, "signatures": int, "kb_versions": [...],
    "applied_at": [...]}``. All zero/empty when the database has never been
    annotated. Read-only.
    """
    if isinstance(db, sqlite3.Connection):
        return _annotation_state(db)
    conn = open_analysis_database(db)
    try:
        return _annotation_state(conn)
    finally:
        conn.close()


def no_annotations() -> dict[str, Any]:
    """The :func:`annotation_state` shape for a never-annotated database.

    Exposed so a caller that cannot reach the database (a closed store, an
    unreadable file) can show the same "not annotated" state without inventing
    a second copy of this dict.
    """
    return {"annotated": 0, "signatures": 0, "kb_versions": [], "applied_at": []}


def _annotation_state(conn: sqlite3.Connection) -> dict[str, Any]:
    if not _has_annotation_tables(conn):
        return no_annotations()
    return {
        "annotated": conn.execute(
            "SELECT COUNT(DISTINCT log_id) FROM log_annotations").fetchone()[0],
        "signatures": conn.execute(
            "SELECT COUNT(*) FROM kb_signatures").fetchone()[0],
        "kb_versions": [r[0] for r in conn.execute(
            "SELECT DISTINCT kb_version FROM kb_signatures ORDER BY kb_version")],
        "applied_at": [r[0] for r in conn.execute(
            "SELECT DISTINCT applied_at FROM kb_signatures ORDER BY applied_at")],
    }


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


# ── Applicability gating (platform + iOS version range) ───────────────────────

def _case_platform(conn: sqlite3.Connection) -> tuple[str, str | None]:
    """Return ``(platform, ios_version)`` for the database under annotation.

    The platform is "ios" for every database this tool currently produces; the
    version comes from ``case_metadata.ios_version``, which extract fills from
    SystemVersion.plist when the source carried one. ``None`` when unknown.
    """
    try:
        row = conn.execute(
            "SELECT ios_version FROM case_metadata ORDER BY id DESC LIMIT 1"
        ).fetchone()
    except sqlite3.DatabaseError:
        return ("ios", None)
    return ("ios", (row[0] if row else None) or None)


def _apply_version_gates(
    sigs: list[Signature], case: tuple[str, str | None]
) -> tuple[list[Signature], list[str]]:
    """Split *sigs* into (applicable, skipped-ids) for this case.

    WHY an unknown case version applies EVERY signature rather than none: the
    version is often genuinely absent (a bare .logarchive carries no
    SystemVersion.plist), and silently withholding annotations there would be a
    far worse failure than showing one that may not apply — the analyst can see
    a signature's declared range, but cannot see annotations that never appeared.
    """
    platform, version = case
    keep: list[Signature] = []
    skipped: list[str] = []
    for sig in sigs:
        if sig.platform and sig.platform.lower() != platform:
            skipped.append(sig.id)
            continue
        if version is not None and not _version_in_range(version, sig.ios_min, sig.ios_max):
            skipped.append(sig.id)
            continue
        keep.append(sig)
    return keep, skipped


def _version_in_range(version: str, low: str | None, high: str | None) -> bool:
    """True when *version* falls within [*low*, *high*] (either bound optional).

    An unparseable version on either side is treated as "no constraint": a
    malformed bound in the knowledge base must not silently suppress a signature.
    """
    parsed = _version_tuple(version)
    if parsed is None:
        return True
    if low is not None:
        low_parsed = _version_tuple(low)
        if low_parsed is not None and parsed < low_parsed:
            return False
    if high is not None:
        high_parsed = _version_tuple(high)
        if high_parsed is not None and parsed > high_parsed:
            return False
    return True


def _version_tuple(value: str) -> tuple[int, ...] | None:
    """Parse a dotted version ("17.5.1") into a comparable tuple, or None."""
    parts = value.strip().split(".")
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        return None


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
    if sig.match.event_type is not None:
        # Same normalised-lookup shape as log_level; also a non-indexed residual
        # refinement, applied on the already-narrowed candidate set.
        et_id = _resolve_lookup_id(conn, "event_types", sig.match.event_type)
        if et_id is _NO_MATCH:
            return 0
        where.append("event_type_id = ?"); params.append(et_id)
    if sig.match.library is not None:
        # WHY every matching id and not one: `libraries` is UNIQUE(name, uuid), so
        # the same path legitimately recurs under several UUIDs (one per build of
        # the binary). Resolving to a single id would silently match only one of
        # them and under-report.
        lib_ids = _resolve_lookup_ids(conn, "libraries", sig.match.library)
        if lib_ids is _NO_MATCH:
            return 0
        where.append(f"library_id IN ({','.join('?' * len(lib_ids))})")
        params.extend(lib_ids)

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

def _resolve_lookup_ids(conn: sqlite3.Connection, table: str, name: str):
    """Return every id in *table* whose ``name`` is *name*, or :data:`_NO_MATCH`.

    The multi-valued counterpart of :func:`_resolve_lookup_id`, for lookup tables
    whose name is not unique on its own (see the `libraries` note at the call site).
    """
    rows = conn.execute(f"SELECT id FROM {table} WHERE name = ?", (name,)).fetchall()
    return [r[0] for r in rows] if rows else _NO_MATCH


def _insert_kb_signature(
    conn: sqlite3.Connection,
    sig: Signature,
    kb: KnowledgeBase,
    applied_at: str,
) -> int:
    cur = conn.execute(
        """
        INSERT INTO kb_signatures
            (signature_id, action, description, interpretation, caveats,
             confidence, tags, references_json, platform, ios_min, ios_max,
             match_json, extract_json, author, created, sig_version, status,
             source_file, kb_version, kb_sha256, applied_at, match_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
        """,
        (
            sig.id, sig.action, sig.description, sig.interpretation, sig.caveats,
            sig.confidence, json.dumps(list(sig.tags)),
            json.dumps(list(sig.references)), sig.platform, sig.ios_min, sig.ios_max,
            json.dumps(_match_to_dict(sig.match)), json.dumps(_extract_to_dict(sig)),
            sig.author, sig.created, sig.version, sig.status,
            sig.source_file, kb.version, kb.sha256, applied_at,
        ),
    )
    rid = cur.lastrowid
    if rid is None:
        raise RuntimeError("kb_signatures insert returned no rowid")
    return rid


def _match_to_dict(match: Any) -> dict[str, Any]:
    """The match rule as a plain dict, omitting the fields it does not set.

    Stored per applied signature so a reader can see exactly which constraints
    selected a line, without needing the YAML the rule came from.
    """
    return {
        name: value
        for name, value in (
            ("format_str", match.format_str),
            ("format_str_any", list(match.format_str_any) if match.format_str_any else None),
            ("dynamic", match.dynamic or None),
            ("process", match.process),
            ("subsystem", match.subsystem),
            ("category", match.category),
            ("log_level", match.log_level),
            ("event_type", match.event_type),
            ("library", match.library),
            ("message_regex", match.message_regex),
        )
        if value is not None
    }


def _extract_to_dict(sig: Signature) -> dict[str, Any]:
    """The extraction spec as a plain dict (empty when the signature extracts nothing)."""
    out: dict[str, Any] = {}
    if sig.extract_regex:
        out["extract_regex"] = sig.extract_regex
    if sig.extract_fields:
        out["extract_fields"] = dict(sig.extract_fields)
    return out


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
