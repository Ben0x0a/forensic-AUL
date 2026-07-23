"""Filtered export of an analysis database to CSV / JSON / JSONL.

Defines : the export logic — ``run_export`` plus the ``ExportFilters`` container
          that decouples it from any CLI argument parser, and the format-writer
          registry (``export_formats``). Row filtering/streaming is delegated to
          the shared read layer (``ops/query/reader.py``) so a filter behaves
          identically in ``run_export`` and ``query_logs``. Knowledge-base
          aware: when annotations exist on the rows being exported, every
          extracted value label (from the ``extracted_values`` table) becomes
          its own column (CSV) or a key in the per-row ``extracted_values``
          object (JSON).
Used by : launcher/cmds/export_cmd.py (argparse glue → ``run_export``) and any
          external caller importing ``forensic_aul.ops.export``.
Uses    : forensic_aul.ops.query.reader (filters → streamed LogRow) and the
          standard library (sqlite3, csv, json).

Adding an output format = write one ``_write_<fmt>`` function with the shared
writer signature and register it in ``_WRITERS`` — format inference and the CLI
``--format`` choices derive from the registry.

A row is emitted once per matching log entry; multiple annotations / extracted
values on the same log are merged into that one row (distinct values for the same
label are joined with "; ").

Errors are raised (``ValueError`` / ``FileNotFoundError``) rather than turned into
exit codes — the CLI wrapper maps them to process exit status and user messages.
"""

from __future__ import annotations

import csv
import json
import logging
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

from forensic_aul.engine.database.access import open_analysis_database
from forensic_aul.outcomes import ExportResult
from forensic_aul.ops.query.reader import (
    LogFilters,
    LogRow,
    build_where,
    discover_labels,
    has_kb_tables,
    iter_logs,
    resolve_time_bounds,
)

log = logging.getLogger(__name__)


# ── Filters / output options ──────────────────────────────────────────────────

@dataclass
class ExportFilters(LogFilters):
    """Filters and output options for :func:`run_export`.

    Extends the shared :class:`~forensic_aul.ops.query.reader.LogFilters`
    vocabulary with the two export-only knobs (output format, extracted-field
    emission). Mirrors the CLI flags but is independent of argparse so the
    export logic can be driven programmatically (GUI, scripts, tests) as well
    as from the CLI.
    """

    fmt: str | None = None              # a key of _WRITERS; None → infer from output suffix
    include_fields: bool = True         # emit extracted_fields columns/objects


# ── Public entry point ────────────────────────────────────────────────────────

def run_export(
    database: Path,
    output: Path,
    filters: ExportFilters | None = None,
) -> ExportResult:
    """Export rows from *database* to *output*.

    *database* is a SQLite store produced by ``run_extract`` (and optionally
    annotated by ``annotate_database``). The output format is taken from
    ``filters.fmt`` or inferred from *output*'s suffix.

    Returns:
        An :class:`~forensic_aul.outcomes.ExportResult` with the ``output_path``,
        the number of ``rows`` written, and the resolved ``fmt``.

    Raises:
        FileNotFoundError: *database* does not exist.
        InvalidDatabaseError: *database* is not an analysis database.
        ValueError: the format cannot be determined, a filter value is malformed,
            or a knowledge-base filter is requested on a database with no
            annotations.
    """
    f = filters or ExportFilters()

    fmt = f.fmt or _infer_format(output)
    if fmt is None:
        raise ValueError(f"cannot infer format from {output.name}; set ExportFilters.fmt")
    if fmt not in _WRITERS:
        raise ValueError(f"unknown export format {fmt!r}; expected one of {export_formats()}")

    time_from_ns, time_to_ns = resolve_time_bounds(f)

    conn = open_analysis_database(database)
    try:
        rows = _run(conn, output, f, fmt, time_from_ns, time_to_ns)
    finally:
        conn.close()
    return ExportResult(output_path=output, rows=rows, fmt=fmt)


def _run(
    conn: sqlite3.Connection,
    output: Path,
    f: ExportFilters,
    fmt: str,
    time_from_ns: int | None,
    time_to_ns: int | None,
) -> int:
    has_kb = has_kb_tables(conn)

    # Annotation-based filters require the KB tables to exist.
    if not has_kb and (f.signature or f.action or f.tag or f.annotated_only):
        raise ValueError("this database has no KB annotations — run `annotate` first")

    where, params = build_where(conn, f, time_from_ns, time_to_ns)

    # Discover the universe of extracted labels (only relevant when include_fields).
    include_fields = f.include_fields and has_kb
    labels: list[str] = []
    if include_fields:
        labels = discover_labels(conn, where, params)
        log.info(f"Export will emit {len(labels)} extracted-value column(s)")

    output.parent.mkdir(parents=True, exist_ok=True)

    rows = iter_logs(conn, where, params, has_kb=has_kb)
    return _WRITERS[fmt].write(output, rows, labels, include_fields)


# ── Canonical record shape ────────────────────────────────────────────────────

# Single source of truth for the exported columns: every writer derives both its
# header/keys and its values from this ordered mapping, so a new column is added
# in exactly one place. ``event_order`` is the forensic ordering rank (monotonic
# with physical layout); it is emitted so the tamper signal — wall-clock going
# backwards while event_order keeps rising — is visible in the primary analyst
# output.
_BASE_FIELDS: dict[str, Callable[[LogRow], object]] = {
    "timestamp": lambda r: r.timestamp_iso,
    "timestamp_unix_ns": lambda r: r.timestamp_unix_ns,
    "event_order": lambda r: r.event_order,
    "process": lambda r: r.process,
    "pid": lambda r: r.pid,
    "tid": lambda r: r.tid,
    "log_level": lambda r: r.log_level,
    "event_type": lambda r: r.event_type,
    "subsystem": lambda r: r.subsystem,
    "category": lambda r: r.category,
    "message": lambda r: r.message,
    "matched_signatures": lambda r: list(r.signature_ids),
}


# ── CSV writer ────────────────────────────────────────────────────────────────

def _write_csv(
    out: Path,
    rows: Iterator[LogRow],
    labels: list[str],
    include_fields: bool,
) -> int:
    extra_cols = list(labels) if include_fields else []
    header = list(_BASE_FIELDS) + extra_cols

    n = 0
    with out.open("w", newline="", encoding="utf-8-sig") as fp:  # BOM so Excel auto-detects UTF-8
        w = csv.writer(fp)
        w.writerow(header)
        for log_row in rows:
            row = [
                # A list-valued field (matched_signatures) flattens to one cell.
                ",".join(v) if isinstance(v := get(log_row), list) else v
                for get in _BASE_FIELDS.values()
            ]
            if include_fields:
                for label in extra_cols:
                    row.append(log_row.value_for(label))
            w.writerow(row)
            n += 1
    return n


# ── JSON / JSONL writers ──────────────────────────────────────────────────────

def _write_json(
    out: Path,
    rows: Iterator[LogRow],
    labels: list[str],
    include_fields: bool,
    *,
    jsonl: bool = False,
) -> int:
    n = 0
    with out.open("w", encoding="utf-8") as fp:
        if not jsonl:
            fp.write("[")
        first = True
        for log_row in rows:
            obj = {name: get(log_row) for name, get in _BASE_FIELDS.items()}
            if include_fields:
                obj["extracted_values"] = log_row.values_dict()
            line = json.dumps(obj, ensure_ascii=False)
            if jsonl:
                fp.write(line); fp.write("\n")
            else:
                if not first:
                    fp.write(",\n  ")
                else:
                    fp.write("\n  ")
                    first = False
                fp.write(line)
            n += 1
        if not jsonl:
            fp.write("\n]\n")
    return n


def _write_jsonl(
    out: Path,
    rows: Iterator[LogRow],
    labels: list[str],
    include_fields: bool,
) -> int:
    return _write_json(out, rows, labels, include_fields, jsonl=True)


# ── Format registry ───────────────────────────────────────────────────────────

@dataclass(frozen=True)
class _Writer:
    """One registered output format: the writer callable + its file suffixes."""

    write: Callable[[Path, Iterator[LogRow], list[str], bool], int]
    suffixes: tuple[str, ...]


# To add a format (e.g. parquet): implement a writer with the shared signature
# above and register it here — suffix inference and the CLI choices follow.
_WRITERS: dict[str, _Writer] = {
    "csv": _Writer(_write_csv, (".csv",)),
    "json": _Writer(_write_json, (".json",)),
    "jsonl": _Writer(_write_jsonl, (".jsonl",)),
}


def export_formats() -> tuple[str, ...]:
    """The registered format names (the valid values of ``ExportFilters.fmt``)."""
    return tuple(_WRITERS)


def _infer_format(path: Path) -> str | None:
    suf = path.suffix.lower()
    for fmt, writer in _WRITERS.items():
        if suf in writer.suffixes:
            return fmt
    return None
