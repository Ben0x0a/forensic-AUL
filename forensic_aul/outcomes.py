"""Return-value containers for the top-level operations.

Defines : the result dataclasses returned by the library's main entry points —
          ``ExtractResult`` (run_extract), ``DiffResult`` (run_diff) and
          ``ExportResult`` (run_export). They bundle the output path(s) with the
          facts a caller would otherwise have to re-query, so calls chain cleanly:

              res = run_extract(src, "case.db", CaseInfo(case_number="C1"))
              annotate_database(res.db_path, kb)      # reuse the path, no re-query

Used by : forensic_aul.ops.extraction.extract, forensic_aul.ops.identify.diff,
          forensic_aul.ops.export.exporter (construct them); re-exported from
          forensic_aul/__init__.py; consumed by callers and the launcher.
Uses    : the standard library only.

These are immutable data carriers kept in their own module so the orchestration
code can import them without a cycle. The one piece of behaviour is
``ExtractResult.status`` (``ExtractStatus``): a pure verdict computed from the
result's own counters, so it can never disagree with them.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Type-only import of a leaf data module (no runtime dependency at all).
    from forensic_aul.device_info import DeviceInfo


class ExtractStatus(str, Enum):
    """The verdict on one extract.

    * ``OK`` — every chunkset decoded, no error.
    * ``DEGRADED`` — usable, but something was lost or is suspect (parse or write
      errors, undecodable chunksets, a source file changed, an empty source). Read
      ``ExtractResult.status_reasons``.
    * ``FAILED`` — nothing could be decoded: the tool does not understand this
      source (e.g. an OS release whose format changed). Do not analyse it.
    """

    OK = "ok"
    DEGRADED = "degraded"
    FAILED = "failed"


@dataclass(frozen=True)
class ExtractResult:
    """Outcome of ``run_extract`` — the database path plus what was produced."""

    db_path: Path                       # the SQLite database that was written
    metadata_id: int                    # case_metadata row id (for sealing the log hash)
    entry_count: int                    # total log rows written
    parse_errors: int                   # non-fatal parse errors encountered
    # Log rows the database refused to store even one-by-one (normally 0). Each was
    # logged with its source provenance; a non-zero value means the store is
    # knowingly incomplete (never silently) — investigate the ERROR log lines.
    write_errors: int
    source_type: str                    # "logarchive" / "sysdiagnose" / "filesystem"
    # Content fingerprint of the parsed material; None when the extract ran with
    # integrity="fingerprint"/"off" (no chain-of-custody hashing taken).
    source_sha256: str | None
    device_model: str | None = None     # hardware model from the tracev3 header
    ios_build: str | None = None        # build code, e.g. "21F90"
    ios_version: str | None = None       # marketing version, e.g. "17.5.1" (None if unresolved)
    boot_uuid: str | None = None        # first boot UUID seen
    # (first_iso, last_iso) of the log time range; either side may be None on an empty DB.
    time_range: tuple[str | None, str | None] = (None, None)
    # Per-file integrity (end-of-run re-hash vs the registration "before" hash):
    # how many source files were unchanged / changed / could not be verified. A
    # non-zero `source_files_changed` means some parsed data is suspect — inspect
    # `source_files.integrity_ok = 0`; the other files remain usable.
    source_files_verified: int = 0
    source_files_changed: int = 0
    source_files_unverifiable: int = 0
    # The sealed audit log (ExtractOptions(audit_log=True) only): its path and the
    # SHA-256 also stored in case_metadata. None when no audit log was written.
    log_path: Path | None = None
    log_sha256: str | None = None
    # Decodability: chunksets in the source vs chunksets decompressed and walked,
    # and the files of which not one chunkset could be decoded. They feed `status`.
    chunksets: int = 0
    chunksets_decoded: int = 0
    undecodable_files: tuple[str, ...] = ()

    @property
    def status(self) -> ExtractStatus:
        """``OK`` / ``DEGRADED`` / ``FAILED`` — see :class:`ExtractStatus`."""
        return _assess(self)[0]

    @property
    def status_reasons(self) -> tuple[str, ...]:
        """Why the status is not ``OK`` (empty when it is), in plain words."""
        return _assess(self)[1]


def _assess(r: ExtractResult) -> tuple[ExtractStatus, tuple[str, ...]]:
    """The one status policy. Computed from the result's own counters, so the
    verdict can never disagree with the numbers it is drawn from."""
    if r.chunksets and not r.chunksets_decoded:
        return ExtractStatus.FAILED, (
            f"none of the {r.chunksets} chunkset(s) could be decoded — "
            "this source's format is not supported",)
    if r.chunksets and not r.entry_count:
        return ExtractStatus.FAILED, (
            f"{r.chunksets_decoded} chunkset(s) decoded but no log entry produced",)
    reasons: list[str] = []
    if not r.chunksets:
        reasons.append("the source holds no log data")
    if r.chunksets_decoded < r.chunksets:
        reasons.append(f"{r.chunksets - r.chunksets_decoded} of {r.chunksets} chunksets "
                       f"could not be decoded ({len(r.undecodable_files)} file(s) entirely)")
    if r.parse_errors:
        reasons.append(f"{r.parse_errors} parse error(s)")
    if r.write_errors:
        reasons.append(f"{r.write_errors} row(s) refused by the database")
    if r.source_files_changed:
        reasons.append(f"{r.source_files_changed} source file(s) changed during the run")
    return (ExtractStatus.DEGRADED if reasons else ExtractStatus.OK), tuple(reasons)


@dataclass(frozen=True)
class AnnotateResult:
    """Outcome of ``annotate_database`` / ``annotate_connection``.

    Wraps the per-signature match counts with handy totals so callers don't have
    to re-derive them. ``counts`` is the same ``signature_id → match_count``
    mapping the operation used to return.
    """

    counts: dict[str, int]              # signature_id → match_count (every signature run)
    total_matches: int                  # sum of all match counts
    signatures_run: int                 # number of signatures evaluated
    signatures_matched: int             # number of signatures with ≥1 match
    # The annotated database (set by the path-based annotate_database; None when
    # called via annotate_connection on a caller-owned connection).
    db_path: Path | None = None


@dataclass(frozen=True)
class AcquireResult:
    """Outcome of ``acquire`` — the collected logarchive plus provenance.

    Bundles the collected ``.logarchive`` path with its hash, the device metadata
    read from the device and the traceability report path, so a caller can chain
    straight into ``run_extract(result.logarchive_path, …)``.
    """

    logarchive_path: Path               # the written .faul container (logarchive + sidecar)
    logarchive_sha256: str              # content fingerprint ("" if hashing failed)
    file_count: int                     # number of files hashed inside it
    device: "DeviceInfo"                # metadata read from the device (IMEI, serial, …)
    report_path: Path | None = None     # legacy loose .acquisition.json; None when embedded in the .faul


@dataclass(frozen=True)
class DiffResult:
    """Outcome of ``run_diff`` — the two output paths plus the row counts."""

    # None when run_diff was called with csv_out=None (SQLite-only run) — the
    # retained/excluded counts are still computed identically either way.
    csv_path: Path | None
    sqlite_path: Path                   # all post-cutoff rows with an ``excluded`` flag
    retained: int                       # rows written to the CSV
    excluded: int                       # rows flagged as baseline noise
    # The retained rows by tier (see ops/identify/diff.py): templates the
    # baseline never produced, and known templates with new values.
    new_templates: int = 0
    new_values: int = 0


@dataclass(frozen=True)
class IdentifyResult:
    """Outcome of ``run_identify_workflow`` — the four artefacts plus the diff.

    ``diff`` nests the :class:`DiffResult` (CSV / flagged-SQLite paths and the
    retained / excluded row counts) so callers get the whole chain in one value.
    """

    baseline_archive: Path              # acquisition #1 (pre-action logarchive)
    action_archive: Path                # acquisition #2 (post-action logarchive)
    baseline_db: Path                   # extract of the baseline archive
    action_db: Path                     # extract of the post-action archive
    diff: DiffResult                    # the attribution outputs
    # What the operator said the action was (may be empty).
    action_description: str = ""
    # Conditions that may have put noise in the diff (e.g. a lock-state change).
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExportResult:
    """Outcome of ``run_export`` — the output path, row count and format."""

    output_path: Path                   # the file that was written
    rows: int                           # number of rows emitted
    fmt: str                            # "csv" / "json" / "jsonl"
