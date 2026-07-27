"""Re-verify the chain of custody of an extracted database.

Defines : the *logic* behind the ``verify`` command — ``verify_database``
          re-hashes the logarchive (global + per-file) and the operational log
          file, compares each digest against the value stored at extract time,
          and returns a structured :class:`VerifyResult`. No printing lives here;
          the CLI handler and the GUI render the result.
Used by : launcher/cmds/verify_hash_cmd.py, forensic_aul.__init__ (public API).
Uses    : forensic_aul.engine.integrity (hash_logarchive, compute_sha256).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from forensic_aul.engine.database.access import open_analysis_database
from forensic_aul.engine.integrity import compute_sha256, hash_logarchive


@dataclass(frozen=True)
class Check:
    """One pass/fail/skip verification step."""

    label: str
    status: str            # "ok" | "fail" | "skip"
    detail: str = ""       # human note (reason for skip, error, …)
    stored: str | None = None
    actual: str | None = None


@dataclass(frozen=True)
class FileMismatch:
    path: str
    stored: str
    actual: str


@dataclass
class PerFileResult:
    total: int
    matched: int
    missing_hash: int      # source_files row with no stored sha256 (not counted)
    missing_file: int      # stored hash but file absent on disk (counts as fail)
    mismatches: list[FileMismatch] = field(default_factory=list)


@dataclass
class VerifyResult:
    database: Path
    case_number: str | None
    imei: str | None
    checks: list[Check] = field(default_factory=list)
    per_file: PerFileResult | None = None

    @property
    def passed(self) -> int:
        n = sum(1 for c in self.checks if c.status == "ok")
        if self.per_file is not None:
            n += self.per_file.matched
        return n

    @property
    def failed(self) -> int:
        n = sum(1 for c in self.checks if c.status == "fail")
        if self.per_file is not None:
            n += len(self.per_file.mismatches) + self.per_file.missing_file
        return n

    @property
    def ok(self) -> bool:
        return self.failed == 0


def verify_database(
    database: Path | str,
    *,
    logarchive: Path | None = None,
    log_file: Path | None = None,
    skip_files: bool = False,
) -> VerifyResult:
    """Re-verify *database* against its stored hashes; return a VerifyResult.

    *logarchive* / *log_file* override the paths stored in ``case_metadata``.

    Raises:
        FileNotFoundError: *database* does not exist.
        InvalidDatabaseError: *database* is not an analysis database.
        ValueError: ``case_metadata`` is empty (not an extract DB).
    """
    db_path = Path(database)
    conn = open_analysis_database(db_path)
    try:
        row = conn.execute("""
            SELECT case_number, imei,
                   logarchive_path, logarchive_sha256,
                   log_file_path, log_file_sha256
            FROM case_metadata ORDER BY id DESC LIMIT 1
        """).fetchone()
        if row is None:
            raise ValueError("case_metadata is empty — not an extract database?")
        (case_number, imei,
         logarchive_path, logarchive_sha256,
         log_file_path, log_file_sha256) = row

        result = VerifyResult(database=db_path, case_number=case_number, imei=imei)

        _verify_logarchive(
            result, conn, logarchive, logarchive_path, logarchive_sha256, skip_files,
        )
        _verify_log_file(result, log_file, log_file_path, log_file_sha256)
        return result
    finally:
        conn.close()


def _verify_logarchive(
    result: VerifyResult,
    conn: sqlite3.Connection,
    override: Path | None,
    stored_path: str | None,
    stored_sha: str | None,
    skip_files: bool,
) -> None:
    archive = override or (Path(stored_path) if stored_path else None)

    if archive is None:
        result.checks.append(Check(
            "logarchive hash", "fail",
            "no path stored and no override given"))
        return
    if not archive.is_dir():
        result.checks.append(Check(
            "logarchive hash", "fail", f"directory missing: {archive}"))
        return

    try:
        global_sha, file_hashes = hash_logarchive(archive)
    except Exception as exc:  # noqa: BLE001 — surfaced as a failed check
        result.checks.append(Check("logarchive hash", "fail", f"could not hash: {exc}"))
        return

    if not stored_sha:
        result.checks.append(Check(
            "logarchive global SHA-256", "skip", "none stored in case_metadata"))
    elif global_sha == stored_sha:
        result.checks.append(Check(
            "logarchive global SHA-256", "ok", stored=stored_sha, actual=global_sha))
    else:
        result.checks.append(Check(
            "logarchive global SHA-256", "fail", "mismatch",
            stored=stored_sha, actual=global_sha))

    if not skip_files:
        result.per_file = _verify_per_file(conn, file_hashes)


def _verify_per_file(
    conn: sqlite3.Connection,
    fresh_hashes: dict[str, str],
) -> PerFileResult:
    rows = conn.execute(
        "SELECT file_path, sha256 FROM source_files ORDER BY file_path").fetchall()
    pf = PerFileResult(total=len(rows), matched=0, missing_hash=0, missing_file=0)
    for rel, stored in rows:
        if not stored:
            pf.missing_hash += 1
            continue
        actual = fresh_hashes.get(rel)
        if actual is None:
            pf.missing_file += 1
        elif actual == stored:
            pf.matched += 1
        else:
            pf.mismatches.append(FileMismatch(rel, stored, actual))
    return pf


def _verify_log_file(
    result: VerifyResult,
    override: Path | None,
    stored_path: str | None,
    stored_sha: str | None,
) -> None:
    log_path = override or (Path(stored_path) if stored_path else None)

    if log_path is None:
        result.checks.append(Check("log-file hash", "skip", "no path stored / no override"))
    elif not log_path.is_file():
        result.checks.append(Check("log-file hash", "fail", f"file missing: {log_path}"))
    elif not stored_sha:
        result.checks.append(Check("log-file hash", "skip", "none stored in case_metadata"))
    else:
        actual = compute_sha256(log_path)
        if actual == stored_sha:
            result.checks.append(Check("log-file SHA-256", "ok", stored=stored_sha, actual=actual))
        else:
            result.checks.append(Check(
                "log-file SHA-256", "fail", "mismatch", stored=stored_sha, actual=actual))
