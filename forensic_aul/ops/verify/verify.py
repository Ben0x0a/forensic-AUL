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
        IncompleteDatabaseError: the extract that produced it never completed —
            re-run it rather than attesting a half-written store.
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

    global_matches = bool(stored_sha) and global_sha == stored_sha

    if not skip_files:
        result.per_file = _verify_per_file(conn, file_hashes)

    if not stored_sha:
        result.checks.append(Check(
            "logarchive global SHA-256", "skip", "none stored in case_metadata"))
    elif global_matches:
        result.checks.append(Check(
            "logarchive global SHA-256", "ok", stored=stored_sha, actual=global_sha))
    else:
        result.checks.append(Check(
            "logarchive global SHA-256", "fail", _global_mismatch_reason(result.per_file),
            stored=stored_sha, actual=global_sha))


def _global_mismatch_reason(per_file: PerFileResult | None) -> str:
    """Say *what kind* of change a failed global hash indicates.

    The global hash covers each file's relative path **and** its content digest
    (see engine/integrity.hash_logarchive), so a mismatch means one of the two
    moved — and which one matters enormously to an analyst. The per-file results
    separate them: a content change moves a per-file digest, whereas a rename
    leaves every recorded digest intact and shows up as a file that is no longer
    where the database says it was.

    A bare "mismatch" would leave that distinction for the reader to work out, on
    the check most likely to be read as evidence tampering.
    """
    if per_file is None:
        # --skip-files: the evidence that separates the two cases was not
        # gathered, so claim only what is actually known.
        return ("mismatch — re-run without --skip-files to tell a content change "
                "from a renamed or moved file")
    if per_file.mismatches:
        return (f"mismatch — {len(per_file.mismatches)} file(s) changed content "
                "(see the per-file results)")
    if per_file.missing_file:
        return (f"mismatch — content is intact but {per_file.missing_file} recorded "
                "file(s) are no longer at their recorded path inside the archive "
                "(renamed, moved or removed)")
    if per_file.total and per_file.matched == per_file.total:
        # Everything the extract recorded still matches, so the difference is in
        # a path — or in a file present in the archive that was never parsed and
        # therefore has no source_files row to check.
        return ("mismatch — every recorded file's content matches, so the "
                "difference is in file paths/names, or in a file the extract did "
                "not record")
    return "mismatch"


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
