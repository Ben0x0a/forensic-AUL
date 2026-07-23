"""Forensic integrity utilities for AUL Parser.

Generic SHA-256 hashing and post-extraction tamper-evident sealing:

  compute_sha256      — SHA-256 a single file (streaming, 1 MiB chunks).
  hash_logarchive     — deterministic SHA-256 fingerprint of an entire
                        logarchive directory (sorted walk, cumulative hash).
  seal_log_file       — SHA-256 the operational log and store the digest in
                        case_metadata at the end of an extract session.
  verify_source_files — Re-hash every registered source file after parsing and
                        record whether each one changed during the run.
"""

from __future__ import annotations

import hashlib
import logging
import sqlite3
from pathlib import Path

from forensic_aul.config import HASH_CHUNK_SIZE as _CHUNK_SIZE

log = logging.getLogger(__name__)


def compute_sha256(path: Path | str) -> str:
    """Compute the hex-encoded SHA-256 digest of a single file.

    Reads the file in 1 MiB chunks to avoid loading large files into RAM.
    Returns a lowercase 64-character hex string.

    Raises:
        OSError: if the file cannot be read.
    """
    path = Path(path)
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_logarchive(logarchive: Path | str) -> tuple[str, dict[str, str]]:
    """Compute a deterministic SHA-256 fingerprint of an entire logarchive.

    The global hash is the SHA-256 of all per-file SHA-256 digests,
    concatenated in sorted path order (relative to *logarchive* root).

    Returns:
        (global_sha256, {relative_path: file_sha256}) — both lowercase hex.

    The returned dict can be used to populate `source_files.sha256` during
    extraction and to verify individual files later.
    """
    root = Path(logarchive)
    if not root.is_dir():
        raise ValueError(f"Not a directory: {root}")

    all_files: list[Path] = sorted(root.rglob("*"))
    file_hashes: dict[str, str] = {}
    global_h = hashlib.sha256()

    for path in all_files:
        # Symlinks skipped: rglob follows them, which could pull in files
        # outside the root and yield a non-reproducible hash.
        if path.is_symlink() or not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        try:
            digest = compute_sha256(path)
        except OSError as exc:
            log.warning(f"integrity: cannot hash {rel}: {exc}")
            continue
        file_hashes[rel] = digest
        global_h.update(bytes.fromhex(digest))

    return global_h.hexdigest(), file_hashes


def seal_log_file(
    db_path: Path,
    log_path: Path,
    metadata_id: int | None,
) -> str:
    """Hash the operational log file and store the digest in case_metadata.

    Produces the tamper-evident seal on the audit log at the end of a session:
    computes the log file's SHA-256 and, when *metadata_id* is given, writes it
    (with the log path) into ``case_metadata``. Returns the hex digest so the
    caller can report it even on a failed/interrupted run (metadata_id None).

    Raises:
        OSError: the log file cannot be read.
        sqlite3.Error: the digest could not be written to the database.
    """
    digest = compute_sha256(log_path)
    if metadata_id is not None:
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute(
                "UPDATE case_metadata SET log_file_path = ?, log_file_sha256 = ? WHERE id = ?",
                (str(log_path), digest, metadata_id),
            )
    return digest


def verify_source_files(
    conn: sqlite3.Connection,
    logarchive_root: Path,
) -> tuple[int, int, int]:
    """Re-hash every registered source file and record the "after" digest + status.

    For each ``source_files`` row, re-computes the SHA-256 of the file on disk now
    that the run is complete and stores it in ``sha256_after``, setting
    ``integrity_ok`` to:

      * ``1`` — unchanged (matches the "before" ``sha256``),
      * ``0`` — **changed** during the run (its parsed data must be treated with
        caution), or
      * ``NULL`` — no baseline hash to compare against, or the file is no longer
        readable.

    A changed/unreadable file does **not** invalidate the others: every other
    row's data stays independently usable, and the per-file flag pinpoints exactly
    which file to distrust.

    Returns ``(unchanged, changed, unverifiable)`` counts.
    """
    rows = conn.execute("SELECT id, file_path, sha256 FROM source_files").fetchall()

    n_ok = n_changed = n_unverifiable = 0
    updates: list[tuple[str | None, int | None, int]] = []

    for sid, rel, before in rows:
        try:
            after: str | None = compute_sha256(logarchive_root / rel)
        except OSError as exc:
            log.warning(f"integrity: cannot re-hash {rel}: {exc}")
            after, ok = None, None
            n_unverifiable += 1
        else:
            if before is None:
                ok = None
                n_unverifiable += 1
            elif after == before:
                ok = 1
                n_ok += 1
            else:
                ok = 0
                n_changed += 1
                log.warning(f"integrity: {rel} CHANGED during the run (before={before} after={after})")
        updates.append((after, ok, sid))

    conn.executemany(
        "UPDATE source_files SET sha256_after = ?, integrity_ok = ? WHERE id = ?",
        updates,
    )
    conn.commit()
    return n_ok, n_changed, n_unverifiable
