"""Integration tests — end-to-end extract from real sysdiagnose / FFS archives.

These run the full pipeline (forensic_aul.ops.extraction.extract.run_extract) against real
acquisitions and assert the resulting database and provenance metadata. The
real evidence is private and heavy, so it cannot ship as a fixture: each test is
skipped automatically when its sample is absent. Sample paths default to the
known local locations and can be overridden via environment variables:

    FAUL_SYSDIAGNOSE_SAMPLE   path to a sysdiagnose .tar.gz
    FAUL_FFS_SAMPLE           path to a full-file-system .zip
    FAUL_LOGARCHIVE_SAMPLE    path to a .logarchive directory (for the .faul test)

Run only these:
    pytest tests/integration/test_source_extract.py -v
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from forensic_aul.engine import faul_format
from forensic_aul.ops.extraction.extract import run_extract

pytestmark = pytest.mark.integration

# ── Sample paths (override via env) ─────────────────────────────────────────

_SYSDIAGNOSE = Path(
    os.environ.get(
        "FAUL_SYSDIAGNOSE_SAMPLE",
        "/Volumes/Ben10_1TB/TM/2026_Julie/iPhone 11/2026-05-20/10_Sysdiagnose/"
        "sysdiagnose_2026.05.20_22-01-51+0200_iPhone-OS_iPhone_21F90.tar.gz",
    )
)
_FFS = Path(
    os.environ.get(
        "FAUL_FFS_SAMPLE",
        "/Volumes/Ben10_1TB/TM/2026_Julie/iPhone 11/2026-05-20/9_FFS/EXTRACTION_FFS.zip",
    )
)
_LOGARCHIVE = Path(
    os.environ.get("FAUL_LOGARCHIVE_SAMPLE", "tests/data/iphoneSE_afterbackup.logarchive")
)


def _extract(archive: Path, db_path: Path) -> None:
    run_extract(
        logarchive=archive,
        db_path=db_path,
        case_number="TEST-SOURCE",
        imei="000000000000000",
        notes="pytest source integration run",
        batch_size=500,
    )


def _assert_extracted(db_path: Path, *, archive: Path, expected_type: str) -> None:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        assert conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0] > 0
        assert conn.execute("SELECT COUNT(*) FROM source_files").fetchone()[0] > 0
        meta = conn.execute(
            "SELECT source_type, source_path, source_fingerprint, logarchive_sha256 "
            "FROM case_metadata LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    assert meta["source_type"] == expected_type
    assert meta["source_path"] == str(archive)
    assert meta["source_fingerprint"]          # non-null for archive sources
    assert meta["logarchive_sha256"]           # content fingerprint present


def test_extract_from_sysdiagnose(tmp_path):
    if not _SYSDIAGNOSE.is_file():
        pytest.skip(f"sysdiagnose sample not found: {_SYSDIAGNOSE}")
    db = tmp_path / "sd.db"
    _extract(_SYSDIAGNOSE, db)
    _assert_extracted(db, archive=_SYSDIAGNOSE, expected_type="sysdiagnose")


def test_extract_from_ffs(tmp_path):
    if not _FFS.is_file():
        pytest.skip(f"FFS sample not found: {_FFS}")
    db = tmp_path / "ffs.db"
    _extract(_FFS, db)
    _assert_extracted(db, archive=_FFS, expected_type="filesystem")


def _entry_count(db_path: Path) -> int:
    conn = sqlite3.connect(str(db_path))
    try:
        return conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    finally:
        conn.close()


def test_extract_from_faul_matches_logarchive(tmp_path):
    """A .faul packed from a logarchive extracts to a byte-identical row count."""
    if not _LOGARCHIVE.is_dir():
        pytest.skip(f"logarchive sample not found: {_LOGARCHIVE}")

    # Baseline: extract the logarchive directory directly.
    db_dir = tmp_path / "dir.db"
    _extract(_LOGARCHIVE, db_dir)
    baseline = _entry_count(db_dir)
    assert baseline > 0

    # Pack the same logarchive into a .faul (with a sidecar) and extract that.
    sidecar = {"case": {"case_number": "TEST-SOURCE"}, "device": {"imei": "000000000000000"}}
    faul = faul_format.pack_faul(_LOGARCHIVE, tmp_path / "acq.faul", sidecar=sidecar)
    db_faul = tmp_path / "faul.db"
    _extract(faul, db_faul)

    assert _entry_count(db_faul) == baseline
    conn = sqlite3.connect(str(db_faul))
    try:
        source_type = conn.execute(
            "SELECT source_type FROM case_metadata LIMIT 1"
        ).fetchone()[0]
    finally:
        conn.close()
    assert source_type == "faul"
