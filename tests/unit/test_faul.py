"""Unit tests for the ``.faul`` portable-evidence container.

Covers : forensic_aul/engine/faul_format.py (pack / detect / read / extract) and
         its integration with the extract source layer (detection wins over a
         plain FFS zip; the embedded sidecar is surfaced on PreparedSource) and
         the sidecar auto-fill (load_sidecar_for reads inside a .faul).
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from forensic_aul.engine import faul_format
from forensic_aul.ops.extraction.sources import (
    SourceType,
    detect_source_type,
    prepare_source,
)


# ── Fixtures ────────────────────────────────────────────────────────────────--

def _build_logarchive(root: Path) -> Path:
    """A minimal logarchive tree (a couple of files in nested dirs)."""
    (root / "Persist").mkdir(parents=True)
    (root / "Persist" / "0000000000000001.tracev3").write_bytes(b"trace-bytes-1")
    (root / "timesync").mkdir()
    (root / "timesync" / "0000.timesync").write_bytes(b"sync-bytes")
    return root


_SIDECAR = {
    "case": {"case_number": "CASE-42", "exhibit_number": "EX-1", "analyst": "Alice", "notes": "n"},
    "device": {"imei": "356938035643809"},
}


def _make_faul(tmp_path: Path, *, sidecar: dict | None = _SIDECAR) -> Path:
    la = _build_logarchive(tmp_path / "acq.logarchive")
    out = tmp_path / "acq.faul"
    return faul_format.pack_faul(la, out, sidecar=sidecar)


# ── pack / detect / read ────────────────────────────────────────────────────--

def test_pack_is_stored_and_detected(tmp_path):
    faul = _make_faul(tmp_path)
    assert faul.exists()
    # Every entry stored uncompressed (no decompression on extract).
    with zipfile.ZipFile(faul) as zf:
        assert faul_format.MANIFEST_ARCNAME in zf.namelist()
        for info in zf.infolist():
            assert info.compress_type == zipfile.ZIP_STORED
    assert faul_format.is_faul(faul) is True


def test_manifest_and_sidecar_roundtrip(tmp_path):
    faul = _make_faul(tmp_path)
    manifest = faul_format.read_manifest(faul)
    assert manifest["format"] == "faul"
    assert manifest["format_version"] == faul_format.FORMAT_VERSION
    assert manifest["logarchive"] == "acq.logarchive"
    assert faul_format.read_sidecar(faul) == _SIDECAR


def test_no_sidecar_reads_none(tmp_path):
    faul = _make_faul(tmp_path, sidecar=None)
    assert faul_format.is_faul(faul) is True
    assert faul_format.read_sidecar(faul) is None


def test_extract_logarchive_is_byte_identical(tmp_path):
    faul = _make_faul(tmp_path)
    dest = tmp_path / "restored"
    dest.mkdir()
    n = faul_format.extract_logarchive(faul, dest)
    assert n == 2
    assert (dest / "Persist" / "0000000000000001.tracev3").read_bytes() == b"trace-bytes-1"
    assert (dest / "timesync" / "0000.timesync").read_bytes() == b"sync-bytes"


def test_pack_is_atomic_no_tmp_left(tmp_path):
    faul = _make_faul(tmp_path)
    assert not faul.with_name(faul.name + ".tmp").exists()


def test_newer_format_version_refused(tmp_path, monkeypatch):
    faul = _make_faul(tmp_path)
    # A container claiming a future major version must not be half-read.
    monkeypatch.setattr(faul_format, "FORMAT_VERSION", 0)
    assert faul_format.read_manifest(faul) is None


# ── Detection: .faul vs plain FFS zip (same magic) ──────────────────────────--

def test_faul_detection_beats_ffs_zip(tmp_path):
    faul = _make_faul(tmp_path)
    assert detect_source_type(faul) is SourceType.FAUL

    # A plain FFS zip (no faul marker) is NOT a .faul.
    ffs = tmp_path / "fs.zip"
    with zipfile.ZipFile(ffs, "w") as zf:
        zf.writestr("private/var/db/diagnostics/Persist/0.tracev3", b"t")
        zf.writestr("private/var/db/uuidtext/dsc/0", b"d")
    assert faul_format.is_faul(ffs) is False
    assert detect_source_type(ffs) is SourceType.FILESYSTEM


def test_non_zip_is_not_faul(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"not a zip at all")
    assert faul_format.is_faul(f) is False


# ── prepare_source integration ───────────────────────────────────────────────

def test_prepare_faul_surfaces_sidecar_and_tree(tmp_path):
    faul = _make_faul(tmp_path)
    with prepare_source(faul, integrity="off") as prepared:
        assert prepared.source_type is SourceType.FAUL
        assert prepared.sidecar == _SIDECAR
        root = prepared.logarchive_root
        assert (root / "Persist" / "0000000000000001.tracev3").is_file()
        # Archive fingerprint is None only in "off" mode; take it in full mode.
    with prepare_source(faul, integrity="fingerprint") as prepared:
        assert prepared.archive_fingerprint is not None
        assert prepared.verify_unchanged() is True


# ── Sidecar auto-fill reads inside the .faul ──────────────────────────────────

def test_load_sidecar_for_reads_faul(tmp_path):
    from forensic_aul.ops.acquisition.report import load_sidecar_for

    faul = _make_faul(tmp_path)
    loaded = load_sidecar_for(faul)
    assert loaded is not None
    assert loaded["case"]["case_number"] == "CASE-42"
    assert loaded["device"]["imei"] == "356938035643809"


# ── CLI case-field precedence (explicit flag overrides sidecar) ───────────────

def test_resolve_case_fields_precedence(tmp_path):
    from types import SimpleNamespace

    from launcher.cmds.extract_cmd import _resolve_case_fields

    faul = _make_faul(tmp_path)
    # No explicit flags → all come from the sidecar.
    args = SimpleNamespace(case_number=None, imei=None, exhibit_number=None, analyst=None, notes=None)
    case, imei, exhibit, analyst, notes = _resolve_case_fields(args, faul)
    assert (case, imei, exhibit, analyst) == ("CASE-42", "356938035643809", "EX-1", "Alice")

    # Explicit flag wins over the sidecar value.
    args = SimpleNamespace(case_number="OVERRIDE", imei=None, exhibit_number=None, analyst=None, notes=None)
    case, imei, *_ = _resolve_case_fields(args, faul)
    assert case == "OVERRIDE"
    assert imei == "356938035643809"   # untouched flag still falls back to sidecar
