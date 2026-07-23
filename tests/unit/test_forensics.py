"""Tests for forensic_aul.engine.integrity + database.writer — hashing & source files."""

import hashlib
import sqlite3
from pathlib import Path

import pytest
from forensic_aul.engine.integrity import compute_sha256, hash_logarchive, verify_source_files
from forensic_aul.engine.database.writer import register_source_file
from forensic_aul.engine.database.schema import init_schema


class TestComputeSha256:
    def test_known_value(self, tmp_path):
        f = tmp_path / "test.bin"
        content = b"forensic-aul test"
        f.write_bytes(content)
        expected = hashlib.sha256(content).hexdigest()
        assert compute_sha256(f) == expected

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        expected = hashlib.sha256(b"").hexdigest()
        assert compute_sha256(f) == expected

    def test_returns_64_char_hex(self, tmp_path):
        f = tmp_path / "f.bin"
        f.write_bytes(b"x" * 1024)
        digest = compute_sha256(f)
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)


class TestHashLogarchive:
    def _make_logarchive(self, tmp_path: Path) -> Path:
        archive = tmp_path / "test.logarchive"
        archive.mkdir()
        (archive / "file_a.tracev3").write_bytes(b"tracev3_content")
        subdir = archive / "Persist"
        subdir.mkdir()
        (subdir / "file_b.tracev3").write_bytes(b"another_file")
        return archive

    def test_returns_tuple(self, tmp_path):
        archive = self._make_logarchive(tmp_path)
        result = hash_logarchive(archive)
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_archive_hash_is_hex_string(self, tmp_path):
        archive = self._make_logarchive(tmp_path)
        archive_hash, _ = hash_logarchive(archive)
        assert isinstance(archive_hash, str)
        assert len(archive_hash) == 64

    def test_file_hashes_dict(self, tmp_path):
        archive = self._make_logarchive(tmp_path)
        _, file_hashes = hash_logarchive(archive)
        assert isinstance(file_hashes, dict)
        assert len(file_hashes) >= 2  # at least 2 files

    def test_file_hashes_keys_are_relative(self, tmp_path):
        archive = self._make_logarchive(tmp_path)
        _, file_hashes = hash_logarchive(archive)
        for key in file_hashes:
            assert not Path(key).is_absolute(), f"Key should be relative: {key}"

    def test_archive_hash_changes_with_content(self, tmp_path):
        a1 = tmp_path / "v1.logarchive"
        a1.mkdir()
        (a1 / "f.tracev3").write_bytes(b"version_1")
        a2 = tmp_path / "v2.logarchive"
        a2.mkdir()
        (a2 / "f.tracev3").write_bytes(b"version_2")
        h1, _ = hash_logarchive(a1)
        h2, _ = hash_logarchive(a2)
        assert h1 != h2


class TestRegisterSourceFile:
    def test_returns_int_id(self, tmp_path, writer):
        f = tmp_path / "test.tracev3"
        f.write_bytes(b"data")
        file_hashes = {"test.tracev3": hashlib.sha256(b"data").hexdigest()}
        fid = register_source_file(writer, tmp_path, f, "tracev3", file_hashes)
        assert isinstance(fid, int)
        assert fid > 0

    def test_sha256_stored(self, tmp_path, conn, writer):
        f = tmp_path / "test2.tracev3"
        content = b"hello"
        f.write_bytes(content)
        expected_hash = hashlib.sha256(content).hexdigest()
        file_hashes = {"test2.tracev3": expected_hash}
        fid = register_source_file(writer, tmp_path, f, "tracev3", file_hashes)
        row = conn.execute(
            "SELECT sha256 FROM source_files WHERE id = ?", (fid,)
        ).fetchone()
        assert row[0] == expected_hash

    def test_idempotent(self, tmp_path, writer):
        f = tmp_path / "x.tracev3"
        f.write_bytes(b"x")
        fid1 = register_source_file(writer, tmp_path, f, "tracev3", {})
        fid2 = register_source_file(writer, tmp_path, f, "tracev3", {})
        assert fid1 == fid2


class TestVerifySourceFiles:
    """End-of-run per-file integrity re-hash (sha256_after / integrity_ok)."""

    @staticmethod
    def _setup(tmp_path):
        root = tmp_path / "arch"
        root.mkdir()
        files = {"a.tracev3": b"alpha", "b.timesync": b"bravo", "c.dsc": b"charlie"}
        for rel, data in files.items():
            (root / rel).write_bytes(data)
        conn = sqlite3.connect(":memory:")
        init_schema(conn)
        for rel, data in files.items():
            conn.execute(
                "INSERT INTO source_files(file_path, file_type, sha256, parsed_at) "
                "VALUES (?, ?, ?, ?)",
                (rel, "tracev3", hashlib.sha256(data).hexdigest(), "2024-01-01T00:00:00Z"),
            )
        conn.commit()
        return root, conn

    def test_all_unchanged(self, tmp_path):
        root, conn = self._setup(tmp_path)
        ok, changed, unverifiable = verify_source_files(conn, root)
        assert (ok, changed, unverifiable) == (3, 0, 0)
        rows = conn.execute(
            "SELECT integrity_ok, sha256 = sha256_after FROM source_files"
        ).fetchall()
        assert all(io == 1 and same == 1 for io, same in rows)

    def test_detects_a_changed_file(self, tmp_path):
        root, conn = self._setup(tmp_path)
        # Tamper with one file after registration ("during the run").
        (root / "b.timesync").write_bytes(b"TAMPERED")
        ok, changed, unverifiable = verify_source_files(conn, root)
        assert (ok, changed, unverifiable) == (2, 1, 0)
        flagged = conn.execute(
            "SELECT file_path FROM source_files WHERE integrity_ok = 0"
        ).fetchall()
        assert flagged == [("b.timesync",)]
        # The other two stay usable (integrity_ok = 1).
        assert conn.execute(
            "SELECT COUNT(*) FROM source_files WHERE integrity_ok = 1"
        ).fetchone()[0] == 2

    def test_missing_file_is_unverifiable(self, tmp_path):
        root, conn = self._setup(tmp_path)
        (root / "c.dsc").unlink()
        ok, changed, unverifiable = verify_source_files(conn, root)
        assert (ok, changed, unverifiable) == (2, 0, 1)
        row = conn.execute(
            "SELECT sha256_after, integrity_ok FROM source_files WHERE file_path = 'c.dsc'"
        ).fetchone()
        assert row == (None, None)
