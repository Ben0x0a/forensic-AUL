"""Unit tests for the input-source preparation layer.

Covers : forensic_aul/ops/extraction/source.py — type detection, the pure FFS path
         mapping, the quick archive fingerprint, the temp-path placeholder, and
         end-to-end extraction of small *synthetic* sysdiagnose/FFS archives
         (no private fixtures — the archives are built in-memory in each test).
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

import pytest

from forensic_aul.ops.extraction.source import (
    SourceType,
    _ffs_target_relpath,
    find_loose_dirs,
    _quick_fingerprint,
    detect_source_type,
    prepare_source,
)


# ── detect_source_type ──────────────────────────────────────────────────────

def test_detect_directory_is_logarchive(tmp_path):
    assert detect_source_type(tmp_path) is SourceType.LOGARCHIVE


def test_detect_gzip_is_sysdiagnose(tmp_path):
    f = tmp_path / "x.tar.gz"
    f.write_bytes(b"\x1f\x8b\x08\x00rest")
    assert detect_source_type(f) is SourceType.SYSDIAGNOSE


def test_detect_zip_is_filesystem(tmp_path):
    f = tmp_path / "x.zip"
    f.write_bytes(b"PK\x03\x04rest")
    assert detect_source_type(f) is SourceType.FILESYSTEM


def test_detect_unrecognised_raises(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"not an archive")
    with pytest.raises(ValueError):
        detect_source_type(f)


def test_detect_missing_raises(tmp_path):
    with pytest.raises(ValueError):
        detect_source_type(tmp_path / "nope")


# ── _ffs_target_relpath (pure mapping) ────────────────────────────────────────

@pytest.mark.parametrize(
    "name, expected",
    [
        ("filesystem1/private/var/db/diagnostics/Persist/0.tracev3", "Persist/0.tracev3"),
        ("filesystem1/private/var/db/diagnostics/Special/0.tracev3", "Special/0.tracev3"),
        ("filesystem1/private/var/db/diagnostics/timesync/0.timesync", "timesync/0.timesync"),
        ("filesystem1/private/var/db/diagnostics/HighVolume/0.tracev3", "HighVolume/0.tracev3"),
        ("filesystem1/private/var/db/uuidtext/12/ABCDEF", "12/ABCDEF"),
        ("filesystem1/private/var/db/uuidtext/dsc/F834", "dsc/F834"),
        # No leading root folder — marker at the very start.
        ("private/var/db/diagnostics/Persist/0.tracev3", "Persist/0.tracev3"),
    ],
)
def test_ffs_mapping_hits(name, expected):
    assert _ffs_target_relpath(name) == PurePosixPath(expected)


@pytest.mark.parametrize(
    "name",
    [
        "filesystem1/private/var/mobile/Library/SMS/sms.db",  # unrelated
        "filesystem1/private/var/db/diagnostics/",            # directory entry
        "private/var/db/diagnostics/timesync/",               # directory entry
        "notprivate/var/db/diagnostics/x",                    # marker not on a boundary
    ],
)
def test_ffs_mapping_misses(name):
    assert _ffs_target_relpath(name) is None


# ── _quick_fingerprint ────────────────────────────────────────────────────────

def test_quick_fingerprint_stable_and_sensitive(tmp_path):
    a = tmp_path / "a.bin"
    a.write_bytes(b"A" * 1000)
    fp = _quick_fingerprint(a)
    assert fp == _quick_fingerprint(a)  # stable for identical bytes

    b = tmp_path / "b.bin"
    b.write_bytes(b"A" * 999 + b"B")  # tail differs
    assert _quick_fingerprint(b) != fp

    c = tmp_path / "c.bin"
    c.write_bytes(b"A" * 1001)  # size differs
    assert _quick_fingerprint(c) != fp


# ── End-to-end extraction of synthetic archives ───────────────────────────────

def _sysversion_plist(version: str) -> bytes:
    import plistlib
    return plistlib.dumps({"ProductVersion": version, "ProductName": "iPhone OS"})


def _info_plist(identifier: str) -> bytes:
    import plistlib
    return plistlib.dumps({"ArchiveIdentifier": identifier, "OSArchiveVersion": 4})


def _build_sysdiagnose(path: Path) -> None:
    """Write a minimal sysdiagnose .tar.gz with a system_logs.logarchive subtree."""
    wrapper = "sysdiagnose_DEMO"
    files = {
        f"{wrapper}/system_logs.logarchive/Persist/0.tracev3": b"trace",
        f"{wrapper}/system_logs.logarchive/timesync/0.timesync": b"ts",
        f"{wrapper}/system_logs.logarchive/dsc/F834": b"dsc",
        f"{wrapper}/system_logs.logarchive/Info.plist": _info_plist("ARCHIVE-SD-1"),
        f"{wrapper}/logs/SystemVersion/SystemVersion.plist": _sysversion_plist("17.5.1"),
        f"{wrapper}/logs/other.txt": b"ignored",  # outside the logarchive
    }
    with tarfile.open(path, "w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))


def _build_ffs(path: Path) -> None:
    """Write a minimal FFS .zip under a filesystem1/ root folder."""
    files = {
        "filesystem1/private/var/db/diagnostics/Persist/0.tracev3": b"trace",
        "filesystem1/private/var/db/diagnostics/timesync/0.timesync": b"ts",
        "filesystem1/private/var/db/uuidtext/12/ABCDEF": b"uuid",
        "filesystem1/private/var/db/uuidtext/dsc/F834": b"dsc",
        "filesystem1/System/Library/CoreServices/SystemVersion.plist": _sysversion_plist("16.3"),
        "filesystem1/private/var/mobile/sms.db": b"ignored",  # unrelated
    }
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)


def test_prepare_sysdiagnose_temp(tmp_path):
    arc = tmp_path / "sd.tar.gz"
    _build_sysdiagnose(arc)
    with prepare_source(arc) as prepared:
        assert prepared.source_type is SourceType.SYSDIAGNOSE
        root = prepared.logarchive_root
        assert (root / "Persist" / "0.tracev3").is_file()
        assert (root / "timesync" / "0.timesync").is_file()
        assert (root / "dsc" / "F834").is_file()
        assert not (root / "logs").exists()  # outside-logarchive content dropped
        assert prepared.archive_fingerprint is not None
        assert prepared.verify_unchanged() is True
        # Temp dir → placeholder, not a real path.
        assert prepared.recorded_logarchive_path.startswith("(temporary")
        # iOS version from SystemVersion.plist + ArchiveIdentifier from Info.plist.
        assert prepared.ios_product_version == "17.5.1"
        assert prepared.archive_identifier == "ARCHIVE-SD-1"
        tmp_root = root
    # Auto-cleaned on context exit.
    assert not tmp_root.exists()


def test_prepare_ffs_reads_system_version(tmp_path):
    arc = tmp_path / "ffs.zip"
    _build_ffs(arc)
    with prepare_source(arc) as prepared:
        assert prepared.ios_product_version == "16.3"   # from SystemVersion.plist
        assert not (prepared.logarchive_root / "System").exists()  # not extracted into the logarchive


def test_logarchive_dir_has_no_system_version(tmp_path):
    import plistlib
    (tmp_path / "Persist").mkdir()
    (tmp_path / "Persist" / "0.tracev3").write_bytes(b"trace")
    (tmp_path / "Info.plist").write_bytes(plistlib.dumps({"ArchiveIdentifier": "DIR-1"}))
    with prepare_source(tmp_path) as prepared:
        assert prepared.ios_product_version is None         # dir carries only the build code
        assert prepared.archive_identifier == "DIR-1"


def test_ios_version_for_build():
    from forensic_aul.engine.ios_builds import ios_version_for_build
    assert ios_version_for_build("21F90") == "17.5.1"
    assert ios_version_for_build("21f90") == "17.5.1"   # case-insensitive
    assert ios_version_for_build("ZZZ999") is None      # unknown → None (no guessing)
    assert ios_version_for_build(None) is None
    assert ios_version_for_build("") is None


def test_prepare_ffs_with_work_dir(tmp_path):
    arc = tmp_path / "ffs.zip"
    _build_ffs(arc)
    work = tmp_path / "work"
    with prepare_source(arc, work_dir=work) as prepared:
        assert prepared.source_type is SourceType.FILESYSTEM
        root = prepared.logarchive_root
        assert (root / "Persist" / "0.tracev3").is_file()
        assert (root / "timesync" / "0.timesync").is_file()
        assert (root / "12" / "ABCDEF").is_file()
        assert (root / "dsc" / "F834").is_file()
        assert not (root / "private").exists()  # unrelated tree dropped
        # Kept work dir → records the real path, not a placeholder.
        assert prepared.recorded_logarchive_path == str(root)
        assert "12/ABCDEF" in prepared.file_hashes
    # --work-dir is kept after exit.
    assert root.exists()


def test_prepare_logarchive_dir_passthrough(tmp_path):
    # A directory is used in place: no archive fingerprint, no temp dir.
    (tmp_path / "Persist").mkdir()
    (tmp_path / "Persist" / "0.tracev3").write_bytes(b"trace")
    with prepare_source(tmp_path) as prepared:
        assert prepared.source_type is SourceType.LOGARCHIVE
        assert prepared.logarchive_root == tmp_path
        assert prepared.archive_fingerprint is None
        assert prepared.verify_unchanged() is True
        assert prepared.recorded_logarchive_path == str(tmp_path)


def test_prepare_empty_zip_raises(tmp_path):
    arc = tmp_path / "empty.zip"
    with zipfile.ZipFile(arc, "w") as zf:
        zf.writestr("filesystem1/private/var/mobile/sms.db", b"x")
    with pytest.raises(ValueError):
        prepare_source(arc)


def test_prepare_sysdiagnose_without_logarchive_raises(tmp_path):
    arc = tmp_path / "bad.tar.gz"
    with tarfile.open(arc, "w:gz") as tf:
        data = b"x"
        info = tarfile.TarInfo("sysdiagnose_DEMO/logs/other.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    with pytest.raises(ValueError):
        prepare_source(arc)


# ── Loose-dirs source (two uncompressed folders) ─────────────────────────────

def _build_loose_dirs(base: Path) -> tuple[Path, Path]:
    """Write a diagnostics/ + uuidtext/ pair on disk; return the two roots."""
    diagnostics = base / "diagnostics"
    uuidtext = base / "uuidtext"
    (diagnostics / "Persist").mkdir(parents=True)
    (diagnostics / "Persist" / "0.tracev3").write_bytes(b"trace")
    (diagnostics / "timesync").mkdir()
    (diagnostics / "timesync" / "0.timesync").write_bytes(b"ts")
    (uuidtext / "12").mkdir(parents=True)
    (uuidtext / "12" / "ABCDEF").write_bytes(b"uuid")
    (uuidtext / "dsc").mkdir()
    (uuidtext / "dsc" / "F834").write_bytes(b"dsc")
    return diagnostics, uuidtext


def _assert_logarchive_layout(root: Path) -> None:
    assert (root / "Persist" / "0.tracev3").is_file()
    assert (root / "timesync" / "0.timesync").is_file()
    assert (root / "12" / "ABCDEF").is_file()
    assert (root / "dsc" / "F834").is_file()


def test_prepare_loose_dirs_via_mapping(tmp_path):
    from forensic_aul.ops.extraction.source import (
        LOOSE_DIAGNOSTICS_KEY,
        LOOSE_UUIDTEXT_KEY,
    )
    diagnostics, uuidtext = _build_loose_dirs(tmp_path)
    source = {LOOSE_DIAGNOSTICS_KEY: diagnostics, LOOSE_UUIDTEXT_KEY: uuidtext}
    with prepare_source(source) as prepared:
        assert prepared.source_type is SourceType.LOOSE_DIRS
        _assert_logarchive_layout(prepared.logarchive_root)
        # Merged root is hard-linked (no copy): same inode as the original, and
        # NOT a symlink (so the forensic hasher still picks it up).
        linked = prepared.logarchive_root / "Persist" / "0.tracev3"
        assert not linked.is_symlink()
        assert linked.stat().st_ino == (diagnostics / "Persist" / "0.tracev3").stat().st_ino
        # No single archive to attest, but content hashes are computed.
        assert prepared.archive_fingerprint is None
        assert prepared.verify_unchanged() is True
        assert "12/ABCDEF" in prepared.file_hashes
        assert prepared.ios_product_version is None
        tmp_root = prepared.logarchive_root
    assert not tmp_root.exists()  # temp dir auto-cleaned


def test_prepare_loose_dirs_function_and_work_dir(tmp_path):
    from forensic_aul.ops.extraction.source import prepare_loose_dirs
    diagnostics, uuidtext = _build_loose_dirs(tmp_path)
    work = tmp_path / "work"
    with prepare_loose_dirs(diagnostics, uuidtext, work_dir=work) as prepared:
        root = prepared.logarchive_root
        _assert_logarchive_layout(root)
        assert prepared.recorded_logarchive_path == str(root)  # kept, real path
    assert root.exists()  # --work-dir retained


def test_prepare_loose_dirs_copy_fallback(tmp_path, monkeypatch):
    # When hard links are unavailable (exFAT / network drive / cross-volume), the
    # files are COPIED instead — the result must be identical and hashes populated.
    import os as _os
    from forensic_aul.ops.extraction import source as _src
    diagnostics, uuidtext = _build_loose_dirs(tmp_path)

    def _no_hardlinks(*_a, **_k):
        raise OSError("simulated: filesystem without hard-link support")

    monkeypatch.setattr(_src.os, "link", _no_hardlinks)
    with _src.prepare_loose_dirs(diagnostics, uuidtext) as prepared:
        _assert_logarchive_layout(prepared.logarchive_root)
        # Copied (not linked): a regular file, not a symlink, and a *distinct* inode.
        copied = prepared.logarchive_root / "Persist" / "0.tracev3"
        assert not copied.is_symlink()
        assert copied.stat().st_ino != (diagnostics / "Persist" / "0.tracev3").stat().st_ino
        # Forensic hashing still works through the copies.
        assert "12/ABCDEF" in prepared.file_hashes
        assert prepared.content_sha256


def test_prepare_loose_dirs_bad_input_raises(tmp_path):
    from forensic_aul.ops.extraction.source import (
        LOOSE_DIAGNOSTICS_KEY,
        LOOSE_UUIDTEXT_KEY,
        prepare_loose_dirs,
    )
    diagnostics, uuidtext = _build_loose_dirs(tmp_path)
    # Not a directory.
    with pytest.raises(ValueError):
        prepare_loose_dirs(tmp_path / "nope", uuidtext)
    # Mapping missing the required keys.
    with pytest.raises(ValueError):
        prepare_source({LOOSE_DIAGNOSTICS_KEY: diagnostics})
    # Two empty dirs → no files.
    (tmp_path / "empty_d").mkdir()
    (tmp_path / "empty_u").mkdir()
    with pytest.raises(ValueError):
        prepare_source({
            LOOSE_DIAGNOSTICS_KEY: tmp_path / "empty_d",
            LOOSE_UUIDTEXT_KEY: tmp_path / "empty_u",
        })


# ── Integrity modes ───────────────────────────────────────────────────────────

class TestIntegrityModes:
    def test_full_is_default_and_hashes(self, tmp_path):
        arc = tmp_path / "sd.tar.gz"
        _build_sysdiagnose(arc)
        with prepare_source(arc) as prepared:
            assert prepared.content_sha256 is not None
            assert prepared.file_hashes
            assert prepared.archive_fingerprint is not None

    def test_fingerprint_skips_per_file_hashing(self, tmp_path):
        arc = tmp_path / "sd.tar.gz"
        _build_sysdiagnose(arc)
        with prepare_source(arc, integrity="fingerprint") as prepared:
            assert prepared.content_sha256 is None
            assert prepared.file_hashes == {}
            # The cheap archive fingerprint IS still taken…
            assert prepared.archive_fingerprint is not None
            # …and the post-run re-check still works.
            assert prepared.verify_unchanged() is True

    def test_off_takes_no_attestation(self, tmp_path):
        arc = tmp_path / "sd.tar.gz"
        _build_sysdiagnose(arc)
        with prepare_source(arc, integrity="off") as prepared:
            assert prepared.content_sha256 is None
            assert prepared.file_hashes == {}
            assert prepared.archive_fingerprint is None
            assert prepared.verify_unchanged() is True  # nothing to compare

    def test_logarchive_dir_fingerprint_mode(self, tmp_path):
        root = tmp_path / "a.logarchive"
        (root / "Persist").mkdir(parents=True)
        (root / "Persist" / "0.tracev3").write_bytes(b"trace")
        with prepare_source(root, integrity="fingerprint") as prepared:
            assert prepared.content_sha256 is None
            assert prepared.file_hashes == {}

    def test_loose_dirs_integrity_threaded(self, tmp_path):
        diag, uuid_dir = _build_loose_dirs(tmp_path)
        with prepare_source(
            {"diagnostics": diag, "uuidtext": uuid_dir}, integrity="off"
        ) as prepared:
            assert prepared.content_sha256 is None
            assert prepared.file_hashes == {}

    def test_invalid_mode_raises(self, tmp_path):
        arc = tmp_path / "sd.tar.gz"
        _build_sysdiagnose(arc)
        with pytest.raises(ValueError, match="integrity mode"):
            prepare_source(arc, integrity="none")


# ── find_loose_dirs ───────────────────────────────────────────────────────────

class TestFindLooseDirs:
    def _build_fs(self, root: Path, base: str = "") -> None:
        prefix = root / base if base else root
        (prefix / "private/var/db/diagnostics/Persist").mkdir(parents=True)
        (prefix / "private/var/db/diagnostics/Persist/0.tracev3").write_bytes(b"t")
        (prefix / "private/var/db/uuidtext/dsc").mkdir(parents=True)

    def test_found_at_root(self, tmp_path):
        self._build_fs(tmp_path)
        dirs = find_loose_dirs(tmp_path)
        assert dirs is not None
        assert dirs["diagnostics"].is_dir() and dirs["uuidtext"].is_dir()

    def test_found_under_intermediate_folder(self, tmp_path):
        self._build_fs(tmp_path, "filesystem1")
        dirs = find_loose_dirs(tmp_path)
        assert dirs is not None
        assert "filesystem1" in str(dirs["diagnostics"])

    def test_none_when_absent(self, tmp_path):
        (tmp_path / "unrelated").mkdir()
        assert find_loose_dirs(tmp_path) is None
        assert find_loose_dirs(tmp_path / "does-not-exist") is None

    def test_none_when_uuidtext_missing(self, tmp_path):
        (tmp_path / "private/var/db/diagnostics").mkdir(parents=True)
        assert find_loose_dirs(tmp_path) is None

    def test_mapping_feeds_prepare_source(self, tmp_path):
        self._build_fs(tmp_path)
        dirs = find_loose_dirs(tmp_path)
        with prepare_source(dirs, integrity="off") as prepared:
            assert prepared.source_type is SourceType.LOOSE_DIRS


# ── Source-handler registry (adding a source is one drop-in module) ───────────

class TestSourceHandlerRegistry:
    def test_new_handler_is_one_registry_entry(self, tmp_path, monkeypatch):
        """Registering a handler makes detect + prepare handle it with no other change."""
        import forensic_aul.ops.extraction.sources as sources
        from forensic_aul.ops.extraction.sources.base import (
            ExtractOutcome,
            SourceHandler,
            prepare_archive,
        )

        def fake_matches(path):
            return path.is_file() and path.read_bytes()[:4] == b"FAKE"

        def fake_extract(archive, root):
            (root / "Persist").mkdir(parents=True)
            (root / "Persist" / "0.tracev3").write_bytes(b"trace")
            return ExtractOutcome(product_version="18.0")

        def fake_prepare(path, *, work_dir=None, integrity="full", reset_work_dir=False):
            return prepare_archive(
                path, SourceType.SYSDIAGNOSE, fake_extract,
                work_dir=work_dir, integrity=integrity, reset_work_dir=reset_work_dir,
            )

        handler = SourceHandler(
            SourceType.SYSDIAGNOSE, 5, fake_matches, fake_prepare, "a fake test container",
        )
        # Prepended → probed first (its FAKE magic is unambiguous).
        monkeypatch.setattr(sources, "_HANDLERS", (handler, *sources._HANDLERS))

        arc = tmp_path / "evidence.fake"
        arc.write_bytes(b"FAKE" + b"payload" * 10)
        assert detect_source_type(arc) is SourceType.SYSDIAGNOSE
        with prepare_source(arc, integrity="off") as prepared:
            assert (prepared.logarchive_root / "Persist" / "0.tracev3").is_file()
            assert prepared.ios_product_version == "18.0"

    def test_unrecognised_error_lists_registered_formats(self, tmp_path):
        bad = tmp_path / "junk.bin"
        bad.write_bytes(b"\x00\x01junk")
        try:
            detect_source_type(bad)
            raise AssertionError("should have raised")
        except ValueError as exc:  # SourceError is a ValueError
            assert "sysdiagnose" in str(exc) and "full-file-system" in str(exc)


# ── Work-root contamination guard (review item L9) ────────────────────────────
#
# Source preparation hashes and parses EVERYTHING under the work root, so a root
# left behind by a previous run would fold that run's evidence into this
# acquisition. These tests pin the guard that prevents it.

def test_reused_work_root_is_refused(tmp_path):
    """A non-empty work root must stop the run, not be silently reused."""
    from forensic_aul.ops.extraction.sources.base import SourceError

    arc = tmp_path / "sd.tar.gz"
    _build_sysdiagnose(arc)
    work = tmp_path / "work"

    with prepare_source(arc, work_dir=work, integrity="off") as first:
        assert (first.logarchive_root / "Persist" / "0.tracev3").is_file()

    with pytest.raises(SourceError) as exc:
        prepare_source(arc, work_dir=work, integrity="off")
    message = str(exc.value)
    assert "not empty" in message
    assert "--reset-work-dir" in message          # names the way forward
    assert str(work) in message                   # names the directory


def test_stale_evidence_cannot_enter_a_new_acquisition(tmp_path):
    """The contamination this guard exists to prevent, demonstrated.

    A file from a previous run sits in the work root. Without the guard it would
    be hashed into content_sha256 and registered as a source file of THIS case.
    """
    from forensic_aul.ops.extraction.sources.base import SourceError

    arc = tmp_path / "sd.tar.gz"
    _build_sysdiagnose(arc)
    work = tmp_path / "work"
    stale_root = work / "sd.tar.logarchive"       # the root this source maps to
    (stale_root / "Persist").mkdir(parents=True)
    (stale_root / "Persist" / "OTHER_CASE.tracev3").write_bytes(b"other device")

    with pytest.raises(SourceError):
        prepare_source(arc, work_dir=work, integrity="off")

    # Refused means untouched: the operator's data is still there to inspect.
    assert (stale_root / "Persist" / "OTHER_CASE.tracev3").is_file()


def test_reset_work_dir_starts_clean(tmp_path):
    """--reset-work-dir deletes the stale root, so nothing carries over."""
    arc = tmp_path / "sd.tar.gz"
    _build_sysdiagnose(arc)
    work = tmp_path / "work"
    stale_root = work / "sd.tar.logarchive"
    (stale_root / "Persist").mkdir(parents=True)
    (stale_root / "Persist" / "OTHER_CASE.tracev3").write_bytes(b"other device")

    with prepare_source(arc, work_dir=work, integrity="full", reset_work_dir=True) as p:
        root = p.logarchive_root
        assert (root / "Persist" / "0.tracev3").is_file()
        assert not (root / "Persist" / "OTHER_CASE.tracev3").exists()
        # And it is absent from the chain of custody, not merely off disk.
        assert not any("OTHER_CASE" in name for name in p.file_hashes)


def test_reset_only_removes_faul_s_own_root(tmp_path):
    """Reset must never delete the operator's --work-dir, only the root inside it."""
    arc = tmp_path / "sd.tar.gz"
    _build_sysdiagnose(arc)
    work = tmp_path / "work"
    work.mkdir()
    keepsake = work / "analyst-notes.txt"
    keepsake.write_text("do not delete me", encoding="utf-8")
    (work / "sd.tar.logarchive").mkdir()
    (work / "sd.tar.logarchive" / "stale").write_bytes(b"x")

    with prepare_source(arc, work_dir=work, integrity="off", reset_work_dir=True):
        pass
    assert keepsake.read_text(encoding="utf-8") == "do not delete me"


def test_empty_work_root_is_accepted(tmp_path):
    """An existing but empty root is fine — nothing can carry over from it."""
    arc = tmp_path / "sd.tar.gz"
    _build_sysdiagnose(arc)
    work = tmp_path / "work"
    (work / "sd.tar.logarchive").mkdir(parents=True)

    with prepare_source(arc, work_dir=work, integrity="off") as p:
        assert (p.logarchive_root / "Persist" / "0.tracev3").is_file()


def test_work_root_path_occupied_by_a_file_is_refused(tmp_path):
    from forensic_aul.ops.extraction.sources.base import SourceError

    arc = tmp_path / "sd.tar.gz"
    _build_sysdiagnose(arc)
    work = tmp_path / "work"
    work.mkdir()
    (work / "sd.tar.logarchive").write_bytes(b"not a directory")

    with pytest.raises(SourceError, match="not a directory"):
        prepare_source(arc, work_dir=work, integrity="off")


def test_loose_dirs_runs_collide_on_a_shared_work_dir(tmp_path):
    """Loose-dirs uses a FIXED root name, so any two runs collide — and are caught.

    This is the sharpest case: the two runs need not share a source name, or even
    a device.
    """
    from forensic_aul.ops.extraction.sources.base import SourceError

    def _make_pair(tag: str) -> tuple[Path, Path]:
        diag = tmp_path / tag / "diagnostics"
        uuid = tmp_path / tag / "uuidtext"
        (diag / "Persist").mkdir(parents=True)
        (diag / "Persist" / f"{tag}.tracev3").write_bytes(b"trace")
        (uuid / "12").mkdir(parents=True)
        (uuid / "12" / "ABCDEF").write_bytes(b"uuid")
        return diag, uuid

    work = tmp_path / "work"
    diag_a, uuid_a = _make_pair("caseA")
    with prepare_source({"diagnostics": diag_a, "uuidtext": uuid_a},
                        work_dir=work, integrity="off"):
        pass

    diag_b, uuid_b = _make_pair("caseB")
    with pytest.raises(SourceError, match="not empty"):
        prepare_source({"diagnostics": diag_b, "uuidtext": uuid_b},
                       work_dir=work, integrity="off")


def test_temp_work_root_is_always_fresh(tmp_path):
    """Without --work-dir there is no reuse to guard against — twice must work."""
    arc = tmp_path / "sd.tar.gz"
    _build_sysdiagnose(arc)
    roots = []
    for _ in range(2):
        with prepare_source(arc, integrity="off") as p:
            roots.append(p.logarchive_root)
            assert (p.logarchive_root / "Persist" / "0.tracev3").is_file()
    assert roots[0] != roots[1]
