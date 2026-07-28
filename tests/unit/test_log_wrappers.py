"""Unit tests for the `log show` / `log collect` subprocess wrappers.

Subprocess invocation is mocked so the tests run anywhere — they verify
argument construction, error handling, and output discovery, not the
behaviour of Apple's binary itself.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from forensic_aul.validation import log_collect, log_show


def _completed(returncode: int, stderr: bytes = b"") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=b"", stderr=stderr
    )


# ── log_show ──────────────────────────────────────────────────────────────────

class TestLogShow:
    def test_argv_includes_default_flags(self, tmp_path: Path):
        archive = tmp_path / "arch.logarchive"
        archive.mkdir()
        out = tmp_path / "ref.ndjson"

        captured: dict[str, list[str]] = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return _completed(0)

        with patch("forensic_aul.validation.log_show.require_macos_log_tools"):
            with patch("subprocess.run", side_effect=fake_run):
                # touch the file so .stat().st_size doesn't fail
                out.write_bytes(b"")
                log_show.run(archive, out)

        assert "/usr/bin/log" in captured["cmd"]
        assert "show" in captured["cmd"]
        assert "--style" in captured["cmd"] and "ndjson" in captured["cmd"]
        for flag in log_show.DEFAULT_FLAGS:
            assert flag in captured["cmd"]
        assert str(archive) in captured["cmd"]

    def test_custom_flags_replace_defaults(self, tmp_path: Path):
        archive = tmp_path / "arch.logarchive"
        archive.mkdir()
        out = tmp_path / "ref.ndjson"

        captured: dict[str, list[str]] = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return _completed(0)

        with patch("forensic_aul.validation.log_show.require_macos_log_tools"):
            with patch("subprocess.run", side_effect=fake_run):
                out.write_bytes(b"")
                log_show.run(archive, out, flags=("--info",))

        assert "--info" in captured["cmd"]
        assert "--debug" not in captured["cmd"]

    def test_missing_archive_raises(self, tmp_path: Path):
        with patch("forensic_aul.validation.log_show.require_macos_log_tools"):
            with pytest.raises(FileNotFoundError):
                log_show.run(tmp_path / "absent.logarchive", tmp_path / "out.ndjson")

    def test_nonzero_exit_raises_and_unlinks(self, tmp_path: Path):
        archive = tmp_path / "arch.logarchive"
        archive.mkdir()
        out = tmp_path / "ref.ndjson"

        with patch("forensic_aul.validation.log_show.require_macos_log_tools"):
            with patch("subprocess.run", return_value=_completed(1, b"bad")):
                with pytest.raises(RuntimeError, match="bad"):
                    log_show.run(archive, out)
        # The wrapper should clean up the partial file.
        assert not out.exists()

    def test_subprocess_filenotfound_translated(self, tmp_path: Path):
        archive = tmp_path / "arch.logarchive"
        archive.mkdir()
        out = tmp_path / "ref.ndjson"

        with patch("forensic_aul.validation.log_show.require_macos_log_tools"):
            with patch("subprocess.run", side_effect=FileNotFoundError):
                with pytest.raises(RuntimeError, match="Could not invoke"):
                    log_show.run(archive, out)


# ── log_collect ───────────────────────────────────────────────────────────────

class TestLogCollect:
    def test_argv_includes_udid_and_output(self, tmp_path: Path):
        captured: dict[str, list[str]] = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            # Simulate the binary creating the archive.
            (tmp_path / "system_logs.logarchive").mkdir()
            return _completed(0)

        with patch("forensic_aul.validation.log_collect.require_macos_log_tools"):
            with patch("subprocess.run", side_effect=fake_run):
                result = log_collect.run("UDID-XYZ", tmp_path)

        assert "/usr/bin/log" in captured["cmd"]
        assert "collect" in captured["cmd"]
        assert "--device-udid" in captured["cmd"]
        assert "UDID-XYZ" in captured["cmd"]
        assert result.name == "system_logs.logarchive"

    def test_empty_udid_rejected(self, tmp_path: Path):
        with patch("forensic_aul.validation.log_collect.require_macos_log_tools"):
            with pytest.raises(ValueError):
                log_collect.run("", tmp_path)

    def test_missing_output_dir_rejected(self, tmp_path: Path):
        with patch("forensic_aul.validation.log_collect.require_macos_log_tools"):
            with pytest.raises(FileNotFoundError):
                log_collect.run("UDID", tmp_path / "absent")

    def test_nonzero_exit_surfaces_stderr(self, tmp_path: Path):
        with patch("forensic_aul.validation.log_collect.require_macos_log_tools"):
            with patch(
                "subprocess.run",
                return_value=_completed(1, b"device not paired"),
            ):
                with pytest.raises(RuntimeError, match="device not paired"):
                    log_collect.run("UDID", tmp_path)

    def test_no_archive_produced_raises(self, tmp_path: Path):
        with patch("forensic_aul.validation.log_collect.require_macos_log_tools"):
            with patch("subprocess.run", return_value=_completed(0)):
                with pytest.raises(RuntimeError, match="produced no .logarchive"):
                    log_collect.run("UDID", tmp_path)

    def test_picks_first_when_multiple(self, tmp_path: Path):
        def fake_run(cmd, **kwargs):
            (tmp_path / "a.logarchive").mkdir()
            (tmp_path / "b.logarchive").mkdir()
            return _completed(0)

        with patch("forensic_aul.validation.log_collect.require_macos_log_tools"):
            with patch("subprocess.run", side_effect=fake_run):
                result = log_collect.run("UDID", tmp_path)
        assert result.name in {"a.logarchive", "b.logarchive"}
