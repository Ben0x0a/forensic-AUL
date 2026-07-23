"""Unit tests for forensic_aul.ops.acquisition.acquire — the library acquire().

Device collection is hardware-bound and needs the optional pymobiledevice3, so the
orchestration is exercised with the connect / collect / hash / report steps
monkeypatched. This keeps the test fast and dependency-free while still covering
the control flow (confirm hook, abort, errors, result assembly) and the helpers.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import forensic_aul.ops.acquisition.acquire as acq
from forensic_aul.ops.acquisition.acquire import (
    AcquisitionAborted,
    AcquisitionError,
    _parse_start_time,
    sanitise_filename_token,
    acquire,
)


def _fake_device(imei: str = "356938035643809", udid: str = "00008030-001A2B3C4D5E") -> SimpleNamespace:
    return SimpleNamespace(imei=imei, udid=udid, display_table=lambda: "(device table)")


@pytest.fixture
def patched(monkeypatch):
    """Patch the connect / collect / hash / report steps with in-memory fakes.

    Returns the fake device so tests can tweak it (e.g. drop the IMEI).
    """
    device = _fake_device()

    async def fake_connect(udid=None):
        return ("LOCKDOWN", device)

    async def fake_close(lockdown):
        return None

    async def fake_collect(lockdown, out, *, size_limit, age_limit, start_unix):
        # Materialise the (temp) logarchive so the existence check passes.
        Path(out).mkdir(parents=True, exist_ok=True)

    def fake_hash(path):
        return "deadbeefcafe", {"Persist/0000.tracev3": "aa", "timesync/0.timesync": "bb"}

    captured: dict = {}

    def fake_build(logarchive_path, dev, *, case_number, exhibit, analyst, notes,
                   logarchive_sha256, file_count, file_hashes=None):
        captured["file_hashes"] = file_hashes
        captured["case_number"] = case_number
        return {"case": {"case_number": case_number}, "device": {"imei": dev.imei}}

    def fake_pack(logarchive_dir, out_path, *, sidecar=None, logarchive_arcname=None):
        # Stand in for the real stored-zip packer: record what was bundled and
        # materialise the .faul so the result's existence check passes.
        captured["sidecar"] = sidecar
        captured["packed_from"] = Path(logarchive_dir)
        Path(out_path).write_bytes(b"PK\x03\x04 fake-faul")
        return Path(out_path)

    monkeypatch.setattr(acq, "connect_device", fake_connect)
    monkeypatch.setattr(acq, "close_lockdown", fake_close)
    monkeypatch.setattr(acq, "collect_logarchive", fake_collect)
    monkeypatch.setattr(acq, "hash_logarchive", fake_hash)
    monkeypatch.setattr(acq, "build_report_dict", fake_build)
    monkeypatch.setattr(acq, "pack_faul", fake_pack)
    device._captured = captured   # {file_hashes, case_number, sidecar, packed_from}
    return device


# ── Helpers ───────────────────────────────────────────────────────────────────

class TestHelpers:
    @pytest.mark.parametrize("raw,expected", [
        ("CASE-2024-001", "CASE-2024-001"),
        ("a/b\\c", "a_b_c"),
        ("..//evil", "____evil"),   # every forbidden char (. and /) → _
        (".hidden.", "_hidden_"),
    ])
    def test_sanitise(self, raw, expected):
        out = sanitise_filename_token(raw)
        assert out == expected
        # Safety: no path separators or traversal survive.
        assert "/" not in out and "\\" not in out and ".." not in out

    def test_parse_start_time_variants(self):
        assert _parse_start_time(None) is None
        assert _parse_start_time(1_700_000_000) == 1_700_000_000   # int passthrough
        assert isinstance(_parse_start_time("1h"), int)            # relative
        assert _parse_start_time("2024-01-15T12:00:00") == 1_705_320_000
        assert _parse_start_time("not-a-time") is None             # unparseable → ignored

    def test_parse_start_time_relative_arithmetic(self):
        now = int(datetime.now(tz=timezone.utc).timestamp())
        # Shared duration parser: seconds unit is accepted alongside m/h/d.
        assert abs(_parse_start_time("30s") - (now - 30)) <= 2
        assert abs(_parse_start_time("10m") - (now - 600)) <= 2
        assert abs(_parse_start_time("1.5h") - (now - 5400)) <= 2
        assert abs(_parse_start_time("2d") - (now - 172_800)) <= 2


# ── Public surface ────────────────────────────────────────────────────────────

def test_acquire_exported():
    import forensic_aul as f
    for name in ("acquire", "AcquireResult", "AcquisitionError", "AcquisitionAborted", "DeviceInfo"):
        assert name in f.__all__ and hasattr(f, name)


# ── Orchestration ─────────────────────────────────────────────────────────────

class TestAcquire:
    def test_happy_path(self, tmp_path, patched):
        res = acquire("CASE-1", output_dir=tmp_path)
        assert res.logarchive_path.parent == tmp_path
        assert res.logarchive_path.suffix == ".faul"   # the portable container
        assert res.logarchive_path.exists()
        # Filename embeds the sanitised case and the device IMEI.
        assert res.logarchive_path.name.startswith("CASE-1-356938035643809-")
        assert res.logarchive_sha256 == "deadbeefcafe"
        assert res.file_count == 2
        assert res.device is patched
        # The sidecar is embedded in the .faul — no separate report file on disk.
        assert res.report_path is None
        assert res.extract_result is None        # extract not requested
        # The per-file hash map is forwarded into the embedded sidecar for
        # independent integrity checks (not just the aggregate hash + count).
        assert patched._captured["file_hashes"] == {
            "Persist/0000.tracev3": "aa", "timesync/0.timesync": "bb"}
        # The sidecar dict is what gets packed into the container.
        assert patched._captured["sidecar"]["case"]["case_number"] == "CASE-1"

    def test_raw_produces_loose_layout(self, tmp_path, patched, monkeypatch):
        # --raw / pack=False writes a loose .logarchive + a sidecar file, and
        # never invokes the .faul packer.
        written: dict = {}

        def fake_report(logarchive_path, dev, *, case_number, exhibit, analyst,
                        notes, logarchive_sha256, file_count, file_hashes=None):
            rp = Path(str(logarchive_path) + ".acquisition.json")
            rp.write_text("{}", encoding="utf-8")
            written["report"] = rp
            return rp

        def boom_pack(*a, **k):
            raise AssertionError("pack_faul must not be called with pack=False")

        monkeypatch.setattr(acq, "write_acquisition_report", fake_report)
        monkeypatch.setattr(acq, "pack_faul", boom_pack)

        res = acquire("CASE-1", output_dir=tmp_path, pack=False)
        assert res.logarchive_path.suffix == ".logarchive"
        assert res.logarchive_path.parent == tmp_path
        assert res.report_path is not None and res.report_path.exists()

    def test_confirm_proceed(self, tmp_path, patched):
        seen = {}
        def confirm(device):
            seen["imei"] = device.imei
            return True
        res = acquire("CASE-1", output_dir=tmp_path, confirm=confirm)
        assert seen["imei"] == patched.imei
        assert res.logarchive_path.exists()

    def test_confirm_abort_raises(self, tmp_path, patched):
        with pytest.raises(AcquisitionAborted):
            acquire("CASE-1", output_dir=tmp_path, confirm=lambda _device: False)

    def test_empty_case_number_rejected(self, tmp_path, patched):
        with pytest.raises(AcquisitionError):
            acquire("", output_dir=tmp_path)

    def test_missing_imei_uses_udid_fragment(self, tmp_path, patched, monkeypatch):
        patched.imei = ""   # Wi-Fi-only device
        res = acquire("CASE-1", output_dir=tmp_path)
        # Falls back to the first 8 chars of the UDID in the filename.
        assert "-00008030-" in res.logarchive_path.name

    def test_import_error_propagates(self, tmp_path, monkeypatch):
        async def boom(udid=None):
            raise ImportError("pymobiledevice3 is not installed")
        monkeypatch.setattr(acq, "connect_device", boom)
        with pytest.raises(ImportError):
            acquire("CASE-1", output_dir=tmp_path)
