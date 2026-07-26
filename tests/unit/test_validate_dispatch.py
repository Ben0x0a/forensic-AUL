"""Unit tests for the validate environment probe + L3 dispatch guards —
forensic_aul/testing/platform.py and pipeline._run_l3_from_device.

The live L3 run needs macOS + root (Apple ``log collect``), which CI can't provide,
so the *guards* are what we test here: with the capability probe monkeypatched, the
dispatch must refuse early (and never touch the device) off-macOS or off-root.
"""

from __future__ import annotations

import argparse
import os

from forensic_aul.testing import pipeline, platform
from forensic_aul.testing.platform import Caps


def _caps(mac: bool, log_tool: bool, root: bool) -> Caps:
    return Caps(is_macos=mac, has_log=log_tool, is_root=root)


def test_capabilities_reflects_probes(monkeypatch):
    monkeypatch.setattr(platform, "is_macos", lambda: True)
    monkeypatch.setattr(platform, "has_log_binary", lambda: True)
    monkeypatch.setattr(platform, "is_root", lambda: False)
    caps = platform.capabilities()
    assert (caps.is_macos, caps.has_log, caps.is_root) == (True, True, False)
    assert "root=False" in caps.summary()


def test_is_root_guarded_without_geteuid(monkeypatch):
    # Windows has no os.geteuid → must degrade to False, not raise.
    monkeypatch.delattr(os, "geteuid", raising=False)
    assert platform.is_root() is False


def _fake_device_tripwire(monkeypatch):
    """Trip if the dispatch tries to touch the device after a failed guard."""
    tripped = []
    monkeypatch.setattr(platform, "resolve_device", lambda *a, **k: tripped.append(True))
    return tripped


def test_from_device_refused_off_macos(monkeypatch):
    monkeypatch.setattr(platform, "capabilities", lambda: _caps(False, False, False))
    tripped = _fake_device_tripwire(monkeypatch)
    args = argparse.Namespace(from_device="", collect_last=None)
    rc = pipeline._run_l3_from_device(args, pipeline._Resources(), set())
    assert rc == 1 and not tripped


def test_from_device_refused_without_root(monkeypatch):
    monkeypatch.setattr(platform, "capabilities", lambda: _caps(True, True, False))
    tripped = _fake_device_tripwire(monkeypatch)
    args = argparse.Namespace(from_device="", collect_last=None)
    rc = pipeline._run_l3_from_device(args, pipeline._Resources(), set())
    assert rc == 1 and not tripped
