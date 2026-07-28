"""Unit tests for forensic_aul.validation.platform — device resolution.

Network/usbmux access is mocked: tests run on every OS.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from forensic_aul.validation.platform import DeviceRef, resolve_device


def _dev(udid: str, name: str) -> DeviceRef:
    return DeviceRef(udid=udid, name=name, product_type="iPhone15,2", product_version="18.1")


class TestResolveDevice:
    def test_auto_pick_single_device(self):
        with patch("forensic_aul.validation.platform.list_devices", return_value=[_dev("UDID1", "Alice")]):
            d = resolve_device(None)
            assert d.udid == "UDID1"

    def test_no_device_raises(self):
        with patch("forensic_aul.validation.platform.list_devices", return_value=[]):
            with pytest.raises(RuntimeError, match="No iOS device"):
                resolve_device(None)

    def test_multiple_devices_no_selector_raises(self):
        with patch(
            "forensic_aul.validation.platform.list_devices",
            return_value=[_dev("UDID1", "Alice"), _dev("UDID2", "Bob")],
        ):
            with pytest.raises(RuntimeError, match="2 devices are connected"):
                resolve_device(None)

    def test_match_by_exact_udid(self):
        devices = [_dev("UDID1", "Alice"), _dev("UDID2", "Bob")]
        with patch("forensic_aul.validation.platform.list_devices", return_value=devices):
            d = resolve_device("UDID2")
            assert d.name == "Bob"

    def test_match_by_udid_case_insensitive(self):
        devices = [_dev("ABC123", "Alice")]
        with patch("forensic_aul.validation.platform.list_devices", return_value=devices):
            d = resolve_device("abc123")
            assert d.udid == "ABC123"

    def test_match_by_exact_name(self):
        devices = [_dev("UDID1", "Alice"), _dev("UDID2", "Bob")]
        with patch("forensic_aul.validation.platform.list_devices", return_value=devices):
            d = resolve_device("Bob")
            assert d.udid == "UDID2"

    def test_match_by_name_case_insensitive(self):
        devices = [_dev("UDID1", "Alice")]
        with patch("forensic_aul.validation.platform.list_devices", return_value=devices):
            d = resolve_device("ALICE")
            assert d.udid == "UDID1"

    def test_ambiguous_name_raises(self):
        devices = [_dev("UDID1", "iPhone"), _dev("UDID2", "iPhone")]
        with patch("forensic_aul.validation.platform.list_devices", return_value=devices):
            with pytest.raises(RuntimeError, match="ambiguous"):
                resolve_device("iPhone")

    def test_no_match_raises_with_listing(self):
        devices = [_dev("UDID1", "Alice")]
        with patch("forensic_aul.validation.platform.list_devices", return_value=devices):
            with pytest.raises(RuntimeError, match="No device matches"):
                resolve_device("Charlie")


class TestDeviceRefDisplay:
    def test_display_includes_name_and_udid(self):
        d = _dev("ABCDEF123", "iPhone de Test")
        s = d.display()
        assert "iPhone de Test" in s
        assert "ABCDEF123" in s

    def test_display_handles_missing_name(self):
        d = DeviceRef(udid="X", name="", product_type="", product_version="")
        assert "(unnamed)" in d.display()
