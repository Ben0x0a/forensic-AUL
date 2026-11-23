"""DeviceInfo.display_table — the masked summary identify shows (I4)."""

from __future__ import annotations

from dataclasses import MISSING, fields

from forensic_aul import DeviceInfo
from forensic_aul.device_info import SimInfo


def _device() -> DeviceInfo:
    values = {f.name: f"{f.name}-value-1234" for f in fields(DeviceInfo)
              if f.default is MISSING and f.default_factory is MISSING}
    values.update(imei="356938035643809", phone_number="+41 79 123 45 67",
                  device_name="Alice's iPhone", wifi_mac="aa:bb:cc:dd:ee:ff")
    device = DeviceInfo(**values)
    device.sims = [SimInfo(slot="kOne", is_embedded=False, iccid="8941000000000000001",
                           imsi="228011234567890", mcc="228", mnc="01", meid="",
                           carrier_bundle="x", carrier_version="1")]
    return device


def test_masked_summary_hides_personal_and_subscriber_identifiers():
    text = _device().display_table(masked=True)
    for secret in ("356938035643809", "+41 79 123 45 67", "Alice", "aa:bb:cc:dd:ee:ff",
                   "8941000000000000001", "228011234567890"):
        assert secret not in text, secret
    assert "••••3809" in text, "the last four IMEI digits stay, to recognise the device"


def test_full_summary_is_unchanged_by_default():
    text = _device().display_table()
    assert "356938035643809" in text and "Alice's iPhone" in text
