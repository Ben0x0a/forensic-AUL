"""Unit tests for the synthesised logarchive — forensic_aul/validation/logarchive_build.py.

The contract: a packaged acquisition (no ``Info.plist``, because a phone stores log
data and not the archive wrapper a Mac wraps around it) must come out as a bundle
Apple's ``log show`` will read. We cannot invoke ``log show`` in CI, so the tests
pin the two things that decide whether it accepts the bundle:

* the plist carries ``OSArchiveVersion`` and a ``{ContinuousTime, UUID}`` pair per
  log stream, taken from the real tracev3 headers rather than invented;
* the evidence is copied verbatim — the build adds a wrapper and changes nothing.

A tracev3 here is a genuine header chunk built byte-by-byte, so the values must
survive the real parser, not a stub.
"""

from __future__ import annotations

import plistlib
import struct
import uuid
from pathlib import Path

import pytest

from forensic_aul.validation.logarchive_build import (
    OS_ARCHIVE_VERSION,
    build_info_plist,
    build_logarchive,
    read_header_facts,
)


def _tracev3_header(continuous_time: int, boot_uuid: uuid.UUID) -> bytes:
    """A byte-accurate tracev3 header chunk (tag 0x1000) with its four sub-chunks."""
    out = bytearray()
    out += struct.pack("<IIQ", 0x1000, 0x11, 0xD0)          # tag, sub-tag, data size
    out += struct.pack("<II", 125, 3)                        # mach timebase (ARM)
    out += struct.pack("<Q", continuous_time)                # continuous_time
    out += struct.pack("<Q", 1_700_000_000)                  # unknown_time
    out += struct.pack("<IIII", 0, 0, 0, 0)                  # unknown, bias, dst, flags
    out += struct.pack("<IIQ", 0x6100, 8, continuous_time)   # sub-chunk 0
    out += struct.pack("<IIII", 0x6101, 56, 0, 0)            # sub-chunk 1
    out += b"21F90".ljust(16, b"\0")                         # build version
    out += b"iPhone14,2".ljust(32, b"\0")                    # hardware model
    out += struct.pack("<II", 0x6102, 24)                    # sub-chunk 2
    out += boot_uuid.bytes                                   # boot UUID (big-endian)
    out += struct.pack("<II", 1, 0)                          # logd pid, exit status
    out += struct.pack("<II", 0x6103, 48)                    # sub-chunk 3
    out += b"/var/db/timezone/zoneinfo/UTC".ljust(48, b"\0")
    return bytes(out)


_BOOT = uuid.UUID("aabbccdd-1122-3344-5566-778899aabbcc")


@pytest.fixture
def prepared(tmp_path: Path) -> Path:
    """A source normalised to logarchive shape but WITHOUT an Info.plist — exactly
    what the extraction layer hands back for a sysdiagnose or an FFS zip."""
    root = tmp_path / "prepared"
    (root / "Persist").mkdir(parents=True)
    (root / "Special").mkdir()
    (root / "timesync").mkdir()
    # Two Persist files: the build must take the NEWEST by rotation order.
    (root / "Persist" / "0000000000000001.tracev3").write_bytes(_tracev3_header(1_000, _BOOT))
    (root / "Persist" / "0000000000000002.tracev3").write_bytes(_tracev3_header(9_000, _BOOT))
    (root / "Special" / "0000000000000001.tracev3").write_bytes(_tracev3_header(5_000, _BOOT))
    (root / "logdata.LiveData.tracev3").write_bytes(_tracev3_header(7_000, _BOOT))
    (root / "timesync" / "0000000000000001.timesync").write_bytes(b"ts-payload")
    (root / "0A").mkdir()
    (root / "0A" / "1B2C3D4E5F60718293A4B5C6D7E8F9").write_bytes(b"uuidtext-payload")
    return root


def test_header_facts_come_from_the_real_parser(tmp_path):
    path = tmp_path / "x.tracev3"
    path.write_bytes(_tracev3_header(4_242, _BOOT))
    facts = read_header_facts(path)
    assert facts is not None
    assert facts.continuous_time == 4_242
    assert facts.boot_uuid == _BOOT.hex.upper()


def test_unreadable_tracev3_yields_no_facts(tmp_path):
    """A truncated file must degrade to None, not raise — one bad file in a
    multi-GB acquisition must not abort the whole validation run."""
    path = tmp_path / "truncated.tracev3"
    path.write_bytes(b"\x00\x10\x00\x00")
    assert read_header_facts(path) is None


def test_info_plist_has_every_key_log_show_requires(prepared):
    info = build_info_plist(prepared)

    assert info["OSArchiveVersion"] == OS_ARCHIVE_VERSION
    for key in ("EndTimeRef", "PersistMetadata", "SpecialMetadata", "LiveMetadata"):
        assert set(info[key]) == {"ContinuousTime", "UUID"}, key
        assert info[key]["UUID"] == _BOOT.hex.upper()

    # Per stream: the newest file's time, not the first one found.
    assert info["PersistMetadata"]["ContinuousTime"] == 9_000
    assert info["SpecialMetadata"]["ContinuousTime"] == 5_000
    assert info["LiveMetadata"]["ContinuousTime"] == 7_000
    # EndTimeRef is the newest across every stream.
    assert info["EndTimeRef"]["ContinuousTime"] == 9_000

    # A stream the acquisition does not carry is simply absent, not zero-filled —
    # a fabricated 0 would make `log show` report events from the epoch.
    assert "SignpostMetadata" not in info


def test_build_writes_a_readable_plist_and_copies_evidence_verbatim(prepared, tmp_path):
    bundle = build_logarchive(prepared, tmp_path / "out", name="case")

    assert bundle.name == "case.logarchive"
    info = plistlib.loads((bundle / "Info.plist").read_bytes())
    assert info["OSArchiveVersion"] == OS_ARCHIVE_VERSION

    # Every evidence file is present and byte-identical; only Info.plist is new.
    for rel in ("Persist/0000000000000002.tracev3", "timesync/0000000000000001.timesync",
                "0A/1B2C3D4E5F60718293A4B5C6D7E8F9", "logdata.LiveData.tracev3"):
        assert (bundle / rel).read_bytes() == (prepared / rel).read_bytes(), rel
    assert not (prepared / "Info.plist").exists(), "the source must not be modified"

    # The wrapper says it was derived: an analyst must be able to tell this bundle
    # apart from one a real `log collect` produced.
    assert "synthesised" in info["ArchiveIdentifier"]


def test_build_refuses_when_no_header_is_readable(tmp_path):
    """Without a boot UUID and a continuous time the plist would be a fiction, and
    `log show` would either refuse it or report nonsense timestamps."""
    root = tmp_path / "empty"
    (root / "Persist").mkdir(parents=True)
    (root / "Persist" / "junk.tracev3").write_bytes(b"not a header")
    with pytest.raises(ValueError, match="cannot synthesise"):
        build_info_plist(root)
