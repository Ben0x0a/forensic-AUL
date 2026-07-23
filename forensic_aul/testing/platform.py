"""Platform helpers for the ``test`` subcommand.

The ``test`` subcommand can run in three modes:

* **Mac with iPhone**  — use ``log collect`` + ``log show`` natively.
* **Mac without iPhone** — use ``log show`` against a logarchive on disk.
* **Linux/Windows** — only mode 3 (DB+ndjson both supplied) works.

This module centralises the platform checks and the device-name/UDID
resolution so the rest of the testing pipeline does not have to know
about ``pymobiledevice3`` or ``shutil.which``.
"""

from __future__ import annotations

import logging
import platform as _platform
import shutil
from dataclasses import dataclass

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class DeviceRef:
    """Compact reference to a connected iOS device.

    Used by the CLI and (later) by the GUI: it lets the user copy/paste a
    UDID, type a name (case-insensitive), or rely on auto-selection when
    a single device is connected.
    """
    udid: str
    name: str
    product_type: str = ""
    product_version: str = ""

    def display(self) -> str:
        bits = [self.name or "(unnamed)"]
        if self.product_type:
            bits.append(self.product_type)
        if self.product_version:
            bits.append(f"iOS {self.product_version}")
        bits.append(self.udid)
        return "  ·  ".join(bits)


def is_macos() -> bool:
    return _platform.system() == "Darwin"


def has_log_binary() -> bool:
    """True if Apple's ``/usr/bin/log`` is available (only on macOS)."""
    return shutil.which("log") is not None


def require_macos_log_tools() -> None:
    """Raise a clear error if ``log`` cannot be invoked on this host."""
    if not is_macos():
        raise RuntimeError(
            "This action needs Apple's `log` tool, which only ships with macOS. "
            "On Linux/Windows, supply the reference ndjson explicitly:\n"
            "    forensic-aul test <logarchive_or_db>  <reference.ndjson>"
        )
    if not has_log_binary():
        raise RuntimeError(
            "Apple's `log` binary was not found in PATH. Expected at /usr/bin/log."
        )


def list_devices() -> list[DeviceRef]:
    """Return a compact list of every device visible via usbmux.

    Uses :func:`forensic_aul.ops.acquisition.device.list_connected_devices`,
    which itself wraps ``pymobiledevice3``. We only keep the four fields
    the user actually needs for selection.
    """
    import asyncio

    from forensic_aul.ops.acquisition.device import list_connected_devices

    infos = asyncio.run(list_connected_devices())
    return [
        DeviceRef(
            udid=info.udid,
            name=info.device_name,
            product_type=info.product_type,
            product_version=info.product_version,
        )
        for info in infos
    ]


def resolve_device(name_or_udid: str | None) -> DeviceRef:
    """Resolve a device by exact UDID or by name (case-insensitive).

    Behaviour:

    * ``name_or_udid is None`` — auto-select if exactly one device is
      connected; raise otherwise.
    * Otherwise, match first by exact UDID, then by exact name (case
      insensitive). Reject ambiguous and missing matches with a clear
      error message.
    """
    devices = list_devices()
    if not devices:
        raise RuntimeError(
            "No iOS device is connected. Plug a phone in, trust this computer, "
            "and try again."
        )

    if name_or_udid is None:
        if len(devices) > 1:
            listing = "\n  ".join(d.display() for d in devices)
            raise RuntimeError(
                f"{len(devices)} devices are connected — pick one with "
                f"`--from-device <NAME_OR_UDID>`:\n  {listing}"
            )
        return devices[0]

    target = name_or_udid.strip()
    target_norm = target.lower()

    by_udid = [d for d in devices if d.udid.lower() == target_norm]
    if len(by_udid) == 1:
        return by_udid[0]

    by_name = [d for d in devices if d.name.lower() == target_norm]
    if len(by_name) == 1:
        return by_name[0]
    if len(by_name) > 1:
        listing = "\n  ".join(d.display() for d in by_name)
        raise RuntimeError(
            f"Device name {target!r} is ambiguous ({len(by_name)} matches); "
            f"specify the UDID instead:\n  {listing}"
        )

    listing = "\n  ".join(d.display() for d in devices)
    raise RuntimeError(
        f"No device matches {target!r}. Connected devices:\n  {listing}"
    )
