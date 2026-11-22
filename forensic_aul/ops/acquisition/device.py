"""Device discovery and metadata retrieval via pymobiledevice3.

pymobiledevice3 is an *optional* dependency — it is only imported when this
module is actually used (i.e. during ``forensic-aul acquire``).  All other
subcommands work without it.

Public API
----------
list_connected_devices() -> list[DeviceInfo]
connect_device(udid) -> tuple[LockdownClient, DeviceInfo]

Both are async coroutines; call them inside ``asyncio.run()``.
"""

from __future__ import annotations

import logging

from forensic_aul.device_info import DeviceInfo, SimInfo

log = logging.getLogger(__name__)


def _require_pymobiledevice3():
    try:
        import pymobiledevice3  # noqa: F401
    except ImportError:
        raise ImportError(
            "pymobiledevice3 is required for the 'acquire' subcommand.\n"
            "Install it with:  pip install pymobiledevice3"
        ) from None
    return pymobiledevice3


# ── Internal helpers ──────────────────────────────────────────────────────────

def _s(d: dict, *keys: str, default: str = "") -> str:
    for k in keys:
        v = d.get(k)
        if v is not None and v != "":
            return str(v)
    return default


def _parse_sims(all_values: dict) -> list[SimInfo]:
    sims: list[SimInfo] = []
    bundles = all_values.get("CarrierBundleInfoArray") or []
    # eSIM flags indexed by slot
    sim1_embedded = bool(all_values.get("SIM1IsEmbedded", False))
    sim2_embedded = bool(all_values.get("SIM2IsEmbedded", False))
    embedded_map = {"kOne": sim1_embedded, "kTwo": sim2_embedded}

    for bundle in bundles:
        if not isinstance(bundle, dict):
            continue
        slot = str(bundle.get("Slot", ""))
        sims.append(SimInfo(
            slot=slot,
            is_embedded=embedded_map.get(slot, False),
            iccid=str(bundle.get("IntegratedCircuitCardIdentity", "")),
            imsi=str(bundle.get("InternationalMobileSubscriberIdentity", "")),
            mcc=str(bundle.get("MCC", "")),
            mnc=str(bundle.get("MNC", "")),
            meid=str(bundle.get("MobileEquipmentIdentifier", "")),
            carrier_bundle=str(bundle.get("CFBundleIdentifier", "")),
            carrier_version=str(bundle.get("CFBundleVersion", "")),
        ))
    return sims


async def _device_info_from_lockdown(lockdown, connection_type: str = "USB") -> DeviceInfo:
    """Extract a :class:`DeviceInfo` from an open LockdownClient."""
    try:
        all_values: dict = lockdown.all_values
        if hasattr(all_values, "__await__"):
            all_values = await all_values
        if not isinstance(all_values, dict):
            all_values = {}
    except Exception:
        all_values = {}

    ecid_raw = all_values.get("UniqueChipID", 0)
    ecid_hex = hex(int(ecid_raw)) if ecid_raw else ""

    return DeviceInfo(
        # Primary identifiers
        udid=_s(all_values, "UniqueDeviceID") or str(getattr(lockdown, "udid", "")),
        imei=_s(all_values, "InternationalMobileEquipmentIdentity"),
        imei2=_s(all_values, "InternationalMobileEquipmentIdentity2"),
        meid=_s(all_values, "MobileEquipmentIdentifier"),
        serial_number=_s(all_values, "SerialNumber"),
        mlb_serial=_s(all_values, "MLBSerialNumber"),
        ecid=ecid_hex,
        chip_id=_s(all_values, "ChipID"),
        # Device identity
        device_name=_s(all_values, "DeviceName"),
        device_class=_s(all_values, "DeviceClass"),
        product_type=_s(all_values, "ProductType"),
        hardware_model=_s(all_values, "HardwareModel"),
        model_number=_s(all_values, "ModelNumber"),
        cpu_architecture=_s(all_values, "CPUArchitecture"),
        hardware_platform=_s(all_values, "HardwarePlatform"),
        # Software
        product_version=_s(all_values, "ProductVersion"),
        build_version=_s(all_values, "BuildVersion"),
        baseband_version=_s(all_values, "BasebandVersion"),
        firmware_version=_s(all_values, "FirmwareVersion"),
        # Telephony
        phone_number=_s(all_values, "PhoneNumber"),
        sims=_parse_sims(all_values),
        # Network
        wifi_mac=_s(all_values, "WiFiAddress"),
        bluetooth_mac=_s(all_values, "BluetoothAddress"),
        ethernet_mac=_s(all_values, "EthernetAddress"),
        # State
        activation_state=_s(all_values, "ActivationState"),
        password_protected=bool(all_values.get("PasswordProtected", False)),
        timezone=_s(all_values, "TimeZone"),
        timezone_offset_utc=float(all_values.get("TimeZoneOffsetFromUTC", 0.0)),
        device_time_utc=float(all_values.get("TimeIntervalSince1970", 0.0)),
        region_info=_s(all_values, "RegionInfo"),
        connection_type=connection_type,
    )


# ── Public API ────────────────────────────────────────────────────────────────

async def list_connected_devices() -> list[DeviceInfo]:
    """Return a :class:`DeviceInfo` for every device visible via usbmux."""
    _require_pymobiledevice3()

    from pymobiledevice3.usbmux import list_devices as _list
    try:
        mux_devices = await _list()
    except TypeError:
        import asyncio
        mux_devices = await asyncio.get_event_loop().run_in_executor(None, _list)

    results: list[DeviceInfo] = []
    for mdev in mux_devices:
        udid = str(mdev.serial)
        conn = str(getattr(mdev, "connection_type", "USB"))
        try:
            lockdown = await _open_lockdown(udid)
            info = await _device_info_from_lockdown(lockdown, connection_type=conn)
            await close_lockdown(lockdown)
        except Exception as exc:
            log.warning(f"Could not query device {udid}: {exc}")
            info = DeviceInfo(
                udid=udid, imei="", imei2="", meid="", serial_number="",
                mlb_serial="", ecid="", chip_id="",
                device_name="(unavailable)", device_class="", product_type="",
                hardware_model="", model_number="", cpu_architecture="",
                hardware_platform="", product_version="", build_version="",
                baseband_version="", firmware_version="", phone_number="",
                connection_type=conn,
            )
        results.append(info)

    return results


async def connect_device(udid: str | None = None) -> tuple[object, DeviceInfo]:
    """Open a LockdownClient and return ``(lockdown, DeviceInfo)``.

    If *udid* is None, connects to the first available device.
    Raises ``RuntimeError`` if no device is found.
    """
    _require_pymobiledevice3()

    lockdown = await _open_lockdown(udid)
    conn_type = "USB"
    try:
        from pymobiledevice3.usbmux import list_devices as _list
        mux_devices = await _list()
        target = (udid or "").upper().replace("-", "")
        for mdev in mux_devices:
            if not target or str(mdev.serial).upper().replace("-", "") == target:
                conn_type = str(getattr(mdev, "connection_type", "USB"))
                break
    except Exception:
        pass

    info = await _device_info_from_lockdown(lockdown, connection_type=conn_type)
    return lockdown, info


# ── Lockdown open/close helpers ───────────────────────────────────────────────

async def _open_lockdown(udid: str | None):
    try:
        from pymobiledevice3.lockdown import create_using_usbmux
        client = create_using_usbmux(serial=udid)
        if hasattr(client, "__await__"):
            client = await client
        return client
    except (ImportError, AttributeError) as _e:
        log.debug("create_using_usbmux not available (%s); falling back to LockdownClient", _e)

    from pymobiledevice3.lockdown import LockdownClient
    try:
        return LockdownClient(udid=udid)
    except TypeError:
        # Older pymobiledevice3 had no ``udid`` kwarg. We refuse to fall back
        # to a no-arg ``LockdownClient()`` when a specific UDID was requested,
        # as that would silently target an arbitrary connected device.
        if udid is not None:
            raise RuntimeError(
                f"Installed pymobiledevice3 cannot target a specific UDID ({udid}); "
                "upgrade pymobiledevice3 to a version that supports `udid=` kwarg."
            )
        return LockdownClient()


async def close_lockdown(lockdown) -> None:
    """Best-effort close of a LockdownClient, sync or async."""
    try:
        close = getattr(lockdown, "close", None) or getattr(lockdown, "aclose", None)
        if close is None:
            return
        result = close()
        if hasattr(result, "__await__"):
            await result
    except Exception:
        log.debug("close_lockdown: error during close", exc_info=True)
