# Acquisition sidecar (`.acquisition.json`)

The traceability record written by [`acquire`](../cli/acquire.md): the case fields
the operator supplied, the acquisition facts (timestamps, hashes) and the full
device metadata read from lockdown. Source:
`forensic_aul/ops/acquisition/{report,device,acquire}.py` and
`forensic_aul/engine/integrity.py`.

## Where it lives

| Output layout | Sidecar location |
|---|---|
| `.faul` container (default) | **Inside** the archive, as `<name>.logarchive.acquisition.json`, named by `faul/manifest.json`'s `sidecar` field |
| `acquire --raw` (loose layout) | A neighbouring file: `<logarchive name>` + `.acquisition.json` |

The suffix is **appended**, never substituted — `foo.logarchive` yields
`foo.logarchive.acquisition.json` (`sidecar_path_for()`). `load_sidecar_for(path)`
handles both shapes transparently: it reads from within a `.faul` when the path is
one, otherwise it looks for the neighbouring file. It is best-effort — a missing or
malformed sidecar returns `None` rather than raising.

The loose file is written **atomically** (temp file + `os.replace`); a partial
sidecar would be a forensic hazard.

The sidecar is not self-hashing (a chicken-and-egg problem). Its forensic anchor is
the logarchive SHA-256 it contains; operators who need chain-of-custody over the
file itself should hash or sign it externally.

## Top-level structure

```json
{
  "forensic_aul_version": "0.1.0",
  "report_format_version": 1,
  "case":        { … },
  "acquisition": { … },
  "device":      { … }
}
```

| Field | Type | Meaning |
|---|---|---|
| `forensic_aul_version` | string | `forensic_aul.__version__` at acquisition time |
| `report_format_version` | int | Currently `1` |

## `case` — operator-supplied

| Field | Type | Notes |
|---|---|---|
| `case_number` | string | Required by `acquire` |
| `exhibit_number` | string | `""` when not given |
| `analyst` | string | `""` when not given |
| `notes` | string | `""` when not given |

These are the only editable fields; everything under `device` comes from the
device and is never overridable.

## `acquisition` — generated

| Field | Type | Meaning |
|---|---|---|
| `timestamp_utc` | string | Second-precision UTC, `%Y-%m-%dT%H:%M:%SZ`, taken when the report dict is built |
| `logarchive_path` | string | Absolute resolved path of the logarchive at acquisition time (for a packed `.faul` this is the temp collection directory) |
| `logarchive_sha256` | string | Global digest of the whole logarchive; `""` if hashing failed |
| `file_count` | int | Number of hashed files; defaults to `len(file_hashes)` when the map is present |
| `file_hashes` | object \| null | `{relative_path: sha256}`, or `null` when hashing was unavailable |

### The `file_hashes` map and the global digest

`hash_logarchive()` walks the logarchive, **skipping symlinks and non-regular
files** (following them could pull in data from outside the root and make the hash
non-reproducible). Each file's SHA-256 is computed in 1 MiB chunks and keyed by its
POSIX path relative to the logarchive root. A file that cannot be read is logged and
omitted from the map.

The global `logarchive_sha256` is the SHA-256 of all per-file digests (as raw
bytes) concatenated in **sorted path order** — deterministic, and independent of
filesystem walk order.

```json
"file_hashes": {
  "Extra/shutdown.log": "3b1f…",
  "logdata.LiveData.tracev3": "9c02…",
  "timesync/0000000000000001.timesync": "af77…"
}
```

Because each file is hashed independently, a later verification can pinpoint
exactly which file changed rather than invalidating the whole archive.

## `device` — from lockdown

`DeviceInfo.to_dict()`, in this order. All values are strings unless noted; a value
the device did not report is `""` (or `0.0` / `false`).

**Primary identifiers** (never overridable)

| Field | Lockdown key |
|---|---|
| `udid` | `UniqueDeviceID` |
| `imei` | `InternationalMobileEquipmentIdentity` |
| `imei2` | `InternationalMobileEquipmentIdentity2` (dual-SIM) |
| `meid` | `MobileEquipmentIdentifier` |
| `serial_number` | `SerialNumber` |
| `mlb_serial` | `MLBSerialNumber` (motherboard) |
| `ecid` | `UniqueChipID`, rendered as a hex string |
| `chip_id` | `ChipID` |

**Device identity**

| Field | Lockdown key | Example |
|---|---|---|
| `device_name` | `DeviceName` | user-assigned name |
| `device_class` | `DeviceClass` | `iPhone` |
| `product_type` | `ProductType` | `iPhone12,3` |
| `hardware_model` | `HardwareModel` | `D421AP` |
| `model_number` | `ModelNumber` | `MWC22` (region SKU) |
| `cpu_architecture` | `CPUArchitecture` | `arm64e` |
| `hardware_platform` | `HardwarePlatform` | `t8030` |

**Software**

| Field | Lockdown key | Example |
|---|---|---|
| `product_version` | `ProductVersion` | `17.4.1` |
| `build_version` | `BuildVersion` | `23A355` |
| `baseband_version` | `BasebandVersion` | modem firmware |
| `firmware_version` | `FirmwareVersion` | iBoot version |

**Telephony**

| Field | Meaning |
|---|---|
| `phone_number` | `PhoneNumber` (may be empty) |
| `sims` | list of SIM objects (below) |

Each entry of `sims` is derived from `CarrierBundleInfoArray`, with the eSIM flag
taken from `SIM1IsEmbedded` / `SIM2IsEmbedded` by slot:

| Field | Type | Source key |
|---|---|---|
| `slot` | string | `Slot` (`kOne`, `kTwo`, …) |
| `is_embedded` | bool | eSIM (`true`) vs physical |
| `iccid` | string | `IntegratedCircuitCardIdentity` |
| `imsi` | string | `InternationalMobileSubscriberIdentity` |
| `mcc` | string | `MCC` |
| `mnc` | string | `MNC` |
| `meid` | string | `MobileEquipmentIdentifier` |
| `carrier_bundle` | string | `CFBundleIdentifier` |
| `carrier_version` | string | `CFBundleVersion` |

**Network addresses**

| Field | Lockdown key |
|---|---|
| `wifi_mac` | `WiFiAddress` |
| `bluetooth_mac` | `BluetoothAddress` |
| `ethernet_mac` | `EthernetAddress` |

**State at acquisition**

| Field | Type | Lockdown key | Notes |
|---|---|---|---|
| `activation_state` | string | `ActivationState` | e.g. `Activated` |
| `password_protected` | bool | `PasswordProtected` | |
| `timezone` | string | `TimeZone` | e.g. `Europe/Zurich` |
| `timezone_offset_utc` | float | `TimeZoneOffsetFromUTC` | seconds |
| `device_time_utc` | float | `TimeIntervalSince1970` | the device clock at acquisition — the reference for detecting a shifted clock |
| `region_info` | string | `RegionInfo` | |

**Connection**

| Field | Type | Notes |
|---|---|---|
| `connection_type` | string | `USB` by default; taken from usbmux when available |

## Example

```json
{
  "forensic_aul_version": "0.1.0",
  "report_format_version": 1,
  "case": {
    "case_number": "CASE-2024-001",
    "exhibit_number": "EX-03",
    "analyst": "J. Doe",
    "notes": ""
  },
  "acquisition": {
    "timestamp_utc": "2024-06-01T09:14:07Z",
    "logarchive_path": "/var/folders/…/CASE-2024-001-35…-2024_06_01_09_14_07Z.logarchive",
    "logarchive_sha256": "b0f1…",
    "file_count": 412,
    "file_hashes": { "logdata.LiveData.tracev3": "9c02…" }
  },
  "device": {
    "udid": "00008030-0011…",
    "imei": "35…",
    "product_type": "iPhone12,3",
    "product_version": "17.4.1",
    "build_version": "21E236",
    "device_time_utc": 1717233247.0,
    "timezone": "Europe/Zurich",
    "sims": [],
    "connection_type": "USB"
  }
}
```

## How `extract` auto-fills case fields from it

The CLI's `_resolve_case_fields()` (`launcher/cmds/extract_cmd.py`) calls
`load_sidecar_for(source)` and merges:

| `extract` field | Falls back to |
|---|---|
| `--case-number` | `case.case_number` |
| `--imei` | `device.imei` |
| `-e, --exhibit-number` | `case.exhibit_number` |
| `--analyst` | `case.analyst` |
| `--notes` | `case.notes` |

Rules:

- **An explicit CLI flag always wins**; only fields left unset fall back to the
  sidecar, and an empty string in the sidecar is treated as absent.
- This is why the case identifiers are documented as *"required unless supplied by
  a `.faul` sidecar"*.
- A multi-directory source (the `{diagnostics, uuidtext}` loose-dirs mapping) has
  no sidecar, so the flags are returned unchanged.
- When any field was filled in, an INFO line is logged.

The resolved values land in `case_metadata` — see
[database schema](database-schema.md#case_metadata).

Independently of the CLI, the extract source layer surfaces a `.faul`'s embedded
sidecar on `PreparedSource.sidecar`, so other front-ends can perform the same
auto-fill.

## See also

- [`.faul` container](faul-format.md) — where the sidecar travels
- [`acquire` CLI](../cli/acquire.md), [`verify-hash` CLI](../cli/verify-hash.md)
- [Database schema](database-schema.md)
