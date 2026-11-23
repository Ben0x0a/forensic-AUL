"""Device metadata collected at acquisition — pure data containers.

Defines : SimInfo, DeviceInfo (with display_table / to_dict).
Used by : forensic_aul.ops.acquisition (device discovery fills them; acquire and
          report consume them), forensic_aul.ops.workflows.identify,
          forensic_aul.outcomes (AcquireResult), forensic_aul.__init__ (public API).
Uses    : dataclasses only — a leaf module, so result types can reference it
          without importing the acquisition layer (no import cycle).
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ── SIM info ──────────────────────────────────────────────────────────────────

@dataclass
class SimInfo:
    slot: str               # "kOne" | "kTwo" | …
    is_embedded: bool       # eSIM vs physical
    iccid: str              # Integrated Circuit Card Identifier
    imsi: str               # International Mobile Subscriber Identity
    mcc: str                # Mobile Country Code
    mnc: str                # Mobile Network Code
    meid: str               # Mobile Equipment Identifier (from carrier bundle)
    carrier_bundle: str     # e.g. "com.apple.SFR_fr"
    carrier_version: str    # e.g. "65.0"


# ── DeviceInfo ────────────────────────────────────────────────────────────────

@dataclass
class DeviceInfo:
    """Forensically relevant device attributes collected from lockdown."""

    # ── Primary identifiers (never overridable — come from device only) ────────
    udid: str                   # UniqueDeviceID
    imei: str                   # InternationalMobileEquipmentIdentity
    imei2: str                  # InternationalMobileEquipmentIdentity2 (dual-SIM)
    meid: str                   # MobileEquipmentIdentifier (CDMA)
    serial_number: str          # SerialNumber (external label)
    mlb_serial: str             # MLBSerialNumber (motherboard)
    ecid: str                   # UniqueChipID as hex string
    chip_id: str                # ChipID

    # ── Device identity ────────────────────────────────────────────────────────
    device_name: str            # user-assigned name ("John's iPhone")
    device_class: str           # "iPhone" | "iPad" | …
    product_type: str           # "iPhone12,3"
    hardware_model: str         # "D421AP"
    model_number: str           # "MWC22" (region SKU)
    cpu_architecture: str       # "arm64e"
    hardware_platform: str      # "t8030"

    # ── Software ───────────────────────────────────────────────────────────────
    product_version: str        # "17.4.1"
    build_version: str          # "23A355"
    baseband_version: str       # modem firmware, e.g. "7.00.00"
    firmware_version: str       # iBoot version

    # ── Telephony / SIM ────────────────────────────────────────────────────────
    phone_number: str           # "+33 6 XX XX XX" (may be empty)
    sims: list[SimInfo] = field(default_factory=list)

    # ── Network addresses ──────────────────────────────────────────────────────
    wifi_mac: str = ""
    bluetooth_mac: str = ""
    ethernet_mac: str = ""

    # ── State at acquisition ───────────────────────────────────────────────────
    activation_state: str = ""  # "Activated"
    password_protected: bool = False
    timezone: str = ""          # "Europe/Zurich"
    timezone_offset_utc: float = 0.0  # seconds
    device_time_utc: float = 0.0      # TimeIntervalSince1970 — clock sync reference
    region_info: str = ""       # "ZD/A"

    # ── Connection metadata ────────────────────────────────────────────────────
    connection_type: str = "USB"

    def display_table(self) -> str:
        lines = [
            ("UDID",              self.udid),
            ("IMEI",              self.imei or "(not available)"),
            ("IMEI2",             self.imei2 or "(not available)"),
            ("Serial",            self.serial_number or "(not available)"),
            ("Name",              self.device_name),
            ("Model",             f"{self.product_type}  {self.hardware_model}".strip()),
            ("iOS",               f"{self.product_version} ({self.build_version})"),
            ("Baseband",          self.baseband_version or "(not available)"),
            ("Phone number",      self.phone_number or "(not available)"),
            ("Wi-Fi MAC",         self.wifi_mac or "(not available)"),
            ("Bluetooth MAC",     self.bluetooth_mac or "(not available)"),
            ("Timezone",          self.timezone or "(not available)"),
            ("Locked",            "Yes" if self.password_protected else "No"),
            ("Activation",        self.activation_state or "(not available)"),
            ("Connection",        self.connection_type),
        ]
        label_w = max(len(r[0]) for r in lines)
        rows = "\n".join(f"  {label:<{label_w}} : {value}" for label, value in lines)

        sim_lines = []
        for i, sim in enumerate(self.sims, 1):
            sim_type = "eSIM" if sim.is_embedded else "SIM"
            sim_lines.append(
                f"  SIM {i} ({sim_type:<4})  ICCID={sim.iccid}  IMSI={sim.imsi}"
                f"  MCC={sim.mcc} MNC={sim.mnc}  carrier={sim.carrier_bundle}"
            )
        if sim_lines:
            rows += "\n" + "\n".join(sim_lines)
        return rows

    def to_dict(self) -> dict:
        """Return a JSON-serialisable dict of all fields."""
        return {
            "udid":               self.udid,
            "imei":               self.imei,
            "imei2":              self.imei2,
            "meid":               self.meid,
            "serial_number":      self.serial_number,
            "mlb_serial":         self.mlb_serial,
            "ecid":               self.ecid,
            "chip_id":            self.chip_id,
            "device_name":        self.device_name,
            "device_class":       self.device_class,
            "product_type":       self.product_type,
            "hardware_model":     self.hardware_model,
            "model_number":       self.model_number,
            "cpu_architecture":   self.cpu_architecture,
            "hardware_platform":  self.hardware_platform,
            "product_version":    self.product_version,
            "build_version":      self.build_version,
            "baseband_version":   self.baseband_version,
            "firmware_version":   self.firmware_version,
            "phone_number":       self.phone_number,
            "sims": [
                {
                    "slot":             s.slot,
                    "is_embedded":      s.is_embedded,
                    "iccid":            s.iccid,
                    "imsi":             s.imsi,
                    "mcc":              s.mcc,
                    "mnc":              s.mnc,
                    "meid":             s.meid,
                    "carrier_bundle":   s.carrier_bundle,
                    "carrier_version":  s.carrier_version,
                }
                for s in self.sims
            ],
            "wifi_mac":                 self.wifi_mac,
            "bluetooth_mac":            self.bluetooth_mac,
            "ethernet_mac":             self.ethernet_mac,
            "activation_state":         self.activation_state,
            "password_protected":       self.password_protected,
            "timezone":                 self.timezone,
            "timezone_offset_utc":      self.timezone_offset_utc,
            "device_time_utc":          self.device_time_utc,
            "region_info":              self.region_info,
            "connection_type":          self.connection_type,
        }
