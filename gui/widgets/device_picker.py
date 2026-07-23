"""A connected-device picker: a combo of enumerated devices + a rescan button.

Defines : DevicePicker, a small composite that lists connected iOS devices in a
          combo and offers a rescan button, with scanning / failed label states.
          Extracted verbatim from AcquireScreen's device block so both the Acquire
          pipeline view and the Identify wizard can reuse the same widget without
          duplicating the enumeration UI. Pure view widget — no business logic; the
          owning screen's controller drives the scan and consumes ``selected_udid``.
Used by : gui.views.screens_pipeline (AcquireScreen), gui.views.screens_identify
          (IdentifyScreen).
Uses    : PySide6, gui.widgets.components (ComboBox, make_icon).
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QHBoxLayout, QPushButton, QWidget

from gui.widgets.components import ComboBox, make_icon


class DevicePicker(QWidget):
    """A combo listing connected devices + a rescan button.

    The owning screen wires :attr:`rescanRequested` to its controller's rescan and
    drives the display via :meth:`set_scanning` / :meth:`set_devices` /
    :meth:`set_scan_failed`; it reads the choice through :meth:`selected_udid`.
    """

    rescanRequested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._device = ComboBox()
        self._device.addItem("No device scanned — click ⟳ to enumerate", None)

        rescan = QPushButton()
        rescan.setProperty("iconbtn", "true")
        rescan.setIcon(make_icon("refresh", 14))
        rescan.setToolTip("Re-scan for connected devices")
        rescan.setCursor(Qt.CursorShape.PointingHandCursor)
        # The picker only announces the intent; the screen's controller runs the
        # (async) enumeration off-thread and calls the setters below with results.
        rescan.clicked.connect(self.rescanRequested.emit)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        layout.addWidget(self._device, 1)
        layout.addWidget(rescan)

    # ── Display states (driven by the owning screen's controller) ─────────────────

    def set_scanning(self) -> None:
        self._device.clear()
        self._device.addItem("Scanning…", None)
        self._device.setEnabled(False)

    def set_devices(self, devices: list[Any]) -> None:
        self._device.setEnabled(True)
        self._device.clear()
        if not devices:
            self._device.addItem("No devices connected", None)
            return
        for dev in devices:
            name = getattr(dev, "device_name", "") or ""  # user-assigned, e.g. "John's iPhone"
            model = getattr(dev, "product_type", None) or getattr(dev, "device_class", None) or "device"
            version = getattr(dev, "product_version", "")
            ident = getattr(dev, "imei", None) or getattr(dev, "udid", "?")
            # Join only the parts present, so a device missing a field stays tidy.
            parts = [p for p in (name, model, f"iOS {version}" if version else "", ident) if p]
            self._device.addItem(" · ".join(parts), getattr(dev, "udid", None))

    def set_scan_failed(self) -> None:
        self._device.setEnabled(True)
        self._device.clear()
        self._device.addItem("Scan unavailable (is pymobiledevice3 installed?)", None)

    # ── Selection ─────────────────────────────────────────────────────────────────

    def selected_udid(self) -> str | None:
        return self._device.currentData()
