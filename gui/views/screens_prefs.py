"""Preferences screen: Settings + About.

Defines : SettingsScreen — workstation display preferences (recent-DB list,
          appearance, reduce-motion, preferred timezone) backed by
          :class:`gui.settings_store.SettingsStore`, plus an About panel with the
          wordmark and version/platform rows.
Used by : gui.views.shell (stacked screen, reached via the Preferences submenu).
Uses    : PySide6, gui.settings_store, gui.widgets.components, forensic_aul.__version__.

Preferences are display-only and stored locally — they are never written to a
case database or its audit trail (a forensic boundary the mockup states explicitly).
"""

from __future__ import annotations

import platform
from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from forensic_aul import __version__
from gui.settings_store import SettingsStore
from gui.views.screen_base import ScrollScreen
from gui.widgets.components import (
    ComboBox,
    Divider,
    Panel,
    asset_pixmap,
    eyebrow,
    h1,
    h2,
    help_label,
    make_icon,
    mono,
    style_combo,
    subtitle,
)


class SettingsScreen(ScrollScreen):
    """Display preferences for this workstation, plus an About panel."""

    screen_id = "settings"

    def __init__(self, settings: SettingsStore) -> None:
        super().__init__(max_width=860)
        self._settings = settings

        self.content.addWidget(eyebrow("Preferences"))
        self.content.addWidget(h1("Settings"))
        self.content.addWidget(subtitle(
            "Display preferences for this workstation. Stored locally — never "
            "written to the case database or its audit trail."
        ))

        # ── Interface ──────────────────────────────────────────────────────────
        interface = Panel()
        interface.add(h2("Interface"))
        interface.body.addLayout(self._pref_row(
            "Show recent databases",
            "List recently-opened databases at the top of each pipeline step.",
            self._checkbox("recentDb"),
        ))
        interface.add(Divider())
        interface.body.addLayout(self._pref_row(
            "Reduce motion",
            "Suppress non-essential transitions in the log panel and timeline.",
            self._checkbox("reduceMotion"),
        ))
        self.content.addWidget(interface)

        # ── Time ──────────────────────────────────────────────────────────────
        time_panel = Panel()
        time_panel.add(h2("Time"))
        time_panel.body.addLayout(self._pref_row(
            "Preferred timezone",
            "UTC keeps cases portable. Local converts for display. Raw keeps each "
            "row's source zone — mixed-zone cases stay mixed.",
            self._combo("tz", [("utc", "UTC"), ("local", _local_label()), ("raw", "Raw")]),
        ))
        self.content.addWidget(time_panel)
        self.content.addWidget(mono(f"{self._settings.path} · sync: off"))

        # ── About ──────────────────────────────────────────────────────────────
        self.content.addWidget(self._about_panel())
        self.content.addStretch(1)

    def _checkbox(self, key: str) -> QCheckBox:
        """A native on/off control bound to *key* (label lives in the row, not here)."""
        box = QCheckBox()
        box.setChecked(bool(self._settings.get(key)))
        box.setCursor(Qt.CursorShape.PointingHandCursor)
        box.toggled.connect(lambda v, k=key: self._settings.set(k, v))
        return box

    def _combo(self, key: str, options: list[tuple[str, str]]) -> ComboBox:
        """A native picker bound to *key*; *options* are ``(value, label)`` pairs."""
        combo = ComboBox()
        combo.setCursor(Qt.CursorShape.PointingHandCursor)
        for value, label in options:
            combo.addItem(label, value)
        current = str(self._settings.get(key))
        index = combo.findData(current)
        if index >= 0:
            combo.setCurrentIndex(index)
        combo.currentIndexChanged.connect(
            lambda _i, k=key, c=combo: self._settings.set(k, c.currentData())
        )
        style_combo(combo)
        return combo

    def _pref_row(self, label: str, help_text: str, control: QWidget) -> QHBoxLayout:
        """A settings row: bold label, muted help, right-aligned control."""
        row = QHBoxLayout()
        row.setContentsMargins(0, 6, 0, 6)
        row.setSpacing(18)
        text_col = QVBoxLayout()
        text_col.setSpacing(2)
        name = QLabel(label)
        name.setStyleSheet("color:#e6e9ef; font-weight:500; font-size:12px;")
        text_col.addWidget(name)
        text_col.addWidget(help_label(help_text))
        row.addLayout(text_col, 1)
        holder = QWidget()
        holder_layout = QHBoxLayout(holder)
        holder_layout.setContentsMargins(0, 0, 0, 0)
        holder_layout.addStretch(1)
        holder_layout.addWidget(control)
        row.addWidget(holder)
        return row

    def _about_panel(self) -> Panel:
        panel = Panel()
        panel.body.setContentsMargins(0, 0, 0, 0)

        hero = QWidget()
        hero.setStyleSheet("background:#0a0c12; border-top-left-radius:6px; border-top-right-radius:6px;")
        hero_layout = QVBoxLayout(hero)
        hero_layout.setContentsMargins(24, 22, 24, 22)
        wordmark = QLabel()
        pixmap = asset_pixmap("faul-wordmark.png")
        if not pixmap.isNull():
            wordmark.setPixmap(pixmap.scaledToHeight(96, Qt.TransformationMode.SmoothTransformation))
        wordmark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hero_layout.addWidget(wordmark)
        panel.body.addWidget(hero)

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(20, 18, 20, 18)
        inner_layout.setSpacing(10)
        inner_layout.addWidget(h2("About"))

        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(4)
        rows = [
            ("version", __version__),
            ("platform", f"{platform.system()} {platform.release()} · {platform.machine()}"),
            ("python", platform.python_version()),
            ("license", "forensic-aul · open source · MIT"),
        ]
        for i, (key, value) in enumerate(rows):
            key_label = QLabel(key.upper())
            key_label.setProperty("role", "statLabel")
            value_label = QLabel(value)
            value_label.setStyleSheet("color:#e6e9ef;")
            grid.addWidget(key_label, i, 0, Qt.AlignmentFlag.AlignTop)
            grid.addWidget(value_label, i, 1)
        grid.setColumnStretch(1, 1)
        inner_layout.addLayout(grid)

        blurb = help_label(
            "A patient triage workbench for Apple unified logs. Acquires, parses, "
            "exports — sealed and audited at every step."
        )
        inner_layout.addWidget(blurb)

        buttons = QHBoxLayout()
        copy_btn = QPushButton("Copy version")
        copy_btn.setProperty("variant", "ghost")
        copy_btn.setProperty("sm", "true")
        copy_btn.setIcon(make_icon("copy", 11))
        copy_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        copy_btn.clicked.connect(self._copy_version)
        buttons.addWidget(copy_btn)
        buttons.addStretch(1)
        inner_layout.addLayout(buttons)

        panel.body.addWidget(inner)
        return panel

    def _copy_version(self) -> None:
        from PySide6.QtWidgets import QApplication

        QApplication.clipboard().setText(f"forensic-aul {__version__}")


def _local_label() -> str:
    """A "Local +HH:MM" label reflecting this workstation's UTC offset."""
    offset = datetime.now().astimezone().utcoffset()
    minutes = int(offset.total_seconds() // 60) if offset else 0
    sign = "+" if minutes >= 0 else "−"
    return f"Local {sign}{abs(minutes) // 60:02d}:{abs(minutes) % 60:02d}"
