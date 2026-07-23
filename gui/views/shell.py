"""The FAUL application shell — frameless window, sidebar, screen stack, log panel.

Defines : MainWindow — a macOS-style frameless window with a draggable titlebar
          (functional traffic-light controls), a left sidebar navigating the
          pipeline / reference / preferences sections, a stacked screen area, and
          a docked, resizable application-log panel. Future screens appear in the
          sidebar greyed-out with a "available in vN" tooltip.
Used by : gui.app.build_main_window().
Uses    : PySide6, the v1 screens (gui.views.screens_*), gui.widgets.components,
          gui.widgets.log_panel, gui.settings_store, gui.recent_store, gui.theme.

WHY frameless: the design is explicitly a macOS window; a custom titlebar with
traffic lights is core to its identity. Native resize is preserved with a corner
QSizeGrip, and the window stays movable via titlebar drag.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizeGrip,
    QSplitter,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from gui.recent_store import RecentStore
from gui.settings_store import SettingsStore
from gui.theme import build_stylesheet
from gui.views.screen_exploit import ExploitScreen
from gui.views.screen_identify_hub import IdentifyHub
from gui.views.screens_data import ExportScreen, VerifyHashScreen
from gui.views.screens_pipeline import AcquireScreen, ExtractScreen
from gui.views.screens_prefs import SettingsScreen
from gui.widgets.components import TrafficLights, asset_pixmap, make_icon
from gui.widgets.log_panel import LogPanel

# Sidebar layout. Each item: (id, number/badge, label, enabled, future_tag).
# Disabled items are placeholders for later roadmap versions. Consumed by:
# MainWindow._build_sidebar.
_PIPELINE = [
    ("acquire", "1", "Acquire", True, ""),
    ("extract", "2", "Extract", True, ""),
    ("exploit", "3", "Exploit", True, ""),
    ("export", "4", "Export", True, ""),
    ("verify-hash", "·", "Verify hash", True, ""),
]
_REFERENCE = [
    ("identify", "·", "Identify", True, ""),
    ("kb", "·", "Knowledge base", False, "v4"),
]
# Preference submenu: (id, label, enabled, future_tag).
_PREFS = [
    ("settings", "Settings", True, ""),
    ("kb-debug", "KB match debug", False, "v4"),
    ("update-kb", "Update KB", False, "v3"),
    ("validate-kb", "Lint KB", False, "v4"),
    ("validate-faul", "Validate FAUL", False, "v2"),
]

# Human labels for the titlebar breadcrumb. Consumed by: MainWindow._set_title.
_SCREEN_LABELS = {
    "acquire": "Acquire", "extract": "Extract", "exploit": "Exploit",
    "export": "Export", "verify-hash": "Verify hash", "settings": "Settings",
    "identify": "Identify",
}


class _TitleBar(QWidget):
    """Draggable titlebar; double-click toggles maximise (macOS convention)."""

    def __init__(self, window: QWidget, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("titlebar")
        self.setFixedHeight(36)
        self._window = window
        self._press_pos = None

    def mousePressEvent(self, event) -> None:  # noqa: N802 - Qt override
        if event.button() == Qt.MouseButton.LeftButton:
            # Remember the offset from the window origin to drag it 1:1.
            self._press_pos = event.globalPosition().toPoint() - self._window.frameGeometry().topLeft()

    def mouseMoveEvent(self, event) -> None:  # noqa: N802 - Qt override
        if self._press_pos is not None and event.buttons() & Qt.MouseButton.LeftButton:
            self._window.move(event.globalPosition().toPoint() - self._press_pos)

    def mouseReleaseEvent(self, _event) -> None:  # noqa: N802 - Qt override
        self._press_pos = None

    def mouseDoubleClickEvent(self, _event) -> None:  # noqa: N802 - Qt override
        self._window.toggle_maximise()


class MainWindow(QWidget):
    """Top-level window: titlebar + (sidebar | stacked screens + log panel)."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowFlag(Qt.WindowType.FramelessWindowHint, True)
        # Translucent so the area outside the rounded #appRoot corners is see-through,
        # giving the frameless window genuine rounded corners (see _build_main / QSS).
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setWindowTitle("FAUL · forensic-aul")
        icon = asset_pixmap("faul-icon.png")
        if not icon.isNull():
            self.setWindowIcon(QIcon(icon))
        self.resize(1180, 800)
        self.setMinimumSize(980, 640)

        self._settings = SettingsStore(self)
        self._recents = RecentStore()

        self._nav_buttons: dict[str, QPushButton] = {}
        self._nav_group = QButtonGroup(self)
        self._nav_group.setExclusive(True)
        self._screen_index: dict[str, int] = {}

        # All content lives in a rounded #appRoot frame; the window itself is
        # transparent, so #appRoot's border-radius reads as rounded window corners.
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        self._app_root = QFrame()
        self._app_root.setObjectName("appRoot")
        outer.addWidget(self._app_root)

        root = QVBoxLayout(self._app_root)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._build_titlebar())

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        body.addWidget(self._build_sidebar())
        body.addWidget(self._build_main(), 1)
        root.addLayout(body, 1)

        # Corner grip for native-feeling resize on a frameless window (child of the
        # rounded frame so it sits inside the visible window area).
        self._grip = QSizeGrip(self._app_root)
        self._grip.resize(16, 16)

        self.apply_theme()
        self.set_current("acquire")

    # ── Titlebar ────────────────────────────────────────────────────────────────

    def _build_titlebar(self) -> QWidget:
        bar = _TitleBar(self)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(12, 0, 12, 0)
        layout.setSpacing(10)
        layout.addWidget(TrafficLights(self.close, self.showMinimized, self.toggle_maximise))
        layout.addStretch(1)
        self._title_label = QLabel()
        self._title_label.setObjectName("titleText")
        self._title_label.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(self._title_label)
        layout.addStretch(1)
        # Right-side spacer balances the traffic lights so the title stays centred.
        spacer = QWidget()
        spacer.setFixedWidth(56)
        layout.addWidget(spacer)
        return bar

    def _set_title(self, screen_id: str) -> None:
        label = _SCREEN_LABELS.get(screen_id, "")
        self._title_label.setText(
            "<span id='titleApp' style='color:#e6e9ef;font-weight:600'>FAUL</span>"
            "<span style='color:#3f4452'> · </span>"
            "<span style='color:#7a8090'>forensic-aul</span>"
            "<span style='color:#3f4452'> &nbsp;—&nbsp; </span>"
            f"<span style='color:#b8bdc7'>{label}</span>"
        )

    def toggle_maximise(self) -> None:
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()

    # ── Sidebar ────────────────────────────────────────────────────────────────

    def _build_sidebar(self) -> QWidget:
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(220)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 0, 0, 8)
        layout.setSpacing(0)

        layout.addWidget(self._build_brand())
        self._add_section(layout, "PIPELINE", _PIPELINE)
        self._add_section(layout, "REFERENCE", _REFERENCE)
        layout.addStretch(1)
        layout.addWidget(self._section_label("SYSTEM"))
        layout.addWidget(self._build_preferences())
        return sidebar

    def _build_brand(self) -> QWidget:
        brand = QWidget()
        brand.setObjectName("sidebarBrand")
        layout = QHBoxLayout(brand)
        layout.setContentsMargins(14, 12, 14, 14)
        layout.setSpacing(10)
        mark = QLabel()
        pixmap = asset_pixmap("faul-icon.png")
        if not pixmap.isNull():
            mark.setPixmap(pixmap.scaled(28, 28, Qt.AspectRatioMode.KeepAspectRatio,
                                         Qt.TransformationMode.SmoothTransformation))
        layout.addWidget(mark)
        text = QVBoxLayout()
        text.setSpacing(2)
        name = QLabel("FAUL")
        name.setObjectName("sidebarBrandName")
        sub = QLabel("forensic-aul")
        sub.setObjectName("sidebarBrandSub")
        text.addWidget(name)
        text.addWidget(sub)
        layout.addLayout(text)
        layout.addStretch(1)
        return brand

    def _section_label(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setProperty("role", "sidebarSection")
        return label

    def _add_section(self, layout: QVBoxLayout, title: str, items: list) -> None:
        layout.addWidget(self._section_label(title))
        for screen_id, badge, label, enabled, tag in items:
            layout.addWidget(self._nav_button(screen_id, badge, label, enabled, tag))

    def _nav_button(self, screen_id, badge, label, enabled, tag, *, indent=False) -> QPushButton:
        button = QPushButton()
        button.setProperty("nav", "true")
        button.setCheckable(enabled)
        button.setEnabled(enabled)
        button.setCursor(Qt.CursorShape.PointingHandCursor if enabled else Qt.CursorShape.ArrowCursor)
        if not enabled and tag:
            button.setToolTip(f"Available in {tag}")

        row = QHBoxLayout(button)
        row.setContentsMargins(28 if indent else 16, 0, 14, 0)
        row.setSpacing(10)
        if badge:
            num = QLabel(badge)
            num.setProperty("role", "navNum")
            num.setFixedWidth(12)
            num.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
            row.addWidget(num)
        text = QLabel(label)
        text.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        text.setStyleSheet("background:transparent;")
        row.addWidget(text)
        row.addStretch(1)
        # Future screens are conveyed by the greyed/disabled state + a tooltip,
        # not an inline badge (which would overflow the fixed-width sidebar).

        if enabled:
            button.clicked.connect(lambda _checked=False, sid=screen_id: self.set_current(sid))
            self._nav_group.addButton(button)
            self._nav_buttons[screen_id] = button
        return button

    def _build_preferences(self) -> QWidget:
        holder = QWidget()
        layout = QVBoxLayout(holder)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        toggle = QPushButton()
        toggle.setProperty("nav", "true")
        toggle.setCheckable(False)
        toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        row = QHBoxLayout(toggle)
        row.setContentsMargins(16, 0, 14, 0)
        row.setSpacing(10)
        gear = QLabel()
        gear.setPixmap(make_icon("gear", 13, "#7a8090").pixmap(13, 13))
        gear.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        row.addWidget(gear)
        text = QLabel("Preferences")
        text.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        text.setStyleSheet("background:transparent;")
        row.addWidget(text)
        row.addStretch(1)
        self._prefs_caret = QLabel("▸")
        self._prefs_caret.setProperty("role", "navNum")
        self._prefs_caret.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        row.addWidget(self._prefs_caret)
        layout.addWidget(toggle)

        submenu = QWidget()
        sub_layout = QVBoxLayout(submenu)
        sub_layout.setContentsMargins(0, 0, 0, 0)
        sub_layout.setSpacing(0)
        for screen_id, label, enabled, tag in _PREFS:
            sub_layout.addWidget(self._nav_button(screen_id, "", label, enabled, tag, indent=True))
        submenu.setVisible(False)
        layout.addWidget(submenu)

        def _toggle_submenu() -> None:
            visible = not submenu.isVisible()
            submenu.setVisible(visible)
            self._prefs_caret.setText("▾" if visible else "▸")

        toggle.clicked.connect(_toggle_submenu)
        self._prefs_submenu = submenu
        return holder

    # ── Main area (screens + log panel) ──────────────────────────────────────────

    def _build_main(self) -> QWidget:
        main = QWidget()
        main.setObjectName("main")
        layout = QVBoxLayout(main)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setHandleWidth(1)
        splitter.setChildrenCollapsible(False)

        self._stack = QStackedWidget()
        self._add_screen(AcquireScreen(self._settings, self._recents))
        self._add_screen(ExtractScreen(self._settings, self._recents))
        self._add_screen(ExploitScreen(self._settings, self._recents))
        self._add_screen(ExportScreen(self._settings, self._recents))
        self._add_screen(VerifyHashScreen(self._settings, self._recents))
        self._add_screen(IdentifyHub(self._settings, self._recents))
        self._add_screen(SettingsScreen(self._settings))
        splitter.addWidget(self._stack)

        self._log_panel = LogPanel()
        splitter.addWidget(self._log_panel)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 0)
        splitter.setSizes([560, 200])
        # Collapsing the log panel only hides its body; the splitter keeps the
        # pane's height unless we resize it. Remember the open size and shrink to
        # just the header on collapse, restoring it on expand.
        self._main_splitter = splitter
        self._log_open_sizes = [560, 200]
        self._log_panel.collapsedChanged.connect(self._on_log_collapsed)
        layout.addWidget(splitter, 1)
        return main

    def _on_log_collapsed(self, collapsed: bool) -> None:
        sizes = self._main_splitter.sizes()
        if collapsed:
            self._log_open_sizes = sizes  # remember to restore on expand
            header = self._log_panel.header_height
            self._main_splitter.setSizes([sum(sizes) - header, header])
        else:
            self._main_splitter.setSizes(self._log_open_sizes)

    def _add_screen(self, screen: QWidget) -> None:
        index = self._stack.addWidget(screen)
        self._screen_index[screen.screen_id] = index
        if hasattr(screen, "navigate"):
            screen.navigate = self.set_current
        # The Identify hub holds child screens that navigate; it exposes
        # set_navigate to forward the shell's callback to them (it has no
        # navigate attribute of its own).
        if hasattr(screen, "set_navigate"):
            screen.set_navigate(self.set_current)

    @property
    def log_panel(self) -> LogPanel:
        return self._log_panel

    # ── Navigation ──────────────────────────────────────────────────────────────

    def set_current(self, screen_id: str, *, prefill: dict | None = None) -> None:
        index = self._screen_index.get(screen_id)
        if index is None:
            return
        self._stack.setCurrentIndex(index)
        button = self._nav_buttons.get(screen_id)
        if button is not None:
            button.setChecked(True)
        # Forward an optional payload to a target screen that knows how to consume
        # it (e.g. Acquire → Extract hand-off pre-filling the case metadata).
        if prefill:
            target = self._stack.widget(index)
            prefiller = getattr(target, "prefill", None)
            if callable(prefiller):
                prefiller(prefill)
        # Reveal the Preferences submenu when navigating into it.
        if screen_id == "settings" and not self._prefs_submenu.isVisible():
            self._prefs_submenu.setVisible(True)
            self._prefs_caret.setText("▾")
        self._set_title(screen_id)

    # ── Theming ───────────────────────────────────────────────────────────────────

    def apply_theme(self) -> None:
        # Single dark theme — no per-setting re-theming to react to.
        self.setStyleSheet(build_stylesheet())

    # ── Window plumbing ───────────────────────────────────────────────────────────

    def resizeEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().resizeEvent(event)
        # Keep the resize grip pinned to the bottom-right corner.
        self._grip.move(self.width() - self._grip.width(), self.height() - self._grip.height())

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt override
        # WHY block on close: a worker thread destroyed mid-run aborts the
        # process (and could leave a half-written database). For a forensic tool
        # it is safer to wait for the in-flight operation to finish than to risk
        # corrupting its output, so we drain any running worker before closing.
        for index in range(self._stack.count()):
            screen = self._stack.widget(index)
            thread = getattr(screen, "_thread", None)
            try:
                if thread is not None and thread.isRunning():
                    thread.wait()
            except RuntimeError:
                pass  # the C++ thread object was already finalised — nothing to wait on
        super().closeEvent(event)
