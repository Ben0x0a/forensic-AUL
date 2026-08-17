"""Shared, themable UI primitives for the FAUL shell.

Defines : the small building blocks every screen reuses — stroke icons rendered
          from SVG (``make_icon``), heading/label factories (``eyebrow``, ``h1``,
          ``subtitle`` …), :class:`Pill`, :class:`Panel`, :class:`Divider`,
          :class:`Stat`, :func:`field_row`, and :class:`TrafficLights`.
Used by : gui.views.shell and gui.views.screens.* (composition only).
Uses    : PySide6 (QtWidgets/QtGui/QtCore, QtSvg when available); gui.theme
          (DARK_TOKENS, so colours are sourced from the palette, never literals).
          No business logic.

WHY a primitives module: QSS styles *appearance* but not structure; the mockup's
look comes as much from consistent spacing/composition as from colour. Centralising
the structural pieces keeps every screen visually consistent and the screen files
focused on content, mirroring the mockup's ``ui.jsx`` shared component layer.
"""

from __future__ import annotations

from collections.abc import Callable
from importlib.resources import files

from PySide6.QtCore import QByteArray, QPoint, QSize, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPixmap
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from gui.theme import DARK_TOKENS

try:  # QtSvg ships with the standard PySide6 wheel, but degrade gracefully.
    from PySide6.QtSvg import QSvgRenderer

    _HAVE_SVG = True
except ImportError:  # pragma: no cover - environment-dependent
    _HAVE_SVG = False

# Default icon tint — matches the mockup's "text-dim". Sourced from DARK_TOKENS
# (not a literal) so it stays in lock-step with the rest of the palette.
# Consumed by: make_icon().
_ICON_COLOUR = DARK_TOKENS["text_dim"]

# ── Icon path data (ported verbatim from project/ui.jsx) ──────────────────────
# Each entry is the inner markup of a 24×24 stroke icon; ``make_icon`` wraps it in
# an <svg> with stroke colour/width matching the mockup. ``$C`` is the fill slot
# for solid glyphs. Consumed by: make_icon().
_ICON_PATHS: dict[str, str] = {
    "check": '<path d="M4 12l5 5 11-12"/>',
    "x": '<path d="M5 5l14 14M19 5L5 19"/>',
    "warn": '<path d="M12 3l10 18H2L12 3z"/><path d="M12 10v5M12 18v.5"/>',
    "shield": '<path d="M12 3l8 3v6c0 5-3.5 8.5-8 9-4.5-.5-8-4-8-9V6l8-3z"/>',
    "lock": '<rect x="5" y="11" width="14" height="9" rx="1.5"/><path d="M8 11V7a4 4 0 018 0v4"/>',
    "phone": '<rect x="7" y="2" width="10" height="20" rx="2"/><path d="M11 19h2"/>',
    "mac": '<rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M9 20h6M12 16v4"/>',
    "folder": '<path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v9a2 2 0 01-2 2H5a2 2 0 01-2-2V7z"/>',
    "file": '<path d="M6 3h8l4 4v14a1 1 0 01-1 1H6a1 1 0 01-1-1V4a1 1 0 011-1z"/><path d="M14 3v4h4"/>',
    "db": ('<ellipse cx="12" cy="5" rx="8" ry="2.5"/>'
           '<path d="M4 5v6c0 1.4 3.6 2.5 8 2.5s8-1.1 8-2.5V5M4 11v6c0 1.4 3.6 2.5 8 2.5s8-1.1 8-2.5v-6"/>'),
    "play": '<path d="M7 4l13 8-13 8V4z" fill="$C" stroke="none"/>',
    "stop": '<rect x="5" y="5" width="14" height="14" rx="1"/>',
    "search": '<circle cx="11" cy="11" r="6"/><path d="M16 16l4 4"/>',
    "filter": '<path d="M3 5h18l-7 9v6l-4-2v-4L3 5z"/>',
    "down": '<path d="M6 9l6 6 6-6"/>',
    # Arrow onto a baseline — "follow the end of the stream". Distinct from the
    # bare "down" chevron, which means "expand/collapse"; the log panel had both
    # meanings on the same glyph and neither was readable.
    "to-bottom": '<path d="M12 3v11M7 10l5 5 5-5M5 20h14"/>',
    "up": '<path d="M6 15l6-6 6 6"/>',
    "right": '<path d="M9 6l6 6-6 6"/>',
    "left": '<path d="M15 6l-6 6 6 6"/>',
    "plus": '<path d="M12 5v14M5 12h14"/>',
    "copy": '<rect x="8" y="8" width="12" height="12" rx="1.5"/><path d="M4 16V5a1 1 0 011-1h11"/>',
    "export": '<path d="M12 3v12M7 8l5-5 5 5"/><path d="M5 17v3h14v-3"/>',
    "refresh": ('<path d="M3 12a9 9 0 0115-6.7L21 8M21 3v5h-5M21 12a9 9 0 01-15 6.7'
                'L3 16M3 21v-5h5"/>'),
    "gear": ('<circle cx="12" cy="12" r="3"/>'
             '<path d="M19.4 15a1.7 1.7 0 00.3 1.8l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.7 1.7 0 00-1.8-.3 '
             '1.7 1.7 0 00-1 1.5V21a2 2 0 11-4 0v-.1a1.7 1.7 0 00-1.1-1.5 1.7 1.7 0 00-1.8.3l-.1.1a2 '
             '2 0 11-2.8-2.8l.1-.1a1.7 1.7 0 00.3-1.8 1.7 1.7 0 00-1.5-1H3a2 2 0 110-4h.1a1.7 1.7 0 '
             '001.5-1.1 1.7 1.7 0 00-.3-1.8l-.1-.1a2 2 0 112.8-2.8l.1.1a1.7 1.7 0 001.8.3H9a1.7 1.7 0 '
             '001-1.5V3a2 2 0 114 0v.1a1.7 1.7 0 001 1.5 1.7 1.7 0 001.8-.3l.1-.1a2 2 0 112.8 2.8l-.1.1a'
             '1.7 1.7 0 00-.3 1.8V9a1.7 1.7 0 001.5 1H21a2 2 0 110 4h-.1a1.7 1.7 0 00-1.5 1z"/>'),
    "list": '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
    "eye": '<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    "tag": '<path d="M3 12V4a1 1 0 011-1h8l9 9-9 9-9-9z"/><circle cx="8" cy="8" r="1"/>',
    "diff": '<path d="M9 3v18M9 7l-3-3M9 7l3-3M15 21V3M15 17l-3 3M15 17l3 3"/>',
    "kb": '<path d="M4 4h16v3H4zM4 10h16v3H4zM4 16h10v3H4z"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    "hash": '<path d="M5 9h15M4 15h15M10 4l-2 16M16 4l-2 16"/>',
    "pulse": '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
}

# Cache rendered icons by (name, size, colour) so repeated buttons share pixmaps.
_ICON_CACHE: dict[tuple[str, int, str], QIcon] = {}


def make_icon(name: str, size: int = 14, colour: str = _ICON_COLOUR) -> QIcon:
    """Return a crisp 1.6-stroke icon by *name* (see :data:`_ICON_PATHS`).

    Renders the SVG at 2× into a high-DPI pixmap so it stays sharp. Returns an
    empty :class:`QIcon` for an unknown name or when QtSvg is unavailable, so a
    caller can always set it without guarding.
    """
    key = (name, size, colour)
    cached = _ICON_CACHE.get(key)
    if cached is not None:
        return cached
    inner = _ICON_PATHS.get(name)
    if inner is None or not _HAVE_SVG:
        icon = QIcon()
        _ICON_CACHE[key] = icon
        return icon
    inner = inner.replace("$C", colour)
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" '
        f'fill="none" stroke="{colour}" stroke-width="1.6" '
        f'stroke-linecap="round" stroke-linejoin="round">{inner}</svg>'
    )
    renderer = QSvgRenderer(QByteArray(svg.encode("utf-8")))
    scale = 2  # render at 2× for retina crispness, then mark the DPR
    pixmap = QPixmap(size * scale, size * scale)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    renderer.render(painter)
    painter.end()
    pixmap.setDevicePixelRatio(scale)
    icon = QIcon(pixmap)
    _ICON_CACHE[key] = icon
    return icon


# ── Packaged assets ─────────────────────────────────────────────────────────

def asset_pixmap(name: str) -> QPixmap:
    """Load a bundled image from ``gui/assets`` as a QPixmap.

    Uses importlib.resources so it works whether the package is run from source,
    pip-installed, or frozen — never assumes a filesystem layout via ``__file__``.
    """
    pixmap = QPixmap()
    try:
        data = files("gui").joinpath("assets", name).read_bytes()
        pixmap.loadFromData(data)
    except (FileNotFoundError, OSError, ModuleNotFoundError):
        pass  # a missing decorative asset must not stop the GUI
    return pixmap


# ── Label factories ───────────────────────────────────────────────────────────

def _role_label(text: str, role: str, *, wrap: bool = False) -> QLabel:
    label = QLabel(text)
    label.setProperty("role", role)
    if wrap:
        label.setWordWrap(True)
    return label


def eyebrow(text: str) -> QLabel:
    """Uppercase section kicker (the mockup's ``.eyebrow``)."""
    return _role_label(text.upper(), "eyebrow")


def h1(text: str) -> QLabel:
    return _role_label(text, "h1")


def h2(text: str) -> QLabel:
    return _role_label(text, "h2")


def subtitle(text: str) -> QLabel:
    return _role_label(text, "subtitle", wrap=True)


def help_label(text: str) -> QLabel:
    return _role_label(text, "help", wrap=True)


def mono(text: str) -> QLabel:
    return _role_label(text, "mono")


class Pill(QLabel):
    """Small status badge. *kind* ∈ ok/warn/err/info/violet/neutral."""

    def __init__(self, text: str, kind: str = "neutral", parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self.setProperty("pill", kind)
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Maximum)


class Divider(QFrame):
    """A 1px horizontal rule (the mockup's ``.divider``)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setProperty("role", "divider")
        self.setFixedHeight(1)
        self.setFrameShape(QFrame.Shape.NoFrame)


class Panel(QFrame):
    """A surface card with internal padding and a vertical layout.

    Add children to :attr:`body` (the inner QVBoxLayout). *elev* uses the raised
    ``bg_elev`` surface instead of the default ``bg_surface``.
    """

    def __init__(self, *, elev: bool = False, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setProperty("card", "elev" if elev else "true")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(14, 14, 14, 14)
        self.body.setSpacing(10)

    def add(self, widget: QWidget) -> QWidget:
        self.body.addWidget(widget)
        return widget


class Stat(QWidget):
    """A KPI block: big value over an uppercase label, with an optional delta."""

    def __init__(
        self,
        label: str,
        value: str,
        delta: str = "",
        *,
        value_colour: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        lbl = _role_label(label.upper(), "statLabel")
        val = _role_label(value, "statValue")
        if value_colour:
            val.setStyleSheet(f"color: {value_colour};")
        layout.addWidget(lbl)
        layout.addWidget(val)
        if delta:
            layout.addWidget(_role_label(delta, "statDelta"))


class ComboBox(QComboBox):
    """A QComboBox whose drop-down lines up with the field.

    WHY override placement: on macOS Qt *overlays* the popup on the field and
    shifts it left by the current-item checkmark gutter — so the popup overhangs on
    the left and leaves a sliver of the field showing on the right, and its width
    follows the widest item rather than the (possibly wider) field. We instead force
    the popup to the field's own left edge and width, dropped just beneath it, so
    the drop-down sits squarely under the box.
    """

    def showPopup(self) -> None:  # noqa: N802 - Qt override
        super().showPopup()
        popup = self.view().window()  # the top-level popup container
        if popup is not None:
            below = self.mapToGlobal(QPoint(0, self.height()))
            popup.setGeometry(below.x(), below.y(), self.width(), popup.height())


def style_combo(combo: QComboBox, *, item_height: int = 28) -> QComboBox:
    """Give *combo*'s popup items a consistent height; return the combo (chainable).

    WHY a SizeHintRole rather than relying on the QSS ``::item {{ min-height }}``:
    not every Qt style honours that QSS hint for a combo's popup view, but the
    per-item SizeHintRole is applied by the view's layout regardless of style — so
    the dropdown rows line up with the rest of the UI's row rhythm everywhere.
    """
    for i in range(combo.count()):
        combo.setItemData(i, QSize(0, item_height), Qt.ItemDataRole.SizeHintRole)
    return combo


def field_row(label: str, field: QWidget, *, required: bool = False) -> QWidget:
    """A right-aligned label + field, mirroring the mockup's ``.field-row`` grid."""
    row = QWidget()
    layout = QHBoxLayout(row)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(12)
    text = f"{label} <span style='color:#f87171'>*</span>" if required else label
    lbl = QLabel(text)
    lbl.setTextFormat(Qt.TextFormat.RichText)
    lbl.setProperty("role", "subtitle")
    lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
    lbl.setFixedWidth(130)
    layout.addWidget(lbl)
    layout.addWidget(field, 1)
    return row


class TrafficLights(QWidget):
    """The macOS window-control dots — close / minimise / zoom, left to right.

    Each dot triggers the matching callback when clicked. Painted (not styled)
    because QSS cannot render the inset highlight; hovering brightens the row.
    """

    _COLOURS = ("#ff5f57", "#febc2e", "#28c840")
    _SPACING = 20
    _DIAMETER = 12

    def __init__(
        self,
        on_close: Callable[[], None],
        on_minimise: Callable[[], None],
        on_zoom: Callable[[], None],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._callbacks = (on_close, on_minimise, on_zoom)
        self._hover = False
        self.setFixedSize(56, 14)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMouseTracking(True)

    def enterEvent(self, _event) -> None:  # noqa: N802 - Qt override
        self._hover = True
        self.update()

    def leaveEvent(self, _event) -> None:  # noqa: N802 - Qt override
        self._hover = False
        self.update()

    def mousePressEvent(self, event) -> None:  # noqa: N802 - Qt override
        index = int(event.position().x()) // self._SPACING
        if 0 <= index < len(self._callbacks):
            self._callbacks[index]()

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt override
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        for i, colour in enumerate(self._COLOURS):
            dot = QColor(colour)
            if not self._hover:
                dot.setAlpha(235)
            painter.setBrush(dot)
            painter.drawEllipse(i * self._SPACING, 1, self._DIAMETER, self._DIAMETER)
        painter.end()


def repolish(widget: QWidget) -> None:
    """Force a style re-evaluation after a dynamic property changes.

    QSS selectors on dynamic properties (``variant``, ``pill``, ``chipOn``…) are
    only re-matched when the widget is re-polished, so setting the property alone
    changes nothing on screen. Public because five widgets across the GUI need it
    and were each open-coding the unpolish/polish pair.
    """
    widget.style().unpolish(widget)
    widget.style().polish(widget)


# Back-compat alias for the in-module call sites that predate the rename.
_repolish = repolish


# ── Shared inputs / buttons / result panel ─────────────────────────────────────
# Moved here from screens_pipeline.py: these are cross-screen primitives (the
# data screens use them too), so they belong in the shared component layer.

def mono_input(placeholder: str = "", text: str = "") -> QLineEdit:
    """A monospace line edit (case numbers, paths, hashes)."""
    edit = QLineEdit(text)
    edit.setProperty("mono", "true")
    if placeholder:
        edit.setPlaceholderText(placeholder)
    return edit


def primary_button(text: str, icon: str = "play") -> QPushButton:
    """The filled call-to-action button."""
    button = QPushButton(text)
    button.setProperty("variant", "primary")
    button.setIcon(make_icon(icon, 12, "#ffffff"))
    button.setCursor(Qt.CursorShape.PointingHandCursor)
    return button


def ghost_button(text: str, icon: str | None = None) -> QPushButton:
    """The borderless secondary button."""
    button = QPushButton(text)
    button.setProperty("variant", "ghost")
    if icon:
        button.setIcon(make_icon(icon, 12))
    button.setCursor(Qt.CursorShape.PointingHandCursor)
    return button


def icon_button(
    icon: str,
    tooltip: str,
    slot: Callable[[], None],
    *,
    size: int = 13,
    colour: str | None = None,
) -> QPushButton:
    """A borderless, icon-only button (log-panel controls, drawer header).

    One definition rather than one per panel: the two that existed had drifted on
    icon size and cursor, so the same control looked different depending on which
    panel it sat in.
    """
    button = QPushButton()
    button.setProperty("iconbtn", "true")
    button.setIcon(make_icon(icon, size, colour or DARK_TOKENS["text_faint"]))
    button.setToolTip(tooltip)
    button.setCursor(Qt.CursorShape.PointingHandCursor)
    button.clicked.connect(lambda _checked=False: slot())
    return button


def result_panel(ok: bool, message: str) -> Panel:
    """An elevated panel showing an operation outcome (done/failed + message)."""
    panel = Panel(elev=True)
    header = QHBoxLayout()
    icon = QLabel()
    colour = DARK_TOKENS["ok"] if ok else DARK_TOKENS["err"]
    icon.setPixmap(make_icon("check" if ok else "warn", 14, colour).pixmap(14, 14))
    header.addWidget(icon)
    header.addWidget(Pill("done" if ok else "failed", "ok" if ok else "err"))
    header.addStretch(1)
    panel.body.addLayout(header)
    label = QLabel(message)
    label.setTextFormat(Qt.TextFormat.RichText)
    label.setWordWrap(True)
    label.setStyleSheet(f"color:{DARK_TOKENS['text_hi']};")
    panel.add(label)
    return panel


def clear_layout(layout: QVBoxLayout | QHBoxLayout) -> None:
    """Remove and delete every item in *layout* (widgets and nested layouts)."""
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.deleteLater()
        else:
            child = item.layout()
            if child is not None:
                clear_layout(child)
