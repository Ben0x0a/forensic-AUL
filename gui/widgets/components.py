"""Shared, themable UI primitives for the FAUL shell.

Defines : the small building blocks every screen reuses — heading/label factories (``eyebrow``, ``h1``,
          ``subtitle`` …), :class:`Pill`, :class:`Panel`, :class:`Divider`,
          :class:`Stat`, and :func:`field_row`.
Used by : gui.views.shell and gui.views.screens.* (composition only).
Uses    : PySide6 (QtWidgets/QtGui/QtCore); gui.icons (make_icon); gui.tokens
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

from PySide6.QtCore import QPoint, QSize, Qt
from PySide6.QtGui import QPixmap
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

from gui.icons import make_icon
from gui.tokens import DARK_TOKENS

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


def repolish(widget: QWidget) -> None:
    """Force a style re-evaluation after a dynamic property changes.

    QSS selectors on dynamic properties (``variant``, ``pill``, ``chipOn``…) are
    only re-matched when the widget is re-polished, so setting the property alone
    changes nothing on screen. Public because five widgets across the GUI need it
    and were each open-coding the unpolish/polish pair.
    """
    widget.style().unpolish(widget)
    widget.style().polish(widget)


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
    _no_default(button)
    return button


def ghost_button(text: str, icon: str | None = None) -> QPushButton:
    """The borderless secondary button."""
    button = QPushButton(text)
    button.setProperty("variant", "ghost")
    if icon:
        button.setIcon(make_icon(icon, 12))
    button.setCursor(Qt.CursorShape.PointingHandCursor)
    _no_default(button)
    return button


def _no_default(button: QPushButton) -> None:
    """Stop Qt painting its own "default button" highlight over our styling.

    Under Fusion a focused push button gets a native default-button indicator —
    a filled accent rectangle drawn *outside* the stylesheet. On a ghost button
    that renders as a solid violet block beside the real primary, so the row
    appears to have two call-to-action buttons. The same workaround already
    existed one-off on PathPicker's Browse button; it belongs on the factories.
    """
    button.setAutoDefault(False)
    button.setDefault(False)


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
    """Remove and delete every item in *layout* (widgets and nested layouts).

    WHY ``setParent(None)`` as well as ``deleteLater()``: taking a widget out of
    a layout does not detach it from its parent, and ``deleteLater`` only runs
    when the event loop next processes deferred deletions. Until then the widget
    is still a live child and still paints at its old geometry — so swapping an
    action row left the previous row's buttons showing underneath the new ones.
    Unparenting makes the removal immediate; deleteLater still owns the actual
    destruction, which must stay deferred (the widget may be mid-signal).
    """
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.setParent(None)
            widget.deleteLater()
        else:
            child = item.layout()
            if child is not None:
                clear_layout(child)
