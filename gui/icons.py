"""SVG stroke icons rendered to QIcon — shared by widgets and the stylesheet.

Defines : make_icon (and its path table / cache).
Used by : gui.theme (rasterised glyphs for QSS indicators), gui.widgets.* and
          gui.views.* (buttons, labels).
Uses    : PySide6 (QtGui, QtCore, QtSvg when available), gui.tokens (default tint).

WHY its own module: the stylesheet needs icons and the widgets need the palette;
with icons inside the widget module the two depended on each other.
"""

from __future__ import annotations

from PySide6.QtCore import QByteArray, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap

from gui.tokens import DARK_TOKENS

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
