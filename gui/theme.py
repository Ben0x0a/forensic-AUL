"""FAUL design system → Qt Style Sheet (QSS).

Defines : DARK_TOKENS (the design palette + metrics ported from the
          mockup's ``styles.css``) and build_stylesheet(), which interpolates a
          token set into the application-wide QSS string.
Used by : gui.views.shell (applies the sheet), gui.app (initial application).
Uses    : gui.widgets.components (the check glyph rendered for the checkbox
          indicator); otherwise pure string assembly.

WHY generate QSS from a token dict: QSS has no CSS custom properties, so the
single source of truth lives here as Python and is interpolated into the rules.
Widgets opt into looks via object names and dynamic properties (``nav="true"``,
``card="true"``, ``pill="ok"``, ``choiceOn="true"``…) selected below — set them
in code when a widget is built.

Not 1:1 with the web mock: QSS has no box-shadow, CSS transitions, flex/grid or
:focus-within. Those are dropped or approximated (e.g. the toggle switch and
traffic-light dots are custom-painted, not styled here). The palette, surfaces,
radii, tables, fields, pills and the violet accent carry the visual identity.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

# ── Design tokens (ported from project/styles.css) ───────────────────────────
# Dark is the primary, forensic-tuned theme. Consumed by: build_stylesheet().
DARK_TOKENS: dict[str, str] = {
    # Cool-gray dark surfaces
    "bg_base": "#0a0c0f",
    "bg_window": "#14171c",
    "bg_surface": "#1a1e25",
    "bg_elev": "#232830",
    "bg_input": "#0c0e12",
    "bg_row_hover": "#1f242c",
    "bg_row_sel": "#2a2235",
    # Borders
    "border": "#262b34",
    "border_strong": "#353b46",
    "border_faint": "#1d2129",
    # Text
    "text_hi": "#e6e9ef",
    "text": "#b8bdc7",
    "text_dim": "#7a8090",
    "text_faint": "#545a68",
    "text_mute": "#3f4452",
    # Accent (violet)
    "accent": "#8b5cf6",
    "accent_hi": "#a78bfa",
    "accent_dim": "#6d44d4",
    # Semantic
    "ok": "#4ade80",
    "warn": "#f5b544",
    "err": "#f87171",
    "info": "#60a5fa",
    # Titlebar gradient stops
    "title_top": "#1f242c",
    "title_bottom": "#181c22",
    # Metrics
    "radius": "6px",
    "radius_lg": "10px",
    "field_h": "30px",
    "row_h": "30px",
    "pad": "14px",
}

# Back-compat alias: older callers imported ``TOKENS``.
# FAUL ships a single, dark theme — it is a forensic lab tool tuned for dark, and a
# second (light) palette was unused gold-plating that doubled token maintenance.
TOKENS = DARK_TOKENS

# System font stacks (Qt resolves the first available family).
_FONT_UI = '"SF Pro Text", "Segoe UI", system-ui, "Helvetica Neue", sans-serif'
_FONT_MONO = '"SF Mono", "Menlo", "Cascadia Mono", "Consolas", monospace'


# Cached filesystem paths for glyphs QSS has to draw as images, keyed by
# (icon name, colour, size). WHY files: several QSS pseudo-elements
# (``QCheckBox::indicator``, ``QAbstractSpinBox::up-arrow``, …) can only draw a
# mark via ``image: url(...)`` — they cannot render text or SVG data — so the
# shared SVG icons are rasterised once to PNGs and referenced by path.
# Consumed by: build_stylesheet().
_GLYPH_PATHS: dict[tuple[str, str, int], str] = {}


def _glyph_url(name: str, colour: str, size: int = 12) -> str:
    """Return a path to *name* rendered at *size* in *colour* (rasterised once).

    Returns "" when Qt/QtSvg is unavailable or the render fails; the calling QSS
    rule then simply draws no image, which degrades to a plain (but still
    correctly coloured) control rather than erroring.
    """
    key = (name, colour, size)
    cached = _GLYPH_PATHS.get(key)
    if cached is not None:
        return cached
    try:
        from PySide6.QtCore import QSize, Qt

        from gui.widgets.components import make_icon

        pixmap = make_icon(name, size, colour).pixmap(QSize(size, size))
        if pixmap.isNull():
            return ""
        image = pixmap.toImage().scaled(
            size, size, Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        safe = colour.lstrip("#")
        path = Path(tempfile.gettempdir()) / f"faul_glyph_{name}_{safe}_{size}.png"
        if not image.save(str(path)):
            return ""
        _GLYPH_PATHS[key] = path.as_posix()
        return _GLYPH_PATHS[key]
    except Exception:  # noqa: BLE001 — a missing glyph must never break theming
        return ""


def build_stylesheet(tokens: dict[str, str] | None = None) -> str:
    """Return the application-wide QSS string built from *tokens* (defaults to dark)."""
    t = tokens or DARK_TOKENS
    check = _glyph_url("check", "#ffffff", 12)
    arrow_up = _glyph_url("up", DARK_TOKENS["text_faint"], 8)
    arrow_down = _glyph_url("down", DARK_TOKENS["text_faint"], 8)
    return f"""
/* ── Base ─────────────────────────────────────────────────────────────── */
/* WHY no `background` here: an opaque background on *every* QWidget makes each
   label, checkbox and row-container paint a filled rectangle, which shows up as
   dark "bands" wherever a widget sits on a differently-coloured surface (e.g. a
   label inside a card). Backgrounds are instead set only on the structural
   containers that need them (#main, #sidebar, cards, inputs, …); everything else
   stays transparent and shows its parent surface. */
QWidget {{
    color: {t['text']};
    font-family: {_FONT_UI};
    font-size: 13px;
}}
/* Rounded window: the frameless window is translucent, so this frame's rounded
   corners read as the window's corners. The corner-touching children below
   (titlebar, sidebar, #main, log panel) repeat the matching radius so no square
   corner pokes through the rounding. */
#appRoot {{ background: {t['bg_window']}; border-radius: 10px; }}
/* Paint the page surface behind the (transparent) screens and splitter; round the
   bottom-right so the window corner stays clean behind the log panel. */
#main {{ background: {t['bg_window']}; border-bottom-right-radius: 10px; }}
QToolTip {{
    background: {t['bg_elev']};
    color: {t['text_hi']};
    border: 1px solid {t['border_strong']};
    padding: 4px 7px;
}}

/* ── Window / titlebar ────────────────────────────────────────────────── */
#titlebar {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 {t['title_top']}, stop:1 {t['title_bottom']});
    border-bottom: 1px solid {t['border_faint']};
    border-top-left-radius: 10px;
    border-top-right-radius: 10px;
}}
#titleText {{ color: {t['text_dim']}; font-size: 12px; font-weight: 500; }}
#titleApp  {{ color: {t['text_hi']}; font-weight: 600; }}
#titleCase {{ color: {t['text_hi']}; font-weight: 600; }}
#titleSep  {{ color: {t['text_mute']}; }}

/* ── Sidebar ──────────────────────────────────────────────────────────── */
#sidebar {{
    background: {t['bg_window']};
    border-right: 1px solid {t['border']};
    border-bottom-left-radius: 10px;
}}
#sidebarBrand {{ border-bottom: 1px solid {t['border_faint']}; }}
#sidebarBrandName {{ color: {t['text_hi']}; font-size: 14px; font-weight: 700; }}
#sidebarBrandSub  {{ color: {t['text_faint']}; font-family: {_FONT_MONO}; font-size: 10px; }}
QLabel[role="sidebarSection"] {{
    color: {t['text_faint']};
    font-size: 10px;
    font-weight: 600;
    padding: 12px 16px 4px;
}}
QPushButton[nav="true"] {{
    text-align: left;
    padding: 0 16px;
    min-height: 30px;
    border: none;
    border-left: 2px solid transparent;
    background: transparent;
    color: {t['text']};
    font-size: 13px;
    font-weight: 400;
}}
QPushButton[nav="true"]:hover {{ background: {t['bg_row_hover']}; }}
QPushButton[nav="true"]:checked {{
    background: rgba(139, 92, 246, 0.12);
    border-left: 2px solid {t['accent']};
    color: {t['text_hi']};
}}
QPushButton[nav="true"]:disabled {{ color: {t['text_mute']}; }}
QLabel[role="navNum"] {{
    color: {t['text_faint']};
    font-family: {_FONT_MONO};
    font-size: 10px;
}}

/* ── Headings ─────────────────────────────────────────────────────────── */
QLabel[role="h1"] {{ color: {t['text_hi']}; font-size: 18px; font-weight: 600; }}
QLabel[role="h2"] {{ color: {t['text_hi']}; font-size: 14px; font-weight: 600; }}
QLabel[role="eyebrow"] {{ color: {t['text_faint']}; font-size: 10px; font-weight: 600; }}
QLabel[role="subtitle"] {{ color: {t['text_dim']}; font-size: 12px; }}
QLabel[role="help"] {{ color: {t['text_faint']}; font-size: 11px; }}
QLabel[role="mono"] {{ font-family: {_FONT_MONO}; color: {t['text_dim']}; font-size: 11px; }}
QLabel[role="ok"]   {{ color: {t['ok']}; }}
QLabel[role="warn"] {{ color: {t['warn']}; }}
QLabel[role="err"]  {{ color: {t['err']}; }}

/* Scroll areas are structural, not surfaces: an opaque viewport paints the
   palette's (light) Base colour over whatever card it sits in. Both the page
   scroller and the record-detail drawer rely on this. */
QScrollArea {{ background: transparent; border: none; }}
QScrollArea > QWidget > QWidget {{ background: transparent; }}

/* ── Cards / panels ───────────────────────────────────────────────────── */
QFrame[card="true"] {{
    background: {t['bg_surface']};
    border: 1px solid {t['border']};
    border-radius: {t['radius']};
}}
QFrame[card="elev"] {{
    background: {t['bg_elev']};
    border: 1px solid {t['border']};
    border-radius: {t['radius']};
}}
QFrame[role="divider"] {{ background: {t['border']}; max-height: 1px; min-height: 1px; border: none; }}

/* ── Inputs ───────────────────────────────────────────────────────────── */
QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QDateTimeEdit, QDateEdit, QTimeEdit {{
    background: {t['bg_input']};
    border: 1px solid {t['border']};
    border-radius: {t['radius']};
    color: {t['text_hi']};
    min-height: {t['field_h']};
    padding: 0 10px;
    selection-background-color: {t['accent']};
}}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus,
QDoubleSpinBox:focus, QDateTimeEdit:focus, QDateEdit:focus, QTimeEdit:focus {{
    border-color: {t['accent']};
}}
QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled,
QDoubleSpinBox:disabled, QDateTimeEdit:disabled {{ color: {t['text_mute']}; }}
/* Spin/step buttons: Fusion draws these as raised native widgets with a light
   base. Flatten them onto the field so a date picker reads as one control. */
QAbstractSpinBox {{ font-family: {_FONT_MONO}; font-size: 12px; }}
QAbstractSpinBox::up-button, QAbstractSpinBox::down-button {{
    background: transparent;
    border: none;
    width: 16px;
}}
QAbstractSpinBox::up-arrow, QAbstractSpinBox::down-arrow {{
    width: 7px; height: 7px;
}}
QAbstractSpinBox::up-arrow {{ image: url({arrow_up}); }}
QAbstractSpinBox::down-arrow {{ image: url({arrow_down}); }}
/* Calendar popup — otherwise a bright native panel over a dark app. */
QCalendarWidget QWidget {{ alternate-background-color: {t['bg_surface']}; }}
QCalendarWidget QAbstractItemView:enabled {{
    background: {t['bg_elev']};
    color: {t['text_hi']};
    selection-background-color: {t['accent']};
    selection-color: #ffffff;
}}
QCalendarWidget QAbstractItemView:disabled {{ color: {t['text_mute']}; }}
QCalendarWidget QWidget#qt_calendar_navigationbar {{
    background: {t['bg_surface']};
    border-bottom: 1px solid {t['border']};
}}
QCalendarWidget QToolButton {{
    background: transparent;
    color: {t['text_hi']};
    border: none;
    padding: 4px 8px;
}}
QCalendarWidget QToolButton:hover {{ background: {t['bg_row_hover']}; border-radius: 4px; }}
QCalendarWidget QSpinBox {{ min-height: 22px; }}
QLineEdit[mono="true"] {{ font-family: {_FONT_MONO}; font-size: 12px; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
/* Popup list: rounded, accent selection. Item height comes from style_combo's
   SizeHintRole; the current-item checkmark and positioning are left native. */
QComboBox QAbstractItemView {{
    background: {t['bg_elev']};
    border: 1px solid {t['border_strong']};
    border-radius: {t['radius']};
    padding: 4px;
    selection-background-color: {t['accent']};
    color: {t['text']};
    outline: none;
}}

/* ── Buttons ──────────────────────────────────────────────────────────── */
QPushButton {{
    background: {t['bg_elev']};
    border: 1px solid {t['border_strong']};
    border-radius: {t['radius']};
    color: {t['text_hi']};
    min-height: {t['field_h']};
    padding: 0 14px;
    font-size: 13px;
    font-weight: 500;
}}
QPushButton:hover {{ background: {t['bg_row_hover']}; }}
QPushButton:disabled {{ color: {t['text_mute']}; border-color: {t['border']}; background: {t['bg_elev']}; }}
QPushButton[variant="primary"] {{
    background: {t['accent']};
    border-color: {t['accent']};
    color: #ffffff;
}}
QPushButton[variant="primary"]:hover {{ background: {t['accent_hi']}; border-color: {t['accent_hi']}; }}
QPushButton[variant="primary"]:disabled {{ background: {t['bg_elev']}; border-color: {t['border']}; color: {t['text_mute']}; }}
QPushButton[variant="danger"] {{
    background: transparent;
    border-color: rgba(248,113,113,0.35);
    color: {t['err']};
}}
QPushButton[variant="ghost"] {{ background: transparent; border-color: transparent; color: {t['text_dim']}; }}
QPushButton[variant="ghost"]:hover {{ color: {t['text_hi']}; background: {t['bg_row_hover']}; }}
QPushButton[sm="true"] {{ min-height: 24px; padding: 0 10px; font-size: 11px; }}

/* ── Selectable choice cards (scope / format / mode pickers) ──────────── */
QPushButton[choice="true"] {{
    text-align: left;
    background: {t['bg_elev']};
    border: 1px solid {t['border']};
    border-radius: {t['radius']};
    color: {t['text']};
    padding: 12px 14px;
    font-weight: 400;
    /* Tall enough for title + a two-line caption (Qt button sizeHint ignores
       QLabel word-wrap height, so the floor is set here, not via sizeHint). */
    min-height: 70px;
}}
QPushButton[choice="true"]:hover {{ border-color: {t['border_strong']}; }}
QPushButton[choice="true"][choiceOn="true"] {{
    background: {t['bg_row_sel']};
    border: 1px solid {t['accent']};
    color: {t['text_hi']};
}}

/* ── Chips ────────────────────────────────────────────────────────────── */
QPushButton[chip="true"] {{
    background: {t['bg_elev']};
    border: 1px solid {t['border']};
    border-radius: 12px;
    color: {t['text']};
    min-height: 24px;
    padding: 0 12px;
    font-family: {_FONT_MONO};
    font-size: 11px;
    font-weight: 400;
}}
QPushButton[chip="true"]:hover {{ border-color: {t['border_strong']}; }}
QPushButton[chip="true"][chipOn="true"] {{
    background: rgba(139, 92, 246, 0.12);
    border-color: {t['accent']};
    color: {t['text_hi']};
}}

/* ── Pills / badges ───────────────────────────────────────────────────── */
QLabel[pill="ok"], QLabel[pill="warn"], QLabel[pill="err"], QLabel[pill="info"],
QLabel[pill="neutral"], QLabel[pill="violet"] {{
    font-family: {_FONT_MONO};
    font-size: 10px;
    padding: 2px 7px;
    border-radius: 3px;
    border: 1px solid {t['border']};
}}
QLabel[pill="ok"]      {{ color: {t['ok']};   border-color: rgba(74,222,128,0.30);  background: rgba(74,222,128,0.10); }}
QLabel[pill="warn"]    {{ color: {t['warn']}; border-color: rgba(245,181,68,0.30);  background: rgba(245,181,68,0.10); }}
QLabel[pill="err"]     {{ color: {t['err']};  border-color: rgba(248,113,113,0.30); background: rgba(248,113,113,0.10); }}
QLabel[pill="info"]    {{ color: {t['info']}; border-color: rgba(96,165,250,0.30);  background: rgba(96,165,250,0.10); }}
QLabel[pill="violet"]  {{ color: {t['accent_hi']}; border-color: rgba(139,92,246,0.30); background: rgba(139,92,246,0.12); }}
QLabel[pill="neutral"] {{ color: {t['text_dim']}; background: {t['bg_elev']}; }}

/* ── Recent / list rows ───────────────────────────────────────────────── */
QFrame[recentList="true"] {{
    background: {t['bg_surface']};
    border: 1px solid {t['border']};
    border-radius: {t['radius']};
}}
QPushButton[recentRow="true"] {{
    text-align: left;
    background: transparent;
    border: none;
    border-bottom: 1px solid {t['border_faint']};
    border-radius: 0;
    color: {t['text']};
    font-family: {_FONT_MONO};
    font-size: 12px;
    padding: 9px 14px;
    min-height: 0;
    font-weight: 400;
}}
QPushButton[recentRow="true"]:hover {{ background: {t['bg_row_hover']}; }}

/* ── Stat blocks ──────────────────────────────────────────────────────── */
QLabel[role="statValue"] {{
    color: {t['text_hi']}; font-family: {_FONT_MONO};
    font-size: 22px; font-weight: 600;
}}
QLabel[role="statLabel"] {{ color: {t['text_faint']}; font-size: 10px; font-weight: 600; }}
QLabel[role="statDelta"] {{ color: {t['text_dim']}; font-family: {_FONT_MONO}; font-size: 11px; }}

/* ── Checkboxes ───────────────────────────────────────────────────────── */
QCheckBox {{ color: {t['text']}; spacing: 8px; }}
QCheckBox::indicator {{
    width: 14px; height: 14px;
    border: 1px solid {t['border_strong']};
    border-radius: 3px;
    background: {t['bg_input']};
}}
QCheckBox::indicator:checked {{
    background: {t['accent']}; border-color: {t['accent']};
    image: url({check});
}}
QCheckBox:disabled {{ color: {t['text_mute']}; }}

/* ── In-screen tabs (QTabWidget in document mode: flat underline tabs) ── */
QTabWidget::pane {{ border: none; background: transparent; top: -1px; }}
/* Fusion paints a light "tab bar base" line across the full width beside the
   tabs; neither the pane border nor a transparent QTabBar suppresses it, so it
   is overpainted with the window colour and the selected tab's accent underline
   provides the only rule the eye should see. */
QTabWidget::tab-bar {{ alignment: left; }}
QTabBar {{ background: transparent; border: none; }}
QTabBar::tab:!selected {{ border-bottom: 2px solid {t['bg_window']}; }}
/* min-width + generous padding so a label is never squeezed to an ellipsis
   ("Overvi…"); the tab bar is also told not to elide (setElideMode) and not to
   stretch its tabs (setExpanding) at each construction site. */
QTabBar::tab {{
    background: {t['bg_window']};
    color: {t['text_dim']};
    padding: 7px 16px;
    min-width: 76px;
    border: none;
    border-bottom: 2px solid transparent;
    font-size: 12px;
}}
QTabBar::tab:hover {{ color: {t['text_hi']}; }}
QTabBar::tab:selected {{ color: {t['text_hi']}; border-bottom-color: {t['accent']}; }}

/* ── Tables ───────────────────────────────────────────────────────────── */
QTableView, QTableWidget {{
    background: {t['bg_surface']};
    alternate-background-color: {t['bg_surface']};
    gridline-color: {t['border_faint']};
    border: 1px solid {t['border']};
    border-radius: {t['radius']};
    color: {t['text']};
    font-family: {_FONT_MONO};
    font-size: 12px;
    selection-background-color: {t['bg_row_sel']};
    selection-color: {t['text_hi']};
}}
QHeaderView::section {{
    background: {t['bg_elev']};
    color: {t['text_dim']};
    border: none;
    border-bottom: 1px solid {t['border']};
    padding: 6px 10px;
    font-family: {_FONT_UI};
    font-size: 11px;
}}
QTableView::item, QTableWidget::item {{ padding: 4px 8px; }}

/* ── Progress ─────────────────────────────────────────────────────────── */
QProgressBar {{
    background: {t['bg_input']};
    border: 1px solid {t['border']};
    border-radius: 4px;
    height: 8px;
    text-align: center;
    color: {t['text_dim']};
    font-size: 10px;
}}
QProgressBar::chunk {{
    border-radius: 3px;
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                stop:0 {t['accent_dim']}, stop:1 {t['accent']});
}}

/* ── Content / scroll area ────────────────────────────────────────────── */
#contentScroll, #contentScroll > QWidget > QWidget {{ background: {t['bg_window']}; border: none; }}

/* ── Log panel ────────────────────────────────────────────────────────── */
#logPanel {{ background: {t['bg_base']}; border-top: 1px solid {t['border']}; border-bottom-right-radius: 10px; }}
#logPanelHeader {{ background: {t['bg_elev']}; border-bottom: 1px solid {t['border']}; }}
#logPanelTitle {{
    color: {t['text_dim']}; font-size: 10px; font-weight: 600;
}}
#logPanelCount {{ color: {t['text_faint']}; font-family: {_FONT_MONO}; font-size: 10px; }}
#logBody {{
    background: {t['bg_base']};
    border: none;
    color: {t['text']};
    font-family: {_FONT_MONO};
    font-size: 11px;
}}
QPushButton[lvltoggle="debug"], QPushButton[lvltoggle="info"],
QPushButton[lvltoggle="warn"], QPushButton[lvltoggle="err"] {{
    background: transparent;
    border: 1px solid {t['border_strong']};
    border-radius: 3px;
    color: {t['text_faint']};
    min-height: 18px; max-height: 18px;
    padding: 0 7px;
    font-family: {_FONT_MONO}; font-size: 10px; font-weight: 500;
}}
QPushButton[lvltoggle="info"][on="true"] {{ color: {t['info']}; border-color: rgba(96,165,250,0.4);  background: rgba(96,165,250,0.10); }}
QPushButton[lvltoggle="warn"][on="true"] {{ color: {t['warn']}; border-color: rgba(245,181,68,0.4);  background: rgba(245,181,68,0.10); }}
QPushButton[lvltoggle="err"][on="true"]  {{ color: {t['err']};  border-color: rgba(248,113,113,0.4); background: rgba(248,113,113,0.10); }}
QPushButton[lvltoggle="debug"][on="true"]{{ color: {t['text']}; background: {t['bg_row_hover']}; }}
QPushButton[iconbtn="true"] {{
    background: transparent; border: none; border-radius: 3px;
    color: {t['text_faint']}; min-height: 22px; max-height: 22px;
    min-width: 22px; max-width: 26px; padding: 0;
}}
QPushButton[iconbtn="true"]:hover {{ color: {t['text_hi']}; background: {t['bg_row_hover']}; }}
QPushButton[iconbtn="true"][on="true"] {{ color: {t['accent_hi']}; }}

/* ── Dropzone ─────────────────────────────────────────────────────────── */
QFrame[drop="true"] {{
    border: 1px dashed {t['border_strong']};
    border-radius: {t['radius_lg']};
    background: {t['bg_input']};
}}

/* ── Scrollbars ───────────────────────────────────────────────────────── */
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 0; }}
QScrollBar::handle:vertical {{ background: rgba(128,128,128,0.32); border-radius: 5px; min-height: 24px; }}
QScrollBar::handle:vertical:hover {{ background: rgba(128,128,128,0.5); }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 0; }}
QScrollBar::handle:horizontal {{ background: rgba(128,128,128,0.32); border-radius: 5px; min-width: 24px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
"""
