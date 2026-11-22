"""FAUL design tokens — the single source of the GUI palette and metrics.

Defines : DARK_TOKENS (ported from the mockup's ``styles.css``).
Used by : gui.theme (QSS interpolation), gui.icons (default icon tint),
          gui.widgets.components and the views that colour widgets in code.
Uses    : nothing — a pure-data leaf, so any GUI module may import it without a cycle.
"""

from __future__ import annotations

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
    # Metrics
    "radius": "6px",
    "radius_lg": "10px",
    "field_h": "30px",
    "row_h": "30px",
    "pad": "14px",
}
