"""Render export-run output as text. Pure formatting — returns a string."""

from __future__ import annotations

from forensic_aul.outcomes import ExportResult


def format_export_result(res: ExportResult) -> str:
    """One-line summary of a completed export."""
    return f"  Wrote {res.rows} row(s) → {res.output_path}"
