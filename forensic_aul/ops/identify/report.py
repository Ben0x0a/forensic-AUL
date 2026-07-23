"""Render an identify/diff result as text. Pure formatting — returns a string."""

from __future__ import annotations

from forensic_aul.outcomes import DiffResult


def format_diff_result(res: DiffResult) -> str:
    """Summary of a completed identify/diff (retained vs excluded line counts)."""
    return "\n".join([
        "  Identify complete.",
        f"    Retained : {res.retained}  →  {res.csv_path}",
        f"    Excluded : {res.excluded}  (full set in {res.sqlite_path})",
    ])
