"""Render an identify/diff result as text. Pure formatting — returns a string."""

from __future__ import annotations

from forensic_aul.outcomes import DiffResult, RankingResult


def format_diff_result(res: DiffResult) -> str:
    """Summary of a completed identify/diff (retained vs excluded line counts)."""
    return "\n".join([
        "  Identify complete.",
        f"    Retained : {res.retained}" + (f"  →  {res.csv_path}" if res.csv_path else ""),
        f"      new template : {res.new_templates}  (read these first)",
        f"      new values   : {res.new_values}",
        *([f"      unresolved   : {res.unresolved}  (timestamp unknown, not compared)"]
          if res.unresolved else []),
        f"    Excluded : {res.excluded}  (full set in {res.sqlite_path})",
    ])


def format_ranking(ranking: RankingResult, top: list[tuple]) -> str:
    """Summary of a repeated identify: counts, then the *top* ranked templates
    (rows from ``repeat.ranked_templates``)."""
    lines = [
        f"  Repeated {ranking.cycles}×: {ranking.templates} templates retained, "
        f"{ranking.in_every_cycle} new in every repetition",
    ]
    for rank, new_cycles, cycles, rows, process, message in top:
        text = (message or "").replace("\n", " ")
        if len(text) > 70:
            text = text[:67] + "..."
        lines.append(f"    {rank:>3}. [{new_cycles}/{ranking.cycles}] {process or '?'}: {text}  ({rows} rows)")
    return "\n".join(lines)
