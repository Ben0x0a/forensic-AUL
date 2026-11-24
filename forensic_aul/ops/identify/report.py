"""Render an identify/diff result as text. Pure formatting — returns a string."""

from __future__ import annotations

from forensic_aul.outcomes import DiffResult, IdentifyResult, RankingResult


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
        f"  Ranking: {ranking.templates:,} templates retained, {ranking.in_every_cycle:,} "
        f"new in all {ranking.cycles} repetitions. Top {len(top)}:",
    ]
    for rank, new_cycles, cycles, rows, process, message in top:
        text = (message or "").replace("\n", " ")
        if len(text) > 70:
            text = text[:67] + "..."
        lines.append(f"    {rank:>3}. [{new_cycles}/{ranking.cycles}] {process or '?'}: {text}  ({rows:,} rows)")
    return "\n".join(lines)


def format_identify_result(res: IdentifyResult, top: list[tuple] | None = None) -> str:
    """Summary of an identify run: the action, one table row per repetition,
    the ranking's *top* rows (from ``repeat.ranked_templates``) when repeated,
    and last the result files, named relative to the run folder (the full
    paths are in the log). Pure formatting."""
    lines = ["  Done."]
    if res.action_description:
        lines.append(f"  Action : {res.action_description}")
    lines += ["", "  Repetition   Retained   New template   New values   Excluded"]
    for number, cycle in enumerate(res.cycles or (res,), 1):
        d = cycle.diff
        lines.append(f"  {number:>10}   {d.retained:>8,}   {d.new_templates:>12,}"
                     f"   {d.new_values:>10,}   {d.excluded:>8,}")
    if res.ranking is not None and top is not None:
        lines += ["", format_ranking(res.ranking, top)]
    if res.identified_db is not None:
        folder = res.identified_db.parent
        lines += ["", f"  Results in {folder}/"]
        files = [
            (res.identified_db, "every line after each baseline, flagged"),
            (res.csv_path, "the retained lines (new_template / new_message)"),
            (res.ranking.csv_path if res.ranking else None, "the templates ranked across repetitions"),
        ]
        named = [(path.name, what) for path, what in files if path is not None]
        named.append(("intermediate/", "captures and extracts"))
        width = max(len(name) for name, _ in named) + 2
        lines += [f"    {name:<{width}}{what}" for name, what in named]
    return "\n".join(lines)
