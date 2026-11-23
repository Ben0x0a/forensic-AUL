"""Rank the templates of a repeated identify: which lines every repetition produced.

Defines : rank_repeated (several identified databases → one ``repeat_ranking``
          table; returns an outcomes.RankingResult).
Used by : forensic_aul.ops.workflows.identify (``IdentifyOptions.repeat`` > 1).
Uses    : sqlite3, forensic_aul.ops.identify.diff (has_literal_text, the tier
          names).

The same action performed N times, each cycle diffed against its own baseline
(ops/identify/diff.py), gives N identified databases. A line that belongs to the
action shows up in every one of them; background noise that slipped past one
baseline rarely does it N times. So the retained rows of all cycles are grouped
by **template** and ranked on how many cycles had it as ``new_template``:

  ``new_template_cycles = N``  in every action window and in no baseline (a
                               template found in baseline *j* would be
                               ``new_values`` in cycle *j*) — read these first;
  lower counts                 seen in some repetitions only, or also idly.

The template key is the format string with the process, or the message itself
when the format string is missing or generic (``has_literal_text``): lines that
share ``%{public}s`` have nothing else in common.

WHY one cycle at a time (ATTACH, copy, DETACH) rather than attaching them all:
SQLite caps attached databases (10 by default), and a repetition count should
not be limited by that.
"""

from __future__ import annotations

import contextlib
import csv
import sqlite3
from collections.abc import Sequence
from pathlib import Path

from forensic_aul.ops.identify.diff import TIER_NEW_TEMPLATE, has_literal_text, read_only_uri
from forensic_aul.outcomes import RankingResult

# The output table. Consumed by: the frontends, docs/formats/identify-database.md.
RANKING_TABLE_NAME = "repeat_ranking"


# The CSV columns, in order. Consumed by: rank_repeated.
_CSV_COLUMNS = ("rank", "new_template_cycles", "cycles", "rows", "process", "template",
                "example_message")


def rank_repeated(
    identified_dbs: Sequence[Path], out_db: Path, csv_out: Path | None = None,
) -> RankingResult:
    """Rank the retained templates of *identified_dbs* into *out_db* (replaced).

    *csv_out*, when given, also receives the ranking as CSV (UTF-8 with BOM, so
    Excel detects the encoding), in rank order — the form analysts sort and
    filter in their own tools.
    """
    if not identified_dbs:
        raise ValueError("rank_repeated needs at least one identified database")
    out_db.parent.mkdir(parents=True, exist_ok=True)
    if out_db.exists():
        out_db.unlink()
    # URI mode, so the per-cycle ATTACH below can open its input read-only.
    with contextlib.closing(sqlite3.connect(out_db.resolve().as_uri(), uri=True)) as conn:
        conn.create_function("faul_has_literal_text", 1, has_literal_text, deterministic=True)
        conn.execute("""
            CREATE TEMP TABLE retained (
                cycle INTEGER, template TEXT, process TEXT, tier TEXT, message TEXT
            )
        """)
        for cycle, db in enumerate(identified_dbs, 1):
            conn.execute("ATTACH DATABASE ? AS cycle_db", (read_only_uri(Path(db)),))
            conn.execute("""
                INSERT INTO retained
                SELECT ?,
                       CASE WHEN faul_has_literal_text(format_string) THEN format_string
                            ELSE message END,
                       COALESCE(process, ''), tier, message
                FROM cycle_db.identified_logs
                WHERE excluded = 0
            """, (cycle,))
            conn.commit()
            conn.execute("DETACH DATABASE cycle_db")
        conn.execute(f"""
            CREATE TABLE {RANKING_TABLE_NAME} AS
            SELECT ROW_NUMBER() OVER (
                       ORDER BY new_template_cycles DESC, cycles DESC, rows DESC, template
                   ) AS rank,
                   *
            FROM (
                SELECT template, process,
                       COUNT(DISTINCT CASE WHEN tier = ? THEN cycle END) AS new_template_cycles,
                       COUNT(DISTINCT cycle) AS cycles,
                       COUNT(*)              AS rows,
                       MIN(message)          AS example_message
                FROM retained
                WHERE template IS NOT NULL
                GROUP BY template, process
            )
        """, (TIER_NEW_TEMPLATE,))
        templates, in_every = conn.execute(
            f"SELECT COUNT(*), SUM(new_template_cycles = ?) FROM {RANKING_TABLE_NAME}",
            (len(identified_dbs),),
        ).fetchone()
        conn.commit()
        if csv_out is not None:
            _write_csv(conn, csv_out)
    return RankingResult(out_db, len(identified_dbs), templates, in_every or 0, csv_out)


def _write_csv(conn: sqlite3.Connection, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.writer(fh)
        writer.writerow(_CSV_COLUMNS)
        writer.writerows(conn.execute(
            f"SELECT {', '.join(_CSV_COLUMNS)} FROM {RANKING_TABLE_NAME} ORDER BY rank"))


def ranked_templates(ranking_db: Path, limit: int = 10) -> list[tuple]:
    """The first *limit* ranked templates: ``(rank, new_template_cycles, cycles,
    rows, process, example_message)``."""
    with contextlib.closing(sqlite3.connect(read_only_uri(ranking_db), uri=True)) as conn:
        return conn.execute(
            f"SELECT rank, new_template_cycles, cycles, rows, process, example_message "
            f"FROM {RANKING_TABLE_NAME} ORDER BY rank LIMIT ?", (limit,),
        ).fetchall()


__all__ = ["RANKING_TABLE_NAME", "rank_repeated", "ranked_templates"]
