"""A repeated identify: merge the repetitions, rank the templates they all produced.

Defines : merge_repetitions (N identified databases → one, rows tagged with their
          ``repetition``), rank_repeated (the ``repeat_ranking`` table, and its
          CSV, inside that database), ranked_templates (read its top).
Used by : forensic_aul.ops.workflows.identify (``IdentifyOptions.repeat`` > 1);
          ranked_templates also through the public API (CLI summary).
Uses    : sqlite3, csv, forensic_aul.ops.identify.diff (the identified schema,
          has_literal_text, the tier names, read_only_uri),
          forensic_aul.outcomes (RankingResult).

The same action performed N times, each cycle diffed against its own baseline
(ops/identify/diff.py), gives N identified databases. They are merged into the
run's one result database, so the viewer and the CSV see every repetition. A
line that belongs to the action shows up in every repetition; background noise
that slipped past one baseline rarely does it N times. So the retained rows are
grouped by **template** and ranked on how many repetitions had it as
``new_template``:

  ``new_template_cycles = N``  in every action window and in no baseline (a
                               template found in baseline *j* would be
                               ``new_values`` in repetition *j*) — read first;
  lower counts                 seen in some repetitions only, or also idly.

The template key is the format string with the process, or the message itself
when the format string is missing or generic (``has_literal_text``): lines that
share ``%{public}s`` have nothing else in common.

WHY one repetition at a time (ATTACH, copy, DETACH) rather than attaching them
all: SQLite caps attached databases (10 by default), and a repetition count
should not be limited by that.
"""

from __future__ import annotations

import contextlib
import csv
import sqlite3
from collections.abc import Sequence
from pathlib import Path

from forensic_aul.ops.identify.diff import (
    IDENTIFIED_COLUMNS,
    TIER_NEW_TEMPLATE,
    create_identified_schema,
    has_literal_text,
    read_only_uri,
)
from forensic_aul.outcomes import RankingResult

# The ranking table. Consumed by: the frontends, docs/formats/identify-database.md.
RANKING_TABLE_NAME = "repeat_ranking"

# The ranking CSV columns, in order. Consumed by: rank_repeated.
_CSV_COLUMNS = ("rank", "new_template_cycles", "cycles", "rows", "process", "template",
                "example_message")


def merge_repetitions(cycle_dbs: Sequence[Path], out_db: Path) -> None:
    """Copy every row of *cycle_dbs* into *out_db* (replaced), tagged 1…N."""
    if not cycle_dbs:
        raise ValueError("merge_repetitions needs at least one identified database")
    out_db.parent.mkdir(parents=True, exist_ok=True)
    if out_db.exists():
        out_db.unlink()
    columns = ", ".join(c for c in IDENTIFIED_COLUMNS if c != "repetition")
    # URI mode, so each ATTACH can open its input read-only.
    with contextlib.closing(sqlite3.connect(out_db.resolve().as_uri(), uri=True)) as conn:
        create_identified_schema(conn)
        conn.commit()
        for number, db in enumerate(cycle_dbs, 1):
            conn.execute("ATTACH DATABASE ? AS cycle_db", (read_only_uri(Path(db)),))
            conn.execute(
                f"INSERT INTO identified_logs ({columns}, repetition) "
                f"SELECT {columns}, ? FROM cycle_db.identified_logs ORDER BY id",
                (number,),
            )
            conn.commit()
            conn.execute("DETACH DATABASE cycle_db")


def rank_repeated(db: Path, csv_out: Path | None = None) -> RankingResult:
    """Rank *db*'s retained templates across its repetitions (``repeat_ranking``,
    replaced), and write the ranking to *csv_out* when given (UTF-8 with BOM, in
    rank order — the form analysts sort and filter in their own tools)."""
    with contextlib.closing(sqlite3.connect(db)) as conn:
        conn.create_function("faul_has_literal_text", 1, has_literal_text, deterministic=True)
        conn.execute(f"DROP TABLE IF EXISTS {RANKING_TABLE_NAME}")
        conn.execute(f"""
            CREATE TABLE {RANKING_TABLE_NAME} AS
            SELECT ROW_NUMBER() OVER (
                       ORDER BY new_template_cycles DESC, cycles DESC, rows DESC, template
                   ) AS rank,
                   *
            FROM (
                SELECT template, process,
                       COUNT(DISTINCT CASE WHEN tier = ? THEN repetition END)
                                                  AS new_template_cycles,
                       COUNT(DISTINCT repetition) AS cycles,
                       COUNT(*)                   AS rows,
                       MIN(message)               AS example_message
                FROM (
                    SELECT CASE WHEN faul_has_literal_text(format_string) THEN format_string
                                ELSE message END AS template,
                           COALESCE(process, '') AS process, tier, repetition, message
                    FROM identified_logs
                    WHERE excluded = 0
                )
                WHERE template IS NOT NULL
                GROUP BY template, process
            )
        """, (TIER_NEW_TEMPLATE,))
        cycles = conn.execute("SELECT MAX(repetition) FROM identified_logs").fetchone()[0] or 1
        templates, in_every = conn.execute(
            f"SELECT COUNT(*), SUM(new_template_cycles = ?) FROM {RANKING_TABLE_NAME}",
            (cycles,),
        ).fetchone()
        conn.commit()
        if csv_out is not None:
            _write_csv(conn, csv_out)
    return RankingResult(db, cycles, templates, in_every or 0, csv_out)


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


__all__ = ["RANKING_TABLE_NAME", "merge_repetitions", "rank_repeated", "ranked_templates"]
