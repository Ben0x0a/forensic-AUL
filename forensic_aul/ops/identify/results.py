"""Read/annotate access to a diff database produced by ``run_diff``.

Defines : ``ResultCounts`` (per-category row counts) and ``IdentifyResults`` —
          a thin, path-based read/annotate layer over the ``identified_logs`` /
          ``hidden_keys`` tables a diff DB carries. Distinct from
          ``forensic_aul.engine.database.access.open_analysis_database``: that
          function validates a *logs*-table extract DB, whereas a diff DB has
          no ``logs`` table at all — only ``identified_logs``.
Used by : any front-end (CLI, GUI) that wants to browse/filter/hide rows in an
          existing diff DB after ``run_diff``/``run_identify_workflow`` has
          produced it; re-exported from ``forensic_aul/__init__.py``.
Uses    : forensic_aul.errors (InvalidDatabaseError), forensic_aul.ops.identify
          .diff (_create_hidden_keys_objects, for backward-compatible upgrade
          of older diff DBs), forensic_aul.ops.query.reader (_escape_like —
          the one source of truth for LIKE escaping), sqlite3, csv.
"""

from __future__ import annotations

import csv
import logging
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from forensic_aul.errors import InvalidDatabaseError
from forensic_aul.ops.identify.diff import _CSV_HEADER, _create_hidden_keys_objects
from forensic_aul.ops.query.reader import _escape_like

log = logging.getLogger(__name__)

# Column order shared with run_diff's own CSV (see diff.py: _CSV_HEADER) so a
# result-store export is indistinguishable from the diff's own CSV output,
# just re-filterable through the flags below.
_EXPORT_HEADER = _CSV_HEADER

# rows() SELECT — every identified_logs column in insertion order, aliased so
# sqlite3.Row access by name matches the table's own column names.
_ROWS_COLUMNS = (
    "id, timestamp, timestamp_unix_ns, event_order, process, pid, tid, "
    "log_level, event_type, subsystem, category, message, matched_signatures, "
    "excluded, note"
)


@dataclass(frozen=True)
class ResultCounts:
    """Per-category row counts over an ``identified_logs`` table."""

    retained: int      # excluded=0, not hidden, not kb-known
    noise: int         # excluded=1
    kb_known: int      # matched_signatures != ''
    hidden: int        # rows matching a hidden_keys entry


class IdentifyResults:
    """Read/annotate access to a diff database produced by ``run_diff``.

    Opens once and keeps the connection for the lifetime of the object; use as
    a context manager or call :meth:`close` explicitly.
    """

    def __init__(self, database: Path | str) -> None:
        path = Path(database)
        if not path.is_file():
            raise FileNotFoundError(f"{path} is not a file")

        conn = sqlite3.connect(str(path))
        try:
            has_table = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='identified_logs'"
            ).fetchone()
        except sqlite3.DatabaseError as exc:
            # Never leak the connection on a rejected file.
            conn.close()
            raise InvalidDatabaseError(f"{path} is not a SQLite database: {exc}") from exc
        except BaseException:
            conn.close()
            raise
        if has_table is None:
            conn.close()
            raise InvalidDatabaseError(
                f"{path} is a SQLite database but not an identify results "
                "database (no `identified_logs` table — was it produced by "
                "run_diff?)"
            )

        # Backward compatibility: a diff DB from before hidden_keys existed
        # still has to work for reads and gains the hiding machinery on open
        # (idempotent DDL — see diff._create_hidden_keys_objects). Best-effort:
        # a read-only file still serves reads even if this write fails.
        try:
            _create_hidden_keys_objects(conn)
            conn.commit()
        except sqlite3.OperationalError as exc:
            log.warning(f"could not create hidden_keys/v_identified_visible (read-only database?): {exc}")

        conn.row_factory = sqlite3.Row
        self._conn = conn

    def __enter__(self) -> "IdentifyResults":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        self._conn.close()

    def counts(self) -> ResultCounts:
        """Return the per-category row counts (see :class:`ResultCounts`)."""
        row = self._conn.execute("""
            SELECT
                SUM(CASE WHEN excluded = 0 AND matched_signatures = '' AND NOT EXISTS (
                        SELECT 1 FROM hidden_keys hk
                        WHERE hk.message = il.message AND hk.process = COALESCE(il.process, '')
                    ) THEN 1 ELSE 0 END) AS retained,
                SUM(CASE WHEN excluded = 1 THEN 1 ELSE 0 END) AS noise,
                SUM(CASE WHEN matched_signatures != '' THEN 1 ELSE 0 END) AS kb_known,
                SUM(CASE WHEN EXISTS (
                        SELECT 1 FROM hidden_keys hk
                        WHERE hk.message = il.message AND hk.process = COALESCE(il.process, '')
                    ) THEN 1 ELSE 0 END) AS hidden
            FROM identified_logs il
        """).fetchone()
        return ResultCounts(
            retained=row["retained"] or 0,
            noise=row["noise"] or 0,
            kb_known=row["kb_known"] or 0,
            hidden=row["hidden"] or 0,
        )

    def count(
        self,
        *,
        include_noise: bool = False,
        include_kb_known: bool = False,
        include_hidden: bool = False,
        search: str | None = None,
    ) -> int:
        """Total rows :meth:`rows` would return for the same flags.

        A ``COUNT(*)`` — never materialises the rows, so a paging consumer
        (the GUI table) can size itself without loading the whole result set.
        """
        where, params = self._build_where(
            include_noise=include_noise,
            include_kb_known=include_kb_known,
            include_hidden=include_hidden,
            search=search,
        )
        return self._conn.execute(
            f"SELECT COUNT(*) FROM identified_logs il WHERE {where}", params
        ).fetchone()[0]

    def rows(
        self,
        *,
        include_noise: bool = False,
        include_kb_known: bool = False,
        include_hidden: bool = False,
        search: str | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[sqlite3.Row]:
        """Return matching rows, ordered ``timestamp_unix_ns ASC, id ASC``."""
        where, params = self._build_where(
            include_noise=include_noise,
            include_kb_known=include_kb_known,
            include_hidden=include_hidden,
            search=search,
        )
        sql = f"SELECT {_ROWS_COLUMNS} FROM identified_logs il WHERE {where} " \
              "ORDER BY timestamp_unix_ns ASC, id ASC"
        if limit is not None:
            sql += " LIMIT ? OFFSET ?"
            params.extend([limit, offset])
        elif offset:
            # SQLite requires a LIMIT for OFFSET to apply; -1 means "no limit".
            sql += " LIMIT -1 OFFSET ?"
            params.append(offset)
        return self._conn.execute(sql, params).fetchall()

    def hide(self, message: str | None, process: str | None) -> None:
        """Mark ``(message, process)`` as hidden (reversible; see :meth:`unhide`).

        *process* ``None`` is stored as ``''`` — matching the COALESCE used by
        ``v_identified_visible`` and by :meth:`rows`'s hidden-key check.

        Raises:
            ValueError: *message* is None — ``hidden_keys.message`` is NOT
                NULL, and a NULL-message row has no identical-lines key to
                hide by anyway.
        """
        if message is None:
            raise ValueError("cannot hide by message: this row has no message")
        self._conn.execute(
            "INSERT OR IGNORE INTO hidden_keys (message, process) VALUES (?, ?)",
            (message, process or ""),
        )
        self._conn.commit()

    def unhide(self, message: str, process: str | None) -> None:
        """Reverse :meth:`hide` for ``(message, process)``."""
        self._conn.execute(
            "DELETE FROM hidden_keys WHERE message = ? AND process = ?",
            (message, process or ""),
        )
        self._conn.commit()

    def hidden_keys(self) -> list[tuple[str, str]]:
        """Return every ``(message, process)`` pair currently hidden."""
        cur = self._conn.execute("SELECT message, process FROM hidden_keys")
        return [(row["message"], row["process"]) for row in cur]

    def export_csv(
        self,
        path: Path,
        *,
        include_noise: bool = False,
        include_kb_known: bool = True,
    ) -> int:
        """Write matching rows to *path* as CSV; returns the row count written.

        Header and column order match ``run_diff``'s own CSV (see diff.py's
        ``_CSV_HEADER``), so a result-store export drops into the same
        downstream tooling. ``include_hidden`` is deliberately not exposed here
        — an export is meant to reflect the analyst's current pruning.
        """
        rows = self.rows(include_noise=include_noise, include_kb_known=include_kb_known)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="", encoding="utf-8-sig") as fp:  # BOM so Excel auto-detects UTF-8
            writer = csv.writer(fp)
            writer.writerow(_EXPORT_HEADER)
            for row in rows:
                writer.writerow([
                    row["timestamp"], row["timestamp_unix_ns"], row["event_order"],
                    row["process"], row["pid"], row["tid"], row["log_level"],
                    row["event_type"], row["subsystem"], row["category"],
                    row["message"], row["matched_signatures"], row["note"],
                ])
        return len(rows)

    def _build_where(
        self,
        *,
        include_noise: bool,
        include_kb_known: bool,
        include_hidden: bool,
        search: str | None,
    ) -> tuple[str, list]:
        clauses: list[str] = []
        params: list = []
        if not include_noise:
            clauses.append("il.excluded = 0")
        if not include_kb_known:
            clauses.append("il.matched_signatures = ''")
        if not include_hidden:
            clauses.append("""NOT EXISTS (
                SELECT 1 FROM hidden_keys hk
                WHERE hk.message = il.message AND hk.process = COALESCE(il.process, '')
            )""")
        if search:
            # Literal substring match: escape LIKE metacharacters so %/_ in the
            # search text match themselves — the same _escape_like the query
            # layer pairs with its ESCAPE declaration (one source of truth for
            # a subtle rule; a drifted copy would silently never match).
            clauses.append(r"il.message LIKE ? ESCAPE '\'")
            params.append(f"%{_escape_like(search)}%")
        where = " AND ".join(clauses) if clauses else "1=1"
        return where, params
