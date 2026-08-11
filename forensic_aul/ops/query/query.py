"""In-memory query API over an analysis database (the public entry points).

Defines : ``query_logs`` (streamed filtered rows), ``LogStore`` (a held-open
          read store for consumers that issue many small reads — paging table
          UIs), and the one-shot conveniences ``count_logs`` / ``fetch_logs``
          (exact paging) and ``fetch_context`` (the rows around a line on the
          forensic ``event_order`` timeline), all thin wrappers over LogStore.
          Rows come back as :class:`~forensic_aul.ops.query.reader.LogRow`
          objects; the filter vocabulary is
          :class:`~forensic_aul.ops.query.reader.LogFilters`. Consumers that
          prefer raw SQL should query the stable ``v_logs`` view (see
          engine/database/schema.py) instead of the normalised tables.
Used by : forensic_aul/__init__.py (re-exports the entry points), the GUI
          (gui/views/screen_exploit.py holds a LogStore) and any launcher
          feature that needs rows in memory rather than a file.
Uses    : forensic_aul.ops.query.reader (filters → SQL → streamed rows),
          forensic_aul.engine.database.access (validated open),
          forensic_aul.engine.database.schema (ensure_views).
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Iterator

from forensic_aul.engine.database.access import open_analysis_database
from forensic_aul.ops.query.reader import (
    LogFilters,
    LogRow,
    build_where,
    count_rows,
    fetch_event_window,
    fetch_page,
    has_fts_index,
    has_kb_tables,
    iter_logs,
    resolve_time_bounds,
)

log = logging.getLogger(__name__)

__all__ = [
    "LogFilters", "LogRow", "LogStore", "query_logs",
    "count_logs", "fetch_logs", "fetch_context",
]


def query_logs(
    database: Path | str,
    *,
    process: list[str] | str | None = None,
    subsystem: list[str] | str | None = None,
    category: list[str] | str | None = None,
    level: list[str] | str | None = None,
    message_prefix: str | None = None,
    message_contains: str | None = None,
    message_match: str | None = None,
    format_str: str | None = None,
    like: str | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
    last: str | None = None,
    signature: list[str] | str | None = None,
    action: str | None = None,
    tag: list[str] | str | None = None,
    annotated_only: bool = False,
    limit: int | None = None,
) -> Iterator[LogRow]:
    """Stream filtered log rows from *database* as :class:`LogRow` objects.

    The stable, in-memory counterpart of :func:`~forensic_aul.run_export` — the
    same filter vocabulary, but yielding rows instead of writing a file, so
    consumers never need to touch the internal schema::

        from forensic_aul import query_logs

        for row in query_logs("case.db",
                              subsystem="com.apple.rapport",
                              message_prefix="Bonjour unauth peer found"):
            print(row.timestamp_iso, row.process, row.message)

    Filter semantics: list-valued filters (*process*, *subsystem*, *category*,
    *level*, *signature*, *tag*) accept a single string or a list — values within a
    filter are OR-combined; different filters are AND-combined.
    *message_prefix* matches the composed message **literally** (``%``/``_``
    are escaped) — the right filter for dynamic messages whose format string
    is NULL or a bare ``%{public}s``; *message_match* is a keyword search via
    the FTS5 index (terms AND-combined, matched literally — needs an extract
    with FTS enabled); *like* is a raw SQL LIKE pattern; *format_str* is an
    exact match on the invariant template. *limit* bounds the number of rows
    yielded. Rows come back ordered by (timestamp_unix_ns, id).

    The generator owns its database connection: it is closed when the iterator
    is exhausted, garbage-collected, or ``.close()``d — safe to abandon early.

    Raises:
        FileNotFoundError: *database* does not exist (raised eagerly, at call).
        InvalidDatabaseError: the file is not an analysis database (raised on
            first iteration, when the connection opens).
        ValueError: a filter value is malformed (eager), an annotation filter
            (*signature*/*action*/*tag*/*annotated_only*) is used on a database
            that has never been annotated, or *message_match* is used on a
            database with no full-text index (both raised on first iteration).
    """
    # Eager validation: path and filter values are checked at call time so the
    # common mistakes surface immediately, not on first iteration of the
    # returned generator.
    db = Path(database)
    if not db.is_file():
        raise FileNotFoundError(f"{db} is not a file")

    filters = LogFilters(
        time_from=time_from,
        time_to=time_to,
        last=last,
        process=_as_list(process),
        subsystem=_as_list(subsystem),
        category=_as_list(category),
        level=_as_list(level),
        like=like,
        message_prefix=message_prefix,
        message_contains=message_contains,
        message_match=message_match,
        format_str=format_str,
        signature=_as_list(signature),
        action=action,
        tag=_as_list(tag),
        annotated_only=annotated_only,
    )
    time_from_ns, time_to_ns = resolve_time_bounds(filters)
    return _stream_rows(db, filters, time_from_ns, time_to_ns, limit)


def _stream_rows(
    db: Path,
    filters: LogFilters,
    time_from_ns: int | None,
    time_to_ns: int | None,
    limit: int | None,
) -> Iterator[LogRow]:
    """Generator body of :func:`query_logs` — owns the database connection.

    WHY a separate generator (not the public function itself): opening the
    connection lazily and closing it in a ``finally`` means it survives for the
    whole iteration yet is still closed when the caller abandons the iterator
    early (generator close/GC runs the finally block). A never-started generator
    then never opens a connection at all, so nothing can leak.
    """
    conn = open_analysis_database(db)
    try:
        _ensure_views_best_effort(conn)
        has_kb = has_kb_tables(conn)
        _require_kb_filters(has_kb, filters)
        where, params = build_where(conn, filters, time_from_ns, time_to_ns)
        yield from iter_logs(conn, where, params, has_kb=has_kb, limit=limit)
    finally:
        conn.close()


class LogStore:
    """A held-open read store over one analysis database (paging + context).

    The one-shot module functions (:func:`count_logs` / :func:`fetch_logs` /
    :func:`fetch_context`) are right for a single library read; a table UI
    paging through a database issues many small reads in a row, where
    reopening the file and re-probing its capabilities per page is pure
    overhead. LogStore opens (and validates) once, caches the capability
    probes, and serves reads until closed. Use as a context manager or call
    :meth:`close` explicitly.

    Attributes:
        has_kb: the database carries the knowledge-base annotation tables.
        has_fts: the database carries a usable full-text index (front-ends
            gate their keyword-search affordance on this — no index means no
            keyword search, never a silent LIKE fallback).

    Raises:
        FileNotFoundError / InvalidDatabaseError: as
        :func:`~forensic_aul.engine.database.access.open_analysis_database`.
    """

    def __init__(self, database: Path | str) -> None:
        conn = open_analysis_database(database)
        try:
            _ensure_views_best_effort(conn)
            self.has_kb = has_kb_tables(conn)
            self.has_fts = has_fts_index(conn)
        except BaseException:
            # Never leak the connection when a capability probe fails.
            conn.close()
            raise
        self._conn = conn

    def __enter__(self) -> "LogStore":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        self._conn.close()

    def count(self, filters: LogFilters | None = None) -> int:
        """Total logs matching *filters* — call once per filter change, then
        page with :meth:`fetch`.

        Raises:
            ValueError: a filter value is malformed, an annotation filter is
                used without KB tables, or ``message_match`` without an index.
        """
        where, params = self._where(filters or LogFilters())
        return count_rows(self._conn, where, params)

    def fetch(
        self,
        filters: LogFilters | None = None,
        *,
        offset: int = 0,
        limit: int = 500,
    ) -> list[LogRow]:
        """One page of :class:`LogRow`s matching *filters*.

        *offset*/*limit* count LOGS (not annotation-joined rows), so pages are
        exact regardless of how many annotations a log carries. Rows come back
        ordered by (timestamp_unix_ns, id), consistent across pages.
        """
        where, params = self._where(filters or LogFilters())
        return fetch_page(
            self._conn, where, params,
            has_kb=self.has_kb, offset=offset, limit=limit,
        )

    def context(self, log_id: int, *, before: int = 20, after: int = 20) -> list[LogRow]:
        """The rows surrounding log *log_id* on the forensic timeline.

        Returns up to *before* + 1 + *after* rows ordered by ``event_order`` —
        the anchor row included (identifiable by ``row.log_id == log_id``).
        WHY event_order and not wall-clock: event_order is the tamper-resilient
        sequence; neighbours by timestamp could be reordered by a shifted clock.

        Raises:
            ValueError: *log_id* does not exist, or the database has no
                ordering assigned (event_order NULL — extract was interrupted
                before the ordering pass).
        """
        row = self._conn.execute(
            "SELECT event_order FROM logs WHERE id = ?", (log_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"log id {log_id} does not exist in this database")
        if row[0] is None:
            raise ValueError(
                "event_order is not assigned on this database (interrupted "
                "extract?) — context view needs the forensic ordering"
            )
        eo = int(row[0])
        return fetch_event_window(
            self._conn, max(0, eo - before), eo + after, has_kb=self.has_kb,
        )

    def _where(self, f: LogFilters) -> tuple[str, list]:
        """Shared filters → WHERE step behind :meth:`count` and :meth:`fetch`."""
        _require_kb_filters(self.has_kb, f)
        time_from_ns, time_to_ns = resolve_time_bounds(f)
        return build_where(self._conn, f, time_from_ns, time_to_ns)


def count_logs(database: Path | str, filters: LogFilters | None = None) -> int:
    """Total logs in *database* matching *filters* — the paging counterpart of
    :func:`fetch_logs`. One-shot convenience over :class:`LogStore`; a caller
    issuing several reads should hold its own store instead.

    Raises:
        FileNotFoundError / InvalidDatabaseError / ValueError: as
        :class:`LogStore` and :meth:`LogStore.count`.
    """
    with LogStore(database) as store:
        return store.count(filters)


def fetch_logs(
    database: Path | str,
    filters: LogFilters | None = None,
    *,
    offset: int = 0,
    limit: int = 500,
) -> list[LogRow]:
    """One page of :class:`LogRow`s — the windowed counterpart of
    :func:`query_logs`. One-shot convenience over :meth:`LogStore.fetch`; for
    a one-shot streamed read prefer :func:`query_logs`.
    """
    with LogStore(database) as store:
        return store.fetch(filters, offset=offset, limit=limit)


def fetch_context(
    database: Path | str,
    log_id: int,
    *,
    before: int = 20,
    after: int = 20,
) -> list[LogRow]:
    """The rows surrounding log *log_id* on the forensic timeline
    (event_order). One-shot convenience over :meth:`LogStore.context`.
    """
    with LogStore(database) as store:
        return store.context(log_id, before=before, after=after)


def _require_kb_filters(has_kb: bool, f: LogFilters) -> None:
    """Shared guard: annotation filters demand an annotated database."""
    if not has_kb and (f.signature or f.action or f.tag or f.annotated_only):
        raise ValueError("this database has no KB annotations — run `annotate` first")


def _ensure_views_best_effort(conn: sqlite3.Connection) -> None:
    """Create the stable read views on databases that predate them.

    Best-effort by design: a read-only database (or read-only filesystem) can
    still be queried through the normalised tables, so a failed CREATE VIEW is
    logged and ignored rather than raised.
    """
    from forensic_aul.engine.database.schema import ensure_views

    try:
        ensure_views(conn)
    except sqlite3.Error as exc:
        log.debug("could not create read views (read-only database?): %s", exc)


def _as_list(value: list[str] | str | None) -> list[str] | None:
    """Accept a bare string where a list is expected (single-value convenience)."""
    if value is None or isinstance(value, list):
        return value
    return [value]
