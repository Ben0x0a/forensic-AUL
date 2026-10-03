"""Validated opening of an analysis database (the shared entry gate).

Defines : ``open_analysis_database`` — the one place a path is turned into a
          connection for the path-based readers (``query_logs``, ``run_export``,
          ``summarise``, ``annotate_database``, …). Centralising it gives every
          reader the same, clear errors instead of a raw ``sqlite3.DatabaseError``
          ("file is not a database") leaking to the consumer, and one place where
          an interrupted extract's output is refused.
Used by : forensic_aul.ops.query, forensic_aul.ops.export.exporter,
          forensic_aul.ops.summary.summary, forensic_aul.ops.annotation.matcher,
          forensic_aul.ops.verify.verify.
Uses    : forensic_aul.errors (InvalidDatabaseError, IncompleteDatabaseError),
          forensic_aul.engine.database.schema (the extract_status vocabulary),
          sqlite3.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from forensic_aul.engine.database.schema import EXTRACT_STATUS_COMPLETE
from forensic_aul.errors import IncompleteDatabaseError, InvalidDatabaseError


def _extract_status(conn: sqlite3.Connection) -> str | None:
    """Return the newest ``case_metadata.extract_status``, or None if unknowable.

    None covers the two "no claim was made" cases, which are deliberately NOT
    treated as incomplete: a database written before the column existed, and one
    whose ``case_metadata`` is empty or NULL there (a hand-built fixture, or a
    store assembled by something other than ``run_extract``). Only a database
    that actively says it did not finish is refused — silence is not a claim.
    """
    try:
        row = conn.execute(
            "SELECT extract_status FROM case_metadata ORDER BY id DESC LIMIT 1"
        ).fetchone()
    except sqlite3.OperationalError:
        # No such column / no such table — an older schema, which cannot report.
        return None
    return row[0] if row else None


def open_analysis_database(
    database: Path | str, *, allow_incomplete: bool = False
) -> sqlite3.Connection:
    """Open *database* and verify it is an analysis store; return the connection.

    Checks, in order: the path is an existing file; SQLite can read it (a text
    file / random binary raises ``sqlite3.DatabaseError`` only on first use, so
    the schema is probed eagerly here); it carries the ``logs`` table every
    ``run_extract`` output has; and its extract run actually finished. The caller
    owns (and must close) the returned connection.

    *allow_incomplete* opens a database whose run did not finish — a ``.partial``
    left by a cancelled, crashed or killed extract. It is the escape valve that
    keeps the refusal above from being a dead end, and is deliberately **not**
    exposed by the CLI or the GUI: the answer an analyst wants is "re-run the
    extract", and a flag for reading a knowingly-partial store would be a
    foot-gun offered for a workflow nobody has. Kept as a library kwarg so the
    guard stays testable and so a future caller has a supported way in.

    Raises:
        FileNotFoundError: *database* does not exist or is not a file.
        InvalidDatabaseError: the file is not a SQLite database, or is one but
            was not produced by ``run_extract`` (no ``logs`` table).
        IncompleteDatabaseError: the extract that produced it never completed and
            *allow_incomplete* is False.
    """
    path = Path(database)
    if not path.is_file():
        raise FileNotFoundError(f"{path} is not a file")

    conn = sqlite3.connect(str(path))
    try:
        has_logs = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='logs'"
        ).fetchone()
    except sqlite3.DatabaseError as exc:
        conn.close()
        raise InvalidDatabaseError(f"{path} is not a SQLite database: {exc}") from exc
    except BaseException:
        # Never leak the connection, whatever interrupted the probe.
        conn.close()
        raise
    if has_logs is None:
        conn.close()
        raise InvalidDatabaseError(
            f"{path} is a SQLite database but not an analysis database "
            "(no `logs` table — was it produced by run_extract?)"
        )

    if not allow_incomplete:
        status = _extract_status(conn)
        if status is not None and status != EXTRACT_STATUS_COMPLETE:
            conn.close()
            raise IncompleteDatabaseError(
                f"{path} was produced by an extract that never completed "
                f"(extract_status={status!r}). Its ordering, indexes and "
                "full-text index may be missing or partial, so results read from "
                "it would silently under-report. Re-run the extract."
            )
    return conn
