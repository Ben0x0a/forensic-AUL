"""Validated opening of an analysis database (the shared entry gate).

Defines : ``open_analysis_database`` — the one place a path is turned into a
          connection for the path-based readers (``query_logs``, ``run_export``,
          ``summarise``, ``annotate_database``, …). Centralising it gives every
          reader the same, clear errors instead of a raw ``sqlite3.DatabaseError``
          ("file is not a database") leaking to the consumer.
Used by : forensic_aul.ops.query, forensic_aul.ops.export.exporter,
          forensic_aul.ops.summary.summary, forensic_aul.ops.annotation.matcher.
Uses    : forensic_aul.errors (InvalidDatabaseError), sqlite3.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from forensic_aul.errors import InvalidDatabaseError


def open_analysis_database(database: Path | str) -> sqlite3.Connection:
    """Open *database* and verify it is an analysis store; return the connection.

    Checks, in order: the path is an existing file; SQLite can read it (a text
    file / random binary raises ``sqlite3.DatabaseError`` only on first use, so
    the schema is probed eagerly here); and it carries the ``logs`` table every
    ``run_extract`` output has. The caller owns (and must close) the returned
    connection.

    Raises:
        FileNotFoundError: *database* does not exist or is not a file.
        InvalidDatabaseError: the file is not a SQLite database, or is one but
            was not produced by ``run_extract`` (no ``logs`` table).
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
    return conn
