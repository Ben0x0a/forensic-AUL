"""Facts about one identify run, stored inside its identified database.

Defines : write_run_info / read_run_info over an ``identify_run`` key/value table,
          and the key name ACTION_DESCRIPTION_KEY.
Used by : forensic_aul.ops.workflows.identify (writes after the diff);
          forensic_aul.ops.identify.results (reads, for the results viewer).
Uses    : sqlite3, forensic_aul.ops.identify.diff (read_only_uri: a
          percent-encoded URI, so any path opens).

WHY in the identified database and not a sidecar file: the database is the
artefact an analyst keeps, copies and reopens; what the action was must travel
with the rows it explains.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from pathlib import Path

from forensic_aul.ops.identify.diff import read_only_uri

# Keys of the identify_run table. Consumed by: workflows/identify.py, results.py.
ACTION_DESCRIPTION_KEY = "action_description"

_TABLE_NAME = "identify_run"


def write_run_info(db: Path, info: Mapping[str, str]) -> None:
    """Store *info* in *db* (created if absent), replacing keys already there."""
    with sqlite3.connect(db) as conn:
        conn.execute(f"CREATE TABLE IF NOT EXISTS {_TABLE_NAME} (key TEXT PRIMARY KEY, value TEXT)")
        conn.executemany(
            f"INSERT OR REPLACE INTO {_TABLE_NAME} (key, value) VALUES (?, ?)", info.items(),
        )
    conn.close()


def read_run_info(db: Path) -> dict[str, str]:
    """The stored facts, or ``{}`` for a database written before they existed."""
    conn = sqlite3.connect(read_only_uri(db), uri=True)
    try:
        return dict(conn.execute(f"SELECT key, value FROM {_TABLE_NAME}"))
    except sqlite3.OperationalError:
        return {}
    finally:
        conn.close()


__all__ = [
    "ACTION_DESCRIPTION_KEY",
    "read_run_info",
    "write_run_info",
]
