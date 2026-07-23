"""Integration test — serial vs parallel extract must be identical.

Runs the full pipeline twice over the same logarchive (``--jobs 1`` and a
multi-process run) and asserts the *resolved* ordered view is byte-identical.
Surrogate ids (process_id, …) may differ run-to-run under multiprocessing, so
the comparison joins them to their names and orders by the deterministic
``event_order``.

Skipped automatically when the logarchive is absent. Marked slow (two full
extracts): run with ``pytest -m 'integration and slow'`` or override the sample
via ``FAUL_EQUIV_LOGARCHIVE``.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
from pathlib import Path

import pytest

from forensic_aul.ops.extraction.extract import run_extract

pytestmark = [pytest.mark.integration, pytest.mark.slow]

_LOGARCHIVE = Path(
    os.environ.get(
        "FAUL_EQUIV_LOGARCHIVE",
        str(Path(__file__).parent.parent / "data" / "iphoneSE_afterbackup.logarchive"),
    )
)

# Resolved view: surrogate ids → names, ordered by the deterministic event_order.
# The normalised columns (boot_uuid, log_level, event_type, process_uuid) are
# joined back to their names so the digest is independent of run-to-run ids; the
# ISO timestamp is no longer stored (timestamp_unix_ns fully determines it).
_VIEW_SQL = """
SELECT l.event_order, l.source_order, l.tracev3_file_id,
       l.timestamp_mach, l.timestamp_unix_ns,
       b.boot_uuid, l.pid, l.tid, l.euid, ll.name, et.name,
       p.name, s.name, c.name, f.value, lib.name, lib.uuid,
       pu.uuid, l.activity_id, l.parent_activity_id, l.message,
       l.tracev3_chunkset_file_offset, l.tracev3_firehose_inner_offset,
       l.tracev3_entry_inner_offset
FROM logs l
LEFT JOIN processes    p   ON p.id   = l.process_id
LEFT JOIN subsystems   s   ON s.id   = l.subsystem_id
LEFT JOIN categories   c   ON c.id   = l.category_id
LEFT JOIN format_strs  f   ON f.id   = l.format_str_id
LEFT JOIN libraries    lib ON lib.id = l.library_id
LEFT JOIN boots        b   ON b.id   = l.boot_id
LEFT JOIN log_levels   ll  ON ll.id  = l.log_level_id
LEFT JOIN event_types  et  ON et.id  = l.event_type_id
LEFT JOIN process_uuids pu ON pu.id  = l.process_uuid_id
ORDER BY l.event_order
"""


def _resolved_digest(db_path: Path) -> tuple[int, str]:
    conn = sqlite3.connect(str(db_path))
    h = hashlib.sha256()
    n = 0
    try:
        for row in conn.execute(_VIEW_SQL):
            h.update(repr(row).encode())
            n += 1
    finally:
        conn.close()
    return n, h.hexdigest()


def _extract(db_path: Path, jobs: int) -> None:
    run_extract(
        logarchive=_LOGARCHIVE,
        db_path=db_path,
        case_number="TEST-EQUIV",
        imei="000000000000000",
        batch_size=1000,
        jobs=jobs,
    )


def test_serial_and_parallel_extract_are_identical(tmp_path):
    if not _LOGARCHIVE.is_dir():
        pytest.skip(f"logarchive not found: {_LOGARCHIVE}")

    db1 = tmp_path / "serial.db"
    db4 = tmp_path / "parallel.db"
    _extract(db1, jobs=1)
    _extract(db4, jobs=4)

    n1, d1 = _resolved_digest(db1)
    n4, d4 = _resolved_digest(db4)

    assert n1 == n4, f"row count differs: serial={n1} parallel={n4}"
    assert n1 > 0
    assert d1 == d4, "resolved ordered view differs between serial and parallel extract"
