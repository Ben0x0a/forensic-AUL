"""Deterministic forensic ordering for the ``logs`` table.

Defines : :func:`assign_ordering`, which fills the two ordering columns *after*
          the bulk load — so the order is independent of insertion order (and
          therefore of how many parser processes ran in Part B):

            - ``source_order`` : physical position **within each tracev3 file**
                                 (per-file, 1-based, by byte offsets). Combined
                                 with ``tracev3_file_id`` it pinpoints a record's
                                 exact slot in its own stream — the truest
                                 "as it is in the source".
            - ``event_order``  : the merged real timeline = (boot physical rank,
                                 monotonic ``timestamp_mach``). This is what
                                 ``log show`` reconstructs. It is ordered by the
                                 **monotonic** clock, never wall-clock — that is
                                 precisely what keeps time-shifting (clock
                                 tampering) visible: a backwards jump in
                                 ``timestamp_iso`` while ``event_order`` keeps
                                 rising is the tamper signal.

Used by : forensic_aul/extract.py (end of ``_run_extract_inner``).
Uses    : the open sqlite3 connection. The boot rank comes from the ``boots``
          table (``rank`` column), populated from the *physical* timesync layout
          (see extract.py step 4). Boot order deliberately does NOT come from
          ``boot_time`` (wall-clock at boot), which a clock reset could reorder.
"""

from __future__ import annotations

import logging
import sqlite3

from forensic_aul.config import ORDERING_CACHE_SIZE_KIB, ORDERING_UPDATE_BATCH_ROWS
from forensic_aul.engine.database.schema import UNKNOWN_BOOT_RANK

log = logging.getLogger(__name__)

# ``UPDATE … FROM`` (single-join, O(n log n)) landed in SQLite 3.33.0 (2020).
# Below that a correlated subquery would be O(n²) over millions of rows, so we
# refuse rather than silently crawl — every supported Python 3.12 ships ≥ 3.37.
_MIN_SQLITE = (3, 33, 0)


def assign_ordering(conn: sqlite3.Connection) -> None:
    """Populate ``logs.source_order`` and ``logs.event_order`` deterministically.

    Boot rank is read from ``boots.rank`` (joined on ``logs.boot_id``): an integer
    comparison, where the old TEXT ``boot_uuid`` join needed a temp table. A logs
    row with no ``boot_id`` at all (empty boot_uuid) falls back to
    ``UNKNOWN_BOOT_RANK`` so it sorts after every known boot.

    Raises:
        RuntimeError: the bundled SQLite is too old for ``UPDATE … FROM``.
    """
    if sqlite3.sqlite_version_info < _MIN_SQLITE:
        raise RuntimeError(
            f"assign_ordering requires SQLite ≥ {'.'.join(map(str, _MIN_SQLITE))} "
            f"(have {sqlite3.sqlite_version}) for an efficient UPDATE … FROM."
        )

    # Phase 1 — compute BOTH orderings in one SELECT into a TEMP table keyed by id.
    # The two ROW_NUMBER window sorts run under PRAGMA threads (multi-core). A TEMP
    # table lives in the temp database, so building it does NOT touch the main WAL —
    # only the write-back in phase 2 does.
    #   - source_order: per-file physical position (PARTITION BY the file; NULL
    #     offsets, e.g. Loss, sort first; id is the final tiebreak).
    #   - event_order : merged real timeline — COALESCE pushes unknown boots last;
    #     ordered by the monotonic mach clock (NOT wall-clock), tied by physical
    #     position then id.
    with conn:
        conn.execute("DROP TABLE IF EXISTS _ord")
        conn.execute(
            f"""
            CREATE TEMP TABLE _ord AS
            SELECT logs.id AS id,
                   ROW_NUMBER() OVER (
                       PARTITION BY tracev3_file_id
                       ORDER BY tracev3_chunkset_file_offset,
                                tracev3_firehose_inner_offset,
                                tracev3_entry_inner_offset,
                                logs.id
                   ) AS so,
                   ROW_NUMBER() OVER (
                       ORDER BY COALESCE(b.rank, {UNKNOWN_BOOT_RANK}),
                                logs.timestamp_mach,
                                logs.tracev3_file_id,
                                logs.tracev3_chunkset_file_offset,
                                logs.tracev3_firehose_inner_offset,
                                logs.tracev3_entry_inner_offset,
                                logs.id
                   ) AS eo
            FROM logs
            LEFT JOIN boots b ON b.id = logs.boot_id
            """
        )
        # ``CREATE TABLE AS`` gives _ord no rowid alias on id; add a covering PK so
        # the write-back join is an indexed lookup, not a scan, per logs row.
        conn.execute("CREATE UNIQUE INDEX _ord_id ON _ord(id)")

    # Phase 2 — write the two columns back into ``logs`` in id-range batches,
    # committing and TRUNCATE-checkpointing the WAL after each. WHY batched: the old
    # single UPDATE of every row ran in ONE transaction, so the WAL grew to a whole-
    # table rewrite (~24 GB) with no mid-transaction checkpoint and filled the disk.
    # Checkpointing per batch caps the WAL at roughly one batch's worth of pages.
    # The ordering itself is already fully materialised in _ord, so batching the
    # write-back cannot change the result. A larger page cache (restored afterwards)
    # keeps the re-read working set in RAM. Re-runnable: a crash mid-pass leaves some
    # event_order NULL, and assign_ordering is idempotent — re-running completes it.
    prev_cache = conn.execute("PRAGMA cache_size").fetchone()[0]
    conn.execute(f"PRAGMA cache_size={ORDERING_CACHE_SIZE_KIB}")
    try:
        bounds = conn.execute("SELECT MIN(id), MAX(id) FROM logs").fetchone()
        min_id, max_id = (bounds or (None, None))
        if min_id is not None:
            lo = min_id
            while lo <= max_id:
                hi = lo + ORDERING_UPDATE_BATCH_ROWS
                conn.execute(
                    """
                    UPDATE logs SET source_order = o.so, event_order = o.eo
                    FROM _ord o
                    WHERE logs.id = o.id AND logs.id >= ? AND logs.id < ?
                    """,
                    (lo, hi),
                )
                conn.commit()
                # TRUNCATE resets the WAL file to zero between batches; a no-op on a
                # non-WAL connection (e.g. the in-memory unit-test db).
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                lo = hi
    finally:
        conn.execute(f"PRAGMA cache_size={prev_cache}")
        conn.execute("DROP TABLE IF EXISTS _ord")
        conn.commit()

    n_boots = conn.execute("SELECT COUNT(*) FROM boots").fetchone()[0]
    log.info(f"Ordering assigned : source_order (per-file) + event_order (boot,mach) over {n_boots} boot(s)")
