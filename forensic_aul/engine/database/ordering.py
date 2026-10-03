"""Deterministic forensic ordering for the ``logs`` table.

Defines : :func:`assign_ordering`, which fills the ``logs_order`` side table
          *after* the bulk load — so the order is independent of insertion order
          (and therefore of how many parser processes ran in Part B):

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
                                 tampering) visible: a backwards jump in the
                                 wall-clock timestamp while ``event_order`` keeps
                                 rising is the tamper signal.

Used by : forensic_aul/ops/extraction/extract.py (the "ordering" phase).
Uses    : the open sqlite3 connection, and schema.temp_store_on_disk. The boot
          rank comes from the ``boots`` table (``rank`` column), populated from
          the *physical* timesync layout (see extract.py step 4). Boot order
          deliberately does NOT come from ``boot_time`` (wall-clock at boot),
          which a clock reset could reorder.

WHY a side table rather than two columns on ``logs``
----------------------------------------------------
The ordering is only computable once every row is loaded, so it used to be
back-filled with ``UPDATE logs SET source_order = …, event_order = …`` over
every row. SQLite rewrites a whole page per row touched, so storing two 4-byte
integers cost a ~14 GB rewrite of the widest table in the database — 28% of a
large extract's wall time — and, with the full-text index live, an ``UPDATE``
trigger fired a delete+insert into ``logs_fts`` per row although ``message``
never changed. Writing a narrow table instead costs roughly a tenth of that and
needs no ``UPDATE`` at all, so neither cost exists any more.

It also made the pass **atomic**. The old write-back was batched and committed
per batch, so an interrupted run left ``logs`` half-ordered; now the single
INSERT either commits whole or rolls back to an empty table. Re-running is
therefore always a clean recompute, which is what G1's resume design needs from
every post-parse phase (see tasks/g1_cancellation_plan.md).
"""

from __future__ import annotations

import logging
import sqlite3

from forensic_aul.config import ORDERING_CACHE_SIZE_KIB
from forensic_aul.engine.database.schema import UNKNOWN_BOOT_RANK, temp_store_on_disk

log = logging.getLogger(__name__)


def assign_ordering(conn: sqlite3.Connection) -> None:
    """Populate ``logs_order`` deterministically. Idempotent.

    Boot rank is read from ``boots.rank`` (joined on ``logs.boot_id``): an integer
    comparison, where the old TEXT ``boot_uuid`` join needed a temp table. A logs
    row with no ``boot_id`` at all (empty boot_uuid) falls back to
    ``UNKNOWN_BOOT_RANK`` so it sorts after every known boot.
    """
    # Both orderings come from one SELECT, computed by two ROW_NUMBER window
    # sorts that run under PRAGMA threads (multi-core):
    #   - source_order: per-file physical position (PARTITION BY the file; NULL
    #     offsets, e.g. Loss records, sort first; id is the final tiebreak).
    #   - event_order : merged real timeline — COALESCE pushes unknown boots
    #     last; ordered by the monotonic mach clock (NOT wall-clock), tied by
    #     physical position then id.
    #
    # HOW the outer ``ORDER BY id`` earns its place: without it rows arrive in
    # window-function order and scatter across the destination's rowid B-tree.
    # Ordering by id makes every insert an append to the right-hand edge, which
    # is the difference between a sequential build and a random one.
    ordering_sql = f"""
        INSERT INTO logs_order (id, source_order, event_order)
        SELECT id, so, eo
        FROM (
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
        )
        ORDER BY id
    """

    # A larger page cache for the scan feeding the sorts; restored afterwards.
    prev_cache = conn.execute("PRAGMA cache_size").fetchone()[0]
    conn.execute(f"PRAGMA cache_size={ORDERING_CACHE_SIZE_KIB}")
    try:
        # temp_store_on_disk: the two window sorts materialise every row, and
        # apply_pragmas leaves temp_store=MEMORY — which is what made this pass
        # the peak-RSS phase of an extract. See the helper's docstring.
        with temp_store_on_disk(conn), conn:
            # Idempotency. The pass owns this table outright and always recomputes
            # it whole, so clearing first is the honest expression of that — and a
            # bare DELETE lets SQLite take its truncate path instead of visiting
            # rows. A completed run re-ordered (a resume replaying the phase) is
            # then a clean recompute, not a primary-key collision.
            conn.execute("DELETE FROM logs_order")
            conn.execute(ordering_sql)
    finally:
        conn.execute(f"PRAGMA cache_size={prev_cache}")

    n_boots = conn.execute("SELECT COUNT(*) FROM boots").fetchone()[0]
    log.info(f"Ordering assigned : source_order (per-file) + event_order (boot,mach) over {n_boots} boot(s)")
