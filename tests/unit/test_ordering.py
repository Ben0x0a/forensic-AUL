"""Unit tests for forensic ordering — forensic_aul/engine/database/ordering.py.

Pure SQL logic, no real fixtures: synthetic ``logs`` rows with controlled
file/offset/boot/timestamp fields, then assert ``source_order`` and
``event_order`` come out as designed — including the time-shift case that must
stay visible.
"""

from __future__ import annotations

import sqlite3

import pytest

from forensic_aul.engine.database.ordering import assign_ordering
from forensic_aul.engine.database.schema import UNKNOWN_BOOT_RANK, init_schema


@pytest.fixture()
def conn():
    # No apply_pragmas → foreign_keys stays OFF, so we can insert logs rows with
    # synthetic tracev3_file_id values without backing source_files rows.
    c = sqlite3.connect(":memory:")
    init_schema(c)
    yield c
    c.close()


def _seed_boots(c, ranks: dict[str, int]) -> dict[str, int]:
    """Insert boots with the given {boot_uuid: rank} and return {boot_uuid: id}.

    Mirrors what the writer does during extract (register_boot for known boots,
    UNKNOWN_BOOT_RANK for boots absent from the timesync layout).
    """
    ids: dict[str, int] = {}
    for boot_uuid, rank in ranks.items():
        cur = c.execute(
            "INSERT INTO boots(boot_uuid, rank) VALUES (?, ?)", (boot_uuid, rank)
        )
        ids[boot_uuid] = cur.lastrowid
    return ids


def _insert(c, *, rid, file_id, chunk, fh, entry, boot_id, mach, unix_ns=0):
    c.execute(
        """
        INSERT INTO logs (id, tracev3_file_id,
            tracev3_chunkset_file_offset, tracev3_firehose_inner_offset,
            tracev3_entry_inner_offset, boot_id,
            timestamp_unix_ns, timestamp_mach)
        VALUES (?,?,?,?,?,?,?,?)
        """,
        (rid, file_id, chunk, fh, entry, boot_id, unix_ns, mach),
    )


def _rows(c, cols):
    # v_logs, not `logs`: the ordering lives in the logs_order side table and the
    # view is the documented surface that joins the two. Asserting through it
    # keeps these tests about the ordering rules rather than the physical layout.
    return c.execute(f"SELECT {cols} FROM v_logs ORDER BY id").fetchall()


def test_source_order_is_per_file_by_offset(conn):
    a = _seed_boots(conn, {"A": 0})["A"]
    # File 1: three records inserted out of physical order.
    _insert(conn, rid=1, file_id=1, chunk=200, fh=0, entry=0, boot_id=a, mach=10)
    _insert(conn, rid=2, file_id=1, chunk=100, fh=0, entry=0, boot_id=a, mach=20)
    _insert(conn, rid=3, file_id=1, chunk=100, fh=0, entry=8, boot_id=a, mach=30)
    # File 2: its own stream — source_order must restart at 1.
    _insert(conn, rid=4, file_id=2, chunk=50, fh=0, entry=0, boot_id=a, mach=5)
    _insert(conn, rid=5, file_id=2, chunk=10, fh=0, entry=0, boot_id=a, mach=6)
    conn.commit()

    assign_ordering(conn)

    so = dict(conn.execute("SELECT id, source_order FROM v_logs").fetchall())
    # File 1 ordered by (chunk, fh, entry): row2(100,0,0) < row3(100,0,8) < row1(200)
    assert (so[2], so[3], so[1]) == (1, 2, 3)
    # File 2 restarts: row5(10) < row4(50)
    assert (so[5], so[4]) == (1, 2)


def test_event_order_merges_streams_by_boot_then_mach(conn):
    a = _seed_boots(conn, {"A": 0})["A"]
    # Two stores (files 1 and 2) interleave in time within one boot.
    _insert(conn, rid=1, file_id=1, chunk=0, fh=0, entry=0, boot_id=a, mach=100)
    _insert(conn, rid=2, file_id=2, chunk=0, fh=0, entry=0, boot_id=a, mach=50)
    _insert(conn, rid=3, file_id=1, chunk=8, fh=0, entry=0, boot_id=a, mach=150)
    _insert(conn, rid=4, file_id=2, chunk=8, fh=0, entry=0, boot_id=a, mach=120)
    conn.commit()

    assign_ordering(conn)

    # event_order follows mach across files: 50 < 100 < 120 < 150 → rows 2,1,4,3
    order = [r[0] for r in conn.execute("SELECT id FROM v_logs ORDER BY event_order")]
    assert order == [2, 1, 4, 3]


def test_event_order_respects_boot_rank_over_mach(conn):
    # Boot B ranks before boot A physically, even though A's mach values are lower.
    boots = _seed_boots(conn, {"B": 0, "A": 1})  # B physically first
    _insert(conn, rid=1, file_id=1, chunk=0, fh=0, entry=0, boot_id=boots["A"], mach=10)
    _insert(conn, rid=2, file_id=1, chunk=8, fh=0, entry=0, boot_id=boots["B"], mach=999)
    conn.commit()

    assign_ordering(conn)

    order = [r[0] for r in conn.execute("SELECT id FROM v_logs ORDER BY event_order")]
    assert order == [2, 1]  # all of boot B before boot A


def test_unknown_boot_sorts_last(conn):
    # ZZZ is a boot present in logs but absent from timesync → UNKNOWN_BOOT_RANK.
    boots = _seed_boots(conn, {"A": 0, "ZZZ": UNKNOWN_BOOT_RANK})
    _insert(conn, rid=1, file_id=1, chunk=0, fh=0, entry=0, boot_id=boots["A"], mach=500)
    _insert(conn, rid=2, file_id=1, chunk=8, fh=0, entry=0, boot_id=boots["ZZZ"], mach=1)
    conn.commit()

    assign_ordering(conn)

    order = [r[0] for r in conn.execute("SELECT id FROM v_logs ORDER BY event_order")]
    assert order == [1, 2]  # known boot A first; unknown ZZZ last despite tiny mach


def test_null_boot_id_sorts_last(conn):
    # A logs row with no boot_id at all falls back to UNKNOWN_BOOT_RANK via COALESCE.
    a = _seed_boots(conn, {"A": 0})["A"]
    _insert(conn, rid=1, file_id=1, chunk=0, fh=0, entry=0, boot_id=a, mach=500)
    _insert(conn, rid=2, file_id=1, chunk=8, fh=0, entry=0, boot_id=None, mach=1)
    conn.commit()

    assign_ordering(conn)

    order = [r[0] for r in conn.execute("SELECT id FROM v_logs ORDER BY event_order")]
    assert order == [1, 2]


def test_time_shift_stays_visible(conn):
    # Same boot: monotonic mach rises, but wall-clock jumps BACKWARDS (clock reset).
    # event_order must follow mach (true order), so the backwards wall-clock jump is
    # preserved as a visible anomaly rather than being re-sorted away.
    a = _seed_boots(conn, {"A": 0})["A"]
    _insert(conn, rid=1, file_id=1, chunk=0, fh=0, entry=0, boot_id=a, mach=1000, unix_ns=5_000)
    _insert(conn, rid=2, file_id=1, chunk=8, fh=0, entry=0, boot_id=a, mach=2000, unix_ns=1_000)
    conn.commit()

    assign_ordering(conn)

    rows = conn.execute(
        "SELECT id, timestamp_unix_ns FROM v_logs ORDER BY event_order"
    ).fetchall()
    assert [r[0] for r in rows] == [1, 2]            # ordered by mach, not wall-clock
    assert rows[0][1] > rows[1][1]                   # wall-clock decreases → tamper visible


def test_every_row_gets_both_orders(conn):
    # The write-back this used to exercise (a batched id-range UPDATE over `logs`)
    # is gone: the pass is one INSERT into logs_order. What still matters to an
    # analyst is unchanged — every row ends up with both orders, and they are the
    # values the rules dictate.
    a = _seed_boots(conn, {"A": 0})["A"]
    # entry offsets give a deterministic per-file source_order; mach gives event_order.
    _insert(conn, rid=1, file_id=1, chunk=0, fh=0, entry=2, boot_id=a, mach=30)
    _insert(conn, rid=2, file_id=1, chunk=0, fh=0, entry=0, boot_id=a, mach=10)
    _insert(conn, rid=3, file_id=1, chunk=0, fh=0, entry=1, boot_id=a, mach=20)
    conn.commit()

    assign_ordering(conn)

    # event_order follows mach: 10 < 20 < 30 → rows 2, 3, 1
    order = [r[0] for r in conn.execute("SELECT id FROM v_logs ORDER BY event_order")]
    assert order == [2, 3, 1]
    nulls = conn.execute(
        "SELECT COUNT(*) FROM v_logs WHERE event_order IS NULL OR source_order IS NULL"
    ).fetchone()[0]
    assert nulls == 0
    # source_order is per-file by (chunk, fh, entry): row2(0) < row3(1) < row1(2)
    so = dict(conn.execute("SELECT id, source_order FROM v_logs").fetchall())
    assert (so[2], so[3], so[1]) == (1, 2, 3)


def test_an_interrupted_pass_is_never_partially_applied(conn):
    """The pass is all-or-nothing, which is what a resume relies on.

    The old write-back committed batch by batch, so an interrupted run left
    `logs` half-ordered and a reader could not tell a finished ordering from an
    abandoned one. One INSERT inside one transaction cannot do that.

    Interrupting via ``set_progress_handler`` is not an arbitrary choice: it is
    the same mechanism the extract pipeline uses to cancel this very statement
    (see extract.py's cancellation handler), because a single monolithic SQL
    statement runs for minutes with no Python executing in between.
    """
    a = _seed_boots(conn, {"A": 0})["A"]
    for rid in range(1, 6):
        _insert(conn, rid=rid, file_id=1, chunk=0, fh=0, entry=rid, boot_id=a, mach=rid)
    conn.commit()
    assign_ordering(conn)
    before = conn.execute(
        "SELECT id, source_order, event_order FROM logs_order ORDER BY id"
    ).fetchall()
    assert len(before) == 5

    # More rows, so a completed re-run would visibly differ from `before`.
    for rid in range(6, 11):
        _insert(conn, rid=rid, file_id=1, chunk=0, fh=0, entry=rid, boot_id=a, mach=rid)
    conn.commit()

    conn.set_progress_handler(lambda: 1, 1)   # abort at the first opportunity
    try:
        with pytest.raises(sqlite3.OperationalError):
            assign_ordering(conn)
    finally:
        conn.set_progress_handler(None, 0)

    # Rolled back to exactly what was there before — never a half-written table.
    after = conn.execute(
        "SELECT id, source_order, event_order FROM logs_order ORDER BY id"
    ).fetchall()
    assert after == before

    # And a clean re-run completes, now covering all ten rows.
    assign_ordering(conn)
    assert conn.execute("SELECT COUNT(*) FROM logs_order").fetchone()[0] == 10



def test_idempotent(conn):
    a = _seed_boots(conn, {"A": 0})["A"]
    _insert(conn, rid=1, file_id=1, chunk=0, fh=0, entry=0, boot_id=a, mach=10)
    conn.commit()
    assign_ordering(conn)
    assign_ordering(conn)  # second pass must not raise or change values
    row = conn.execute("SELECT source_order, event_order FROM v_logs").fetchone()
    assert row == (1, 1)
