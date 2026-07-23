"""Unit tests for the shutdown.log parser (forensic_aul/ops/extraction/shutdown_log.py)."""

from __future__ import annotations

from forensic_aul.ops.extraction.shutdown_log import (
    find_shutdown_log,
    parse_shutdown_log,
)

_SAMPLE = """\
After 0.63s, these clients are still here:
\t\tremaining client pid: 215 (/System/.../destinationd/UUID)
\t\tremaining client pid: 66 (/usr/libexec/locationd/UUID)
After 2.62s, these clients are still here:
\t\tremaining client pid: 66 (/usr/libexec/locationd/UUID)
\t\tremaining client pid: 0 (/kernel/UUID)
SIGTERM: [1774602168] All buffers flushed
After 1.0s, these clients are still here:
\t\tremaining client pid: 99 (/usr/libexec/foo/UUID)
SIGTERM: [1779303547] All buffers flushed
"""


def test_parse_two_events_with_clients(tmp_path):
    p = tmp_path / "shutdown.log"
    p.write_text(_SAMPLE)
    events = parse_shutdown_log(p)

    assert len(events) == 2

    e0 = events[0]
    assert e0.unix_ns == 1774602168 * 1_000_000_000
    assert e0.iso.startswith("20") and e0.iso.endswith("Z")
    assert e0.delay_seconds == 2.62
    # Three distinct processes lingered; locationd appeared in both checks → 2.62.
    by_path = {c.process_path.split("/")[-2]: c for c in e0.clients}
    assert len(e0.clients) == 3
    assert by_path["locationd"].lingered_seconds == 2.62
    assert by_path["destinationd"].lingered_seconds == 0.63
    assert by_path["kernel"].pid == 0

    e1 = events[1]
    assert e1.unix_ns == 1779303547 * 1_000_000_000
    assert e1.delay_seconds == 1.0
    assert len(e1.clients) == 1 and e1.clients[0].pid == 99


def test_clean_shutdown_no_clients(tmp_path):
    p = tmp_path / "shutdown.log"
    p.write_text("SIGTERM: [1700000000] All buffers flushed\n")
    events = parse_shutdown_log(p)
    assert len(events) == 1
    assert events[0].clients == []
    assert events[0].delay_seconds is None


def test_empty_or_unrecognised(tmp_path):
    p = tmp_path / "shutdown.log"
    p.write_text("garbage line\nanother line without markers\n")
    assert parse_shutdown_log(p) == []


def test_find_shutdown_log_extra_then_root(tmp_path):
    # Extra/ takes priority (logarchive / sysdiagnose layout).
    (tmp_path / "Extra").mkdir()
    (tmp_path / "Extra" / "shutdown.log").write_text("x")
    assert find_shutdown_log(tmp_path) == tmp_path / "Extra" / "shutdown.log"


def test_find_shutdown_log_root(tmp_path):
    # FFS flattens diagnostics/ → shutdown.log at the root.
    (tmp_path / "shutdown.log").write_text("x")
    assert find_shutdown_log(tmp_path) == tmp_path / "shutdown.log"


def test_find_shutdown_log_absent(tmp_path):
    assert find_shutdown_log(tmp_path) is None
