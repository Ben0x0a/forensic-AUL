"""Unit tests for host probes — forensic_aul/engine/utils/system.py.

Focus on :func:`resolve_auto_jobs`: it must take the tighter of the CPU cap and
the memory-derived ceiling, fall back gracefully when RAM is unknown, and never
return below 1. Probes are monkeypatched so the result is deterministic and not
tied to the test runner's hardware.
"""

from __future__ import annotations

import forensic_aul.engine.utils.system as system
from forensic_aul.config import (
    JOBS_AUTO_CAP,
    JOBS_MEMORY_RESERVE_GIB,
    JOBS_WORKER_RSS_GIB,
)

_GIB = 1 << 30


def _patch(monkeypatch, *, cores: int, ram_gib: float | None) -> None:
    """Pin the two host probes so resolve_auto_jobs is hardware-independent."""
    monkeypatch.setattr(system, "physical_cpu_count", lambda: cores)
    ram_bytes = 0 if ram_gib is None else int(ram_gib * _GIB)
    monkeypatch.setattr(system, "total_memory_bytes", lambda: ram_bytes)


def test_cpu_ceiling_caps_high_core_count(monkeypatch):
    # 32 cores but plenty of RAM → capped at JOBS_AUTO_CAP, not the core count.
    _patch(monkeypatch, cores=32, ram_gib=256)
    assert system.resolve_auto_jobs() == JOBS_AUTO_CAP


def test_fewer_cores_than_cap_uses_core_count(monkeypatch):
    # A 4-core RAM-rich host should spawn 4, not the cap of 8.
    _patch(monkeypatch, cores=4, ram_gib=64)
    assert system.resolve_auto_jobs() == 4


def test_low_memory_narrows_below_cpu_ceiling(monkeypatch):
    # 16 cores but tight RAM: ceiling = floor((ram - reserve) / per-worker).
    # 2.5 workers' worth of usable RAM floors to 2 — well clear of either
    # integer boundary, so the assertion does not hinge on float rounding.
    ram_gib = JOBS_MEMORY_RESERVE_GIB + 2.5 * JOBS_WORKER_RSS_GIB
    _patch(monkeypatch, cores=16, ram_gib=ram_gib)
    assert system.resolve_auto_jobs() == 2


def test_unknown_memory_falls_back_to_cpu_ceiling(monkeypatch):
    # RAM probe returns 0 (unsupported platform) → CPU ceiling alone.
    _patch(monkeypatch, cores=6, ram_gib=None)
    assert system.resolve_auto_jobs() == 6


def test_never_below_one(monkeypatch):
    # Even when the reserve exceeds installed RAM, never return < 1.
    _patch(monkeypatch, cores=8, ram_gib=JOBS_MEMORY_RESERVE_GIB - 1)
    assert system.resolve_auto_jobs() == 1


def test_physical_cpu_count_is_positive():
    # On the runner itself the real probe must return a sane positive count.
    assert system.physical_cpu_count() >= 1
