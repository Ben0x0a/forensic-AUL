"""Host capability probes for the parallelism auto-defaults.

Defines : :func:`physical_cpu_count`  — physical (not logical) core count;
          :func:`total_memory_bytes`  — installed RAM in bytes;
          :func:`resolve_auto_jobs`   — the memory-aware ``--jobs`` default.
Used by : launcher.cmds.extract_cmd (resolving the parallelism budget when the
          operator does not pass an explicit ``--jobs``).
Uses    : os, subprocess, sys, and the JOBS_* tunables in forensic_aul.config.

WHY this module exists: the extract default used to be ``os.cpu_count()`` (every
logical core). Benchmarking showed that both over-subscribes throughput (parse
plateaus at ~6 jobs, regresses at 10) and over-subscribes memory (each worker
holds a private string cache, and the ordering/FTS tail peaks independently). The
helpers here turn raw host facts into a budget that respects both ceilings.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys

from forensic_aul.config import (
    JOBS_AUTO_CAP,
    JOBS_MEMORY_RESERVE_GIB,
    JOBS_WORKER_RSS_GIB,
)

log = logging.getLogger(__name__)

_GIB = 1 << 30


def physical_cpu_count() -> int:
    """Return the number of physical CPU cores, falling back to logical count.

    WHY physical, not logical: parsing is CPU-bound and memory-bandwidth-bound,
    so SMT/efficiency siblings add little parse throughput (the benchmark's 10
    logical cores beat their own performance at 6 jobs). When the physical count
    cannot be determined we fall back to ``os.cpu_count()`` — over-counting is
    then reined in by the auto cap and the memory budget in resolve_auto_jobs.
    """
    logical = os.cpu_count() or 1

    # macOS: sysctl is the authoritative source for the physical core count.
    if sys.platform == "darwin":
        try:
            out = subprocess.run(
                ["/usr/sbin/sysctl", "-n", "hw.physicalcpu"],
                capture_output=True, text=True, timeout=5, check=True,
            ).stdout.strip()
            value = int(out)
            if value > 0:
                return value
        except (OSError, ValueError, subprocess.SubprocessError):
            # Probe failed (sandbox, missing binary, odd output) — fall through
            # to the logical count rather than guessing a physical mapping.
            return logical

    # Linux: count distinct (physical_id, core_id) pairs in /proc/cpuinfo, which
    # collapses hyperthread siblings sharing a core. Any parse hiccup falls back.
    if sys.platform.startswith("linux"):
        try:
            cores: set[tuple[str, str]] = set()
            phys = core = None
            with open("/proc/cpuinfo", encoding="utf-8") as fh:
                for line in fh:
                    key, _, val = line.partition(":")
                    key = key.strip()
                    if key == "physical id":
                        phys = val.strip()
                    elif key == "core id":
                        core = val.strip()
                    elif line.strip() == "":  # blank line ends one processor block
                        if phys is not None and core is not None:
                            cores.add((phys, core))
                        phys = core = None
            if cores:
                return len(cores)
        except OSError:
            return logical

    # Other platforms: no portable physical probe — logical is the safe default.
    return logical


def total_memory_bytes() -> int:
    """Return installed physical RAM in bytes, or 0 if it cannot be determined.

    Uses the POSIX ``sysconf`` page-count product, which is available on both
    macOS and Linux. A 0 return signals "unknown" so callers skip the
    memory-aware narrowing rather than acting on a fabricated figure.
    """
    try:
        page_size = os.sysconf("SC_PAGE_SIZE")
        page_count = os.sysconf("SC_PHYS_PAGES")
    except (ValueError, OSError, AttributeError):
        # sysconf or these specific names are unavailable on this platform.
        return 0
    if page_size > 0 and page_count > 0:
        return page_size * page_count
    return 0


def resolve_auto_jobs() -> int:
    """Derive the default ``--jobs`` budget from physical cores and free RAM.

    The budget is the smaller of two ceilings, never below 1:

      1. **CPU ceiling** — ``min(physical cores, JOBS_AUTO_CAP)``. The cap exists
         because parse throughput plateaus then regresses past the knee (see
         JOBS_AUTO_CAP in config.py), so spending more cores buys nothing.
      2. **Memory ceiling** — ``(RAM - JOBS_MEMORY_RESERVE_GIB) /
         JOBS_WORKER_RSS_GIB``. Each parser worker holds a private string cache,
         and the reserve protects the writer plus the multi-GB ordering/FTS tail.
         Skipped when RAM is unknown (total_memory_bytes() == 0).

    WHY the minimum: a RAM-rich 4-core host should not spawn 8 jobs, and a
    32-core host with little free memory should not swap. Taking the tighter of
    the two ceilings keeps both failure modes off the table. An explicit
    ``--jobs N`` bypasses this function entirely.
    """
    cores = physical_cpu_count()
    cpu_ceiling = max(1, min(cores, JOBS_AUTO_CAP))

    ram_bytes = total_memory_bytes()
    if ram_bytes <= 0:
        # Memory unknown — fall back to the CPU ceiling alone.
        log.debug("Auto jobs: RAM unknown; using CPU ceiling %d", cpu_ceiling)
        return cpu_ceiling

    ram_gib = ram_bytes / _GIB
    usable_gib = ram_gib - JOBS_MEMORY_RESERVE_GIB
    # +1e-9 absorbs binary float error (e.g. 0.6 / 0.3 == 1.9999… would otherwise
    # floor to 1 and silently drop a whole worker); the estimate is coarse anyway.
    mem_ceiling = (
        max(1, int(usable_gib / JOBS_WORKER_RSS_GIB + 1e-9)) if usable_gib > 0 else 1
    )

    jobs = max(1, min(cpu_ceiling, mem_ceiling))
    log.debug(
        "Auto jobs: %d (physical cores=%d, cap=%d, RAM=%.1f GiB → mem ceiling=%d)",
        jobs, cores, cpu_ceiling, ram_gib, mem_ceiling,
    )
    return jobs
