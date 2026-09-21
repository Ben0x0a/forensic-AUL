"""Micro-benchmarks for the per-entry hot path of an extraction.

Defines : a registry of named micro-benchmarks (``@bench``), each timing ONE
          function that runs once per log entry, plus ``main()`` which runs them
          and writes a timestamped report.
Used by : a maintainer working on `tasks/` performance items — run it before and
          after a change and paste both reports into the task note.
Uses    : the standard library and forensic_aul's engine only. No evidence, no
          database, no logarchive: every input is synthesised here.

WHY this exists alongside aul_extract_benchmark.py: that one measures a whole
extract against a real case, which is the number that ultimately matters but
needs evidence on disk, takes minutes per run, and moves with I/O noise. This one
answers the narrower question "is this per-entry function still costing what I
think it costs?" in a couple of seconds, on any machine, with no case data. Use
this to choose what to optimise; use the full benchmark to confirm the extract
actually got faster.

Reading the numbers
-------------------
The per-entry µs figure is the honest one. The "extrapolated" column multiplies
it by a nominal entry count to make the stake legible — it is a single-core
figure and takes no account of ``--jobs``, so treat it as an upper bound on what
a fix can save, not a prediction of wall-clock gain.

Usage
-----
    uv run python benchmark/bench_hotpath.py                # all benchmarks
    uv run python benchmark/bench_hotpath.py anchor iso     # a subset
    uv run python benchmark/bench_hotpath.py --entries 500000
    uv run python benchmark/bench_hotpath.py --no-save      # print only

Reports land in ``benchmark/results/`` (git-ignored, like every other benchmark
artefact) as ``<UTC timestamp>_hotpath.md``.

Adding a benchmark
------------------
Write a function that takes the sample count and returns seconds elapsed, and
decorate it with ``@bench("name", "one-line description")``. Keep the setup out
of the timed region, and keep each one measuring a single function — a benchmark
that times two things at once cannot tell you which one moved.
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

# Run from a clone without installing: make the repo root importable.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from forensic_aul.engine.models import TimesyncBoot, TimesyncEntry  # noqa: E402
from forensic_aul.engine.parser.firehose import _ENTRY_HEADER  # noqa: E402
from forensic_aul.engine.utils.time import (  # noqa: E402
    _format_iso8601,
    _select_anchor,
    resolve_mach_timestamp,
)

# A boot's timesync record count. ~130 is what a multi-day iPhone capture shows;
# the anchor search is O(n) in this number in the old implementation, so it is
# the parameter that decides whether that scan matters at all.
N_RECORDS = 130

# Nominal entry count for the "extrapolated" column. A large FFS extract is in
# this range; it is a presentation scale only, never a measured quantity.
NOMINAL_ENTRIES = 40_000_000

_BOOT_NS = 1_700_000_000_000_000_000

_REGISTRY: list[tuple[str, str, Callable[[int], float]]] = []


def bench(name: str, description: str):
    """Register a micro-benchmark: ``fn(samples) -> seconds``."""
    def wrap(fn: Callable[[int], float]) -> Callable[[int], float]:
        _REGISTRY.append((name, description, fn))
        return fn
    return wrap


# ── Shared fixtures ───────────────────────────────────────────────────────────

def make_boot(records: int = N_RECORDS, *, seed: int = 20260817) -> TimesyncBoot:
    """A boot with *records* ascending timesync records, deterministically spaced.

    Seeded so two runs on the same machine are comparable — an unseeded fixture
    would put run-to-run variance into the very number being compared.
    """
    rng = random.Random(seed)
    entries = []
    kernel_time = 0
    for i in range(records):
        kernel_time += rng.randint(1_000_000, 50_000_000)
        entries.append(TimesyncEntry(
            signature=0x207354, unknown_flags=0, kernel_time=kernel_time,
            walltime=_BOOT_NS + kernel_time, timezone=0, daylight_savings=0,
            file_offset=i * 32, timesync_file_id=1,
        ))
    return TimesyncBoot(
        signature=0xBBB0, header_size=48, unknown=0, boot_uuid="B" * 32,
        timebase_numerator=125, timebase_denominator=3, boot_time=_BOOT_NS,
        timezone_offset_mins=0, daylight_savings=0, timesync=entries,
        file_offset=0, timesync_file_id=1,
    )


def make_targets(boot: TimesyncBoot, samples: int, *, seed: int = 20260817) -> list[int]:
    """Continuous-time targets spread uniformly across the boot's whole span.

    Uniform on purpose: entries land all over a capture, so an anchor search must
    be measured across the whole record list. Sampling only late targets would
    flatter a linear scan (early exit) or a binary one (same depth) unfairly.
    """
    rng = random.Random(seed)
    last = boot.timesync[-1].kernel_time
    return [rng.randint(0, last) for _ in range(samples)]


# ── Benchmarks ────────────────────────────────────────────────────────────────

@bench("anchor", "_select_anchor — timesync anchor lookup, once per entry")
def bench_anchor(samples: int) -> float:
    boot = make_boot()
    targets = make_targets(boot, samples)
    _select_anchor(boot, 0, 1, 125, 3)   # warm the cached key index
    start = time.perf_counter()
    for target in targets:
        _select_anchor(boot, target, 1, 125, 3)
    return time.perf_counter() - start


@bench("iso", "_format_iso8601 — ISO 8601 rendering of one instant")
def bench_iso(samples: int) -> float:
    boot = make_boot()
    targets = make_targets(boot, samples)
    start = time.perf_counter()
    for target in targets:
        _format_iso8601(_BOOT_NS + target)
    return time.perf_counter() - start


@bench("resolve", "resolve_mach_timestamp — the whole mach→wall conversion")
def bench_resolve(samples: int) -> float:
    boot = make_boot()
    data = {boot.boot_uuid: boot}
    targets = make_targets(boot, samples)
    resolve_mach_timestamp(data, boot.boot_uuid, 0, 1)   # warm
    start = time.perf_counter()
    for target in targets:
        resolve_mach_timestamp(data, boot.boot_uuid, target, 1)
    return time.perf_counter() - start


@bench("header", "_ENTRY_HEADER.unpack_from — the 24-byte firehose entry header")
def bench_header(samples: int) -> float:
    # A buffer, not a real entry: this measures the unpack alone, which is what
    # runs once per log entry regardless of what the entry then contains.
    buffer = bytes(range(256)) * 8
    unpack = _ENTRY_HEADER.unpack_from
    start = time.perf_counter()
    for _ in range(samples):
        unpack(buffer, 0)
    return time.perf_counter() - start


# ── Runner ────────────────────────────────────────────────────────────────────

def run(names: list[str], samples: int) -> list[tuple[str, str, float]]:
    selected = [b for b in _REGISTRY if not names or b[0] in names]
    unknown = set(names) - {b[0] for b in _REGISTRY}
    if unknown:
        raise SystemExit(
            f"unknown benchmark(s): {', '.join(sorted(unknown))}\n"
            f"available: {', '.join(b[0] for b in _REGISTRY)}"
        )
    results = []
    for name, description, fn in selected:
        elapsed = fn(samples)
        results.append((name, description, elapsed))
        print(f"  {name:<10} {elapsed / samples * 1e6:8.3f} µs/entry   {description}")
    return results


def render(results: list[tuple[str, str, float]], samples: int) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    lines = [
        f"# Hot-path micro-benchmark — {stamp}",
        "",
        f"- samples per benchmark: {samples:,}",
        f"- timesync records per boot: {N_RECORDS}",
        f"- python: {sys.version.split()[0]} on {sys.platform}",
        "",
        f"| benchmark | µs/entry | total for {NOMINAL_ENTRIES:,} entries | what it measures |",
        "|---|---:|---:|---|",
    ]
    for name, description, elapsed in results:
        per_entry = elapsed / samples
        lines.append(
            f"| `{name}` | {per_entry * 1e6:.3f} | "
            f"{per_entry * NOMINAL_ENTRIES:.1f}s | {description} |"
        )
    lines += [
        "",
        "Single-core figures; the extrapolated column ignores `--jobs` and is an "
        "upper bound on what optimising that function can save.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("names", nargs="*",
                        help="benchmarks to run (default: all). "
                             f"Available: {', '.join(b[0] for b in _REGISTRY)}")
    parser.add_argument("--entries", type=int, default=200_000, metavar="N",
                        help="samples per benchmark (default: 200000)")
    parser.add_argument("--no-save", action="store_true",
                        help="print the report instead of writing it to results/")
    args = parser.parse_args()

    print(f"hot-path micro-benchmark — {args.entries:,} samples each\n")
    results = run(args.names, args.entries)
    report = render(results, args.entries)

    if args.no_save:
        print("\n" + report)
        return 0

    out_dir = Path(__file__).resolve().parent / "results"
    out_dir.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    path = out_dir / f"{stamp}_hotpath.md"
    path.write_text(report)
    print(f"\nreport: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
