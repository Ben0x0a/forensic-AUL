#!/usr/bin/env python3
"""Benchmark forensic_aul extraction paths.

Usage:
    python benchmark/aul_extract_benchmark.py /path/to/case.logarchive

The script intentionally writes only under benchmark/results/ and
benchmark/runs/. Extraction benchmarks run on any platform supported by
forensic_aul. The custom Apple logshow pipeline runs only on macOS.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import importlib
import json
import logging
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

try:
    import resource
except ImportError:
    class _ZeroUsage:
        ru_utime = 0.0
        ru_stime = 0.0
        ru_minflt = 0
        ru_majflt = 0
        ru_inblock = 0
        ru_oublock = 0

    class _ResourceShim:
        RUSAGE_SELF = 0
        RUSAGE_CHILDREN = 1

        @staticmethod
        def getrusage(_who: int) -> _ZeroUsage:
            return _ZeroUsage()

    resource = _ResourceShim()  # type: ignore[assignment]


REPO_ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_ROOT = Path(__file__).resolve().parent
RESULTS_ROOT = BENCHMARK_ROOT / "results"
RUNS_ROOT = BENCHMARK_ROOT / "runs"
LOGSHOW_PATH = Path("/usr/bin/log")
LOGSHOW_FLAGS = ("--info", "--debug", "--signpost")
CUSTOM_BATCH_SIZE = 10_000
FAST_SAFE_BATCH_SIZE = 10_000
HEARTBEAT_SECONDS = 30.0
SCRIPT_VERSION = "0.2.1"
DEFAULT_SAMPLE_INTERVAL_SECONDS = 2.0
DEFAULT_SQLITE_SPACE_MULTIPLIER = 1.25
DEFAULT_SQLITE_SPACE_RESERVE_GB = 10.0
CLI_STDOUT_TAIL_LINES = 80


@dataclass
class ResourceSnapshot:
    peak_rss_mb: float = 0.0
    peak_cpu_percent: float = 0.0
    avg_cpu_percent: float = 0.0
    samples: int = 0


@dataclass
class BenchResult:
    key: str
    name: str
    status: str
    details: str
    wall_seconds: float = 0.0
    user_cpu_seconds: float = 0.0
    system_cpu_seconds: float = 0.0
    peak_rss_mb: float = 0.0
    avg_cpu_percent: float = 0.0
    peak_cpu_percent: float = 0.0
    minor_faults: int = 0
    major_faults: int = 0
    block_input_ops: int = 0
    block_output_ops: int = 0
    outputs: dict[str, Path] = field(default_factory=dict)
    sizes: dict[str, int] = field(default_factory=dict)
    row_count: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


@dataclass
class ArchiveStats:
    source_sha256: str
    file_hash_count: int
    total_files: int
    total_size: int
    appledouble_file_count: int
    tracev3_count: int
    tracev3_appledouble_count: int
    tracev3_total_size: int
    tracev3_by_folder: dict[str, int]
    tracev3_size_buckets: dict[str, int]
    timesync_count: int
    timesync_total_size: int
    uuidtext_count: int
    dsc_count: int
    largest_tracev3: list[tuple[str, int]]


class ProcessTreeSampler:
    """Sample RSS and CPU for this process plus descendants when ps is available."""

    def __init__(self, root_pid: int, interval: float = 0.5) -> None:
        self.root_pid = root_pid
        self.interval = interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._peak_rss_kb = 0
        self._peak_cpu = 0.0
        self._cpu_total = 0.0
        self._samples = 0

    def __enter__(self) -> "ProcessTreeSampler":
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._stop.set()
        self._thread.join(timeout=self.interval * 4)

    def snapshot(self) -> ResourceSnapshot:
        avg_cpu = self._cpu_total / self._samples if self._samples else 0.0
        return ResourceSnapshot(
            peak_rss_mb=self._peak_rss_kb / 1024,
            peak_cpu_percent=self._peak_cpu,
            avg_cpu_percent=avg_cpu,
            samples=self._samples,
        )

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                rss_kb, cpu_percent = self._sample_once()
            except Exception:
                rss_kb, cpu_percent = 0, 0.0
            self._peak_rss_kb = max(self._peak_rss_kb, rss_kb)
            self._peak_cpu = max(self._peak_cpu, cpu_percent)
            self._cpu_total += cpu_percent
            self._samples += 1
            self._stop.wait(self.interval)

    def _sample_once(self) -> tuple[int, float]:
        rss_kb, cpu_percent, _worker_rss_kb = sample_process_tree(self.root_pid)
        return rss_kb, cpu_percent


class PhaseHeartbeat:
    """Emit periodic progress while a long blocking phase is running."""

    def __init__(self, label: str, interval: float = HEARTBEAT_SECONDS) -> None:
        self.label = label
        self.interval = interval
        self.started = time.perf_counter()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self) -> "PhaseHeartbeat":
        log_line(f"START {self.label}")
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._stop.set()
        self._thread.join(timeout=self.interval)
        log_line(f"END   {self.label} elapsed={format_seconds(time.perf_counter() - self.started)}")

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            log_line(f"RUN   {self.label} elapsed={format_seconds(time.perf_counter() - self.started)}")


class CliProgressSink:
    """Progress callback for run_extract that prints at percentage steps."""

    def __init__(
        self,
        label: str,
        every_percent: int = 2,
        monitor: "ExtractMonitor | None" = None,
    ) -> None:
        self.label = label
        self.every_percent = every_percent
        self.monitor = monitor
        self._last = -1

    def __call__(self, event: Any) -> None:
        if self.monitor is not None and event.phase:
            self.monitor.set_phase(str(event.phase), str(event.detail or ""))
        pct = int(event.overall * 100)
        if self._last < 0 or pct >= self._last + self.every_percent or pct >= 100:
            self._last = pct
            detail = f" {event.detail}" if event.detail else ""
            log_line(f"{self.label}: {pct:3d}% phase={event.phase}{detail}")


class ExtractPhaseLogHandler(logging.Handler):
    """Map extractor INFO log messages that are not exposed as progress phases."""

    def __init__(self, monitor: "ExtractMonitor") -> None:
        super().__init__(level=logging.INFO)
        self.monitor = monitor

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = record.getMessage()
        except Exception:
            return
        if "Re-verifying per-file integrity" in message:
            self.monitor.set_phase("integrity", "source file re-hash")
        elif "Assigning forensic ordering" in message:
            self.monitor.set_phase("ordering", "merging timeline")
        elif "Building secondary indexes" in message:
            self.monitor.set_phase("index", "building indexes")
        elif "Building FTS5 index" in message:
            self.monitor.set_phase("fts", "full-text index")


class ExtractMonitor:
    """Phase-aware sampler for extract runs.

    It stores aggregates only: no per-sample time series is written to the JSON
    sidecar, so multi-hour runs do not make the report state large.
    """

    def __init__(
        self,
        label: str,
        db_path: Path,
        interval: float,
        root_pid: int | None = None,
    ) -> None:
        self.label = label
        self.db_path = db_path
        self.interval = max(0.5, interval)
        self.root_pid = root_pid if root_pid is not None else os.getpid()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._active_phase = ""
        self._phase_started = 0.0
        self._phases: dict[str, dict[str, Any]] = {}
        self._overall: dict[str, Any] = {
            "samples": 0,
            "peak_rss_mb": 0.0,
            "peak_worker_rss_mb": 0.0,
            "peak_cpu_percent": 0.0,
            "cpu_percent_total": 0.0,
            "peak_wal_bytes": 0,
            "min_free_bytes": None,
            "io_available": False,
            "io_unavailable_reason": None,
            "io_start": None,
            "io_end": None,
        }
        self._psutil = self._load_psutil()

    def __enter__(self) -> "ExtractMonitor":
        self._overall["io_start"] = self._read_io_counters()
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._stop.set()
        self._thread.join(timeout=self.interval * 4)
        self._sample_once()
        self._overall["io_end"] = self._read_io_counters()
        with self._lock:
            self._close_active_phase(time.perf_counter())

    def set_phase(self, phase: str, detail: str = "") -> None:
        now = time.perf_counter()
        phase = phase or "unknown"
        with self._lock:
            if phase == self._active_phase:
                if detail:
                    self._phase_entry(phase)["last_detail"] = detail
                return
            self._close_active_phase(now)
            self._active_phase = phase
            self._phase_started = now
            entry = self._phase_entry(phase)
            entry.setdefault("first_started_monotonic", now)
            entry["last_started_monotonic"] = now
            entry["last_detail"] = detail
            entry["io_start"] = self._read_io_counters_unlocked()
        detail_suffix = f" detail={detail}" if detail else ""
        log_line(f"PHASE {self.label}: {phase}{detail_suffix}")

    def snapshot(self) -> ResourceSnapshot:
        with self._lock:
            samples = int(self._overall["samples"])
            avg_cpu = (
                float(self._overall["cpu_percent_total"]) / samples if samples else 0.0
            )
            return ResourceSnapshot(
                peak_rss_mb=float(self._overall["peak_rss_mb"]),
                peak_cpu_percent=float(self._overall["peak_cpu_percent"]),
                avg_cpu_percent=avg_cpu,
                samples=samples,
            )

    def summary(self) -> dict[str, Any]:
        with self._lock:
            phases = {
                name: self._phase_summary(entry)
                for name, entry in self._phases.items()
            }
            samples = int(self._overall["samples"])
            avg_cpu = (
                float(self._overall["cpu_percent_total"]) / samples if samples else 0.0
            )
            io_delta = io_counter_delta(
                self._overall.get("io_start"),
                self._overall.get("io_end"),
            )
            serial_tail = sum(
                float(phases.get(name, {}).get("wall_seconds", 0.0))
                for name in ("ordering", "index", "fts", "integrity")
            )
            return {
                "script_version": SCRIPT_VERSION,
                "sample_interval_seconds": self.interval,
                "samples": samples,
                "avg_cpu_percent": avg_cpu,
                "peak_cpu_percent": float(self._overall["peak_cpu_percent"]),
                "peak_rss_mb": float(self._overall["peak_rss_mb"]),
                "peak_worker_rss_mb": float(self._overall["peak_worker_rss_mb"]),
                "peak_wal_bytes": int(self._overall["peak_wal_bytes"]),
                "min_free_bytes": self._overall["min_free_bytes"],
                "io_available": bool(self._overall["io_available"]),
                "io_unavailable_reason": self._overall["io_unavailable_reason"],
                "io_delta": io_delta,
                "serial_tail_seconds": serial_tail,
                "phases": phases,
            }

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            self._sample_once()

    def _sample_once(self) -> None:
        rss_kb, cpu_percent, worker_rss_kb = sample_process_tree(self.root_pid)
        wal_size = path_size(self.db_path.with_name(self.db_path.name + "-wal"))
        try:
            free = shutil.disk_usage(self.db_path.parent).free
        except OSError:
            free = None
        io_now = self._read_io_counters()
        with self._lock:
            self._record_sample_unlocked(
                rss_kb=rss_kb,
                cpu_percent=cpu_percent,
                worker_rss_kb=worker_rss_kb,
                wal_size=wal_size,
                free=free,
                io_now=io_now,
            )

    def _record_sample_unlocked(
        self,
        *,
        rss_kb: int,
        cpu_percent: float,
        worker_rss_kb: int,
        wal_size: int,
        free: int | None,
        io_now: dict[str, int] | None,
    ) -> None:
        self._overall["samples"] = int(self._overall["samples"]) + 1
        self._overall["peak_rss_mb"] = max(float(self._overall["peak_rss_mb"]), rss_kb / 1024)
        self._overall["peak_worker_rss_mb"] = max(
            float(self._overall["peak_worker_rss_mb"]), worker_rss_kb / 1024
        )
        self._overall["peak_cpu_percent"] = max(float(self._overall["peak_cpu_percent"]), cpu_percent)
        self._overall["cpu_percent_total"] = float(self._overall["cpu_percent_total"]) + cpu_percent
        self._overall["peak_wal_bytes"] = max(int(self._overall["peak_wal_bytes"]), wal_size)
        if free is not None:
            current = self._overall["min_free_bytes"]
            self._overall["min_free_bytes"] = free if current is None else min(int(current), free)
        if io_now is not None:
            self._overall["io_available"] = True

        if not self._active_phase:
            return
        entry = self._phase_entry(self._active_phase)
        entry["samples"] = int(entry.get("samples", 0)) + 1
        entry["peak_rss_mb"] = max(float(entry.get("peak_rss_mb", 0.0)), rss_kb / 1024)
        entry["peak_worker_rss_mb"] = max(
            float(entry.get("peak_worker_rss_mb", 0.0)), worker_rss_kb / 1024
        )
        entry["peak_cpu_percent"] = max(float(entry.get("peak_cpu_percent", 0.0)), cpu_percent)
        entry["cpu_percent_total"] = float(entry.get("cpu_percent_total", 0.0)) + cpu_percent
        entry["peak_wal_bytes"] = max(int(entry.get("peak_wal_bytes", 0)), wal_size)
        if free is not None:
            current = entry.get("min_free_bytes")
            entry["min_free_bytes"] = free if current is None else min(int(current), free)
        if io_now is not None:
            entry["io_end"] = io_now

    def _close_active_phase(self, now: float) -> None:
        if not self._active_phase:
            return
        entry = self._phase_entry(self._active_phase)
        entry["wall_seconds"] = float(entry.get("wall_seconds", 0.0)) + max(
            0.0, now - self._phase_started
        )
        entry["io_end"] = self._read_io_counters_unlocked()
        self._active_phase = ""
        self._phase_started = 0.0

    def _phase_entry(self, phase: str) -> dict[str, Any]:
        return self._phases.setdefault(
            phase,
            {
                "wall_seconds": 0.0,
                "samples": 0,
                "peak_wal_bytes": 0,
                "peak_rss_mb": 0.0,
                "peak_worker_rss_mb": 0.0,
                "peak_cpu_percent": 0.0,
                "cpu_percent_total": 0.0,
                "min_free_bytes": None,
                "io_start": None,
                "io_end": None,
                "last_detail": "",
            },
        )

    def _phase_summary(self, entry: dict[str, Any]) -> dict[str, Any]:
        samples = int(entry.get("samples", 0))
        avg_cpu = float(entry.get("cpu_percent_total", 0.0)) / samples if samples else 0.0
        return {
            "wall_seconds": float(entry.get("wall_seconds", 0.0)),
            "samples": samples,
            "avg_cpu_percent": avg_cpu,
            "peak_cpu_percent": float(entry.get("peak_cpu_percent", 0.0)),
            "peak_rss_mb": float(entry.get("peak_rss_mb", 0.0)),
            "peak_worker_rss_mb": float(entry.get("peak_worker_rss_mb", 0.0)),
            "peak_wal_bytes": int(entry.get("peak_wal_bytes", 0)),
            "min_free_bytes": entry.get("min_free_bytes"),
            "io_delta": io_counter_delta(entry.get("io_start"), entry.get("io_end")),
            "last_detail": entry.get("last_detail", ""),
        }

    def _load_psutil(self) -> Any | None:
        try:
            return importlib.import_module("psutil")
        except Exception as exc:
            self._overall["io_unavailable_reason"] = f"psutil unavailable: {exc}"
            return None

    def _read_io_counters(self) -> dict[str, int] | None:
        with self._lock:
            return self._read_io_counters_unlocked()

    def _read_io_counters_unlocked(self) -> dict[str, int] | None:
        if self._psutil is None:
            return None
        try:
            proc = self._psutil.Process(self.root_pid)
            procs = [proc, *proc.children(recursive=True)]
            totals = {"read_bytes": 0, "write_bytes": 0, "read_count": 0, "write_count": 0}
            for child in procs:
                try:
                    counters = child.io_counters()
                except Exception:
                    continue
                for key in totals:
                    totals[key] += int(getattr(counters, key, 0) or 0)
            return totals
        except Exception as exc:
            self._overall["io_unavailable_reason"] = f"psutil io_counters unavailable: {exc}"
            return None


def sample_process_tree(root_pid: int) -> tuple[int, float, int]:
    ps_path = "/bin/ps" if Path("/bin/ps").exists() else shutil.which("ps")
    if ps_path is None:
        return 0, 0.0, 0
    completed = subprocess.run(
        [ps_path, "-axo", "pid=,ppid=,rss=,%cpu="],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        return 0, 0.0, 0

    rows: list[tuple[int, int, int, float]] = []
    for line in completed.stdout.splitlines():
        parts = line.split()
        if len(parts) != 4:
            continue
        try:
            rows.append((int(parts[0]), int(parts[1]), int(parts[2]), float(parts[3])))
        except ValueError:
            continue

    descendants = {root_pid}
    changed = True
    while changed:
        changed = False
        for pid, ppid, _rss, _cpu in rows:
            if ppid in descendants and pid not in descendants:
                descendants.add(pid)
                changed = True

    matching = [(rss, cpu) for pid, _ppid, rss, cpu in rows if pid in descendants]
    rss_kb = sum(rss for rss, _cpu in matching)
    cpu_percent = sum(cpu for _rss, cpu in matching)
    worker_rss_kb = max((rss for rss, _cpu in matching), default=0)
    return rss_kb, cpu_percent, worker_rss_kb


def io_counter_delta(
    before: dict[str, int] | None,
    after: dict[str, int] | None,
) -> dict[str, int] | None:
    if before is None or after is None:
        return None
    return {key: int(after.get(key, 0)) - int(before.get(key, 0)) for key in sorted(after)}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark forensic_aul extraction variants against one .logarchive.",
    )
    parser.add_argument("logarchive", type=Path, help="Path to a .logarchive directory")
    parser.add_argument(
        "--skip-default",
        action="store_true",
        help="Skip the single-job default extract run.",
    )
    parser.add_argument(
        "--skip-custom",
        action="store_true",
        help="Skip the logshow NDJSON to SQLite custom pipeline.",
    )
    parser.add_argument(
        "--include-cli",
        action="store_true",
        help=(
            "Also benchmark the launcher CLI extract command as a subprocess. "
            "This is opt-in because it adds another full extraction run."
        ),
    )
    parser.add_argument(
        "--fast-jobs",
        default="half,three-quarter,all",
        help=(
            "Comma-separated fast-safe job variants to run. Supported tokens: "
            "half, three-quarter, all, or an integer job count. "
            "Default: half,three-quarter,all."
        ),
    )
    parser.add_argument(
        "--cli-jobs",
        default="6",
        help=(
            "Comma-separated CLI extract job variants to run when --include-cli is set. "
            "Uses the same token syntax as --fast-jobs. Default: 6."
        ),
    )
    parser.add_argument(
        "--cli-python",
        default=sys.executable,
        help=(
            "Python executable used for the CLI subprocess. "
            "Default: the interpreter running this benchmark."
        ),
    )
    parser.add_argument(
        "--suite-v020",
        action="store_true",
        help=(
            "Use the v0.2.0 CP validation preset: fast-safe jobs 1,6,10, "
            "safe writes, per-phase sampling, and the existing default/custom methods "
            "unless they are skipped separately."
        ),
    )
    parser.add_argument(
        "--sample-interval",
        type=float,
        default=DEFAULT_SAMPLE_INTERVAL_SECONDS,
        help=f"Resource/WAL/free-disk sampling interval in seconds. Default: {DEFAULT_SAMPLE_INTERVAL_SECONDS:g}.",
    )
    parser.add_argument(
        "--skip-determinism-digest",
        action="store_true",
        help=(
            "Skip the ordered-row SHA-256 digest used to compare serial vs parallel output. "
            "Counts and NULL event_order invariants are still captured."
        ),
    )
    parser.add_argument(
        "--append-report",
        type=Path,
        help=(
            "Append to an existing benchmark report. The sidecar JSON state "
            "must match the input logarchive hash."
        ),
    )
    parser.add_argument(
        "--new-report",
        action="store_true",
        help="Always create a new report instead of auto-resuming by logarchive hash.",
    )
    parser.add_argument(
        "--rerun-existing",
        action="store_true",
        help="Re-run requested methods even if the existing report already has an ok result.",
    )
    parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        help="Keep generated SQLite/NDJSON artifacts. By default they are deleted after stats are captured.",
    )
    parser.add_argument(
        "--sqlite-space-multiplier",
        type=float,
        default=DEFAULT_SQLITE_SPACE_MULTIPLIER,
        help=(
            "Required free-space multiplier relative to NDJSON size before starting "
            f"NDJSON-to-SQLite. Default: {DEFAULT_SQLITE_SPACE_MULTIPLIER}."
        ),
    )
    parser.add_argument(
        "--sqlite-space-reserve-gb",
        type=float,
        default=DEFAULT_SQLITE_SPACE_RESERVE_GB,
        help=(
            "Additional free-space reserve required before starting NDJSON-to-SQLite. "
            f"Default: {DEFAULT_SQLITE_SPACE_RESERVE_GB} GB."
        ),
    )
    args = parser.parse_args()
    if args.suite_v020:
        args.fast_jobs = "1,6,10"

    logarchive = args.logarchive.expanduser().resolve()
    if logarchive.suffix != ".logarchive" or not logarchive.is_dir():
        print(f"Expected a single .logarchive directory, got: {logarchive}", file=sys.stderr)
        return 2
    custom_supported = sys.platform == "darwin" and LOGSHOW_PATH.exists()
    if not custom_supported and not args.skip_custom:
        args.skip_custom = True
        log_line("Skipping custom logshow NDJSON to SQLite pipeline; /usr/bin/log is macOS-only")

    log_line(f"Benchmark input: {logarchive}")
    run_extract, extract_import = import_run_extract()
    forensic_version = import_forensic_version()

    machine = collect_machine_specs(forensic_version, extract_import)
    log_line("Collecting logarchive stats and helper hash")
    archive_stats = collect_archive_stats(logarchive)
    log_line(
        "Archive stats: "
        f"tracev3={archive_stats.tracev3_count:,}, "
        f"timesync={archive_stats.timesync_count:,}, "
        f"tracev3_size={format_bytes(archive_stats.tracev3_total_size)}, "
        f"sha256={archive_stats.source_sha256}"
    )

    state = load_or_create_state(
        args=args,
        logarchive=logarchive,
        archive_stats=archive_stats,
        machine=machine,
    )
    run_dir = Path(state["run_dir"])
    report_path = Path(state["report_path"])
    results = [bench_result_from_json(item) for item in state.get("results", [])]
    log_line(f"Run directory: {run_dir}")
    log_line(f"Report path: {report_path}")

    write_benchmark_report(report_path, logarchive, run_dir, machine, archive_stats, results)

    if not args.skip_default:
        default_db = run_dir / "default_extract.db"
        run_or_skip_method(
            results=results,
            key="default_extract",
            report_path=report_path,
            logarchive=logarchive,
            run_dir=run_dir,
            machine=machine,
            archive_stats=archive_stats,
            rerun_existing=args.rerun_existing,
            run=lambda: measure_extract(
                "default_extract",
                "default extract",
                "run_extract(fast_fts=False, fast_write=False, jobs=1)",
                default_db,
                args.sample_interval,
                lambda progress: run_default_extract(run_extract, logarchive, default_db, progress),
            ),
            finish=lambda result: finish_extract_result(
                result,
                default_db,
                keep_artifacts=args.keep_artifacts,
                determinism_digest=not args.skip_determinism_digest,
            ),
        )
    else:
        log_line("Skipping default extract")

    logical_cpus = max(1, os.cpu_count() or 1)
    try:
        fast_variants = fast_safe_job_counts(logical_cpus, args.fast_jobs)
    except ValueError as exc:
        parser.error(str(exc))
    log_line(
        "Fast-safe variants: "
        + ", ".join(f"{label} jobs={jobs}" for label, jobs in fast_variants)
    )
    for label, jobs in fast_variants:
        fast_db = run_dir / f"fast_safe_extract_jobs_{jobs}.db"
        key = f"fast_safe_jobs_{jobs}"
        method_name = f"fast safe extract ({label}, jobs={jobs})"
        run_or_skip_method(
            results=results,
            key=key,
            report_path=report_path,
            logarchive=logarchive,
            run_dir=run_dir,
            machine=machine,
            archive_stats=archive_stats,
            rerun_existing=args.rerun_existing,
            run=lambda jobs=jobs, method_name=method_name, fast_db=fast_db, key=key: measure_extract(
                key,
                method_name,
                (
                    "run_extract(fast_fts=True, fast_write=False, "
                    f"jobs={jobs}, batch_size={FAST_SAFE_BATCH_SIZE})"
                ),
                fast_db,
                args.sample_interval,
                lambda progress, jobs=jobs, fast_db=fast_db: run_fast_safe_extract(
                    run_extract,
                    logarchive,
                    fast_db,
                    jobs,
                    progress,
                ),
            ),
            finish=lambda result, fast_db=fast_db: finish_extract_result(
                result,
                fast_db,
                keep_artifacts=args.keep_artifacts,
                determinism_digest=not args.skip_determinism_digest,
            ),
        )

    if args.include_cli:
        try:
            cli_variants = fast_safe_job_counts(logical_cpus, args.cli_jobs)
        except ValueError as exc:
            parser.error(str(exc))
        log_line(
            "CLI extract variants: "
            + ", ".join(f"{label} jobs={jobs}" for label, jobs in cli_variants)
        )
        for label, jobs in cli_variants:
            cli_db = run_dir / f"cli_extract_jobs_{jobs}.db"
            key = f"cli_extract_jobs_{jobs}"
            method_name = f"CLI extract ({label}, jobs={jobs})"
            run_or_skip_method(
                results=results,
                key=key,
                report_path=report_path,
                logarchive=logarchive,
                run_dir=run_dir,
                machine=machine,
                archive_stats=archive_stats,
                rerun_existing=args.rerun_existing,
                run=lambda jobs=jobs, method_name=method_name, cli_db=cli_db, key=key: run_cli_extract(
                    key=key,
                    name=method_name,
                    logarchive=logarchive,
                    db_path=cli_db,
                    jobs=jobs,
                    python_executable=args.cli_python,
                    sample_interval=args.sample_interval,
                ),
                finish=lambda result, cli_db=cli_db: finish_extract_result(
                    result,
                    cli_db,
                    keep_artifacts=args.keep_artifacts,
                    determinism_digest=not args.skip_determinism_digest,
                ),
            )
    else:
        log_line("Skipping CLI extract benchmark; pass --include-cli to run it")

    if not args.skip_custom:
        custom_ndjson = run_dir / "logshow.ndjson"
        custom_db = run_dir / "logshow.sqlite"
        run_or_skip_method(
            results=results,
            key="custom_logshow_ndjson_to_sqlite",
            report_path=report_path,
            logarchive=logarchive,
            run_dir=run_dir,
            machine=machine,
            archive_stats=archive_stats,
            rerun_existing=args.rerun_existing,
            run=lambda: run_custom_pipeline(
                logarchive,
                custom_ndjson,
                custom_db,
                sqlite_space_multiplier=args.sqlite_space_multiplier,
                sqlite_space_reserve_gb=args.sqlite_space_reserve_gb,
            ),
            finish=lambda result: finish_custom_result(
                result,
                ndjson_path=custom_ndjson,
                db_path=custom_db,
                keep_artifacts=args.keep_artifacts,
            ),
        )
    else:
        log_line("Skipping custom logshow NDJSON to SQLite pipeline")

    log_line(f"Benchmark complete: {report_path}")
    return 0 if all(r.status == "ok" for r in results) else 1


def import_run_extract() -> tuple[Callable[..., Any], str]:
    """Try the requested import path first, then this checkout's actual path."""
    try:
        module = importlib.import_module("forensic_aul.ops.extract")
    except ModuleNotFoundError as exc:
        if exc.name != "forensic_aul.ops.extract":
            raise
        module = importlib.import_module("forensic_aul.ops.extraction.extract")
    return module.run_extract, module.__name__


def import_forensic_version() -> str:
    try:
        module = importlib.import_module("forensic_aul")
        return str(getattr(module, "__version__", "unknown"))
    except Exception:
        return "unknown"


def import_hash_logarchive() -> Callable[[Path], tuple[str, dict[str, str]]]:
    module = importlib.import_module("forensic_aul.engine.integrity")
    return module.hash_logarchive


def fast_safe_job_counts(logical_cpus: int, spec: str) -> list[tuple[str, int]]:
    candidates: list[tuple[str, int]] = []
    for raw_token in spec.split(","):
        token = raw_token.strip().lower()
        if not token:
            continue
        if token in {"half", "1/2", "0.5"}:
            candidates.append(("1/2 cores", max(1, logical_cpus // 2)))
        elif token in {"three-quarter", "three-quarters", "3/4", "0.75"}:
            candidates.append(("3/4 cores", max(1, (logical_cpus * 3) // 4)))
        elif token in {"all", "full", "1/core", "one-per-core"}:
            candidates.append(("1/core", max(1, logical_cpus)))
        else:
            try:
                jobs = int(token)
            except ValueError as exc:
                raise ValueError(f"invalid --fast-jobs token: {raw_token!r}") from exc
            if jobs < 1:
                raise ValueError(f"--fast-jobs values must be >= 1, got {jobs}")
            candidates.append((f"custom", jobs))
    seen: set[int] = set()
    unique: list[tuple[str, int]] = []
    for label, jobs in candidates:
        if jobs in seen:
            continue
        seen.add(jobs)
        unique.append((label, jobs))
    return unique


def run_default_extract(
    run_extract: Callable[..., Any],
    logarchive: Path,
    db_path: Path,
    progress: Callable[[Any], None],
) -> Any:
    return run_extract(
        logarchive=logarchive,
        db_path=db_path,
        case_number="BENCHMARK-DEFAULT",
        fast_fts=False,
        fast_write=False,
        jobs=1,
        overwrite=True,
        progress=progress,
    )


def run_fast_safe_extract(
    run_extract: Callable[..., Any],
    logarchive: Path,
    db_path: Path,
    jobs: int,
    progress: Callable[[Any], None],
) -> Any:
    return run_extract(
        logarchive=logarchive,
        db_path=db_path,
        case_number="BENCHMARK-FAST-SAFE",
        batch_size=FAST_SAFE_BATCH_SIZE,
        fast_fts=True,
        fast_write=False,
        jobs=jobs,
        overwrite=True,
        progress=progress,
    )


def run_cli_extract(
    *,
    key: str,
    name: str,
    logarchive: Path,
    db_path: Path,
    jobs: int,
    python_executable: str,
    sample_interval: float,
) -> BenchResult:
    case_number = f"BENCHMARK-CLI-JOBS-{jobs}"
    imei = "BENCHMARK"
    session_log = db_path.parent / f"{case_number}-AUL-{imei}.log"
    cmd = [
        python_executable,
        "-m",
        "launcher.cli",
        "extract",
        str(logarchive),
        str(db_path),
        "--case-number",
        case_number,
        "--imei",
        imei,
        "--batch-size",
        str(FAST_SAFE_BATCH_SIZE),
        "--jobs",
        str(jobs),
        "--fast-fts",
        "--overwrite",
    ]
    details = (
        "subprocess: python -m launcher.cli extract "
        f"--fast-fts --jobs {jobs} --batch-size {FAST_SAFE_BATCH_SIZE} "
        "(fast_write disabled)"
    )
    result = measure_cli_extract(
        key=key,
        name=name,
        details=details,
        db_path=db_path,
        cmd=cmd,
        sample_interval=sample_interval,
    )
    result.outputs["session_log"] = session_log
    result.sizes["session_log"] = path_size(session_log)
    return result


def measure_cli_extract(
    *,
    key: str,
    name: str,
    details: str,
    db_path: Path,
    cmd: list[str],
    sample_interval: float,
) -> BenchResult:
    before_self = resource.getrusage(resource.RUSAGE_SELF)
    before_children = resource.getrusage(resource.RUSAGE_CHILDREN)
    start = time.perf_counter()
    result = BenchResult(key=key, name=name, status="ok", details=details)
    result.extra["cli_command"] = cmd
    try:
        result.extra["free_disk_before_bytes"] = shutil.disk_usage(db_path.parent).free
    except OSError:
        result.extra["free_disk_before_bytes"] = None

    stdout_tail: collections.deque[str] = collections.deque(maxlen=CLI_STDOUT_TAIL_LINES)
    monitor = ExtractMonitor(name, db_path, sample_interval)
    process: subprocess.Popen[str] | None = None

    with PhaseHeartbeat(name):
        try:
            db_path.parent.mkdir(parents=True, exist_ok=True)
            log_line(f"Running CLI extract: {shell_join(cmd)}")
            process = subprocess.Popen(
                cmd,
                cwd=str(REPO_ROOT),
                env=subprocess_env_for_repo(),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            monitor.root_pid = process.pid
            with monitor:
                assert process.stdout is not None
                for line in process.stdout:
                    cleaned = line.rstrip()
                    if cleaned:
                        stdout_tail.append(cleaned)
                        log_line(f"{name}: {cleaned}")
                        phase = phase_from_cli_output_line(cleaned)
                        if phase is not None:
                            monitor.set_phase(*phase)
                returncode = process.wait()
            result.extra["cli_returncode"] = returncode
            if returncode != 0:
                result.status = "failed"
                result.error = f"CLI extract exited with status {returncode}"
        except Exception as exc:
            result.status = "failed"
            result.error = "".join(traceback.format_exception_only(type(exc), exc)).strip()
            result.extra["traceback"] = traceback.format_exc()
            if process is not None and process.poll() is None:
                terminate_process(process)

    end = time.perf_counter()
    after_self = resource.getrusage(resource.RUSAGE_SELF)
    after_children = resource.getrusage(resource.RUSAGE_CHILDREN)
    sample = monitor.snapshot()
    phase_summary = monitor.summary()

    result.wall_seconds = end - start
    result.user_cpu_seconds = (
        after_self.ru_utime - before_self.ru_utime
        + after_children.ru_utime - before_children.ru_utime
    )
    result.system_cpu_seconds = (
        after_self.ru_stime - before_self.ru_stime
        + after_children.ru_stime - before_children.ru_stime
    )
    result.minor_faults = (
        after_self.ru_minflt - before_self.ru_minflt
        + after_children.ru_minflt - before_children.ru_minflt
    )
    result.major_faults = (
        after_self.ru_majflt - before_self.ru_majflt
        + after_children.ru_majflt - before_children.ru_majflt
    )
    result.block_input_ops = (
        after_self.ru_inblock - before_self.ru_inblock
        + after_children.ru_inblock - before_children.ru_inblock
    )
    result.block_output_ops = (
        after_self.ru_oublock - before_self.ru_oublock
        + after_children.ru_oublock - before_children.ru_oublock
    )
    result.peak_rss_mb = sample.peak_rss_mb
    result.avg_cpu_percent = sample.avg_cpu_percent
    result.peak_cpu_percent = sample.peak_cpu_percent
    result.extra["resource_samples"] = sample.samples
    result.extra["phase_metrics"] = phase_summary
    result.extra["cli_stdout_tail"] = list(stdout_tail)
    try:
        result.extra["free_disk_after_bytes"] = shutil.disk_usage(db_path.parent).free
    except OSError:
        result.extra["free_disk_after_bytes"] = None
    if result.status == "ok":
        log_line(
            f"OK    {name} wall={format_seconds(result.wall_seconds)} "
            f"cpu={format_seconds(result.user_cpu_seconds + result.system_cpu_seconds)} "
            f"peak_rss={result.peak_rss_mb:.1f} MB "
            f"peak_wal={format_bytes(phase_summary.get('peak_wal_bytes', 0))}"
        )
    else:
        log_line(f"FAIL  {name}: {result.error}")
    return result


def subprocess_env_for_repo() -> dict[str, str]:
    env = os.environ.copy()
    existing = env.get("PYTHONPATH")
    repo = str(REPO_ROOT)
    env["PYTHONPATH"] = repo if not existing else repo + os.pathsep + existing
    return env


def terminate_process(process: subprocess.Popen[str]) -> None:
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def phase_from_cli_output_line(line: str) -> tuple[str, str] | None:
    lower = line.lower()
    if "assigning forensic ordering" in lower:
        return ("ordering", "merging timeline")
    if "building secondary indexes" in lower:
        return ("index", "building indexes")
    if "building fts5 index" in lower:
        return ("fts", "full-text index")
    if "re-verifying per-file integrity" in lower:
        return ("integrity", "source file re-hash")
    if "pass 2" in lower or "main parse" in lower or "parsing in parallel" in lower:
        return ("parse", "main tracev3 parse")
    if "source preparation" in lower or "preparing source" in lower:
        return ("prepare", "source preparation")
    if (
        "database initialisation" in lower
        or "case metadata" in lower
        or "timesync files" in lower
        or "string cache" in lower
        or "oversize scan" in lower
    ):
        return ("prepare", "database/timesync/cache setup")
    return None


def shell_join(cmd: list[str]) -> str:
    try:
        return " ".join(shlex_quote(part) for part in cmd)
    except Exception:
        return repr(cmd)


def shlex_quote(value: str) -> str:
    if not value:
        return "''"
    safe = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-")
    if all(char in safe for char in value):
        return value
    return "'" + value.replace("'", "'\"'\"'") + "'"


def measure(key: str, name: str, details: str, func: Callable[[], Any]) -> BenchResult:
    before_self = resource.getrusage(resource.RUSAGE_SELF)
    before_children = resource.getrusage(resource.RUSAGE_CHILDREN)
    start = time.perf_counter()
    result = BenchResult(key=key, name=name, status="ok", details=details)
    with PhaseHeartbeat(name), ProcessTreeSampler(os.getpid()) as sampler:
        try:
            returned = func()
            result.extra["returned"] = summarize_returned(returned)
        except Exception as exc:
            result.status = "failed"
            result.error = "".join(traceback.format_exception_only(type(exc), exc)).strip()
            result.extra["traceback"] = traceback.format_exc()
    end = time.perf_counter()
    after_self = resource.getrusage(resource.RUSAGE_SELF)
    after_children = resource.getrusage(resource.RUSAGE_CHILDREN)
    sample = sampler.snapshot()

    result.wall_seconds = end - start
    result.user_cpu_seconds = (
        after_self.ru_utime - before_self.ru_utime
        + after_children.ru_utime - before_children.ru_utime
    )
    result.system_cpu_seconds = (
        after_self.ru_stime - before_self.ru_stime
        + after_children.ru_stime - before_children.ru_stime
    )
    result.minor_faults = (
        after_self.ru_minflt - before_self.ru_minflt
        + after_children.ru_minflt - before_children.ru_minflt
    )
    result.major_faults = (
        after_self.ru_majflt - before_self.ru_majflt
        + after_children.ru_majflt - before_children.ru_majflt
    )
    result.block_input_ops = (
        after_self.ru_inblock - before_self.ru_inblock
        + after_children.ru_inblock - before_children.ru_inblock
    )
    result.block_output_ops = (
        after_self.ru_oublock - before_self.ru_oublock
        + after_children.ru_oublock - before_children.ru_oublock
    )
    result.peak_rss_mb = sample.peak_rss_mb
    result.avg_cpu_percent = sample.avg_cpu_percent
    result.peak_cpu_percent = sample.peak_cpu_percent
    result.extra["resource_samples"] = sample.samples
    if result.status == "ok":
        log_line(
            f"OK    {name} wall={format_seconds(result.wall_seconds)} "
            f"cpu={format_seconds(result.user_cpu_seconds + result.system_cpu_seconds)} "
            f"peak_rss={result.peak_rss_mb:.1f} MB"
        )
    else:
        log_line(f"FAIL  {name}: {result.error}")
    return result


def measure_extract(
    key: str,
    name: str,
    details: str,
    db_path: Path,
    sample_interval: float,
    func: Callable[[Callable[[Any], None]], Any],
) -> BenchResult:
    before_self = resource.getrusage(resource.RUSAGE_SELF)
    before_children = resource.getrusage(resource.RUSAGE_CHILDREN)
    start = time.perf_counter()
    result = BenchResult(key=key, name=name, status="ok", details=details)
    try:
        result.extra["free_disk_before_bytes"] = shutil.disk_usage(db_path.parent).free
    except OSError:
        result.extra["free_disk_before_bytes"] = None
    monitor = ExtractMonitor(name, db_path, sample_interval)
    logger = logging.getLogger("forensic_aul.ops.extraction.extract")
    handler = ExtractPhaseLogHandler(monitor)
    old_level = logger.level

    with PhaseHeartbeat(name), monitor:
        logger.addHandler(handler)
        if logger.getEffectiveLevel() > logging.INFO:
            logger.setLevel(logging.INFO)
        try:
            progress = CliProgressSink(name, monitor=monitor)
            returned = func(progress)
            result.extra["returned"] = summarize_returned(returned)
        except Exception as exc:
            result.status = "failed"
            result.error = "".join(traceback.format_exception_only(type(exc), exc)).strip()
            result.extra["traceback"] = traceback.format_exc()
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)

    end = time.perf_counter()
    after_self = resource.getrusage(resource.RUSAGE_SELF)
    after_children = resource.getrusage(resource.RUSAGE_CHILDREN)
    sample = monitor.snapshot()
    phase_summary = monitor.summary()

    result.wall_seconds = end - start
    result.user_cpu_seconds = (
        after_self.ru_utime - before_self.ru_utime
        + after_children.ru_utime - before_children.ru_utime
    )
    result.system_cpu_seconds = (
        after_self.ru_stime - before_self.ru_stime
        + after_children.ru_stime - before_children.ru_stime
    )
    result.minor_faults = (
        after_self.ru_minflt - before_self.ru_minflt
        + after_children.ru_minflt - before_children.ru_minflt
    )
    result.major_faults = (
        after_self.ru_majflt - before_self.ru_majflt
        + after_children.ru_majflt - before_children.ru_majflt
    )
    result.block_input_ops = (
        after_self.ru_inblock - before_self.ru_inblock
        + after_children.ru_inblock - before_children.ru_inblock
    )
    result.block_output_ops = (
        after_self.ru_oublock - before_self.ru_oublock
        + after_children.ru_oublock - before_children.ru_oublock
    )
    result.peak_rss_mb = sample.peak_rss_mb
    result.avg_cpu_percent = sample.avg_cpu_percent
    result.peak_cpu_percent = sample.peak_cpu_percent
    result.extra["resource_samples"] = sample.samples
    result.extra["phase_metrics"] = phase_summary
    try:
        result.extra["free_disk_after_bytes"] = shutil.disk_usage(db_path.parent).free
    except OSError:
        result.extra["free_disk_after_bytes"] = None
    if result.status == "ok":
        log_line(
            f"OK    {name} wall={format_seconds(result.wall_seconds)} "
            f"cpu={format_seconds(result.user_cpu_seconds + result.system_cpu_seconds)} "
            f"peak_rss={result.peak_rss_mb:.1f} MB "
            f"peak_wal={format_bytes(phase_summary.get('peak_wal_bytes', 0))}"
        )
    else:
        log_line(f"FAIL  {name}: {result.error}")
    return result


def run_custom_pipeline(
    logarchive: Path,
    ndjson_path: Path,
    db_path: Path,
    *,
    sqlite_space_multiplier: float,
    sqlite_space_reserve_gb: float,
) -> BenchResult:
    logshow = measure(
        "logshow_ndjson_phase",
        "logshow ndjson phase",
        "/usr/bin/log show --style ndjson --info --debug --signpost --archive <logarchive>",
        lambda: run_logshow(logarchive, ndjson_path),
    )
    sqlite_load = measure(
        "ndjson_to_sqlite_phase",
        "ndjson to sqlite phase",
        f"load logshow NDJSON into iLEAPP-style SQLite table with batch_size={CUSTOM_BATCH_SIZE}",
        lambda: load_ndjson_to_sqlite(
            ndjson_path,
            db_path,
            space_multiplier=sqlite_space_multiplier,
            reserve_gb=sqlite_space_reserve_gb,
        ),
    )
    custom_stats = inspect_custom_db(db_path) if db_path.exists() else {}

    combined = BenchResult(
        key="custom_logshow_ndjson_to_sqlite",
        name="custom logshow ndjson to sqlite",
        status="ok" if logshow.status == "ok" and sqlite_load.status == "ok" else "failed",
        details=(
            "/usr/bin/log show --style ndjson, then streaming JSON load into "
            "an iLEAPP-style SQLite logarchive table with selected columns only"
        ),
        wall_seconds=logshow.wall_seconds + sqlite_load.wall_seconds,
        user_cpu_seconds=logshow.user_cpu_seconds + sqlite_load.user_cpu_seconds,
        system_cpu_seconds=logshow.system_cpu_seconds + sqlite_load.system_cpu_seconds,
        peak_rss_mb=max(logshow.peak_rss_mb, sqlite_load.peak_rss_mb),
        avg_cpu_percent=(logshow.avg_cpu_percent + sqlite_load.avg_cpu_percent) / 2,
        peak_cpu_percent=max(logshow.peak_cpu_percent, sqlite_load.peak_cpu_percent),
        minor_faults=logshow.minor_faults + sqlite_load.minor_faults,
        major_faults=logshow.major_faults + sqlite_load.major_faults,
        block_input_ops=logshow.block_input_ops + sqlite_load.block_input_ops,
        block_output_ops=logshow.block_output_ops + sqlite_load.block_output_ops,
        outputs={"ndjson": ndjson_path, "sqlite": db_path},
        sizes={
            "ndjson": path_size(ndjson_path),
            "sqlite": sqlite_file_set_size(db_path),
        },
        row_count=(
            int(custom_stats["logarchive_rows"])
            if custom_stats.get("logarchive_rows") is not None
            else None
        ),
        extra={
            "db_stats": custom_stats,
            "logshow_phase": result_for_json(logshow),
            "sqlite_phase": result_for_json(sqlite_load),
        },
    )
    if logshow.error or sqlite_load.error:
        combined.error = " | ".join(e for e in (logshow.error, sqlite_load.error) if e)
    log_line(
        "Custom pipeline summary: "
        f"ndjson={format_bytes(combined.sizes.get('ndjson', 0))}, "
        f"sqlite={format_bytes(combined.sizes.get('sqlite', 0))}, "
        f"rows={format_count(combined.row_count)}"
    )
    return combined


def run_logshow(logarchive: Path, output_path: Path) -> None:
    if sys.platform != "darwin" or not LOGSHOW_PATH.exists():
        raise RuntimeError("logshow pipeline requires macOS and /usr/bin/log")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        str(LOGSHOW_PATH),
        "show",
        "--style",
        "ndjson",
        *LOGSHOW_FLAGS,
        "--archive",
        str(logarchive),
    ]
    log_line(f"Running logshow: {' '.join(cmd)}")
    with output_path.open("wb") as stdout:
        completed = subprocess.run(
            cmd,
            stdout=stdout,
            stderr=subprocess.PIPE,
            check=False,
        )
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"`{' '.join(cmd)}` failed with {completed.returncode}: {stderr}")
    log_line(f"logshow wrote {output_path} ({format_bytes(path_size(output_path))})")


def preflight_sqlite_space(
    *,
    ndjson_path: Path,
    db_path: Path,
    multiplier: float,
    reserve_gb: float,
) -> None:
    if multiplier <= 0:
        raise ValueError(f"--sqlite-space-multiplier must be > 0, got {multiplier}")
    if reserve_gb < 0:
        raise ValueError(f"--sqlite-space-reserve-gb must be >= 0, got {reserve_gb}")

    ndjson_size = path_size(ndjson_path)
    reserve_bytes = int(reserve_gb * (1024**3))
    required_free = int(ndjson_size * multiplier) + reserve_bytes
    db_path.parent.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(db_path.parent).free
    log_line(
        "SQLite disk preflight: "
        f"ndjson={format_bytes(ndjson_size)}, "
        f"required_free={format_bytes(required_free)} "
        f"(multiplier={multiplier:g}, reserve={reserve_gb:g} GB), "
        f"available={format_bytes(free)}"
    )
    if free < required_free:
        raise RuntimeError(
            "Not enough free disk space for NDJSON-to-SQLite: "
            f"available={format_bytes(free)}, required={format_bytes(required_free)}. "
            "Increase free space, lower --sqlite-space-multiplier/--sqlite-space-reserve-gb, "
            "or run on a larger volume."
        )


def load_ndjson_to_sqlite(
    ndjson_path: Path,
    db_path: Path,
    *,
    space_multiplier: float = DEFAULT_SQLITE_SPACE_MULTIPLIER,
    reserve_gb: float = DEFAULT_SQLITE_SPACE_RESERVE_GB,
) -> dict[str, int]:
    for sidecar in sqlite_sidecars(db_path):
        sidecar.unlink(missing_ok=True)

    preflight_sqlite_space(
        ndjson_path=ndjson_path,
        db_path=db_path,
        multiplier=space_multiplier,
        reserve_gb=reserve_gb,
    )

    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA temp_store=MEMORY;")
        conn.execute("PRAGMA cache_size=-65536;")
        conn.executescript(
            """
            CREATE TABLE logarchive (
                timestamp          TEXT,
                row_number         INTEGER,
                process_image_path TEXT,
                process_id         INTEGER,
                subsystem          TEXT,
                category           TEXT,
                event_message      TEXT,
                trace_id           TEXT
            );
            """
        )
        inserted = 0
        parse_errors = 0
        non_json_lines = 0
        row_number = 0
        batch: list[tuple[Any, ...]] = []

        with ndjson_path.open("rb") as fh:
            for raw_line in fh:
                stripped = raw_line.strip()
                if not stripped or not stripped.startswith(b"{"):
                    non_json_lines += 1
                    continue
                try:
                    raw_text = stripped.decode("utf-8", errors="replace")
                    obj = json.loads(raw_text)
                except json.JSONDecodeError:
                    parse_errors += 1
                    continue

                row_number += 1
                batch.append(row_from_logshow_obj(obj, row_number))
                if len(batch) >= CUSTOM_BATCH_SIZE:
                    inserted += insert_custom_batch(conn, batch)
                    batch.clear()
                    if inserted % 100_000 == 0:
                        log_line(f"NDJSON to SQLite: inserted {inserted:,} rows")

        if batch:
            inserted += insert_custom_batch(conn, batch)

        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        log_line(
            "NDJSON to SQLite complete: "
            f"inserted={inserted:,}, parse_errors={parse_errors:,}, "
            f"non_json_lines={non_json_lines:,}, size={format_bytes(sqlite_file_set_size(db_path))}"
        )
        return {
            "inserted": inserted,
            "parse_errors": parse_errors,
            "non_json_lines": non_json_lines,
        }
    finally:
        conn.close()


def row_from_logshow_obj(obj: dict[str, Any], row_number: int) -> tuple[Any, ...]:
    timestamp = str(obj.get("timestamp") or "")
    return (
        convert_apple_timestamp_to_utc_iso(timestamp),
        row_number,
        obj.get("processImagePath"),
        coerce_int(obj.get("processID")),
        obj.get("subsystem"),
        obj.get("category"),
        str(obj.get("eventMessage", "")),
        str(obj.get("traceID", "")),
    )


def insert_custom_batch(conn: sqlite3.Connection, batch: list[tuple[Any, ...]]) -> int:
    conn.executemany(
        """
        INSERT INTO logarchive(
            timestamp, row_number, process_image_path, process_id,
            subsystem, category, event_message, trace_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        batch,
    )
    conn.commit()
    return len(batch)


def convert_apple_timestamp_to_utc_iso(value: str) -> str:
    if not value:
        return ""
    parsed = parse_apple_datetime(value)
    if parsed is None:
        return value
    return parsed.astimezone(dt.timezone.utc).isoformat()


def parse_apple_datetime(value: str) -> dt.datetime | None:
    if not value:
        return None
    normalized = value.strip().replace("Z", "+0000")
    formats = (
        "%Y-%m-%d %H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S%z",
    )
    for fmt in formats:
        try:
            return dt.datetime.strptime(normalized, fmt)
        except ValueError:
            continue
    try:
        return dt.datetime.fromisoformat(value)
    except ValueError:
        return None


def parse_apple_timestamp_us(value: str) -> int | None:
    parsed = parse_apple_datetime(value)
    if parsed is None:
        return None
    epoch = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
    delta = parsed.astimezone(dt.timezone.utc) - epoch
    return delta // dt.timedelta(microseconds=1)


def coerce_int(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, bool):
        return int(value)
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def finish_extract_result(
    result: BenchResult,
    db_path: Path,
    *,
    keep_artifacts: bool,
    determinism_digest: bool,
) -> None:
    result.outputs["sqlite"] = db_path
    result.sizes["sqlite"] = sqlite_file_set_size(db_path)
    if db_path.exists():
        stats = inspect_extract_db(db_path, determinism_digest=determinism_digest)
        result.extra["db_stats"] = stats
        result.row_count = int(stats["logs_rows"]) if stats.get("logs_rows") is not None else None
    cleanup_large_artifacts(result, keep_artifacts=keep_artifacts)


def finish_custom_result(
    result: BenchResult,
    *,
    ndjson_path: Path,
    db_path: Path,
    keep_artifacts: bool,
) -> None:
    result.outputs.setdefault("ndjson", ndjson_path)
    result.outputs.setdefault("sqlite", db_path)
    result.sizes["ndjson"] = path_size(ndjson_path)
    result.sizes["sqlite"] = sqlite_file_set_size(db_path)
    if db_path.exists():
        stats = inspect_custom_db(db_path)
        result.extra["db_stats"] = stats
        result.row_count = int(stats["logarchive_rows"]) if stats.get("logarchive_rows") is not None else None
    cleanup_large_artifacts(result, keep_artifacts=keep_artifacts)


def inspect_extract_db(db_path: Path, *, determinism_digest: bool) -> dict[str, Any]:
    try:
        conn = sqlite3.connect(str(db_path))
        try:
            first_ns = scalar_int(
                conn,
                "SELECT timestamp_unix_ns FROM logs ORDER BY timestamp_unix_ns ASC LIMIT 1",
            )
            last_ns = scalar_int(
                conn,
                "SELECT timestamp_unix_ns FROM logs ORDER BY timestamp_unix_ns DESC LIMIT 1",
            )
            stats = {
                "sqlite_file_sizes": sqlite_component_sizes(db_path),
                "sqlite_dbstat": dbstat_breakdown(conn),
                "logs_rows": scalar_int(conn, "SELECT COUNT(*) FROM logs"),
                "processes": scalar_int(conn, "SELECT COUNT(*) FROM processes"),
                "subsystems": scalar_int(conn, "SELECT COUNT(*) FROM subsystems"),
                "categories": scalar_int(conn, "SELECT COUNT(*) FROM categories"),
                "libraries": scalar_int(conn, "SELECT COUNT(*) FROM libraries"),
                "source_files": scalar_int(conn, "SELECT COUNT(*) FROM source_files"),
                "distinct_boots": scalar_int(conn, "SELECT COUNT(*) FROM boots"),
                "logs_with_null_event_order": scalar_int(
                    conn,
                    "SELECT COUNT(*) FROM logs WHERE event_order IS NULL",
                ),
                "logs_with_null_source_order": scalar_int(
                    conn,
                    "SELECT COUNT(*) FROM logs WHERE source_order IS NULL",
                ),
                "integrity_changed_files": scalar_int(
                    conn,
                    "SELECT COUNT(*) FROM source_files WHERE integrity_ok = 0",
                ),
                "integrity_unverifiable_files": scalar_int(
                    conn,
                    "SELECT COUNT(*) FROM source_files WHERE integrity_ok IS NULL",
                ),
                "first_timestamp_iso": iso8601_from_unix_ns_for_report(first_ns),
                "last_timestamp_iso": iso8601_from_unix_ns_for_report(last_ns),
                "first_timestamp_unix_ns": first_ns,
                "last_timestamp_unix_ns": last_ns,
                "event_types": grouped_counts(
                    conn,
                    "SELECT event_types.name, COUNT(*) "
                    "FROM logs LEFT JOIN event_types ON event_types.id = logs.event_type_id "
                    "GROUP BY event_types.name",
                ),
                "log_levels": grouped_counts(
                    conn,
                    "SELECT log_levels.name, COUNT(*) "
                    "FROM logs LEFT JOIN log_levels ON log_levels.id = logs.log_level_id "
                    "GROUP BY log_levels.name",
                ),
            }
            if determinism_digest:
                log_line(f"Computing ordered determinism digest for {db_path.name}")
                stats["ordered_digest"] = ordered_logs_digest(conn)
            else:
                stats["ordered_digest"] = {"skipped": True}
            return stats
        finally:
            conn.close()
    except sqlite3.Error:
        return {}


def inspect_custom_db(db_path: Path) -> dict[str, Any]:
    try:
        conn = sqlite3.connect(str(db_path))
        try:
            return {
                "schema": "ileapp_logarchive_selected_columns",
                "logarchive_rows": scalar_int(conn, "SELECT COUNT(*) FROM logarchive"),
                "distinct_process_ids": scalar_int(
                    conn,
                    "SELECT COUNT(DISTINCT process_id) FROM logarchive",
                ),
                "distinct_process_paths": scalar_int(
                    conn,
                    "SELECT COUNT(DISTINCT process_image_path) FROM logarchive "
                    "WHERE process_image_path IS NOT NULL AND process_image_path != ''",
                ),
                "subsystems": scalar_int(
                    conn,
                    "SELECT COUNT(DISTINCT subsystem) FROM logarchive "
                    "WHERE subsystem IS NOT NULL AND subsystem != ''",
                ),
                "categories": scalar_int(
                    conn,
                    "SELECT COUNT(DISTINCT category) FROM logarchive "
                    "WHERE category IS NOT NULL AND category != ''",
                ),
                "first_timestamp": scalar_text(
                    conn,
                    "SELECT MIN(timestamp) FROM logarchive WHERE timestamp IS NOT NULL AND timestamp != ''",
                ),
                "last_timestamp": scalar_text(
                    conn,
                    "SELECT MAX(timestamp) FROM logarchive WHERE timestamp IS NOT NULL AND timestamp != ''",
                ),
            }
        finally:
            conn.close()
    except sqlite3.Error:
        return {}


def scalar_int(conn: sqlite3.Connection, sql: str) -> int | None:
    row = conn.execute(sql).fetchone()
    if row is None or row[0] is None:
        return None
    return int(row[0])


def scalar_text(conn: sqlite3.Connection, sql: str) -> str | None:
    row = conn.execute(sql).fetchone()
    if row is None or row[0] is None:
        return None
    return str(row[0])


def grouped_counts(conn: sqlite3.Connection, sql: str) -> dict[str, int]:
    return {str(key) if key is not None else "": int(count) for key, count in conn.execute(sql)}


def sqlite_component_sizes(db_path: Path) -> dict[str, int]:
    main_db, wal, shm = sqlite_sidecars(db_path)
    return {
        "db": path_size(main_db),
        "wal": path_size(wal),
        "shm": path_size(shm),
        "total": sqlite_file_set_size(db_path),
    }


def dbstat_breakdown(conn: sqlite3.Connection) -> dict[str, Any]:
    try:
        rows = [
            (str(name), int(size or 0))
            for name, size in conn.execute(
                "SELECT name, SUM(pgsize) FROM dbstat GROUP BY name ORDER BY SUM(pgsize) DESC"
            )
        ]
    except sqlite3.Error as exc:
        return {"available": False, "error": str(exc)}

    categories = {
        "tables_bytes": 0,
        "indexes_bytes": 0,
        "fts_bytes": 0,
        "sqlite_internal_bytes": 0,
        "other_bytes": 0,
    }
    objects: list[dict[str, Any]] = []
    for name, size in rows:
        kind = sqlite_object_kind(name)
        categories[f"{kind}_bytes"] += size
        objects.append({"name": name, "bytes": size, "kind": kind})
    return {
        "available": True,
        "total_bytes": sum(size for _name, size in rows),
        "categories": categories,
        "objects": objects,
    }


def sqlite_object_kind(name: str) -> str:
    if name.startswith("logs_fts") or name in {"fts5_config", "fts5_data", "fts5_docsize", "fts5_idx"}:
        return "fts"
    if name.startswith("idx_") or name.startswith("sqlite_autoindex"):
        return "indexes"
    if name.startswith("sqlite_"):
        return "sqlite_internal"
    known_tables = {
        "case_metadata",
        "source_files",
        "processes",
        "libraries",
        "subsystems",
        "categories",
        "format_strs",
        "log_levels",
        "event_types",
        "process_uuids",
        "boots",
        "timesync_anchors",
        "logs",
        "shutdown_events",
        "shutdown_clients",
    }
    return "tables" if name in known_tables else "other"


def ordered_logs_digest(conn: sqlite3.Connection) -> dict[str, Any]:
    digest = hashlib.sha256()
    rows = 0
    start = time.perf_counter()
    query = """
        SELECT
            logs.event_order,
            logs.source_order,
            logs.timestamp_unix_ns,
            logs.timestamp_mach,
            processes.name,
            logs.pid,
            logs.tid,
            log_levels.name,
            event_types.name,
            subsystems.name,
            categories.name,
            logs.message,
            libraries.name,
            libraries.uuid,
            process_uuids.uuid,
            boots.boot_uuid,
            logs.activity_id,
            logs.parent_activity_id
        FROM logs
        LEFT JOIN processes ON processes.id = logs.process_id
        LEFT JOIN log_levels ON log_levels.id = logs.log_level_id
        LEFT JOIN event_types ON event_types.id = logs.event_type_id
        LEFT JOIN subsystems ON subsystems.id = logs.subsystem_id
        LEFT JOIN categories ON categories.id = logs.category_id
        LEFT JOIN libraries ON libraries.id = logs.library_id
        LEFT JOIN process_uuids ON process_uuids.id = logs.process_uuid_id
        LEFT JOIN boots ON boots.id = logs.boot_id
        ORDER BY logs.event_order, logs.source_order, logs.id
    """
    for row in conn.execute(query):
        digest.update(json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        digest.update(b"\n")
        rows += 1
        if rows % 5_000_000 == 0:
            log_line(f"Determinism digest: hashed {rows:,} ordered rows")
    return {
        "sha256": digest.hexdigest(),
        "rows": rows,
        "wall_seconds": time.perf_counter() - start,
    }


def iso8601_from_unix_ns_for_report(unix_ns: int | None) -> str | None:
    if unix_ns is None:
        return None
    seconds, nanos = divmod(int(unix_ns), 1_000_000_000)
    base = dt.datetime.fromtimestamp(seconds, tz=dt.timezone.utc)
    return f"{base:%Y-%m-%dT%H:%M:%S}.{nanos:09d}Z"


def cleanup_large_artifacts(result: BenchResult, *, keep_artifacts: bool) -> None:
    if keep_artifacts:
        result.extra["artifacts_kept"] = True
        return
    deleted: list[str] = []
    for path in artifact_paths_for_result(result):
        if path.exists():
            try:
                path.unlink()
            except OSError as exc:
                result.extra.setdefault("artifact_cleanup_errors", []).append(f"{path}: {exc}")
            else:
                deleted.append(str(path))
    result.extra["artifacts_removed"] = deleted
    if deleted:
        log_line(f"Removed large artifacts for {result.name}: {len(deleted)} file(s)")


def artifact_paths_for_result(result: BenchResult) -> list[Path]:
    paths: list[Path] = []
    for label, path in result.outputs.items():
        if label == "sqlite":
            paths.extend(sqlite_sidecars(path))
        elif label == "ndjson":
            paths.append(path)
    return unique_paths(paths)


def unique_paths(paths: list[Path]) -> list[Path]:
    seen: set[Path] = set()
    unique: list[Path] = []
    for path in paths:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append(path)
    return unique


def sqlite_sidecars(db_path: Path) -> tuple[Path, Path, Path]:
    return (db_path, db_path.with_name(db_path.name + "-wal"), db_path.with_name(db_path.name + "-shm"))


def sqlite_file_set_size(db_path: Path) -> int:
    return sum(path_size(path) for path in sqlite_sidecars(db_path))


def path_size(path: Path) -> int:
    return path.stat().st_size if path.exists() else 0


def collect_archive_stats(logarchive: Path) -> ArchiveStats:
    hash_logarchive = import_hash_logarchive()
    source_sha256, file_hashes = hash_logarchive(logarchive)

    total_files = 0
    total_size = 0
    tracev3_sizes: list[tuple[str, int]] = []
    tracev3_by_folder: collections.Counter[str] = collections.Counter()
    timesync_count = 0
    timesync_total_size = 0
    uuidtext_count = 0
    dsc_count = 0
    appledouble_file_count = 0
    tracev3_appledouble_count = 0

    for path in logarchive.rglob("*"):
        if not path.is_file():
            continue
        total_files += 1
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        total_size += size
        rel = path.relative_to(logarchive).as_posix()
        suffix = path.suffix.lower()
        name = path.name.lower()
        is_appledouble = path.name.startswith("._")
        if is_appledouble:
            appledouble_file_count += 1
        if suffix == ".tracev3":
            if is_appledouble:
                tracev3_appledouble_count += 1
                continue
            tracev3_sizes.append((rel, size))
            first_folder = rel.split("/", 1)[0] if "/" in rel else "."
            tracev3_by_folder[first_folder] += 1
        elif suffix == ".timesync" or name.endswith(".timesync"):
            timesync_count += 1
            timesync_total_size += size
        elif suffix == ".uuidtext" or ".uuidtext" in rel.lower():
            uuidtext_count += 1
        elif suffix == ".dsc" or path.name.startswith("dyld_shared_cache"):
            dsc_count += 1

    tracev3_only_sizes = [size for _rel, size in tracev3_sizes]
    return ArchiveStats(
        source_sha256=source_sha256,
        file_hash_count=len(file_hashes),
        total_files=total_files,
        total_size=total_size,
        appledouble_file_count=appledouble_file_count,
        tracev3_count=len(tracev3_sizes),
        tracev3_appledouble_count=tracev3_appledouble_count,
        tracev3_total_size=sum(tracev3_only_sizes),
        tracev3_by_folder=dict(sorted(tracev3_by_folder.items())),
        tracev3_size_buckets=tracev3_size_buckets(tracev3_only_sizes),
        timesync_count=timesync_count,
        timesync_total_size=timesync_total_size,
        uuidtext_count=uuidtext_count,
        dsc_count=dsc_count,
        largest_tracev3=sorted(tracev3_sizes, key=lambda item: item[1], reverse=True)[:10],
    )


def log_line(message: str) -> None:
    now = dt.datetime.now().isoformat(timespec="seconds")
    print(f"[{now}] {message}", flush=True)


def tracev3_size_buckets(sizes: list[int]) -> dict[str, int]:
    if not sizes:
        return {}
    mb = 1024 * 1024
    max_size = max(sizes)
    if max_size <= 16 * mb:
        thresholds = [64 * 1024, 256 * 1024, 1 * mb, 4 * mb, 16 * mb]
    elif max_size <= 256 * mb:
        thresholds = [256 * 1024, 1 * mb, 4 * mb, 16 * mb, 64 * mb, 256 * mb]
    else:
        thresholds = [1 * mb, 4 * mb, 16 * mb, 64 * mb, 256 * mb, 1024 * mb]

    labels = []
    previous = 0
    for threshold in thresholds:
        labels.append((previous, threshold, f"{format_bytes(previous)}-{format_bytes(threshold)}"))
        previous = threshold
    labels.append((previous, None, f">= {format_bytes(previous)}"))

    buckets = {label: 0 for _lower, _upper, label in labels}
    for size in sizes:
        for lower, upper, label in labels:
            if size >= lower and (upper is None or size < upper):
                buckets[label] += 1
                break
    return buckets


def collect_machine_specs(forensic_version: str, extract_import: str) -> dict[str, str]:
    specs: dict[str, str] = {
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python": sys.version.replace("\n", " "),
        "sqlite": sqlite3.sqlite_version,
        "forensic_aul": forensic_version,
        "extract_import": extract_import,
        "logical_cpu_count": str(os.cpu_count() or "unknown"),
        "log_tool": shutil.which("log") or "/usr/bin/log",
    }
    for key in (
        "kern.osproductversion",
        "kern.osversion",
        "machdep.cpu.brand_string",
        "hw.physicalcpu",
        "hw.logicalcpu",
        "hw.memsize",
    ):
        value = sysctl(key)
        if value is not None:
            specs[key] = value
    if "hw.memsize" in specs:
        try:
            specs["memory_gb"] = f"{int(specs['hw.memsize']) / (1024 ** 3):.2f}"
        except ValueError:
            pass
    return specs


def machine_fingerprint(machine: dict[str, str]) -> str:
    """Stable identity for comparing benchmark runs on the same machine/runtime."""
    keys = (
        "platform",
        "machine",
        "processor",
        "python",
        "sqlite",
        "forensic_aul",
        "extract_import",
        "logical_cpu_count",
        "kern.osproductversion",
        "kern.osversion",
        "machdep.cpu.brand_string",
        "hw.physicalcpu",
        "hw.logicalcpu",
        "hw.memsize",
    )
    payload = {key: machine.get(key, "") for key in keys}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def sysctl(name: str) -> str | None:
    try:
        completed = subprocess.run(
            ["/usr/sbin/sysctl", "-n", name],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def summarize_returned(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, dict):
        return value
    fields = {}
    for name in (
        "entry_count",
        "parse_errors",
        "source_type",
        "source_sha256",
        "device_model",
        "ios_build",
        "ios_version",
        "boot_uuid",
        "time_range",
    ):
        if hasattr(value, name):
            fields[name] = str(getattr(value, name))
    return fields or repr(value)


def result_for_json(result: BenchResult) -> dict[str, Any]:
    return {
        "key": result.key,
        "name": result.name,
        "status": result.status,
        "details": result.details,
        "wall_seconds": result.wall_seconds,
        "user_cpu_seconds": result.user_cpu_seconds,
        "system_cpu_seconds": result.system_cpu_seconds,
        "peak_rss_mb": result.peak_rss_mb,
        "avg_cpu_percent": result.avg_cpu_percent,
        "peak_cpu_percent": result.peak_cpu_percent,
        "row_count": result.row_count,
        "outputs": {key: str(path) for key, path in result.outputs.items()},
        "sizes": result.sizes,
        "error": result.error,
        "extra": result.extra,
    }


def bench_result_from_json(data: dict[str, Any]) -> BenchResult:
    return BenchResult(
        key=str(data.get("key", "")),
        name=str(data.get("name", "")),
        status=str(data.get("status", "unknown")),
        details=str(data.get("details", "")),
        wall_seconds=float(data.get("wall_seconds", 0.0)),
        user_cpu_seconds=float(data.get("user_cpu_seconds", 0.0)),
        system_cpu_seconds=float(data.get("system_cpu_seconds", 0.0)),
        peak_rss_mb=float(data.get("peak_rss_mb", 0.0)),
        avg_cpu_percent=float(data.get("avg_cpu_percent", 0.0)),
        peak_cpu_percent=float(data.get("peak_cpu_percent", 0.0)),
        minor_faults=int(data.get("minor_faults", 0)),
        major_faults=int(data.get("major_faults", 0)),
        block_input_ops=int(data.get("block_input_ops", 0)),
        block_output_ops=int(data.get("block_output_ops", 0)),
        outputs={str(k): Path(v) for k, v in dict(data.get("outputs", {})).items()},
        sizes={str(k): int(v) for k, v in dict(data.get("sizes", {})).items()},
        row_count=data.get("row_count"),
        extra=dict(data.get("extra", {})),
        error=data.get("error"),
    )


def archive_stats_for_json(stats: ArchiveStats) -> dict[str, Any]:
    return {
        "source_sha256": stats.source_sha256,
        "file_hash_count": stats.file_hash_count,
        "total_files": stats.total_files,
        "total_size": stats.total_size,
        "appledouble_file_count": stats.appledouble_file_count,
        "tracev3_count": stats.tracev3_count,
        "tracev3_appledouble_count": stats.tracev3_appledouble_count,
        "tracev3_total_size": stats.tracev3_total_size,
        "tracev3_by_folder": stats.tracev3_by_folder,
        "tracev3_size_buckets": stats.tracev3_size_buckets,
        "timesync_count": stats.timesync_count,
        "timesync_total_size": stats.timesync_total_size,
        "uuidtext_count": stats.uuidtext_count,
        "dsc_count": stats.dsc_count,
        "largest_tracev3": [[rel, size] for rel, size in stats.largest_tracev3],
    }


def archive_stats_from_json(data: dict[str, Any]) -> ArchiveStats:
    return ArchiveStats(
        source_sha256=str(data["source_sha256"]),
        file_hash_count=int(data.get("file_hash_count", 0)),
        total_files=int(data.get("total_files", 0)),
        total_size=int(data.get("total_size", 0)),
        appledouble_file_count=int(data.get("appledouble_file_count", 0)),
        tracev3_count=int(data.get("tracev3_count", 0)),
        tracev3_appledouble_count=int(data.get("tracev3_appledouble_count", 0)),
        tracev3_total_size=int(data.get("tracev3_total_size", 0)),
        tracev3_by_folder={str(k): int(v) for k, v in dict(data.get("tracev3_by_folder", {})).items()},
        tracev3_size_buckets={str(k): int(v) for k, v in dict(data.get("tracev3_size_buckets", {})).items()},
        timesync_count=int(data.get("timesync_count", 0)),
        timesync_total_size=int(data.get("timesync_total_size", 0)),
        uuidtext_count=int(data.get("uuidtext_count", 0)),
        dsc_count=int(data.get("dsc_count", 0)),
        largest_tracev3=[(str(item[0]), int(item[1])) for item in data.get("largest_tracev3", [])],
    )


def state_path_for_report(report_path: Path) -> Path:
    return report_path.with_suffix(".json")


def load_or_create_state(
    *,
    args: argparse.Namespace,
    logarchive: Path,
    archive_stats: ArchiveStats,
    machine: dict[str, str],
) -> dict[str, Any]:
    state_path: Path | None = None
    if args.append_report is not None:
        report_path = args.append_report.expanduser().resolve()
        state_path = state_path_for_report(report_path)
        if not state_path.exists():
            raise SystemExit(f"Missing benchmark state sidecar for report: {state_path}")
    elif not args.new_report:
        state_path = find_existing_state_for_hash_and_machine(
            archive_stats.source_sha256,
            machine_fingerprint(machine),
        )

    if state_path is not None:
        state = json.loads(state_path.read_text(encoding="utf-8"))
        stored_hash = state.get("archive_stats", {}).get("source_sha256")
        stored_fingerprint = state.get("machine_fingerprint") or machine_fingerprint(
            dict(state.get("machine", {}))
        )
        current_fingerprint = machine_fingerprint(machine)
        if stored_hash != archive_stats.source_sha256:
            raise SystemExit(
                "Existing report hash does not match input logarchive: "
                f"{stored_hash} != {archive_stats.source_sha256}"
            )
        if stored_fingerprint != current_fingerprint:
            raise SystemExit(
                "Existing report machine fingerprint does not match this computer/runtime: "
                f"{stored_fingerprint} != {current_fingerprint}. Use --new-report for a separate "
                "report on this machine."
            )
        log_line(f"Appending to existing benchmark state: {state_path}")
        state["logarchive_path"] = str(logarchive)
        state["archive_stats"] = archive_stats_for_json(archive_stats)
        state["machine"] = machine
        state["machine_fingerprint"] = current_fingerprint
        return state

    started_at = dt.datetime.now(dt.timezone.utc)
    timestamp = started_at.isoformat(timespec="seconds").replace("+00:00", "Z")
    safe_timestamp = timestamp.replace(":", "-")
    run_dir = RUNS_ROOT / f"{logarchive.stem}_{safe_timestamp}"
    run_dir.mkdir(parents=True, exist_ok=False)
    report_name = f"{safe_timestamp}_faul_benchmark.md"
    report_path = RESULTS_ROOT / report_name
    return {
        "schema_version": 2,
        "script_version": SCRIPT_VERSION,
        "created_utc": timestamp,
        "updated_utc": timestamp,
        "logarchive_path": str(logarchive),
        "run_dir": str(run_dir),
        "report_path": str(report_path),
        "machine": machine,
        "machine_fingerprint": machine_fingerprint(machine),
        "archive_stats": archive_stats_for_json(archive_stats),
        "results": [],
    }


def find_existing_state_for_hash_and_machine(source_sha256: str, fingerprint: str) -> Path | None:
    candidates: list[Path] = []
    search_roots = (RESULTS_ROOT, BENCHMARK_ROOT)
    for root in search_roots:
        if not root.exists():
            continue
        for path in sorted(root.glob("*_faul_benchmark.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            stored_fingerprint = data.get("machine_fingerprint") or machine_fingerprint(
                dict(data.get("machine", {}))
            )
            if (
                data.get("archive_stats", {}).get("source_sha256") == source_sha256
                and stored_fingerprint == fingerprint
            ):
                candidates.append(path)
    if not candidates:
        return None
    return max(candidates, key=lambda path: path.stat().st_mtime)


def write_benchmark_state(
    report_path: Path,
    logarchive: Path,
    run_dir: Path,
    machine: dict[str, str],
    archive_stats: ArchiveStats,
    results: list[BenchResult],
) -> None:
    state = {
        "schema_version": 2,
        "script_version": SCRIPT_VERSION,
        "updated_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "logarchive_path": str(logarchive),
        "run_dir": str(run_dir),
        "report_path": str(report_path),
        "machine": machine,
        "machine_fingerprint": machine_fingerprint(machine),
        "archive_stats": archive_stats_for_json(archive_stats),
        "results": [result_for_json(result) for result in results],
    }
    state_path_for_report(report_path).write_text(
        json.dumps(state, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def run_or_skip_method(
    *,
    results: list[BenchResult],
    key: str,
    report_path: Path,
    logarchive: Path,
    run_dir: Path,
    machine: dict[str, str],
    archive_stats: ArchiveStats,
    rerun_existing: bool,
    run: Callable[[], BenchResult],
    finish: Callable[[BenchResult], None],
) -> None:
    existing_index = next((i for i, result in enumerate(results) if result.key == key), None)
    if existing_index is not None and results[existing_index].status == "ok" and not rerun_existing:
        log_line(f"Skipping already completed method: {results[existing_index].name}")
        return

    if existing_index is not None:
        log_line(f"Replacing existing method result: {results[existing_index].name}")

    result = run()
    finish(result)
    if existing_index is None:
        results.append(result)
    else:
        results[existing_index] = result
    write_benchmark_report(report_path, logarchive, run_dir, machine, archive_stats, results)


def write_benchmark_report(
    report_path: Path,
    logarchive: Path,
    run_dir: Path,
    machine: dict[str, str],
    archive_stats: ArchiveStats,
    results: list[BenchResult],
) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_text = render_report(
        logarchive=logarchive,
        run_dir=run_dir,
        machine=machine,
        archive_stats=archive_stats,
        results=results,
    )
    report_path.write_text(report_text, encoding="utf-8")
    (run_dir / report_path.name).write_text(report_text, encoding="utf-8")
    log_line(f"Report updated: {report_path}")
    write_benchmark_state(report_path, logarchive, run_dir, machine, archive_stats, results)


def render_report(
    *,
    logarchive: Path,
    run_dir: Path,
    machine: dict[str, str],
    archive_stats: ArchiveStats,
    results: list[BenchResult],
) -> str:
    lines: list[str] = []
    lines.append("# forensic_aul Extraction Benchmark")
    lines.append("")
    lines.append(f"- Benchmark script version: `{SCRIPT_VERSION}`")
    lines.append(f"- Logarchive: `{logarchive}`")
    lines.append(f"- Run directory: `{run_dir}`")
    lines.append(f"- Generated UTC: `{machine.get('timestamp_utc', '')}`")
    lines.append(f"- Machine fingerprint: `{machine_fingerprint(machine)}`")
    lines.append("")
    lines.append("## Logarchive Stats")
    lines.append("")
    lines.append(f"- Archive SHA-256: `{archive_stats.source_sha256}`")
    lines.append(f"- Hashed files: `{format_count(archive_stats.file_hash_count)}`")
    lines.append(f"- Total files: `{format_count(archive_stats.total_files)}`")
    lines.append(f"- Total archive file size: `{format_bytes(archive_stats.total_size)}`")
    lines.append(f"- AppleDouble sidecar files: `{format_count(archive_stats.appledouble_file_count)}`")
    lines.append(f"- Tracev3 files: `{format_count(archive_stats.tracev3_count)}`")
    lines.append(
        f"- AppleDouble tracev3 sidecars skipped from tracev3 stats: "
        f"`{format_count(archive_stats.tracev3_appledouble_count)}`"
    )
    lines.append(f"- Tracev3 total size: `{format_bytes(archive_stats.tracev3_total_size)}`")
    lines.append(f"- Timesync files: `{format_count(archive_stats.timesync_count)}`")
    lines.append(f"- Timesync total size: `{format_bytes(archive_stats.timesync_total_size)}`")
    lines.append(f"- UUIDText files: `{format_count(archive_stats.uuidtext_count)}`")
    lines.append(f"- DSC/cache files: `{format_count(archive_stats.dsc_count)}`")
    lines.append("")
    lines.append("### Tracev3 By Top-Level Folder")
    lines.append("")
    lines.append("| Folder | Count |")
    lines.append("|---|---:|")
    for folder, count in archive_stats.tracev3_by_folder.items():
        lines.append(f"| `{folder}` | {format_count(count)} |")
    lines.append("")
    lines.append("### Tracev3 Size Distribution")
    lines.append("")
    lines.append("| Size interval | Count |")
    lines.append("|---|---:|")
    for label, count in archive_stats.tracev3_size_buckets.items():
        lines.append(f"| {label} | {format_count(count)} |")
    lines.append("")
    lines.append("### Largest Tracev3 Files")
    lines.append("")
    lines.append("| File | Size |")
    lines.append("|---|---:|")
    for rel, size in archive_stats.largest_tracev3:
        lines.append(f"| `{rel}` | {format_bytes(size)} |")
    lines.append("")
    lines.append("## Machine Specs")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    for key in sorted(machine):
        lines.append(f"| {key} | `{machine[key]}` |")
    lines.append("")
    lines.append("## Benchmark Summary")
    lines.append("")
    if results:
        lines.append(
            "| Method | Status | Rows | Wall time | CPU time | Peak RSS | Avg CPU | Peak CPU | Output sizes |"
        )
        lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---|")
        for result in results:
            cpu = result.user_cpu_seconds + result.system_cpu_seconds
            lines.append(
                "| {name} | {status} | {rows} | {wall} | {cpu} | {rss} | {avg_cpu} | {peak_cpu} | {sizes} |".format(
                    name=result.name,
                    status=result.status,
                    rows=format_count(result.row_count),
                    wall=format_seconds(result.wall_seconds),
                    cpu=format_seconds(cpu),
                    rss=f"{result.peak_rss_mb:.1f} MB",
                    avg_cpu=f"{result.avg_cpu_percent:.1f}%",
                    peak_cpu=f"{result.peak_cpu_percent:.1f}%",
                    sizes=format_sizes(result.sizes),
                )
            )
    else:
        lines.append("_No benchmark method has completed yet. This report is updated after each method finishes._")
    lines.append("")
    lines.append("## Resource Detail")
    lines.append("")
    if results:
        lines.append(
            "| Method | User CPU | System CPU | Minor faults | Major faults | Block reads | Block writes | Serial tail | Peak WAL | Min free disk |"
        )
        lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
        for result in results:
            phase_metrics = result.extra.get("phase_metrics") or {}
            lines.append(
                "| {name} | {user} | {system} | {minor} | {major} | {reads} | {writes} | {tail} | {wal} | {free} |".format(
                    name=result.name,
                    user=format_seconds(result.user_cpu_seconds),
                    system=format_seconds(result.system_cpu_seconds),
                    minor=format_count(result.minor_faults),
                    major=format_count(result.major_faults),
                    reads=format_count(result.block_input_ops),
                    writes=format_count(result.block_output_ops),
                    tail=format_seconds(float(phase_metrics.get("serial_tail_seconds", 0.0)))
                    if phase_metrics
                    else "",
                    wal=format_optional_bytes(phase_metrics.get("peak_wal_bytes")) if phase_metrics else "",
                    free=format_optional_bytes(phase_metrics.get("min_free_bytes")) if phase_metrics else "",
                )
            )
    else:
        lines.append("_Pending._")
    lines.append("")
    phase_results = [result for result in results if result.extra.get("phase_metrics")]
    lines.append("## Phase Detail")
    lines.append("")
    if phase_results:
        lines.append(
            "| Method | Phase | Wall time | Avg CPU | Peak CPU | Peak RSS | Peak worker RSS | Peak WAL | Min free disk | IO read | IO written |"
        )
        lines.append("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
        for result in phase_results:
            phases = (result.extra.get("phase_metrics") or {}).get("phases", {})
            for phase in ("prepare", "parse", "ordering", "index", "fts", "integrity"):
                values = phases.get(phase)
                if not values:
                    continue
                io_delta = values.get("io_delta") or {}
                lines.append(
                    "| {name} | {phase} | {wall} | {avg_cpu} | {peak_cpu} | {rss} | {worker} | {wal} | {free} | {read} | {written} |".format(
                        name=result.name,
                        phase=phase,
                        wall=format_seconds(float(values.get("wall_seconds", 0.0))),
                        avg_cpu=f"{float(values.get('avg_cpu_percent', 0.0)):.1f}%",
                        peak_cpu=f"{float(values.get('peak_cpu_percent', 0.0)):.1f}%",
                        rss=f"{float(values.get('peak_rss_mb', 0.0)):.1f} MB",
                        worker=f"{float(values.get('peak_worker_rss_mb', 0.0)):.1f} MB",
                        wal=format_optional_bytes(values.get("peak_wal_bytes")),
                        free=format_optional_bytes(values.get("min_free_bytes")),
                        read=format_optional_bytes(io_delta.get("read_bytes")),
                        written=format_optional_bytes(io_delta.get("write_bytes")),
                    )
                )
    else:
        lines.append("_Pending._")
    lines.append("")
    scaling_rows = fast_safe_scaling_rows(results)
    lines.append("## Parse Scaling")
    lines.append("")
    if scaling_rows:
        lines.append("| Jobs | Parse wall time | Rows | Rows/s | Rows/s/core | Speedup vs jobs=1 |")
        lines.append("|---:|---:|---:|---:|---:|---:|")
        for row in scaling_rows:
            lines.append(
                "| {jobs} | {parse_wall} | {rows} | {rows_per_sec} | {rows_per_core} | {speedup} |".format(
                    jobs=row["jobs"],
                    parse_wall=format_seconds(row["parse_wall_seconds"]),
                    rows=format_count(row["rows"]),
                    rows_per_sec=f"{row['rows_per_second']:.1f}",
                    rows_per_core=f"{row['rows_per_second_per_core']:.1f}",
                    speedup=f"{row['speedup']:.2f}x" if row["speedup"] else "",
                )
            )
    else:
        lines.append("_Pending until fast-safe jobs produce parse phase metrics._")
    lines.append("")
    lines.append("## Method Configurations")
    lines.append("")
    for result in results:
        lines.append(f"### {result.name}")
        lines.append("")
        lines.append(f"- Status: `{result.status}`")
        lines.append(f"- Configuration: `{result.details}`")
        for label, path in result.outputs.items():
            lines.append(f"- {label}: `{path}`")
        db_stats = result.extra.get("db_stats")
        if db_stats:
            lines.append("- Database stats:")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(db_stats, indent=2, sort_keys=True))
            lines.append("```")
        removed = result.extra.get("artifacts_removed")
        if removed:
            lines.append(f"- Large artifacts removed: `{len(removed)}` file(s)")
        if result.extra.get("artifacts_kept"):
            lines.append("- Large artifacts kept: `true`")
        if result.error:
            lines.append(f"- Error: `{result.error}`")
        returned = result.extra.get("returned")
        if returned:
            lines.append("- Extract result:")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(returned, indent=2, sort_keys=True))
            lines.append("```")
        if result.name == "custom logshow ndjson to sqlite":
            lines.append("- Phase breakdown:")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(result.extra, indent=2, sort_keys=True))
            lines.append("```")
        lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append(
        "- The requested `forensic_aul.ops.extract` import is attempted first. "
        "This checkout currently exposes extraction at "
        "`forensic_aul.ops.extraction.extract`, so the benchmark falls back to that path if needed."
    )
    lines.append(
        "- `fast_write=True` is intentionally not used. The fast-safe method keeps SQLite "
        "`synchronous=NORMAL`, enables deferred FTS rebuild, and uses all logical CPUs."
    )
    lines.append(
        "- SQLite sizes include `-wal` and `-shm` sidecars when present. The custom pipeline "
        "reports both the raw NDJSON size and the SQLite file-set size."
    )
    lines.append(
        "- Generated SQLite/NDJSON artifacts are deleted by default after row counts, lookup counts, "
        "time bounds, grouped counts, and byte sizes are recorded. Use `--keep-artifacts` to retain them."
    )
    lines.append(
        "- The custom SQLite pipeline follows iLEAPP's `logarchive` artifact field selection: "
        "UTC timestamp, row number, process image path, process ID, subsystem, category, event message, "
        "and trace ID. This benchmark adapts that mapping from Apple's NDJSON stream."
    )
    lines.append(
        "- Before NDJSON-to-SQLite starts, the script checks free disk space on the SQLite output "
        "volume using `NDJSON size * --sqlite-space-multiplier + --sqlite-space-reserve-gb`."
    )
    lines.append(
        "- Resumable state is stored in the JSON sidecar with the same basename as this report. "
        "The script matches that state by the logarchive SHA-256 plus a machine/runtime "
        "fingerprint, and skips completed method keys unless `--rerun-existing` is used."
    )
    lines.append("")
    return "\n".join(lines)


def format_seconds(value: float) -> str:
    return f"{value:.3f}s"


def format_count(value: int | None) -> str:
    if value is None:
        return ""
    return f"{value:,}"


def format_sizes(sizes: dict[str, int]) -> str:
    if not sizes:
        return ""
    return "<br>".join(f"{name}: {format_bytes(size)}" for name, size in sizes.items())


def format_optional_bytes(value: Any) -> str:
    if value is None or value == "":
        return ""
    try:
        return format_bytes(int(value))
    except (TypeError, ValueError):
        return ""


def fast_safe_scaling_rows(results: list[BenchResult]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for result in results:
        if not result.key.startswith("fast_safe_jobs_") or result.status != "ok":
            continue
        try:
            jobs = int(result.key.rsplit("_", 1)[-1])
        except ValueError:
            continue
        parse = ((result.extra.get("phase_metrics") or {}).get("phases") or {}).get("parse")
        if not parse or not result.row_count:
            continue
        parse_wall = float(parse.get("wall_seconds", 0.0))
        if parse_wall <= 0:
            continue
        rows_per_second = int(result.row_count) / parse_wall
        rows.append(
            {
                "jobs": jobs,
                "parse_wall_seconds": parse_wall,
                "rows": int(result.row_count),
                "rows_per_second": rows_per_second,
                "rows_per_second_per_core": rows_per_second / jobs,
                "speedup": 0.0,
            }
        )
    rows.sort(key=lambda item: item["jobs"])
    baseline = next((row for row in rows if row["jobs"] == 1), rows[0] if rows else None)
    if baseline:
        baseline_wall = baseline["parse_wall_seconds"]
        for row in rows:
            row["speedup"] = baseline_wall / row["parse_wall_seconds"] if row["parse_wall_seconds"] else 0.0
    return rows


def format_bytes(size: int) -> str:
    units = ("B", "KB", "MB", "GB", "TB")
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{size} B"


if __name__ == "__main__":
    raise SystemExit(main())
