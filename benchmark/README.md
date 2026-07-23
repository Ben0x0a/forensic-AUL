# forensic_aul Benchmark

Benchmark driver for comparing `forensic_aul` extraction paths. On macOS it can
also compare the Apple `log show --style ndjson` workflow. On Windows/Linux the
extract and CLI benchmarks still run and the `log show` pipeline is skipped.

```bash
.venv/bin/python benchmark/aul_extract_benchmark.py /path/to/case.logarchive
```

For the current CP validation suite:

```bash
.venv/bin/python benchmark/aul_extract_benchmark.py \
  --new-report \
  --suite-v020 \
  /path/to/case.logarchive
```

## Shipped Files

- `aul_extract_benchmark.py`: benchmark runner.
- `README.md`: preserved benchmark summary and operating notes.

Generated output is intentionally ignored by git:

- `results/`: local Markdown reports and JSON sidecar state files kept for
  documentation and future append/resume usage.
- `runs/`: transient per-run working directories recreated as needed.

Large DB/NDJSON artifacts are deleted by default after stats are captured.

## Local Results

Report filenames use this short convention:

```text
YYYY-MM-DDTHH-MM-SSZ_faul_benchmark.md
YYYY-MM-DDTHH-MM-SSZ_faul_benchmark.json
```

Current local reports:

- `results/2026-06-05T17-25-42Z_faul_benchmark.md`
- `results/2026-06-06T13-46-27Z_faul_benchmark.md`
- `results/2026-06-06T21-00-55Z_faul_benchmark.md`

## Preserved Summary

Input:
`~/samples/aul-benchmark-input.logarchive`

Machine:
Apple M2 Pro, 10 logical CPUs, 32 GB RAM, Python 3.12.2, SQLite 3.45.1.

Archive:
2.09 GB total, 1,104 real `.tracev3` files, 1.45 GB tracev3 payload, 2
timesync files, SHA-256
`12a9f9bf6b93d08aa995d23173efe8f2da6a900bbee0a5460fd88ef8ecd50069`.

## Summary

| Method | Wall time | Rows | Final size | Peak RSS | Peak WAL |
|---|---:|---:|---:|---:|---:|
| default extract | 5283.372s | 47,092,843 | 14.72 GB | 9605.5 MB | 1.23 GB |
| fast-safe jobs=1 | 2988.518s | 47,092,843 | 14.37 GB | 9761.2 MB | 1.97 GB |
| fast-safe jobs=6 | 1543.602s | 47,092,843 | 14.37 GB | 14201.6 MB | 1.97 GB |
| fast-safe jobs=10 | 1607.911s | 47,092,843 | 14.38 GB | 15035.1 MB | 1.97 GB |
| `log show` NDJSON to SQLite | 1308.227s | 47,037,746 | 44.75 GB NDJSON + 12.19 GB SQLite | 2422.0 MB | n/a |

Correctness invariants passed for all `forensic_aul` extract runs:

- `logs_with_null_event_order = 0`
- `logs_with_null_source_order = 0`
- `integrity_changed_files = 0`
- ordered digest identical across default, jobs=1, jobs=6, jobs=10:
  `1fcaaf92eb15ad273dd40927defa065270d63702a741fda9c865c5b7f9c44dbf`

## Improvements

The current fast-safe path is a clear improvement over the previous successful
8-job measurement from `2026-06-06T13-46-27Z`:

| Run | Wall time | Rows | SQLite size |
|---|---:|---:|---:|
| previous fast-safe jobs=8 | 3525.796s | 47,092,843 | 37.15 GB |
| new fast-safe jobs=6 | 1543.602s | 47,092,843 | 14.37 GB |
| new fast-safe jobs=10 | 1607.911s | 47,092,843 | 14.38 GB |

Observed improvement:

- Time: jobs=6 is about 2.28x faster than the previous jobs=8 run.
- Size: final SQLite is about 61% smaller than the previous 37.15 GB DB.
- Determinism: output digest is identical across serial and parallel extract
  runs.
- Custom pipeline: the iLEAPP-style SQLite load now finishes instead of failing
  with disk-full; it produced a 12.19 GB SQLite DB from a 44.75 GB NDJSON file.

## Expected Performance

Use `--fast-jobs 6` as the practical default on this 10-core M2 Pro:

- It was fastest overall in this run.
- Parse scaled from jobs=1 to jobs=6, then plateaued at jobs=10.
- jobs=10 used more memory and CPU without improving wall time.

Parse scaling:

| Jobs | Parse wall time | Rows/s | Rows/s/core | Speedup vs jobs=1 |
|---:|---:|---:|---:|---:|
| 1 | 2014.803s | 23,373.4 | 23,373.4 | 1.00x |
| 6 | 628.869s | 74,884.9 | 12,480.8 | 3.20x |
| 10 | 648.268s | 72,644.1 | 7,264.4 | 3.11x |

Serial tail remains material:

| Method | Ordering | Index | FTS | Integrity | Serial tail |
|---|---:|---:|---:|---:|---:|
| fast-safe jobs=1 | 437.829s | 195.859s | 321.622s | 7.363s | 962.672s |
| fast-safe jobs=6 | 437.172s | 149.423s | 309.302s | 7.378s | 903.276s |
| fast-safe jobs=10 | 451.223s | 172.908s | 317.138s | 7.342s | 948.611s |

Interpretation:

- CP1 size reduction is confirmed by the 14.37 GB final DB.
- CP2 crash avoidance is improved: ordering WAL peak stayed under 500 MB for
  fast-safe runs, but total peak WAL reached 1.97 GB during FTS.
- More parser jobs are not currently the next useful lever after 6 jobs.
- Further work should focus on the serial tail, especially ordering/index/FTS,
  before adding sharding complexity.

## Run Commands

Recommended safe extract benchmark on this machine:

```bash
.venv/bin/python benchmark/aul_extract_benchmark.py \
  --new-report \
  --skip-default \
  --skip-custom \
  --fast-jobs 6 \
  /path/to/case.logarchive
```

CLI wrapper benchmark, useful when comparing CLI behavior against GUI behavior:

```bash
.venv/bin/python benchmark/aul_extract_benchmark.py \
  --new-report \
  --skip-default \
  --skip-custom \
  --fast-jobs "" \
  --include-cli \
  --cli-jobs 6 \
  /path/to/case.logarchive
```

Full v0.2.0 validation suite:

```bash
.venv/bin/python benchmark/aul_extract_benchmark.py \
  --new-report \
  --suite-v020 \
  /path/to/case.logarchive
```

Add a new job count to an existing report without rerunning completed methods:

```bash
.venv/bin/python benchmark/aul_extract_benchmark.py \
  --append-report benchmark/results/2026-..._faul_benchmark.md \
  --skip-default \
  --skip-custom \
  --fast-jobs 8 \
  /path/to/case.logarchive
```

## Notes

- `fast_write=True` is intentionally not part of the headline benchmark because
  it uses `synchronous=OFF`.
- The CLI benchmark is opt-in with `--include-cli`. It runs
  `python -m launcher.cli extract` as a subprocess with safe writes, deferred
  FTS, batch size 10000, and the requested `--cli-jobs` count. Its timing
  includes CLI/session/logging overhead and the sealed operational log.
- Generated DB/NDJSON artifacts are deleted by default. Use `--keep-artifacts`
  only for manual inspection.
- Disk IO byte deltas were unavailable in the latest run because `psutil` is not
  installed in the benchmark venv.
- SQLite table/index/FTS byte breakdown was unavailable because this SQLite build
  does not expose the `dbstat` virtual table.
