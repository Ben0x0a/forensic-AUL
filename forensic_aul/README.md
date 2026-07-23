# `forensic_aul` — library API

`forensic_aul` is the **installable core library** of the forensic_AUL project: it
parses Apple Unified Logs (iOS/macOS) into a normalised, queryable SQLite database
and provides the downstream analysis steps (annotation, diff, export). The CLI in
`launcher/` and the GUI in `gui/` are thin layers built on top of this package; you
can import it directly into your own application instead.

- **Importing is side-effect-free.** No logging is configured, no files are
  touched, and nothing is printed at import time. Configure your own
  `logging` handlers to see the library's diagnostics (it logs via
  `logging.getLogger("forensic_aul.…")`).
- **Runtime deps:** `lz4`, `PyYAML`. **Python:** 3.11–3.14 (tested on all four).

```bash
uv pip install -e .                 # core library only
uv pip install -e ".[acquire]"      # + USB device acquisition (pymobiledevice3)
```

```python
import forensic_aul
forensic_aul.__version__     # e.g. "0.1.0"
```

---

## What is exposed

Everything in the table below is re-exported at the top level
(`from forensic_aul import …`) and listed in `forensic_aul.__all__`. These are the
**only** names you should depend on; everything else under `forensic_aul.*` is an
internal implementation detail and may change.

| Name | Kind | Signature → returns | Does |
|---|---|---|---|
| `run_extract` | func | `(logarchive: Path \| Mapping[str, Path] \| PreparedSource, db_path: Path, *, case_number=None, imei=None, exhibit_number=None, analyst_name=None, notes=None, batch_size=10000, work_dir=None, fast_fts=False, fast_write=False, fts=True, keep_raw=False, jobs=1, overwrite=False, integrity="full", progress=None)` → `ExtractResult` | Full pipeline: source → SQLite. `logarchive` is either a single path — a `.logarchive` dir, a sysdiagnose `.tar.gz`, or an FFS `.zip` (auto-detected by magic bytes, not extension) — **or** a mapping of two already-uncompressed folders `{"diagnostics": dir, "uuidtext": dir}` (see `find_loose_dirs`). **Refuses to write into an existing `db_path` unless `overwrite=True`** (raises `FileExistsError`). **`jobs > 1` uses spawn-based multiprocessing — the calling entry point must be import-safe** (an `if __name__ == "__main__":` guard, or code that only runs inside functions); an import-unsafe caller typically produces an *empty* database, which the run now flags with an ERROR. `integrity` selects the source-hashing mode (`"full"` / `"fingerprint"` / `"off"` — see `INTEGRITY_MODES`). Performance/output toggles: `fts` builds the FTS5 full-text index (**on by default; it is the single largest cost/size addition — programmatic consumers that filter on structured columns should pass `fts=False`**), `fast_fts` defers its rebuild to the end, `fast_write` sets `synchronous=OFF` (faster, less crash-durable), `keep_raw` stores the raw firehose item data as JSON for traceability (off by default to save space). Accepts an already-built `PreparedSource` to skip re-preparation (see `prepare_source`). Returns an `ExtractResult`. |
| `open_or_extract` | func | `(logarchive, db_path: Path, **run_extract_kwargs)` → `Path` | "Parse once, reuse": returns `db_path` immediately when it already exists, otherwise runs `run_extract` and returns the produced path. |
| `query_logs` | func | `(database: Path, *, process=None, subsystem=None, level=None, message_prefix=None, message_contains=None, format_str=None, grep=None, time_from=None, time_to=None, last=None, signature=None, action=None, tag=None, annotated_only=False, limit=None)` → `Iterator[LogRow]` | **The stable in-memory read API** — the same filter vocabulary as `run_export`, but yielding `LogRow` objects instead of writing a file, so consumers never touch the internal schema. List filters accept a single string or a list. `message_prefix` / `message_contains` match the composed message *literally* (`%`/`_` escaped — prefix vs anywhere); `grep` is a raw SQL LIKE; `format_str` matches the invariant template exactly. Raises `FileNotFoundError` / `ValueError`. See *Reading rows back* below. |
| `count_logs` | func | `(database: Path, filters: LogFilters \| None = None)` → `int` | Total logs matching *filters* — the paging counterpart of `fetch_logs` (call once per filter change, then page). |
| `fetch_logs` | func | `(database: Path, filters: LogFilters \| None = None, *, offset=0, limit=500)` → `list[LogRow]` | One exact page of logs (offset/limit count LOGS, not annotation-joined rows), ordered (timestamp_unix_ns, id). Built for table UIs scrolling large databases; for one-shot streamed reads prefer `query_logs`. |
| `fetch_context` | func | `(database: Path, log_id: int, *, before=20, after=20)` → `list[LogRow]` | The rows surrounding a log on the **forensic timeline** (`event_order`, never wall-clock — a shifted clock cannot reorder the context). Anchor included (`row.log_id == log_id`). |
| `LogRow` | class | fields `timestamp_iso, timestamp_unix_ns, event_order, process, pid, tid, log_level, event_type, subsystem, category, message, format_string, signature_ids`; methods `values_dict()`, `value_for(label)` | One log entry with its annotations/extracted values rolled up — what `query_logs` yields. |
| `LogFilters` | dataclass | fields: `time_from, time_to, last, process, subsystem, level, grep, message_prefix, message_contains, format_str, signature, action, tag, annotated_only` | The shared filter vocabulary (`ExportFilters` extends it with `fmt` / `include_fields`). |
| `run_diff` | func | `(baseline_db: Path, action_db: Path, csv_out: Path \| None, sqlite_out: Path)` → `DiffResult` | Attributes log lines to a user action by diffing a post-action DB against a baseline. Writes a SQLite DB (all post-cutoff rows with an `excluded` flag, a `matched_signatures` column when the action DB carries KB annotations, plus a reversible `hidden_keys` prune layer + `v_identified_visible` view) and, unless `csv_out=None`, a CSV of the retained lines. Returns a `DiffResult`. |
| `run_identify_workflow` | func | `(case_number: str \| None = None, *, output_dir=Path("."), udid=None, still_seconds=60, exhibit=None, analyst=None, notes=None, batch_size=1000, jobs=1, fts=False, integrity="off", kb=None, write_csv=True, confirm=None, wait_still=None, wait_for_action=None, status=None, progress=None)` → `IdentifyResult` | The full interactive action-attribution workflow: connect, optionally pause for `still_seconds` (`wait_still`) so the baseline window (starting *before* the pause) absorbs idle/connection noise, acquire a baseline, call `wait_for_action()` while the operator performs the action, acquire again, extract both, optionally annotate the action DB against `kb`, diff. A research-tool default (`integrity="off"`) skips the hashing/acquisition-report chain-of-custody step for speed; pass `"full"`/`"fingerprint"` to keep it. All interaction is injected via callbacks so any front-end (CLI, GUI, tests) can drive it; `progress` receives weighted overall-progress events across the whole run. `case_number` falsy → artefacts prefixed `identify-<UTC timestamp>`. Raises `ImportError` / `ValueError` / `AcquisitionAborted` / `AcquisitionError`. |
| `IdentifyResults` | class | `IdentifyResults(database: Path \| str)` — context manager; `.counts() -> ResultCounts`, `.rows(*, include_noise=False, include_kb_known=False, include_hidden=False, search=None, limit=None, offset=0) -> list[sqlite3.Row]`, `.hide(message, process)`, `.unhide(message, process)`, `.hidden_keys() -> list[tuple[str, str]]`, `.export_csv(path, *, include_noise=False, include_kb_known=True) -> int` | Read/annotate access to a diff database produced by `run_diff` — browse, search, and reversibly hide `(message, process)` pairs after the fact. Upgrades an older diff DB (no `hidden_keys`/`v_identified_visible`) on open. Raises `FileNotFoundError` / `InvalidDatabaseError`. |
| `run_export` | func | `(database: Path, output: Path, filters: ExportFilters \| None = None)` → `ExportResult` | Filtered export of an analysis DB to CSV / JSON / JSONL (format inferred from the suffix or `filters.fmt`). Knowledge-base aware. Returns an `ExportResult`. Raises `FileNotFoundError` / `ValueError` on bad input. |
| `acquire` | func | `(case_number: str, *, output_dir=Path("."), udid=None, start_time=None, size_limit=None, age_limit=None, exhibit=None, analyst=None, notes=None, extract=False, db_path=None, batch_size=1000, confirm=None)` → `AcquireResult` | **Collect a `.logarchive` from a USB-connected iOS device** (needs the optional `pymobiledevice3` — `pip install "forensic-aul[acquire]"`). Hashes it, writes a `.acquisition.json` report, optionally runs `run_extract`. `confirm(device)->bool` is an optional pre-collection hook (the library does no I/O itself). Raises `ImportError` (dep missing), `AcquisitionAborted`, `AcquisitionError`. |
| `ForensicAULError` | exception | — | **Base class of every purposeful library error** (`SourceError`, `InvalidDatabaseError`, `AcquisitionError`, `KnowledgeBaseError`, …). Catch it to handle "the library rejected the input / could not do the work" uniformly; genuine bugs still propagate. |
| `SourceError` | exception | subclasses `ForensicAULError, ValueError` | An evidence source could not be detected / validated / prepared (`detect_source_type` / `prepare_source`). Existing `except ValueError` handlers keep working. |
| `InvalidDatabaseError` | exception | subclasses `ForensicAULError, ValueError` | The given path is not an analysis database (not SQLite, or no `logs` table). Raised by the path-based readers: `query_logs`, `run_export`, `summarise`, `annotate_database`, `verify_database`. |
| `AcquisitionError` / `AcquisitionAborted` | exceptions | subclass `ForensicAULError` | Raised by `acquire` / `run_identify_workflow`: a failure, or the `confirm` hook declining. |
| `DeviceInfo` | dataclass | device metadata (`udid`, `imei`, `serial_number`, SIMs, …) | The connected-device record; passed to the `confirm` hook and on `AcquireResult.device`. |
| `ExportFilters` | dataclass | `LogFilters` fields + `fmt, include_fields` | Declarative filter/option set for `run_export` (decoupled from any CLI). |
| `load_kb` | func | `(root: Path \| str)` → `KnowledgeBase` | Load + validate the YAML knowledge base (the signature definitions). Raises `KnowledgeBaseError` on invalid content. |
| `annotate_database` | func | `(db: Path \| str, kb: KnowledgeBase, *, only_ids=None, only_tags=None)` → `AnnotateResult` | Open the analysis DB at `db`, match every selected signature against `logs`, write `kb_signatures` / `log_annotations`, commit and close. Use this to (re-)annotate **at will** without re-extracting. Returns an `AnnotateResult` (`.counts` is the `signature_id → match_count` mapping). Raises `FileNotFoundError`. |
| `annotate_connection` | func | `(conn: sqlite3.Connection, kb: KnowledgeBase, *, only_ids=None, only_tags=None)` → `AnnotateResult` | Same as `annotate_database` but on a caller-owned connection (for in-memory DBs / caller-managed transactions); `result.db_path` is `None`. |
| `KnowledgeBaseError` | exception | subclasses `ForensicAULError, ValueError` | Raised by `load_kb` for malformed/invalid knowledge bases. |
| `prepare_source` | func | `(source: Path \| Mapping[str, Path], *, work_dir: Path \| None = None, integrity="full")` → `PreparedSource` | Normalise any supported acquisition to a logarchive layout, capturing the content SHA-256, an archive fingerprint, and the iOS version when available. A single path is auto-detected (logarchive / sysdiagnose / FFS); a mapping `{"diagnostics": dir, "uuidtext": dir}` merges the two loose folders (hard-linked, zero-copy) into one logarchive root. `integrity` (see `INTEGRITY_MODES`) can skip the hashing for triage speed. **Pass the result straight to `run_extract`** — it is used as-is (no re-hash, full provenance kept). |
| `find_loose_dirs` | func | `(fs_root: Path)` → `dict[str, Path] \| None` | Locate `private/var/db/diagnostics` + `uuidtext` under an extracted full file system (at the root or one folder down, e.g. `filesystem1/`) and return the mapping `prepare_source` / `run_extract` accept — or `None` when not found. |
| `INTEGRITY_MODES` | const | `("full", "fingerprint", "off")` | The source-hashing modes: `full` = per-file SHA-256 chain-of-custody attestation (default); `fingerprint` = only the cheap head+size+tail archive fingerprint; `off` = no hashing. Non-full modes record NULL hashes and skip the end-of-run re-verification — triage only. |
| `PreparedSource` | dataclass | fields incl. `source_type, original_path, logarchive_root, content_sha256, file_hashes, archive_fingerprint, ios_product_version`; methods `verify_unchanged()`, `cleanup()` | The result of `prepare_source` (a temporary extraction is auto-cleaned via `cleanup()`). |
| `SourceType` | enum | `LOGARCHIVE`, `SYSDIAGNOSE`, `FILESYSTEM`, `LOOSE_DIRS` | Discriminates the acquisition type (`LOOSE_DIRS` = the two-folder mapping). |
| `compute_sha256` | func | `(path: Path \| str)` → `str` | SHA-256 of a single file (chain of custody). |
| `hash_logarchive` | func | `(logarchive: Path \| str)` → `tuple[str, dict[str, str]]` | `(content_digest, {relative_path: sha256})` over a logarchive tree (sorted walk). |
| `LogEntry` | dataclass | the canonical log-row model | Useful for type hints and post-processing of parsed rows. |
| `ProgressSink` / `ProgressEvent` | type / dataclass | `ProgressSink = Callable[[ProgressEvent], None]`; `ProgressEvent(overall, phase, phase_fraction, detail)` | The progress protocol for `run_extract(progress=…)`: build/type your own sink, or use a ready-made one below. |
| `tty_bar_sink` | func | `(stream=None, width=30)` → `ProgressSink \| None` | Live one-line terminal bar (returns `None` off a TTY, so it never corrupts piped output). |
| `logging_progress_sink` | func | `(logger, every_percent=5)` → `ProgressSink` | Emits an INFO log line each time overall progress crosses N %. |
| `callback_progress_sink` | func | `(fn: Callable[[str], None], every_percent=10)` → `ProgressSink` | Hands formatted `"progress NN%  phase  detail"` lines to a plain callable — for hosts with their own log function (e.g. a plugin framework's `logfunc`). |
| `ExtractResult` | dataclass | `db_path, metadata_id, entry_count, parse_errors, write_errors, source_type, source_sha256, device_model, ios_build, ios_version, boot_uuid, time_range, source_files_verified, source_files_changed, source_files_unverifiable` | Returned by `run_extract` — the output path plus the run facts (incl. the per-file integrity re-check counts), so you can chain (e.g. `annotate_database(res.db_path, kb)`) without re-querying. `source_sha256` is `None` when the run used a non-full `integrity` mode. |
| `DiffResult` | dataclass | `csv_path: Path \| None, sqlite_path, retained, excluded` | Returned by `run_diff`. `csv_path` is `None` when `run_diff` was called with `csv_out=None`. |
| `IdentifyResult` | dataclass | `baseline_archive, action_archive, baseline_db, action_db, diff` | Returned by `run_identify_workflow`; `diff` is the nested `DiffResult`. |
| `ResultCounts` | dataclass | `retained, noise, kb_known, hidden` | Returned by `IdentifyResults.counts()` — per-category row counts over a diff database. |
| `ExportResult` | dataclass | `output_path, rows, fmt` | Returned by `run_export`. |
| `AnnotateResult` | dataclass | `counts, total_matches, signatures_run, signatures_matched, db_path` | Returned by `annotate_database` / `annotate_connection`. `.counts` is the `signature_id → match_count` mapping. |
| `AcquireResult` | dataclass | `logarchive_path, logarchive_sha256, file_count, device, report_path, extract_result` | Returned by `acquire`. `extract_result` is set only when `acquire(extract=True)`. |

> Note: `annotate_database` is **path-based** (like `run_extract` / `run_diff` /
> `run_export`), so you can re-annotate a saved database at any time. Reach for
> `annotate_connection` only when you already hold a connection (e.g. an in-memory
> database or a caller-managed transaction).

---

## Quick start

```python
import logging
from pathlib import Path
from forensic_aul import (
    run_extract, prepare_source, load_kb, annotate_database, run_export, ExportFilters,
)

logging.basicConfig(level=logging.INFO)   # the library logs; the host app configures handlers

# 1) Parse an acquisition (logarchive dir / sysdiagnose .tar.gz / FFS .zip) → SQLite.
#    One call — run_extract detects, extracts, hashes and cleans up itself.
res = run_extract(
    Path("acquisition.tar.gz"), Path("case.db"),
    case_number="CASE-2024-001", imei="35…",
    jobs=8,            # parser process budget; result is identical for any value.
                       # run_extract itself defaults to jobs=1; the CLI/GUI resolve a
                       # memory-aware default via engine.utils.system.resolve_auto_jobs.
    overwrite=True,    # replace case.db if it already exists (else FileExistsError)
)
print(res.entry_count, res.ios_version, res.time_range)

# 2) (Optional) Annotate against a YAML knowledge base of action signatures.
#    Path-based + chainable: reuse res.db_path, re-run any time the KB improves.
kb = load_kb(Path("knowledge_base/"))     # the KB data directory (VERSION + signatures/)
ann = annotate_database(res.db_path, kb)
print(ann.total_matches, ann.counts)      # ann.counts → {signature_id: match_count}

# 3) Export a filtered, annotation-aware view.
out = run_export(
    res.db_path, Path("report.csv"),
    ExportFilters(level=["Error", "Fault"], annotated_only=True),
)
print(f"exported {out.rows} rows → {out.output_path}")
```

To inspect the source before committing to a long extract, prepare it first and
hand the `PreparedSource` to `run_extract` — it is used **as-is** (no second
preparation, no re-hash, full provenance kept). Never pass
`src.logarchive_root`: that re-prepares the intermediate directory, hashing
everything twice and recording it (not the real evidence) as the source.

```python
with prepare_source(Path("acquisition.zip")) as src:   # cleaned up on exit
    print(src.source_type, src.content_sha256, src.ios_product_version)
    run_extract(src, Path("case.db"), case_number="C1", imei="35…")
```

If the two unified-log folders are already uncompressed on disk (the on-device
`private/var/db/diagnostics/` and `private/var/db/uuidtext/`), pass them as a
mapping instead of an archive — they are merged into a logarchive root by hard
link (zero-copy, originals untouched):

```python
run_extract(
    {"diagnostics": Path("dump/diagnostics"), "uuidtext": Path("dump/uuidtext")},
    Path("case.db"), case_number="C1",
)
# find_loose_dirs(fs_root) builds that mapping from an extracted full file system.
```

The package ships a `py.typed` marker, so type-checkers (mypy, pyright) and IDEs
pick up its annotations when you depend on it.

### Acquiring from a device (optional)

With the `acquire` extra installed, collect straight from a USB-connected iOS
device and chain into the rest of the pipeline:

```python
from forensic_aul import acquire

res = acquire("CASE-2024-001", output_dir=Path("evidence"), extract=True)
print(res.logarchive_path, res.logarchive_sha256, res.device.imei)
print(res.extract_result.entry_count)     # because extract=True
```

`acquire` performs no console I/O — pass `confirm=lambda device: ...` to show a
summary / prompt before collection. It raises `ImportError` if `pymobiledevice3`
is not installed.

---

## Error handling

Every purposeful library error derives from `ForensicAULError`, so a consumer
can wrap any call in one handler while letting genuine bugs propagate:

```python
from forensic_aul import ForensicAULError, run_extract, query_logs

try:
    res = run_extract(src, db, case_number="C1")
    rows = list(query_logs(res.db_path, subsystem="com.apple.locationd"))
except ForensicAULError as exc:      # bad input, unusable source/database, …
    print(f"forensic_aul rejected the request: {exc}")
```

The concrete types (see the table above) also subclass the builtin exceptions
historically raised (`ValueError` for `SourceError` / `InvalidDatabaseError` /
`KnowledgeBaseError`), so existing `except ValueError` code keeps working.
Builtin errors keep their conventional meaning: `FileNotFoundError` (missing
path), `FileExistsError` (`run_extract` without `overwrite=True`),
`ImportError` (optional `pymobiledevice3` missing).

Two behaviours worth knowing:

- **Best-effort steps never lose evidence**: after a collection, hashing and
  report-writing failures are logged as warnings, not raised — the archive is
  already on disk and must survive.
- **Parse resilience**: a corrupt chunk inside a tracev3 costs a
  `parse_errors` increment and a warning, never the extract; rows the database
  refuses are counted in `ExtractResult.write_errors` and logged loudly.

---

## Reading rows back

Two **stable** read surfaces exist; everything else about the schema is internal
and may change between versions.

**1. `query_logs`** — the same filters as `run_export`, but yielding rows in
memory (constant memory: it streams):

```python
from forensic_aul import query_logs

for row in query_logs(
        "case.db",
        subsystem="com.apple.rapport",
        message_prefix="Bonjour unauth peer found",   # literal prefix, %/_ escaped
        last="24h", limit=1000):
    print(row.timestamp_iso, row.process, row.message)
    print(row.signature_ids, row.values_dict())        # KB annotations, if any
```

**2. The `v_logs` SQL view** — for consumers that prefer raw SQL. It denormalises
the lookup tables into readable columns (`id, timestamp_unix_ns, source_order,
event_order, process, pid, tid, log_level, event_type, subsystem, category,
message, format_string, boot_uuid`) and is the **only** schema surface with a
compatibility promise (columns are only ever appended). It is created by every
new extract, and `query_logs` adds it to older databases on first read.

```sql
SELECT timestamp_unix_ns, process, message
FROM v_logs
WHERE subsystem = 'com.apple.locationd'
ORDER BY event_order;
```

### Matching messages (dynamic messages and `%{public}s`)

Matching on the invariant **format string** (`format_str` filter /
`v_logs.format_string`) is the most robust strategy — but it does not cover
every message class:

- **Dynamic messages** carry no format string at all (`format_string IS NULL`).
  launchd lifecycle lines are the classic case (`Successfully spawned
  BackupAgent2[550] …`, `exited due to exit(0) …`).
- **Generic templates** like a bare `%{public}s` are present but carry no
  distinguishing content — dozens of unrelated messages share them.

For both classes, match on the **composed message** instead: use
`message_prefix` (literal, indexed-friendly) or `grep` (raw SQL LIKE) on
`query_logs`, or `message LIKE …` on `v_logs`.

---

## Internal layout (not part of the stable API)

The package is split into two layers that make the architecture self-documenting:
**`engine/`** is the pure backend (no notion of a command, no prompting, no
presentation), and **`ops/`** holds the callable operations. Each operation
follows a uniform shape — a main module plus helpers, and a `report.py` of pure
`format_*(outcome) -> str` functions a caller renders *at will* (operations
never print or build a report themselves).

### `engine/` — pure backend

| Sub-package | Responsibility |
|---|---|
| `engine/parser/` | low-level tracev3 / firehose / catalog / timesync / dsc / uuidtext decoding; plus `string_cache` (UUIDText+DSC cache) and `format_string` (format-string resolution) |
| `engine/database/` | SQLite schema, batched writer (+ `register_source_file`), post-load ordering |
| `engine/models/` | data structures, split by domain: `chunks`, `firehose`, `strings`, `timesync`, `log_entry` (all re-exported from `engine.models`) |
| `engine/integrity.py` | forensic hashing (`compute_sha256`, `hash_logarchive`) and operational-log sealing / source-file re-verification |
| `engine/ios_builds.py` | build-code → iOS-version lookup (reference data) |
| `engine/utils/` | logging helpers, time conversion, the reusable progress reporter, host probes (`system.py`: physical-core / RAM-aware `--jobs` default) |

### `ops/` — callable operations

| Sub-package | Responsibility |
|---|---|
| `ops/extraction/` | the extract pipeline (`extract.py`), the `shutdown.log` sidecar parser, and input-source detection & preparation (`source.py` — container formats live in an archive-format registry: adding an input = one extractor function + one registry entry, mirroring the export writer registry) |
| `ops/acquisition/` | device acquisition (`acquire`) + device metadata + the `.acquisition.json` report writer |
| `ops/annotation/` | apply a knowledge base to a DB (`matcher`) |
| `ops/knowledge_base/` | load / lint / model the YAML KB (the KB *data* lives in the repo-root `knowledge_base/`) |
| `ops/identify/` | baseline-vs-action diff (`run_diff`), the interactive workflow (`run_identify_workflow`), and the diff-DB read/annotate layer (`IdentifyResults`) |
| `ops/query/` | the in-memory read layer (`query_logs`, `LogRow`, the shared filter→SQL machinery the exporter also uses) |
| `ops/export/` | filtered CSV/JSON/JSONL export (`run_export`; formats live in a writer registry) |
| `ops/summary/` | read-only summary of an analysis DB |
| `ops/verify/` | chain-of-custody re-verification |

### Top-level

| Module | Responsibility |
|---|---|
| `config.py` | tuneable constants/defaults |
| `outcomes.py` | the operation result dataclasses (`ExtractResult`, `DiffResult`, …) |
| `testing/` | **runtime** validation tooling (device capture + `log show` reference + comparator + the `test` pipeline) used by the `faul test` command — *not* the project's pytest suite (that lives in the repo-root `tests/`) |

Prefer the top-level re-exports; importing from these sub-modules ties you to
internal paths that may move between versions.
