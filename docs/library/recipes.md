# Library recipes

Task-oriented, runnable examples. Every symbol used here is exported from the top
level (`from forensic_aul import …`) — see
[`forensic_aul/README.md`](../../forensic_aul/README.md) for the full signature of
each one, and [index.md](index.md) for the mental model.

All snippets assume:

```python
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)   # the library configures nothing itself
```

---

## Extract an acquisition to a database

`run_extract` is the whole pipeline in one call: detect the source, normalise it,
hash it, parse, write SQLite, order, index. It accepts a `.logarchive` directory, a
sysdiagnose `.tar.gz`, a full-file-system `.zip`, or a `.faul` container — detected
by content, not by extension.

```python
from forensic_aul import run_extract

res = run_extract(
    Path("evidence/CASE-001.faul"),
    Path("case.db"),
    case_number="CASE-2024-001",
    imei="35…",
    analyst_name="A. Analyst",
    overwrite=True,        # else FileExistsError when case.db already exists
    fts=False,             # skip the full-text index: big cost, only useful for
                           # interactive keyword search (see "keyword search" below)
)
print(res.entry_count, res.ios_version, res.time_range)
print(res.parse_errors, res.write_errors)
print(res.source_sha256, res.source_files_verified, res.source_files_changed)
```

**Returns** an `ExtractResult` (frozen dataclass) with `db_path`, `metadata_id`,
`entry_count`, `parse_errors`, `write_errors`, `source_type`, `source_sha256`,
`device_model`, `ios_build`, `ios_version`, `boot_uuid`, `time_range`, and the
per-file integrity counters.

For speed on a large acquisition, add `jobs=N` — but read the spawn caveat in
[index.md](index.md#import-safety-guarantees) first.

---

## Reuse an existing database ("parse once")

Extraction is the expensive step. `open_or_extract` returns the database path
immediately when the file already exists, and only extracts otherwise.

```python
from forensic_aul import open_or_extract

db = open_or_extract(
    Path("evidence/CASE-001.faul"),
    Path("case.db"),
    case_number="CASE-2024-001",
    fts=False,
)
```

**Returns** a `Path`. It does *not* verify that an existing file came from the same
source — delete the file to force a fresh extract.

---

## Prepare a source once, then extract

Use `prepare_source` when you want to look at the evidence (type, hash, iOS
version, embedded acquisition sidecar) before committing to a long parse. Hand the
`PreparedSource` straight to `run_extract`: it is used as-is — no second
preparation, no re-hash, full provenance preserved.

```python
from forensic_aul import prepare_source, run_extract

with prepare_source(Path("acquisition.zip"), integrity="full") as src:
    print(src.source_type)            # SourceType.FILESYSTEM
    print(src.content_sha256)         # None when integrity != "full"
    print(src.ios_product_version)    # from SystemVersion.plist, when present
    print(src.sidecar)                # acquisition sidecar, for a .faul container

    run_extract(src, Path("case.db"), case_number="C1")
```

**Returns** a `PreparedSource` (a context manager — exiting removes any temp
directory it created). `integrity` is one of `INTEGRITY_MODES` =
`("full", "fingerprint", "off")`.

> Never pass `src.logarchive_root` to `run_extract`. That re-prepares the
> intermediate directory, hashes everything twice, and records the temp copy —
> not the real evidence — as the source.

If the two unified-log folders are already uncompressed on disk, pass them as a
mapping instead; they are merged into a logarchive root by hard link (zero-copy,
originals untouched):

```python
from forensic_aul import find_loose_dirs, run_extract

dirs = find_loose_dirs(Path("/evidence/ffs_extracted"))   # or None
if dirs:                       # {"diagnostics": …, "uuidtext": …}
    run_extract(dirs, Path("case.db"), case_number="C1")
```

---

## Page through logs in a UI

A table UI needs an exact row count and stable pages. `count_logs` gives the total
for a filter set; `fetch_logs` gives one page. `offset`/`limit` count **logs**, not
annotation-joined rows, so pages never drift.

```python
from forensic_aul import LogFilters, count_logs, fetch_logs, fetch_context

filters = LogFilters(level=["Error", "Fault"], subsystem="com.apple.locationd")

total = count_logs("case.db", filters)                       # -> int
page  = fetch_logs("case.db", filters, offset=0, limit=100)  # -> list[LogRow]

for row in page:
    print(row.log_id, row.timestamp_iso, row.process, row.message)
```

To show what surrounded a line, ask for its context. This walks `event_order` — the
tamper-resilient forensic sequence — not wall-clock time, so a shifted clock cannot
reorder the neighbourhood.

```python
around = fetch_context("case.db", log_id=page[0].log_id, before=20, after=20)
anchor = next(r for r in around if r.log_id == page[0].log_id)
```

**Returns** `list[LogRow]`, ordered by `event_order`, anchor included.

Issuing many small reads (a scrolling table) is cheaper through a held-open store,
which validates and probes the database once:

```python
from forensic_aul import LogStore

with LogStore("case.db") as store:
    store.has_kb            # database carries knowledge-base annotations
    store.has_fts           # database carries a usable full-text index
    total = store.count(filters)
    rows  = store.fetch(filters, offset=200, limit=100)
    ctx   = store.context(rows[0].log_id, before=10, after=10)
```

Gate a keyword-search affordance on `store.has_fts`: without an index there is no
silent fallback, `message_match` raises.

---

## Stream rows and read their values

`query_logs` is the streaming read: same filter vocabulary as export, constant
memory, yielding `LogRow` objects. The generator owns its connection and closes it
when exhausted, garbage-collected, or abandoned.

```python
from forensic_aul import query_logs

for row in query_logs(
        "case.db",
        subsystem="com.apple.rapport",
        message_prefix="Bonjour unauth peer found",   # literal prefix, %/_ escaped
        last="24h",
        limit=1000):
    print(row.timestamp_iso, row.process, row.pid, row.log_level, row.message)
    print(row.signature_ids)          # list[str] — knowledge-base signatures matched
    print(row.values_dict())          # {label: "value"} — extracted named values
    print(row.value_for("wifi_ssid")) # "" when the label is absent on this row
```

`LogRow` fields: `log_id`, `timestamp_unix_ns`, `timestamp_iso` (property),
`event_order`, `process`, `pid`, `tid`, `log_level`, `event_type`, `subsystem`,
`category`, `message`, `format_string`, `signature_ids`; methods `values_dict()`
and `value_for(label)`.

Consumers that prefer raw SQL should read the stable `v_logs` view rather than the
normalised tables:

```sql
SELECT timestamp_unix_ns, process, message
FROM v_logs
WHERE subsystem = 'com.apple.locationd'
ORDER BY event_order;
```

### Keyword search (needs an FTS index)

`message_match` is a full-text keyword search: whitespace-separated terms are
AND-combined and each is matched literally (FTS query syntax in the value is
inert). It requires an extract built with `fts=True` (the `run_extract` default);
on a database without a usable index it raises `ValueError`.

```python
rows = list(query_logs("case.db", message_match="airdrop transfer", limit=50))
```

---

## The filter vocabulary

`LogFilters` is shared by the query layer and, extended as `ExportFilters`, by the
exporter. Within a list field values are OR-combined; across fields they are
AND-combined. List fields accept a bare string as a convenience in `query_logs`.

| Field | Meaning |
|---|---|
| `time_from` / `time_to` | ISO 8601 bounds (lower inclusive, upper exclusive) |
| `last` | shortcut for `time_from = now - DURATION` (`10m`, `1h`, `24h`, `7d`) |
| `process`, `subsystem`, `level` | list filters on the lookup columns |
| `message_prefix` | literal prefix on the composed message (`%`/`_` escaped) |
| `message_contains` | literal substring on the composed message |
| `message_match` | FTS5 keyword search — needs a full-text index |
| `like` | raw SQL `LIKE` pattern on the message |
| `format_str` | exact match on the invariant format-string template |
| `signature`, `action`, `tag`, `annotated_only` | annotation filters — need an annotated database |

`ExportFilters` adds `fmt` (`"csv"` / `"json"` / `"jsonl"`; `None` infers from the
output suffix) and `include_fields` (default `True` — emit the extracted-value
columns/objects).

Matching on `format_str` is the most robust strategy where a format string exists,
but two message classes have none worth matching: **dynamic messages** (no format
string at all — launchd lifecycle lines are the classic case) and **generic
templates** like a bare `%{public}s`. For those, match the composed message with
`message_prefix` / `message_contains` / `like`.

---

## Export to CSV, JSON or JSONL

```python
from forensic_aul import ExportFilters, run_export

out = run_export(
    Path("case.db"),
    Path("report.csv"),                # format inferred from the suffix
    ExportFilters(level=["Error", "Fault"], annotated_only=True, last="7d"),
)
print(out.rows, out.output_path, out.fmt)

# Explicit format, and no extracted-value columns:
run_export(
    Path("case.db"),
    Path("report.out"),
    ExportFilters(fmt="jsonl", include_fields=False),
)
```

**Returns** an `ExportResult` (`output_path`, `rows`, `fmt`). Raises
`FileNotFoundError` / `InvalidDatabaseError` on a bad database, and `ValueError`
when the format cannot be determined or a filter is malformed. Annotation filters
on a never-annotated database also raise `ValueError`.

---

## Load a knowledge base and annotate at will

Annotation is a separate pass over an existing database. Improving the knowledge
base means re-annotating — never re-extracting.

```python
from forensic_aul import annotate_database, load_kb

kb  = load_kb(Path("knowledge_base"))      # dir holding VERSION + signatures/
ann = annotate_database(Path("case.db"), kb)

print(ann.total_matches, ann.signatures_run, ann.signatures_matched)
print(ann.counts)                          # {signature_id: match_count}

# Restrict to part of the knowledge base:
annotate_database(Path("case.db"), kb, only_tags={"network"})
annotate_database(Path("case.db"), kb, only_ids={"airdrop_receive_v1"})
```

**Returns** an `AnnotateResult` (`counts`, `total_matches`, `signatures_run`,
`signatures_matched`, `db_path`). `load_kb` raises `KnowledgeBaseError` on a
malformed knowledge base; `annotate_database` raises `FileNotFoundError` /
`InvalidDatabaseError`.

When you already hold a connection (an in-memory database, or a transaction you
manage yourself), use `annotate_connection(conn, kb, …)` instead — same result,
with `db_path` set to `None`.

See [../formats/knowledge-base.md](../formats/knowledge-base.md) for the YAML
format and the extracted-value labels.

---

## Acquire from a device with a confirm hook

Requires the optional `acquire` extra (`pymobiledevice3`). The library performs no
console I/O: pass `confirm` to show the operator what is connected and let them
approve before collection.

```python
from forensic_aul import AcquisitionAborted, DeviceInfo, acquire

def confirm(device: DeviceInfo) -> bool:
    print(f"{device.device_name} — {device.product_type} "
          f"iOS {device.product_version} — IMEI {device.imei}")
    return input("collect? [y/N] ").strip().lower() == "y"

try:
    res = acquire(
        "CASE-2024-001",
        output_dir=Path("evidence"),
        start_time="24h",     # ISO datetime, "1h"/"24h"/"7d", a unix int, or None
        analyst="A. Analyst",
        extract=True,         # chain straight into run_extract
        confirm=confirm,
    )
except AcquisitionAborted:
    print("operator declined")
else:
    print(res.logarchive_path, res.logarchive_sha256, res.file_count)
    print(res.device.udid, res.device.imei, res.device.product_version)
    print(res.extract_result.entry_count)      # set only because extract=True
```

**Returns** an `AcquireResult`. By default (`pack=True`) the output is a single
portable `.faul` container carrying the logarchive **and** its acquisition sidecar,
named `<case>-<imei|udid>-<UTC>.faul`; `report_path` is then `None`. Pass
`pack=False` for the legacy loose layout (a `.logarchive` directory plus a separate
`.acquisition.json`, whose path lands in `report_path`).

Raises `ImportError` when `pymobiledevice3` is missing, `AcquisitionAborted` when
`confirm` returns `False`, `AcquisitionError` on connection/collection failure.

---

## Run the identify workflow with injected callbacks

`run_identify_workflow` drives the whole action-attribution sequence (baseline
capture → operator performs the action → second capture → extract both → optional
annotation → diff). Every interaction point is a callback, so a CLI, a GUI or a
test can drive it identically.

```python
from forensic_aul import load_kb, run_identify_workflow, tty_bar_sink

def confirm(device):
    print(f"connected: {device.device_name} ({device.product_type})")
    return True

def wait_still(seconds: int) -> None:
    print(f"leave the device untouched for {seconds}s …")
    import time; time.sleep(seconds)

def wait_for_action() -> None:
    input("perform the action on the device, then press Enter …")

res = run_identify_workflow(
    "CASE-2024-001",
    output_dir=Path("identify-run"),
    still_seconds=60,
    kb=load_kb(Path("knowledge_base")),   # annotates the ACTION database only
    confirm=confirm,
    wait_still=wait_still,
    wait_for_action=wait_for_action,
    status=print,                         # human progress lines
    progress=tty_bar_sink(),              # weighted bar across the whole run
)

print(res.baseline_archive, res.action_archive)
print(res.baseline_db, res.action_db)
print(res.diff.sqlite_path, res.diff.csv_path, res.diff.retained, res.diff.excluded)
```

**Returns** an `IdentifyResult` with the four artefact paths and the nested
`DiffResult`. Defaults worth knowing: `integrity="off"` and `fts=False` (identify
is a research tool — the chain-of-custody hashing is pure latency here; pass
`"full"` or `"fingerprint"` to keep it), `write_csv=True`, `jobs=1`,
`batch_size=1000`. A falsy `case_number` prefixes artefacts
`identify-<UTC timestamp>` instead.

Raises `ImportError` (no `pymobiledevice3`), `ValueError` (unusable case number),
`AcquisitionAborted`, `AcquisitionError`. Any callback may raise
`AcquisitionAborted` to abort cleanly.

If you already have two extracted databases, diff them directly:

```python
from forensic_aul import run_diff

d = run_diff(Path("baseline.db"), Path("action.db"),
             Path("identified.csv"),      # None → SQLite only
             Path("identified.db"))
print(d.retained, d.excluded)
```

`run_diff` raises `ValueError` when the baseline database holds no log entries (no
cutoff can be derived).

---

## Read a diff database with IdentifyResults

`IdentifyResults` is the read/annotate layer over a diff database. It opens a
database produced by `run_diff` (identified by its `identified_logs` table — a diff
database has no `logs` table) and upgrades an older one on open.

```python
from forensic_aul import IdentifyResults

with IdentifyResults(Path("identified.db")) as results:
    c = results.counts()
    print(c.retained, c.noise, c.kb_known, c.hidden)

    rows = results.rows(limit=200)          # retained-only by default
    for row in rows:                        # sqlite3.Row, by column name
        print(row["timestamp"], row["process"], row["message"],
              row["matched_signatures"], row["excluded"])

    # Widen the view:
    results.rows(include_noise=True, include_kb_known=True, include_hidden=True,
                 search="airdrop", limit=100, offset=0)
    results.count(include_kb_known=True)    # COUNT(*) without materialising rows

    # Prune known-uninteresting lines — reversible, stored in the database:
    results.hide(rows[0]["message"], rows[0]["process"])
    print(results.hidden_keys())            # [(message, process), …]
    results.unhide(rows[0]["message"], rows[0]["process"])

    n = results.export_csv(Path("attributed.csv"))
    print(f"{n} rows")
```

Notes:

- `rows()` and `count()` default to `include_noise=False`, `include_kb_known=False`,
  `include_hidden=False` — i.e. the *new, unexplained* lines, which is what you
  want first. Rows are ordered `timestamp_unix_ns ASC, id ASC`.
- `hide(message, process)` hides every row with that exact `(message, process)`
  pair; `process=None` is stored as `''`. A `None` *message* raises `ValueError`.
- `export_csv` defaults to `include_kb_known=True` and `include_noise=False`; its
  header and column order match `run_diff`'s own CSV. Hidden rows are never
  exported — the export reflects the analyst's current pruning.
- Raises `FileNotFoundError` / `InvalidDatabaseError`.

---

## Summarise and verify a database

```python
from forensic_aul import summarise, verify_database

s = summarise("case.db", top=10, buckets=40)
print(s.case_number, s.ios_version, s.total_entries, s.range_seconds)
print(s.has_kb, s.annotated_count, s.signature_count)
print(s.top_processes, s.top_subsystems, s.log_levels)

v = verify_database("case.db")
print(v.ok, v.passed, v.failed)
for check in v.checks:
    print(check.status)
```

`summarise` returns a `Summary`; `verify_database` returns a `VerifyResult` whose
`ok` property is `True` when nothing failed. Both raise `FileNotFoundError` /
`InvalidDatabaseError`, and `ValueError` when `case_metadata` is empty.

---

## See also

- [Progress and errors](progress-and-errors.md)
- [`forensic_aul/README.md`](../../forensic_aul/README.md) — per-symbol reference
- [../workflows/case-workflow.md](../workflows/case-workflow.md)
- [../formats/database-schema.md](../formats/database-schema.md)
