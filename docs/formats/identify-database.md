# Identify (diff) database

The output of `run_diff` — used standalone and as the last step of
[`identify`](../cli/identify.md). It is a **separate** SQLite file from the
analysis database: it has no `logs` table, only `identified_logs`. Source:
`forensic_aul/ops/identify/{diff,results,workflow}.py`.

## What the diff computes

Two extracted analysis databases go in: a **baseline** (before the action) and an
**action** database (after it).

- **Cutoff** = `MAX(timestamp_unix_ns)` over the baseline, excluding the `0`
  failure sentinel. An all-unresolved baseline raises `ValueError` instead of
  yielding a cutoff of `0` that would let everything through.
- **Noise set** = the set of `(message, process_name)` tuples present in the
  baseline. Process name is resolved through the join, so the key is comparable
  across databases whose `processes.id` values differ.

Every action-database row with `timestamp_unix_ns > cutoff` **or**
`timestamp_unix_ns = 0` is written to `identified_logs`, classified:

| `excluded` | Meaning |
|---|---|
| `0` | **Retained** — attributable to the action |
| `1` | **Noise** — its `(message, process)` tuple already appears in the baseline |

Rows that predate the cutoff are not written at all: they carry no information
about the action. A row with an unresolved timestamp (`timestamp_unix_ns = 0`)
cannot be proven to predate the action, so it is kept as retained (`excluded = 0`)
with `timestamp = ''` and `note = "unresolved timestamp (timestamp_unix_ns=0)"`
rather than being silently dropped.

Rows are read ordered by `(timestamp_unix_ns ASC, id ASC)`.

## `identified_logs`

| Column | Type | Meaning |
|---|---|---|
| `id` | INTEGER PK | rowid of this diff table (not the source log id) |
| `timestamp` | TEXT | ISO 8601 formatted from `timestamp_unix_ns`; empty for the `0` sentinel |
| `timestamp_unix_ns` | INTEGER | |
| `event_order` | INTEGER | Carried through from the action database so the tamper signal stays visible in the diff too |
| `source_order` | INTEGER | Carried through from the action database — physical position within `source_file` (the other half of the ordering evidence alongside `event_order`) |
| `source_file` | TEXT | The tracev3 file `source_order` ranks within (`source_files.file_path` in the action database) |
| `process` | TEXT | |
| `pid`, `tid` | INTEGER | |
| `log_level` | TEXT | |
| `event_type` | TEXT | |
| `subsystem` | TEXT | |
| `category` | TEXT | |
| `message` | TEXT | |
| `matched_signatures` | TEXT NOT NULL DEFAULT `''` | Comma-joined signature ids (`GROUP_CONCAT`), `''` when the action DB has no KB tables or the row is unannotated |
| `excluded` | INTEGER NOT NULL | `0` retained, `1` baseline noise |
| `note` | TEXT | Currently only the unresolved-timestamp note |

Indexes: `idx_identified_logs_excluded(excluded)`,
`idx_identified_logs_ts(timestamp_unix_ns)`.

Everything is **denormalised** — the lookup tables are joined away at diff time, so
the file stands alone.

`matched_signatures` is built as a **scalar subquery**, not a join, precisely so a
log matched by several signatures still appears exactly once. The subquery is only
inserted when the action database carries the KB annotation tables
(`has_kb_tables`); otherwise the column selects `''`.

The `excluded` flag is the engine's mechanical classification and is **never
rewritten** after the diff runs.

## `hidden_keys` and `v_identified_visible`

A reversible, analyst-driven prune layer sitting on top of `excluded` — the
viewer's "hide identical lines", persisted so a reopened session keeps the pruning.

```sql
CREATE TABLE hidden_keys (
    message TEXT NOT NULL,
    process TEXT NOT NULL,
    UNIQUE (message, process)
);

CREATE VIEW v_identified_visible AS
    SELECT il.* FROM identified_logs il
    LEFT JOIN hidden_keys hk
        ON hk.message = il.message AND hk.process = COALESCE(il.process, '')
    WHERE hk.message IS NULL;
```

- A NULL `process` is stored and compared as `''` (the `COALESCE` above).
- `v_identified_visible` exposes every `identified_logs` column, minus the rows
  whose `(message, process)` pair is hidden. It does **not** filter on `excluded` —
  hiding and exclusion are independent axes.
- Both objects are created with `IF NOT EXISTS`, by `run_diff` and again when a
  diff database is opened by `IdentifyResults`, so a database produced before this
  feature gains them on open (best-effort: a read-only file still serves reads).
- The same open-time upgrade covers `source_order`/`source_file`: a diff database
  produced before L10 lacks those two columns, so `IdentifyResults` adds them via
  `ALTER TABLE ... ADD COLUMN` (guarded by `PRAGMA table_info`, since column
  addition has no `IF NOT EXISTS` form) — reads on an older database keep working,
  with `NULL` in the two new columns for its existing rows.

## Reading it: `IdentifyResults`

`forensic_aul.ops.identify.results.IdentifyResults` is the path-based read/annotate
layer (a context manager). Opening validates that `identified_logs` exists and
raises `InvalidDatabaseError` otherwise — deliberately distinct from
`open_analysis_database`, which requires a `logs` table.

`counts()` returns a `ResultCounts` over four (overlapping) categories:

| Field | Definition |
|---|---|
| `retained` | `excluded = 0` **and** `matched_signatures = ''` **and** not hidden |
| `noise` | `excluded = 1` |
| `kb_known` | `matched_signatures != ''` |
| `hidden` | matches a `hidden_keys` entry |

`rows()` / `count()` share one WHERE builder with three include flags, all default
`False`, each *adding* a restriction when off:

| Flag off ⇒ clause |
|---|
| `include_noise` → `excluded = 0` |
| `include_kb_known` → `matched_signatures = ''` |
| `include_hidden` → `NOT EXISTS (matching hidden_keys row)` |

`search` adds a literal substring match on `message` (`LIKE … ESCAPE '\'` with
`%`/`_` escaped through the same `_escape_like` the query layer uses). Rows come
back ordered by `(timestamp_unix_ns ASC, id ASC)`, with `LIMIT`/`OFFSET` paging.

`hide(message, process)` / `unhide(...)` maintain `hidden_keys`
(`INSERT OR IGNORE` / `DELETE`, committed immediately); `hide` raises `ValueError`
for a NULL message, since `hidden_keys.message` is NOT NULL and such a row has no
identical-lines key anyway. `hidden_keys()` lists the current pairs.

## The CSV of retained lines

`run_diff` writes a CSV alongside the SQLite output unless `csv_out` is `None`
(`identify --no-csv` / `write_csv=False`). It contains the **retained rows only**
(`excluded = 0`) — the excluded ones remain re-inspectable in the SQLite file.
Encoding is UTF-8 with BOM so Excel auto-detects it.

Header, in order:

```
timestamp, timestamp_unix_ns, event_order, source_order, source_file,
process, pid, tid,
log_level, event_type, subsystem, category, message,
matched_signatures, note
```

That is every `identified_logs` column except `id` and `excluded` (the flag is
implied — all rows in this file are retained).

`IdentifyResults.export_csv()` reuses the exact same header and column order, so a
re-filtered export drops into the same downstream tooling. Its defaults differ
slightly: `include_noise=False`, `include_kb_known=True`, and `include_hidden` is
deliberately not exposed — an export reflects the analyst's current pruning.

`run_diff` returns a `DiffResult(csv_path, sqlite_path, retained, excluded)`;
`retained` is the number of rows the CSV would contain, computed identically
whether or not a CSV was written.

## Artefacts of a full `identify` run

`run_identify_workflow` writes every artefact of a run into a single **session
directory**, `<output_dir>/<prefix>/`, where the prefix is
`<case>-<imei|udid>-<UTC>` (or `identify-<UTC>` when no case number is given).
Each file inside repeats that prefix, so it stays self-identifying if copied out:

| File | Content |
|---|---|
| `<prefix>-baseline.logarchive` | Acquisition covering the pre-action window |
| `<prefix>-action.logarchive` | Acquisition covering the post-action window |
| `<prefix>-baseline.db` | Extracted baseline analysis database |
| `<prefix>-action.db` | Extracted action analysis database (optionally annotated) |
| `<prefix>-identified.db` | **This** diff database |
| `<prefix>-identified.csv` | Retained lines (omitted with `write_csv=False`) |

Only the **action** database is annotated when a knowledge base is supplied — the
baseline is diffed away and never needs annotations, and an annotation failure is
logged and swallowed rather than sinking the diff.

Note that identify defaults to `integrity="off"`: it is a research tool, so the
hashing and acquisition-report machinery is skipped unless
`integrity="full"`/`"fingerprint"` is requested.

## See also

- [`identify` CLI](../cli/identify.md)
- [Database schema](database-schema.md) — the analysis databases that go in
- [Knowledge base](knowledge-base.md) — what fills `matched_signatures`
