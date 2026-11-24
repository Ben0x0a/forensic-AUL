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
- **Baseline keys** = the `(message, process)` pairs and the `(format string,
  process)` pairs present in the baseline, copied into two indexed temporary
  tables of the diff's own connection (both inputs are opened read-only).
  Process names and format strings are resolved through the joins, so the keys
  compare across databases whose ids differ. A *generic* format string — no
  literal text once its `%` specifiers are removed, e.g. `%{public}s` — is left
  out of the template keys: two lines sharing it may have nothing in common.

Every action-database row with `timestamp_unix_ns > cutoff` **or**
`timestamp_unix_ns = 0` is written to `identified_logs` with a **tier**:

| `tier` | `excluded` | Meaning |
|---|---|---|
| `new_template` | `0` | The baseline never produced this template for this process (or, for a dynamic message, this message) — **read these first** |
| `new_values` | `0` | A known template for this process with a message the baseline did not have — a familiar event with new values |
| `repeat` | `1` | **Noise** — its `(message, process)` pair already appears in the baseline |
| `unresolved` | `0` | Timestamp not resolved (`timestamp_unix_ns = 0`): kept, since it cannot be proven to predate the action, and not compared |

Retained = `new_template` + `new_values` + `unresolved` — the same rows the former two-way diff
retained; the tier ranks them. On the iOS 27 screenshot test capture: 111,141
post-cutoff rows → 48,145 repeat, 31,071 new values, 31,925 new template (6,724
distinct templates; the top process is `ScreenshotServicesService`).

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
| `format_string` | TEXT | The invariant template (`format_strs.value`); NULL for a dynamic message |
| `matched_signatures` | TEXT NOT NULL DEFAULT `''` | Comma-joined signature ids (`GROUP_CONCAT`), `''` when the action DB has no KB tables or the row is unannotated |
| `tier` | TEXT | `new_template` / `new_values` / `repeat` / `unresolved` (see above); NULL in a database diffed before tiers existed |
| `excluded` | INTEGER NOT NULL | `0` retained, `1` baseline noise (`tier = repeat`) |
| `note` | TEXT | Currently only the unresolved-timestamp note |
| `repetition` | INTEGER NOT NULL DEFAULT 1 | The capture cycle the row came from: 1 for a single run, 1…N after `--repeat N` |

Indexes: `idx_identified_logs_excluded(excluded)`,
`idx_identified_logs_ts(timestamp_unix_ns)`, `idx_identified_logs_tier(tier)`.

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

## `identify_run`

Facts about the run, written by `run_identify_workflow` after the diff (absent
from a database made by `run_diff` alone or `identify --diff`). Source:
`forensic_aul/ops/identify/run_info.py`.

| `key` | `value` |
|---|---|
| `action_description` | the operator's description of the action (may be empty) |

`read_run_info(db)` returns the table as a dict (`{}` when absent).

## `repeat_ranking` (in `<prefix>-identified.db`, and `<prefix>-repeat.csv`)

Written by `run_identify_workflow` when `IdentifyOptions.repeat > 1`
(`merge_repetitions` then `rank_repeated`, `forensic_aul/ops/identify/repeat.py`):
each repetition's diff is merged into the run's `identified_logs` (column
`repetition` = 1…N), and its retained rows are grouped by template. The template is the
format string, or the message when the format string is missing or generic (no
literal text once its `%` specifiers are removed).

| Column | Meaning |
|---|---|
| `rank` | 1 = read first: ordered by `new_template_cycles`, `cycles`, `rows` (descending) |
| `template`, `process` | the group key |
| `new_template_cycles` | repetitions where it was `new_template`. Equal to the repetition count ⇒ in every action window and in no baseline |
| `cycles` | repetitions where it was retained at all |
| `rows` | retained rows across all repetitions |
| `example_message` | one composed message of the group |

`ranked_templates(path, limit)` reads the top of the table.

The same table is written as `<prefix>-repeat.csv` (UTF-8 with BOM, in rank
order) with the columns `rank, new_template_cycles, cycles, rows, process,
template, example_message`. It is always written for a repeated run, whatever
`write_csv` says: it is how the ranking is meant to be read.

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

`tier` keeps one tier only (`il.tier = ?`). `search` adds a literal substring match on `message` (`LIKE … ESCAPE '\'` with
`%`/`_` escaped through the same `_escape_like` the query layer uses). Rows come
back ordered by `(timestamp_unix_ns ASC, id ASC)`, with `LIMIT`/`OFFSET` paging.

`hide(message, process)` / `unhide(...)` maintain `hidden_keys`
(`INSERT OR IGNORE` / `DELETE`, committed immediately); `hide` raises `ValueError`
for a NULL message, since `hidden_keys.message` is NOT NULL and such a row has no
identical-lines key anyway. `hidden_keys()` lists the current pairs.

## The CSV of retained lines

The run's CSV (`<prefix>-identified.csv`, written by `write_identified_csv` from
the result database; `identify --no-csv` / `write_csv=False` skips it) and the
one `run_diff` writes when given `csv_out` hold the **retained rows only**
(`excluded = 0`) — the excluded ones remain re-inspectable in the SQLite file.
Encoding is UTF-8 with BOM so Excel auto-detects it.

Header, in order — the `export` CSV's columns, then two flags:

```
timestamp, timestamp_unix_ns, event_order, source_order, source_file,
process, pid, tid,
log_level, event_type, subsystem, category, message,
matched_signatures, new_template, new_message[, repetition]
```

| Flag | 1 when | 0 when |
|---|---|---|
| `new_template` | the template is new for this process (`tier = new_template`) | the baseline had the template (`new_values`) |
| `new_message` | the exact message is new for this process (`new_template` or `new_values`) | it was in the baseline (`repeat` — only seen in an export with noise included) |

Both are empty for a row that was not compared (`unresolved`). `repetition`
(1…N) is added when the run was repeated. WHY flags beside the format string:
where the template is uninformative (`%{public}s`, `<private>`), whether the
message itself is new is the useful question.

`IdentifyResults.export_csv()` writes the same columns (without `repetition`), so a
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
Each file repeats that prefix, so it stays self-identifying if copied out. Only
the results sit at the top; what they were made from is in `intermediate/`:

```
<output-dir>/
└── <prefix>/
    ├── <prefix>-identified.db      the result: every line after the baseline, flagged
    ├── <prefix>-identified.csv     the retained lines (omitted with --no-csv)
    ├── <prefix>-repeat.csv         --repeat only: the ranking of the templates
    └── intermediate/               what the results were made from
        ├── <prefix>[-<n>]-baseline.logarchive
        ├── <prefix>[-<n>]-action.logarchive
        ├── <prefix>[-<n>]-baseline.db
        ├── <prefix>[-<n>]-action.db
        └── <prefix>-<n>-identified.db   --repeat only: each repetition's diff
```

`IdentifyResult.identified_db` and `.csv_path` point at the results; its other
paths (and `cycles`) point into `intermediate/`.

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
