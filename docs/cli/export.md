# `export`

Export an analysis database to CSV / JSON / JSONL, with filters.

## Synopsis

```bash
faul.py export DATABASE -o FILE [--format {csv,json,jsonl}] [filters]
```

## What it does

`export` streams rows from the `logs` table — joined with `log_annotations` when
the database has been annotated — into a flat file. Filters can target log
columns (process, subsystem, level, message, time range) or annotations
(signature id, action substring, tag).

**Extracted values are included by default.** When the knowledge base extracts
named values (see [`kb`](kb.md)), the export pivots them into one column per
label, named `<signature_id>.<field>`. Pass `--no-fields` to omit them.

Rows are written streaming, so the export is not bounded by RAM. Parent
directories of the output are created automatically.

---

## Options

### Required

| Flag | Default | Meaning |
|---|---|---|
| `DATABASE` | **required** | SQLite database produced by `extract`. |
| `-o, --output FILE` | **required** | Output file path. |

### Format

| Flag | Default | Meaning |
|---|---|---|
| `--format {csv,json,jsonl}` | inferred from the `--output` suffix | Output format. The choices come from the writer registry, so a newly registered format is accepted automatically. |

Suffix inference: `.csv` → `csv`, `.json` → `json`, `.jsonl` → `jsonl`. If the
suffix is unknown and `--format` is absent, the command errors.

### Time filters

| Flag | Default | Meaning |
|---|---|---|
| `--from ISO` | none | Lower bound, **inclusive**. ISO 8601 datetime. |
| `--to ISO` | none | Upper bound, **exclusive**. ISO 8601 datetime. |
| `--last DURATION` | none | Shortcut for `--from now-DURATION`. Accepts `10m`, `1h`, `24h`, `7d`. |

### Log-column filters

| Flag | Default | Meaning |
|---|---|---|
| `--process P` | none | Restrict to this process name. **Repeatable** — repeats are OR-ed. |
| `--subsystem S` | none | Restrict to this subsystem. Repeatable (OR). |
| `--level LVL` | none | Restrict to this log level (`Default` / `Info` / `Debug` / `Error` / `Fault`). Repeatable (OR). |
| `--like PATTERN` | none | SQL `LIKE` pattern on the message column. Use `%` and `_` wildcards — **not** a regular expression. |

### Knowledge-base filters

| Flag | Default | Meaning |
|---|---|---|
| `--signature ID` | none | Only logs carrying this signature annotation. Repeatable (OR). |
| `--action SUBSTR` | none | Only logs whose annotation action contains this substring (case-insensitive). |
| `--tag TAG` | none | Only logs whose annotation carries this tag. Repeatable (OR). |
| `--annotated-only` | off | Skip every log without at least one annotation. |

All four require a database that has been through [`annotate`](annotate.md); on
an un-annotated database they raise an error (exit `1`) telling you to run
`annotate` first.

### Output options

| Flag | Default | Meaning |
|---|---|---|
| `--no-fields` | fields **included** | Do not emit the extracted-value columns (one per label). |

Extracted-value columns are only ever emitted when the database actually has
annotation tables; on an un-annotated database the flag is a no-op.

---

## Filter semantics

- Within a group, repeated values are **OR**-ed (`--process A --process B` =
  A or B).
- Across groups, filters are **AND**-ed (`--process A --level Error` = A *and*
  Error).
- `--like` is a SQL `LIKE`, so `--like '%wifi%'` is a substring search and a bare
  `--like wifi` matches only messages equal to `wifi`.

---

## Examples

```bash
# Everything, as CSV (format inferred from the suffix)
faul.py export cases/case.db -o out/all.csv

# One process, last 24 hours, JSON Lines
faul.py export cases/case.db -o out/locationd.jsonl --process locationd --last 24h

# Two processes, errors and faults only, explicit window
faul.py export cases/case.db -o out/errors.csv \
    --process locationd --process bluetoothd \
    --level Error --level Fault \
    --from 2024-06-01T00:00:00 --to 2024-06-02T00:00:00

# Substring search in messages
faul.py export cases/case.db -o out/wifi.csv --like '%wifi%'

# Only annotated rows carrying a given tag, without the pivoted value columns
faul.py export cases/case.db -o out/tagged.json \
    --tag airplane-mode --annotated-only --no-fields

# Force a format that does not match the suffix
faul.py export cases/case.db -o out/data.txt --format jsonl
```

---

## Output

On success the command prints a one-line summary (output path, row count,
resolved format). Column layout per format is documented in
[`docs/formats/export-formats.md`](../formats/export-formats.md).

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Export written. |
| `1` | The database does not exist; it is not a valid analysis database; the format could not be inferred or is unknown; a filter value is malformed; or an annotation filter was requested on a database with no annotations. |

---

## Common pitfalls

- **`--like` is `LIKE`, not regex.** Wrap the term in `%` for a substring match,
  and remember `_` is a single-character wildcard that needs escaping if literal.
  The library keyword has the same name (`LogFilters.like`, `query_logs(like=…)`).
- **`--to` is exclusive, `--from` is inclusive.** An end-of-day bound of
  `…T23:59:59` silently drops the last second; use the next day's midnight.
- **Annotation filters fail loudly on an un-annotated database** — run
  [`annotate`](annotate.md) first.
- **The set of extracted-value columns depends on the filtered rows.** Two
  exports with different filters can legitimately have different columns; use
  `--no-fields` when you need a stable header.
- **Format is inferred from the suffix, not the content.** `-o out.txt` without
  `--format` is an error, not a default to CSV.
- **Run [`summary`](summary.md) first.** An unfiltered export of a multi-million
  row database is rarely what you want.

---

## See also

- [`summary`](summary.md) — decide what to filter on
- [`annotate`](annotate.md) · [`kb`](kb.md) — populate signatures and extracted values
- [Export formats](../formats/export-formats.md) ·
  [Database schema](../formats/database-schema.md) ·
  [Knowledge base](../formats/knowledge-base.md)
