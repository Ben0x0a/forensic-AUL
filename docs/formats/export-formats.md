# Export formats (CSV / JSON / JSONL)

Output of [`export`](../cli/export.md) / `forensic_aul.run_export`. Source:
`forensic_aul/ops/export/exporter.py` (record shape and writers) and
`forensic_aul/ops/query/reader.py` (row model and the annotation rollup).

## Format selection

| Format name | Suffix | Writer |
|---|---|---|
| `csv` | `.csv` | one header row + one row per log |
| `json` | `.json` | a single JSON array of objects |
| `jsonl` | `.jsonl` | one JSON object per line |

The format comes from `ExportFilters.fmt` when set; otherwise it is **inferred
from the output file's suffix** (case-insensitive). If neither yields a format, a
`ValueError` is raised. The registry (`_WRITERS`) is the single source of the valid
names — `export_formats()` returns them.

## Row cardinality

One row is emitted **per matching log entry**. A log matched by several signatures,
or carrying several extracted values, still produces exactly one row: the streaming
join yields one SQL row per (log × annotation × extracted value) and `LogRow`
accumulates them. Distinct values for the same label are joined with `"; "`;
distinct signature ids are joined with `","` in CSV and kept as a JSON list in
JSON/JSONL.

Rows are ordered by `(timestamp_unix_ns ASC, id ASC)`.

## Base columns

Defined once in `_BASE_FIELDS`; both writers derive header/keys and values from it,
so the order below is exact and identical across formats.

| # | Column / key | Source | Notes |
|---|---|---|---|
| 1 | `timestamp` | `LogRow.timestamp_iso` | ISO 8601, ns-precise, formatted from `timestamp_unix_ns`. **Empty string** when the stored value is the `0` failure sentinel (never a misleading 1970 date) |
| 2 | `timestamp_unix_ns` | `logs.timestamp_unix_ns` | integer |
| 3 | `event_order` | `logs.event_order` | The forensic ordering rank — the merged real timeline across every source file; emitted so the tamper signal (wall-clock going backwards while `event_order` rises) is visible in the primary analyst output. NULL/empty if the extract never ran its ordering pass |
| 4 | `source_order` | `logs.source_order` | Physical position **within its own tracev3 file** (1-based, byte order) — the other half of the ordering evidence: `event_order` shows the merged timeline stays monotonic, `source_order` + `source_file` pin down exactly where in which file a row physically sat. NULL/empty if the ordering pass never ran |
| 5 | `source_file` | `source_files.file_path`, via `logs.tracev3_file_id` | The tracev3 file `source_order` ranks within, path relative to the logarchive root. NULL when the source file's provenance was not resolved |
| 6 | `process` | `processes.name` | |
| 7 | `pid` | `logs.pid` | |
| 8 | `tid` | `logs.tid` | |
| 9 | `log_level` | `log_levels.name` | |
| 10 | `event_type` | `event_types.name` | |
| 11 | `subsystem` | `subsystems.name` | |
| 12 | `category` | `categories.name` | |
| 13 | `message` | `logs.message` | The composed message |
| 14 | `matched_signatures` | rolled-up `kb_signatures.signature_id` | CSV: comma-joined in one cell. JSON/JSONL: a list of strings (empty list when unannotated) |

Any unresolved lookup is NULL in SQL, which becomes an empty cell in CSV and
`null` in JSON.

## Extracted-value columns

When the database carries the knowledge-base tables **and** `include_fields` is
true (the default; `export --no-fields` turns it off), the exporter first calls
`discover_labels()` to collect the sorted, distinct `extracted_values.label`
values among the *matching* rows only — so the column set reflects the filtered
result, not the whole database.

- **CSV** — one extra column per label, appended after `matched_signatures`, in
  sorted label order. A log with no value for a label gets an empty cell; several
  distinct values for one label are joined with `"; "`.
- **JSON / JSONL** — one extra key, `extracted_values`, holding an object of
  `label → value` containing **only the labels present on that log** (values
  joined the same way). The key is present on every row when fields are included,
  even if the object is empty.

`include_fields` is silently ineffective on a database that was never annotated
(`include_fields and has_kb`), so exporting an un-annotated database produces the
14 base columns only.

## CSV specifics

- Written with `csv.writer` defaults (comma delimiter, `"` quoting as needed,
  `\r\n` line terminator).
- Encoding is **UTF-8 with BOM** (`utf-8-sig`) so Excel auto-detects the encoding.

## JSON specifics

- `json` writes a pretty-ish array: `[`, then one compact object per line indented
  by two spaces, then `]`.
- `jsonl` writes one compact object per line, no wrapper.
- Both use `ensure_ascii=False`, so non-ASCII text stays readable.

## Examples

CSV (annotated database, labels `bssid` and `ssid` discovered):

```csv
timestamp,timestamp_unix_ns,event_order,source_order,source_file,process,pid,tid,log_level,event_type,subsystem,category,message,matched_signatures,bssid,ssid
2024-06-01T09:15:02.123456789Z,1717233302123456789,481920,392,7C2A9E11.../0000000000000123.tracev3,wifid,132,4210,Default,Log,com.apple.wifi,,Associated to HomeNet with bssid aa:bb:cc:dd:ee:ff,net.wifi_associate,aa:bb:cc:dd:ee:ff,HomeNet
```

JSONL row for the same entry:

```json
{"timestamp":"2024-06-01T09:15:02.123456789Z","timestamp_unix_ns":1717233302123456789,"event_order":481920,"source_order":392,"source_file":"7C2A9E11.../0000000000000123.tracev3","process":"wifid","pid":132,"tid":4210,"log_level":"Default","event_type":"Log","subsystem":"com.apple.wifi","category":null,"message":"Associated to HomeNet with bssid aa:bb:cc:dd:ee:ff","matched_signatures":["net.wifi_associate"],"extracted_values":{"ssid":"HomeNet","bssid":"aa:bb:cc:dd:ee:ff"}}
```

## Errors

`run_export` raises rather than returning exit codes:

| Exception | Cause |
|---|---|
| `FileNotFoundError` | the database path does not exist |
| `InvalidDatabaseError` | the file is not an analysis database (no `logs` table) |
| `ValueError` | format cannot be inferred / unknown format, malformed filter value, an annotation filter (`signature`/`action`/`tag`/`annotated_only`) on a database with no KB tables, or `message_match` without a usable full-text index |

It returns an `ExportResult(output_path, rows, fmt)`; `rows` is the number of log
entries written.

## Adding a format

Implement a `_write_<fmt>(out, rows, labels, include_fields) -> int` function and
register it in `_WRITERS` with its suffixes — suffix inference and the CLI
`--format` choices both derive from the registry.

## See also

- [Database schema](database-schema.md) — where each column comes from
- [Knowledge base](knowledge-base.md) — how labels are defined and extracted
- [`export` CLI](../cli/export.md)
