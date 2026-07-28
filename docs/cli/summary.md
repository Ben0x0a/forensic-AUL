# `summary`

Print a high-level overview of an analysis database.

## Synopsis

```bash
faul.py summary DATABASE [--top N] [--buckets N]
```

## What it does

`summary` is a **read-only** overview of a database produced by
[`extract`](extract.md). It prints:

- **case metadata** — case number, IMEI, exhibit, analyst, source type and path,
  iOS model / build / version, the covered log time range, and the recorded
  hashes;
- **top-N processes**, **subsystems** and **log levels** by entry count;
- **annotated-action counts** — how many entries carry knowledge-base
  annotations, per action (empty until you run [`annotate`](annotate.md));
- a **temporal distribution** (Unicode histogram) of log entries across the
  covered window.

Run it **before** [`export`](export.md): it tells you which processes,
subsystems, levels and time windows are worth filtering on, so you do not export
two million rows to find out.

Nothing is written — the database is only read.

---

## Options

| Flag | Default | Meaning |
|---|---|---|
| `DATABASE` | **required** | SQLite database produced by `extract`. |
| `--top N` | `10` | How many entries to show per top-N section (processes, subsystems, levels). |
| `--buckets N` | `40` | Approximate number of buckets in the temporal histogram. The bucket width is rounded to a sensible interval, so the count is approximate. |

---

## Examples

```bash
# Standard overview
faul.py summary cases/case.db

# Wider top-N lists and a finer timeline
faul.py summary cases/case.db --top 25 --buckets 120

# Coarse timeline for a quick shape check
faul.py summary cases/case.db --buckets 10
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Overview printed. |
| `1` | The database does not exist (`FileNotFoundError`) or is not a valid analysis database (`InvalidDatabaseError`, a subclass of `ValueError`). |

Any other exception propagates to the CLI crash handler, which writes a crash
report — see [`redact-errors`](redact-errors.md).

---

## Common pitfalls

- **`summary` never annotates.** The annotated-action section stays empty until
  [`annotate`](annotate.md) has been run against this database.
- **A large `--top` / `--buckets` costs query time**, not correctness; on a
  multi-million-row database the aggregate scans dominate.
- **The histogram is approximate by design.** `--buckets` is a target, not a
  guarantee.
- **It reports what is in the database, not what was on the device.** A bounded
  acquisition (`acquire --start-time`, `--age-limit`) narrows the covered window;
  check the case metadata before concluding that logs are "missing".

---

## See also

- [`extract`](extract.md) — produce the database
- [`export`](export.md) — pull out the rows this overview pointed you at
- [`annotate`](annotate.md) — populate the annotation counts
- [Database schema](../formats/database-schema.md) ·
  [Forensic model](../concepts/forensic-model.md)
