# `annotate`

Apply the YAML knowledge base to an extracted SQLite database.

## Synopsis

```bash
faul.py annotate DATABASE [--kb PATH] [--signature ID ...] [--tag TAG ...]
```

## What it does

`annotate` runs every selected knowledge-base signature against the `logs`
table and writes:

- one row per match into **`log_annotations`**;
- one row per signature that produced at least one hit into **`kb_signatures`**;
- any named values a signature extracts into the **`extracted_values`** EAV
  table (these become `<signature_id>.<field>` columns in
  [`export`](export.md)).

Existing log rows are **never modified**. Multi-match is supported: one log entry
can carry annotations from several signatures.

Each run stores the knowledge base's **`kb_sha256` + `kb_version`** on every
annotation, so it is always provable which KB revision produced a given finding.
The annotation schema is created on demand if the database has none yet.

Because annotation is decoupled from extraction, you can **re-run it at will** —
after improving the knowledge base, for example — without re-extracting. Runs are
timestamped to microsecond precision so a rapid identical re-run is not rejected
by the uniqueness guard.

---

## Options

| Flag | Default | Meaning |
|---|---|---|
| `DATABASE` | **required** | SQLite database produced by `extract`. |
| `--kb PATH` | `./knowledge_base` | Knowledge-base root directory. |
| `--signature ID` | all signatures | Restrict to this signature id. **Repeatable.** |
| `--tag TAG` | all signatures | Restrict to signatures carrying this tag. **Repeatable.** |

`--signature` and `--tag` are **unioned**, not intersected: a signature is
selected if its id is in `--signature` **or** it carries one of the `--tag`
values. With neither flag, every signature in the KB runs.

---

## Output

A header naming the database and the loaded knowledge base, then one line per
signature with its match count and elapsed time, then a result block with the
totals (signatures run, signatures that matched, total matches).

---

## Examples

```bash
# Everything in ./knowledge_base
faul.py annotate cases/case.db

# A knowledge base kept elsewhere
faul.py annotate cases/case.db --kb /opt/faul-kb

# Only two signatures
faul.py annotate cases/case.db \
    --signature airplane_mode_toggle --signature wifi_join

# Everything tagged 'connectivity' or 'location'
faul.py annotate cases/case.db --tag connectivity --tag location

# Re-run after editing the KB — no re-extraction needed
faul.py kb validate && faul.py annotate cases/case.db
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Annotation completed (including when zero signatures matched). |
| `1` | `DATABASE` is not a file; the knowledge base failed to load or validate (`KnowledgeBaseError`); or the annotation run raised an exception (the traceback is logged). |

---

## Common pitfalls

- **The KB path defaults to `./knowledge_base` relative to the current working
  directory**, not to the repository root. Running from elsewhere needs `--kb`.
- **`--signature` and `--tag` combine as OR.** To run exactly one signature, use
  `--signature` alone.
- **Zero matches is a success, not an error.** Check the printed counts, not just
  the exit code.
- **Validate before annotating.** `faul.py kb validate` catches structural errors
  and off-vocabulary labels that would otherwise silently produce nothing.
- **Repeated runs accumulate annotation rows**, each stamped with its own
  `applied_at`, `kb_version` and `kb_sha256`. That is deliberate — the history of
  what each KB revision found is preserved. Filter on the KB hash if you need a
  single run's view.
- **A signature referencing format strings absent from this database matches
  nothing**, quietly and cheaply — it is not an error.

---

## See also

- [`kb`](kb.md) — inspect and validate the knowledge base first
- [`export`](export.md) — filter on `--signature` / `--tag` / `--action` and emit
  the extracted-value columns
- [`summary`](summary.md) — see annotated-action counts
- [Knowledge-base format](../formats/knowledge-base.md) ·
  [Database schema](../formats/database-schema.md)
