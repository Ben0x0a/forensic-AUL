# File and data formats

Reference documentation for every format forensic_AUL reads or writes.

| Document | What it covers |
|---|---|
| [Database schema](database-schema.md) | The SQLite analysis database produced by `extract` — every table, column, index, the FTS5 index, the annotation tables, and the stable `v_logs` / `query_logs` read surface |
| [`.faul` container](faul-format.md) | The portable evidence container: stored zip, `faul/manifest.json` marker, layout, detection and unpacking |
| [Acquisition sidecar](acquisition-sidecar.md) | The acquisition report JSON written by `acquire` (embedded in a `.faul`, or loose with `--raw`), and how `extract` auto-fills case fields from it |
| [Knowledge base](knowledge-base.md) | The YAML knowledge base: directory layout, the full signature schema, value extraction, the `labels.yaml` vocabulary, linting and versioning |
| [Export formats](export-formats.md) | The exact CSV / JSON / JSONL output of `export`, including how annotations and extracted values become columns |
| [Identify database](identify-database.md) | The diff database produced by `identify` / `run_diff`: `identified_logs`, the `excluded` flag, `hidden_keys`, `v_identified_visible`, and the retained-lines CSV |

## See also

- [Architecture](../architecture.md) — how the pieces fit together
- [Concepts](../concepts/unified-logs.md) — unified logs, [sources](../concepts/sources.md), the [forensic model](../concepts/forensic-model.md)
- [CLI reference](../cli/extract.md) and the [library API](../library/index.md)
