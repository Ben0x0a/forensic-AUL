# `kb`

Inspect and validate the YAML knowledge base. Read-only.

## Synopsis

```bash
faul.py kb [--kb PATH] list [--tag TAG] [--process P] [--json]
faul.py kb [--kb PATH] show ID
faul.py kb [--kb PATH] validate
faul.py kb [--kb PATH] labels
faul.py kb [--kb PATH] stats
```

## What it does

`kb` performs **read-only** operations on the YAML knowledge base. It never
opens or touches an analysis database — to apply signatures to a database, use
[`annotate`](annotate.md).

Every invocation loads and structurally parses the whole knowledge base first, so
a malformed YAML fails any action, not just `validate`.

The knowledge base itself is documented in
[`docs/formats/knowledge-base.md`](../formats/knowledge-base.md).

---

## Common option

| Flag | Default | Meaning |
|---|---|---|
| `--kb PATH` | `./knowledge_base` | Knowledge-base root directory. Must be given **before** the action: `faul.py kb --kb /opt/kb list`. |

An action is **required** — `faul.py kb` with no action is an argparse error
(exit `2`).

---

## Actions

### `list` — list signatures

| Flag | Default | Meaning |
|---|---|---|
| `--tag TAG` | none | Only signatures carrying this tag. Single value, not repeatable. |
| `--process P` | none | Only signatures that match this process name (`match.process`, exact). Single value. |
| `--json` | off | Emit machine-readable JSON instead of the human table. |

Both filters are AND-ed when given together.

### `show ID` — one signature in full

| Argument | Meaning |
|---|---|
| `ID` | The signature id to print. Unknown id → exit `1`. |

Prints the complete definition: match criteria, action, tags, confidence,
extracted fields, and the source file it came from.

### `validate` — lint the knowledge base

> This is the `kb` sub-action `kb validate`. It is **not** the top-level
> [`validate-tool`](validate-tool.md) command, which checks FAUL's parser
> against Apple's `log show`.

Loads every YAML, reports structural errors, and warns about extracted-field
**labels that are not in the controlled vocabulary** (`labels.yaml`), with
`difflib`-based "did you mean…" suggestions for near-misses.

Run this before [`annotate`](annotate.md).

### `labels` — print the controlled vocabulary

Prints the label vocabulary defined in `labels.yaml` — the set of names that
extracted fields are allowed to use.

### `stats` — knowledge-base counts

Prints totals: number of signatures overall, by tag, by confidence level, and by
source file.

---

## Examples

```bash
# What is in the default knowledge base
faul.py kb list
faul.py kb stats

# Filtered listing, machine-readable
faul.py kb list --tag connectivity --json | jq '.[].id'

# Everything a single process is covered by
faul.py kb list --process locationd

# Inspect one signature
faul.py kb show airplane_mode_toggle

# Lint before annotating
faul.py kb validate

# The allowed extracted-field labels
faul.py kb labels

# A knowledge base kept outside the repo
faul.py kb --kb /opt/faul-kb validate
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | The action completed. **Note:** `validate` returns `0` even when it reports problems — read its output, do not gate on the exit code. |
| `1` | The knowledge base failed to load (`KnowledgeBaseError`: missing directory, malformed YAML, schema violation), or `show` was given an unknown signature id. |
| `2` | argparse error — no action given, or an unknown action / flag. |

---

## Common pitfalls

- **`--kb` goes before the action.** `faul.py kb list --kb PATH` is an argparse
  error; `faul.py kb --kb PATH list` is correct.
- **The default `./knowledge_base` is relative to the current working
  directory.** Running from outside the repo needs an explicit `--kb`.
- **`kb validate` does not fail the build.** It exits `0` and prints its
  findings; parse the output if you want a CI gate.
- **`list --tag` / `--process` take a single value each** — unlike
  `annotate --tag`, they are not repeatable.
- **`list --process` is an exact match** on `match.process`, not a substring.
- **`kb` never touches a database.** If nothing shows up in your export, the
  missing step is [`annotate`](annotate.md), not `kb`.

---

## See also

- [`annotate`](annotate.md) — apply these signatures to a database
- [`export`](export.md) — filter and pivot on signatures, tags and extracted values
- [Knowledge-base format](../formats/knowledge-base.md)
