# CLI reference

The entry point is `faul.py` at the repository root:

```bash
python faul.py [--version] [-v] <COMMAND> [options]
python faul.py                 # no COMMAND → launches the GUI
```

The launcher (`launcher/cli.py`) is a thin dispatcher: it asks each module in
`launcher/cmds/` to register its own subparser, then routes to that module's
`run(args)` and exits with its return code.

---

## Commands

Listed in **workflow order** — the order you would normally run them in.

| Command | Purpose |
|---|---|
| [`acquire`](acquire.md) | Acquire a `.faul` (logarchive + sidecar) from a USB-connected iOS device. |
| [`extract`](extract.md) | Parse a logarchive / sysdiagnose / `.faul` / FFS acquisition into a SQLite database. |
| [`summary`](summary.md) | Print a high-level summary of an analysis database. |
| [`kb`](kb.md) | Inspect / validate the YAML knowledge base (read-only; never touches a database). |
| [`annotate`](annotate.md) | Apply the knowledge base to an extracted database, writing annotations. |
| [`export`](export.md) | Export an analysis database to CSV / JSON / JSONL with filters. |
| [`verify-hash`](verify-hash.md) | Verify the chain of custody of an extracted database (re-hash source + operational log). |
| [`identify`](identify.md) | Identify the log lines produced by a user action (interactive baseline → action → diff, or `--diff` on two existing captures). |
| [`validate-tool`](validate-tool.md) | Validate extract output against Apple's `log show` ndjson ground truth (L1/L2/L3 self-check). |
| [`redact-errors`](redact-errors.md) | List local crash reports, or redact one into a shareable bug report. |

Registration order in `launcher/cli.py` **is** this workflow order, so
`faul.py --help` prints the commands in exactly the order above.

---

## Global options

These are defined on the root parser and must be given **before** the command
name (`python faul.py -v extract …`, not `python faul.py extract -v`).

| Flag | Default | Meaning |
|---|---|---|
| `-h, --help` | — | Show help and exit. Also available per command: `faul.py <COMMAND> --help`. |
| `--version` | — | Print `forensic-aul <version>` and exit. The version comes from `forensic_aul.__version__`. |
| `-v, --verbose` | off | Show `DEBUG` messages **on the console**. The operational log file is always written at `INFO`, whatever this flag says. |

There are no other global flags — in particular there is **no** global
`--log-file` / `--log-level` / `--quiet`. Log-file placement is decided per
extract session (see [Getting started](../getting-started.md#4-where-the-outputs-go)),
and `verify-hash` / `redact-errors` take their own path overrides.

### No subcommand

Invoking `faul.py` with no command launches the GUI via `launcher/gui.py`
(`run_gui()`), and the process exits with Qt's exit code — or `1` if `PySide6`
is not installed. See [`docs/gui.md`](../gui.md).

---

## Recommended order of use

```
acquire ──► extract ──► summary ──► annotate ──► export
   │            │           │                       ▲
   │            └───────────┴──► verify-hash        │
   └──► identify ────────────────────────────────► (diff outputs)
```

1. **`acquire`** — collect a `.faul` from the device (skip if you already have an
   acquisition: sysdiagnose, FFS zip, or a logarchive).
2. **`extract`** — turn the acquisition into `case.db`. This is the only command
   that writes an operational log and chain-of-custody hashes.
3. **`summary`** — see what is in the database before filtering anything.
4. **`kb validate`** then **`annotate`** — apply signatures if you use a
   knowledge base. `annotate` can be re-run at will as the KB improves; no
   re-extraction is needed.
5. **`export`** — produce the filtered CSV / JSON / JSONL deliverable.
6. **`verify-hash`** — before disclosure or handover, prove nothing changed since
   extraction.

Side tracks:

- **`identify`** — attribute log lines to a specific user action, independent of
  the main case pipeline. Use `identify --diff BASELINE ACTION` to re-run just
  the diff on captures you already have.
- **`validate-tool`** — prove FAUL's output matches Apple's own tooling on this
  evidence; a trust check, not part of the normal deliverable path.
- **`redact-errors`** — only when something crashed.

---

## Exit codes

Conventions across the CLI:

| Code | Meaning |
|---|---|
| `0` | Success (and, for `acquire` / `identify`, a clean operator-initiated abort). |
| `1` | Invocation error, missing input, or a failed operation. |
| `2` | `verify-hash` only: the database or its metadata could not be read at all. |
| `130` | `extract` / `identify`: interrupted with Ctrl-C (SIGINT). |

Each command page documents its own exact codes.

---

## See also

- [Getting started](../getting-started.md)
- [Architecture](../architecture.md)
- [Using `forensic_aul` as a library](../library/index.md)
- [Workflows](../workflows/)
