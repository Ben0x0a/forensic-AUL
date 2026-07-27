# `identify`

Attribute log lines to a specific user action.

One command, **two modes**:

- **interactive mode** (default) — the full workflow, from device acquisition to
  diff. Needs a connected iOS device and the `acquire` extra.
- **diff-only mode** (`--diff BASELINE ACTION`) — only the diff step, on two
  archives or databases you already have. No device, no `acquire` extra.

There is no separate `identify-diff` command; `--diff` replaces it.

---

## Interactive mode

### Synopsis

```bash
faul.py identify [--case-number CASE] [-e EXHIBIT] [--analyst NAME]
                 [--notes TEXT] [--udid UDID] [--still SECONDS]
                 [--output-dir DIR] [--yes] [--kb PATH] [--no-csv]
                 [--batch-size N]
```

### What it does

`identify` answers "which log lines does *this* action produce?" by acquiring a
baseline, having you perform the action, acquiring again, and diffing:

1. Connect to the device and show its summary for confirmation.
2. Keep the device **untouched for `--still` seconds** so idle and connection
   noise lands in the *baseline* rather than in the result.
3. Acquire the **baseline** logarchive.
4. Prompt: *"Perform the action on the device now. Press Enter when complete."*
5. Acquire the **post-action** logarchive.
6. Extract both to SQLite.
7. **Diff** them, so only lines attributable to the action remain, and
   optionally annotate the action database with a knowledge base.

Acquisition is iOS via **pymobiledevice3** (needs the `acquire` extra; userspace,
no root). The diff itself is pure SQLite and cross-platform.

### Options

#### Device selection

| Flag | Default | Meaning |
|---|---|---|
| `--udid UDID` | first connected device | UDID of the device to use. |

#### Case identifiers

| Flag | Default | Meaning |
|---|---|---|
| `--case-number CASE` | `identify-<UTC timestamp>` | Investigation / case reference. Also used as the output filename prefix. |
| `-e, --exhibit-number EXHIBIT` | `None` | Exhibit / item reference. |
| `--analyst NAME` | `None` | Analyst name. |
| `--notes TEXT` | `None` | Free-text notes. |

#### Acquisition options

| Flag | Default | Meaning |
|---|---|---|
| `--still SECONDS` | `60` | Seconds to keep the device untouched before the baseline acquisition. `0` skips the pause. |
| `-o, --output-dir DIR` | `.` (current directory) | Directory for the archives, databases and diff outputs. |
| `-y, --yes` | off | Skip the device confirmation prompt before the baseline acquire. |

#### Knowledge base

| Flag | Default | Meaning |
|---|---|---|
| `--kb PATH` | `./knowledge_base` **if it exists**, else no annotation | Knowledge base used to annotate the action database. |

The two cases behave differently on failure:

- **explicit `--kb PATH`** — a load failure is a hard error (exit `1`);
- **implicit default** — a missing directory means "run unannotated"; an
  unloadable one logs a warning and the workflow continues unannotated.

#### Output

| Flag | Default | Meaning |
|---|---|---|
| `--no-csv` | off (CSV written) | Skip the retained-lines CSV; write only the SQLite output. |

#### Performance

| Flag | Default | Meaning |
|---|---|---|
| `--batch-size N` | `100000` (`forensic_aul.config.BATCH_SIZE`) | Batch size for the extract pipeline used on both captures. |

### Outputs

Every run writes into its own **session directory** under `--output-dir`, named
with the run prefix `<case>-<imei|udid>-<UTC>` (or `identify-<UTC>` when no case
number is given) — so one run is one self-contained folder to archive or hand
over, never six files mixed in with other runs:

```
<output-dir>/
└── <prefix>/
    ├── <prefix>-baseline.logarchive
    ├── <prefix>-action.logarchive
    ├── <prefix>-baseline.db
    ├── <prefix>-action.db
    ├── <prefix>-identified.csv
    └── <prefix>-identified.db
```

The prefix is repeated on each file so a file stays self-identifying if it is
copied out of the folder.

| File | Contents |
|---|---|
| `<prefix>-baseline.logarchive` | the baseline capture |
| `<prefix>-action.logarchive` | the post-action capture |
| `<prefix>-baseline.db` | extracted baseline |
| `<prefix>-action.db` | extracted post-action capture |
| `<prefix>-identified.csv` | **retained lines only** (omitted with `--no-csv`) |
| `<prefix>-identified.db` | **every** post-baseline line, each carrying an `excluded` flag |

The `.db` is the forensically complete artefact: nothing is thrown away, the
excluded lines are simply marked. The CSV is the working view.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Workflow completed — **or** the operator declined at the confirmation prompt / aborted (`AcquisitionAborted`). |
| `1` | An explicit `--kb` failed to load; `pymobiledevice3` missing (`ImportError`); a bad value (`ValueError`); acquisition failed (`AcquisitionError`); or an unexpected error (a crash report is written). |
| `130` | Interrupted with Ctrl-C. |

### Examples

```bash
# Standard run, 60 s settle, outputs in ./identify-runs
faul.py identify --case-number CASE-2024-001 --output-dir ./identify-runs

# Skip the settle pause and the device prompt (noisier, faster)
faul.py identify --case-number CASE-2024-001 --still 0 --yes

# Specific device, longer settle, annotate with an external KB
faul.py identify --udid 00008030-0011… --still 120 --kb /opt/faul-kb

# SQLite only, no CSV
faul.py identify --case-number CASE-2024-001 --no-csv
```

---

## Diff-only mode (`--diff`)

### Synopsis

```bash
faul.py identify --diff BASELINE ACTION [--output-prefix PREFIX]
                 [--case-number CASE] [--imei IMEI] [--batch-size N]
```

`--diff` takes **exactly two values**. Passing it switches the command into the
offline mode: every device-related option is ignored and nothing is acquired.

### What it does

Runs **only the diff step** against captures you already have. No device, no
acquisition, no `acquire` extra — useful for re-diffing after improving
something, or for working on another machine.

Each of `BASELINE` and `ACTION` may be:

- a **`.db` file** — used as-is; or
- a **`.logarchive` directory** — extracted first to a sibling `<name>.db`. A
  sibling `.db` left by a previous run is **reused** rather than re-extracted.

Anything else (a `.tar.gz`, a `.faul`, a `.zip`, a directory without the
`.logarchive` suffix) is rejected with exit `1` — unlike [`extract`](extract.md),
this command does **not** auto-detect other source types.

### Options

| Flag | Default | Meaning |
|---|---|---|
| `--diff BASELINE ACTION` | off (interactive mode) | The two captures to diff. Each is a `.logarchive` directory or a `.db` file. |
| `--output-prefix PREFIX` | `<action-stem>-identified`, alongside `ACTION` | Path prefix for the outputs; `.csv` and `.db` are appended. |
| `--case-number CASE` | `IDENTIFY` | Case number recorded if a `.logarchive` has to be extracted. |
| `--imei IMEI` | `UNKNOWN` | IMEI recorded if a `.logarchive` has to be extracted. |
| `--batch-size N` | `100000` (`forensic_aul.config.BATCH_SIZE`) | Batch size for any extraction it has to perform. |

`--output-prefix` and `--imei` are only meaningful together with `--diff`.

### Outputs

| File | Contents |
|---|---|
| `<prefix>.csv` | retained lines only |
| `<prefix>.db` | every post-baseline line, with the `excluded` flag |

Diff-only mode always writes the CSV — `--no-csv` applies to the
interactive mode only.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Diff written. |
| `1` | An input is neither a `.db` file nor a `.logarchive` directory; a required extraction failed; or the diff raised an exception (a crash report is written). |

### Examples

```bash
# Two logarchives (extracted on the fly, reusing any sibling .db)
faul.py identify --diff before.logarchive after.logarchive

# Two existing databases, custom output location
faul.py identify --diff runs/base.db runs/action.db \
    --output-prefix results/airplane-mode

# Record proper case identifiers on the implicit extractions
faul.py identify --diff before.logarchive after.logarchive \
    --case-number CASE-2024-001 --imei 350000000000000
```

---

## Common pitfalls

- **`--still 0` pollutes the result.** Idle chatter and USB-connection noise then
  land in the post-action capture and look like they belong to the action. The
  60 s default exists for a reason.
- **`identify` returns `0` when the operator aborts.** Check for the output files
  rather than the exit status if you script it.
- **`--case-number` is optional here** (unlike [`acquire`](acquire.md)), and
  defaults to a timestamped label — which then names all the output files.
- **`--batch-size` defaults to `100000`** in both modes — the same
  `forensic_aul.config.BATCH_SIZE` the standalone `extract` uses.
- **Diff-only mode reuses a sibling `.db`.** After changing anything about
  extraction, delete the stale sibling or the old database is silently reused.
- **Diff-only mode only accepts `.db` and `.logarchive`** — extract other source
  types with [`extract`](extract.md) first.
- **`--diff` is not a flag with one value.** It consumes the next *two*
  arguments; put it last, or follow it with another `--option`.
- **`--output-prefix` sets a prefix, not a filename**: `.csv` and `.db` replace
  whatever suffix you give it.
- **The action window is bounded by what the device logged**, not by your
  patience — a long gap between the two acquisitions widens the diff.

---

## See also

- [`acquire`](acquire.md) — the underlying device acquisition
- [`extract`](extract.md) · [`annotate`](annotate.md)
- [Forensic model](../concepts/forensic-model.md) ·
  [Unified logs](../concepts/unified-logs.md)
- [Workflows](../workflows/)
