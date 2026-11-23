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
                 [--notes TEXT] [--udid UDID] [--still SECONDS] [--settle SECONDS]
                 [--repeat N]
                 [--output-dir DIR] [--yes] [--action TEXT]
                 [--show-identifiers] [--kb PATH] [--no-csv] [--batch-size N]
```

### What it does

`identify` answers "which log lines does *this* action produce?" by acquiring a
baseline, having you perform the action, acquiring again, and diffing:

1. Connect to the device and show its summary for confirmation, **masked** by
   default (name, phone number, IMSI, ICCID and MACs hidden; UDID, IMEI and
   serial cut to their last 4 characters — `--show-identifiers` shows them).
2. Remind you to **disable Auto-Lock** (*Settings › Display & Brightness ›
   Auto-Lock › Never*) unless lock and unlock events are what you study: a
   lock or unlock during the run puts its lines in the result.
3. Keep the device **untouched for `--still` seconds** so idle and connection
   noise lands in the *baseline* rather than in the result. Meanwhile you are
   asked to describe the action you will perform; a countdown follows.
4. **Prepare** (optional): do what must happen before the action but is not of
   interest — unlock, open the app, reach the right screen — then press Enter.
   Those lines land in the baseline, so the result keeps the action itself. A
   **settle** pause (`--settle`, default 10 s) follows, so the background work
   the preparation set off ends inside the baseline. Answering *N* skips both.
   Don't prepare any part of the action you study: it would be removed as noise.
5. Acquire the **baseline** logarchive. Its window starts before the still
   pause, so the pause and the preparation are both in it.
6. Prompt: *"Perform the action on the device now. Press Enter when complete."*
7. Acquire the **post-action** logarchive. You can then edit the description.
8. Extract both to SQLite.
9. **Diff** them, so only lines attributable to the action remain, and
   optionally annotate the action database with a knowledge base.

The description is stored in the identified database (table `identify_run`).

**Repeating the action** (`--repeat N`) is the way to cut the result down. A
line that belongs to the action appears in every repetition; background noise
that slipped past one baseline rarely does it N times. Each repetition gets its
own files (`<prefix>-<n>-baseline.logarchive`, … `<prefix>-<n>-identified.db`),
and the ranking of the retained templates — by how many repetitions had them as
*new template* — is written to `<prefix>-repeat.csv` (and `<prefix>-repeat.db`).
`N/N` means present in every action window and absent from every baseline: read
those first. The CSV is the way to work with the ranking (a spreadsheet, a
script); the GUI names it in its summary and has no viewer for it. The top lines
are printed at the end.

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
| `--still SECONDS` | `60` (or the `[identify]` settings) | Seconds to keep the device untouched before the baseline acquisition. `0` skips the pause. |
| `-o, --output-dir DIR` | `.` (current directory) | Directory for the archives, databases and diff outputs. |
| `--repeat N` | `1` | Run the whole cycle (still, preparation, baseline, action) N times, each diffed against its own baseline, then rank the templates across repetitions into `<prefix>-repeat.db` (see below). |
| `--settle SECONDS` | `10` (or the `[identify]` settings) | Seconds to keep the device untouched after a preparation. Not used when nothing was prepared. |
| `-y, --yes` | off | Skip the device confirmation prompt before the baseline acquire. |
| `--action TEXT` | asked | Description of the action; skips both description prompts. |
| `--show-identifiers` | off | Show the device identifiers in full in the summary. |

#### Knowledge base

| Flag | Default | Meaning |
|---|---|---|
| `--kb PATH` | the shipped KB (`forensic_aul/knowledge_base/`); if it cannot be loaded, the run continues unannotated | Knowledge base used to annotate the action database. |

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
| `--batch-size N` | the `[identify.extract]` settings (`1000`) | Batch size for the extract pipeline used on both captures. |

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
| `--batch-size N` | the `[identify.extract]` settings (`1000`) | Batch size for any extraction it has to perform. |

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
- **Both captures are extracted with the `[identify.extract]`
  [settings](../configuration.md)** (defaults: batch 1000, no full-text index,
  no hashing, automatic jobs) in both modes.
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
