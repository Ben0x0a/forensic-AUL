# Identifying the log lines produced by an action

*"Which log lines does this device write when a user does X?"*

That question is what the **identify** workflow answers. It is a research
technique: rather than guessing which subsystem records an event, you capture the
device before and after the action and keep only what is new. The output is a
candidate set of log lines attributable to that action — the raw material from
which knowledge-base signatures are written.

> Identify is a **research tool**, not an evidence-processing step. Its defaults
> trade chain-of-custody paperwork for speed (`integrity="off"`, no full-text
> index). It runs against a test device you control, not against an exhibit.

---

## The method

```
   t0 ─── still pause ─── baseline capture ─── operator performs action ─── action capture
   └──────────── baseline window ────────────┘                              │
                                                                            ↓
                                   diff: keep post-cutoff lines not seen in the baseline
```

1. **Connect** to the device and confirm it is the right one.
2. **Capture `t0`** — *before* the still pause. This matters: the baseline window
   starts at `t0`, so both the idle wait *and* the USB/lockdown connection chatter
   land in the baseline noise set instead of leaking into the diff as false
   positives.
3. **Still pause** (default 60 s) — the device is left untouched so the baseline
   absorbs its idle chatter.
4. **Baseline acquisition.** Never skipped, even with a zero-second pause: the
   diff needs its cutoff regardless.
5. **The operator performs the action**, then signals completion.
6. **Action acquisition.**
7. **Extract both** archives to SQLite.
8. **Annotate the action database** against a knowledge base (optional — the
   baseline is diffed away and never needs annotations).
9. **Diff.**

### What the diff actually does

- The **cutoff** is `MAX(timestamp_unix_ns)` over the baseline database. Only rows
  newer than that are considered.
- The **noise set** is every `(message, process)` pair seen in the baseline. A
  post-cutoff row whose pair is already in that set is flagged `excluded` — the
  device says it all the time, so it says nothing about your action.
- Everything else is **retained**.

Two outputs, written — like the captures and databases the run produces — into
the run's own session directory `<output-dir>/<prefix>/` (see
[the `identify` page](../cli/identify.md#outputs) for the full folder layout):

| Output | Content |
|---|---|
| `<prefix>-identified.db` | **every** post-cutoff row, with an `excluded` flag, a `matched_signatures` column when the action database was annotated, plus a reversible `hidden_keys` prune layer and a `v_identified_visible` view |
| `<prefix>-identified.csv` | the retained rows only |

The SQLite output keeps the excluded rows deliberately: "the device already said
this" is a claim you must be able to re-inspect.

---

## CLI

### The full interactive run

```bash
python faul.py identify --case-number CASE-2024-001 -o ./identify-run
```

It connects, prints the device table and asks for confirmation, counts down the
still pause, tells you when to perform the action, waits for Enter, captures again,
extracts, annotates and diffs.

| Option | Default | Meaning |
|---|---|---|
| `--udid UDID` | first connected device | which device |
| `--case-number CASE` | `identify-<UTC timestamp>` | names the session directory and the artefact prefix |
| `-e/--exhibit-number`, `--analyst`, `--notes` | — | recorded metadata |
| `--still SECONDS` | `60` | idle pause before the baseline; `0` skips the pause |
| `--output-dir` / `-o DIR` | cwd | parent of the session directory; all archives, databases and diff outputs land inside it |
| `--yes` / `-y` | off | skip the device confirmation prompt |
| `--kb PATH` | `./knowledge_base` if it exists | annotate the action database |
| `--no-csv` | off | SQLite output only |
| `--batch-size N` | `100000` (`forensic_aul.config.BATCH_SIZE`) | extract batch size |

Knowledge-base handling differs by intent: an **explicit** `--kb` that fails to
load is an error (exit 1); the **implicit** default directory is best-effort — a
missing or unloadable one warns and the run continues unannotated.

Aborting: `Ctrl-C` exits 130; declining the confirmation exits 0 (declining is not
a failure). Both operator pauses are abortable.

Requires the `acquire` extra (`pymobiledevice3`) and a paired iOS device.

### Diff two captures you already have (`--diff`)

```bash
python faul.py identify --diff baseline.logarchive action.logarchive
python faul.py identify --diff baseline.db action.db --output-prefix ./run1-identified
```

`--diff` takes exactly two values and switches `identify` into its offline mode:
no device is used and the `acquire` extra is not needed. (There is no separate
`identify-diff` command.)

Each of the two values may be a `.logarchive` directory (extracted to a sibling
`.db` first) or a pre-built database. Without `--output-prefix`, outputs land
alongside the action input as `<stem>-identified.{csv,db}`. `--case-number` /
`--imei` are recorded if an extraction is needed.

---

## Library

Everything the CLI does is available programmatically, with each interaction point
injected as a callback — so a GUI, a script or a test drives the identical
sequence. See [../library/recipes.md](../library/recipes.md#run-the-identify-workflow-with-injected-callbacks)
for the full snippet.

```python
from forensic_aul import load_kb, run_identify_workflow, tty_bar_sink

res = run_identify_workflow(
    "CASE-2024-001",
    output_dir=Path("identify-run"),
    still_seconds=60,
    kb=load_kb(Path("knowledge_base")),
    confirm=lambda device: True,          # or prompt
    wait_still=lambda s: time.sleep(s),
    wait_for_action=lambda: input("perform the action, then Enter… "),
    status=print,
    progress=tty_bar_sink(),
)
```

**Returns** an `IdentifyResult`: `baseline_archive`, `action_archive`,
`baseline_db`, `action_db`, and the nested `diff` (`DiffResult` with
`sqlite_path`, `csv_path`, `retained`, `excluded`).

Callbacks: `confirm(device) -> bool` (returning `False` aborts),
`wait_still(seconds)`, `wait_for_action()`, `status(line)`, and `progress` (a
`ProgressSink` receiving weighted overall progress across the whole run — see
[../library/progress-and-errors.md](../library/progress-and-errors.md)). Any of
them may raise `AcquisitionAborted` to abort cleanly. All are invoked off the
event loop, so a blocking `input()` is fine.

If you already have two databases:

```python
from forensic_aul import run_diff

d = run_diff(Path("baseline.db"), Path("action.db"),
             Path("identified.csv"), Path("identified.db"))
```

---

## Reviewing the results

Open the diff database with `IdentifyResults` — in the GUI, the Identify hub's
**Results** tab does exactly this.

```python
from forensic_aul import IdentifyResults

with IdentifyResults(Path("identified.db")) as results:
    print(results.counts())    # ResultCounts(retained, noise, kb_known, hidden)
    for row in results.rows(limit=200):
        print(row["timestamp"], row["process"], row["message"])
```

### How to read the four counts

| Count | Meaning | What to do with it |
|---|---|---|
| `retained` | new, unexplained, not hidden | **your candidate set** — start here |
| `noise` | `excluded=1` — the pair was already in the baseline | ignore, but keep re-inspectable |
| `kb_known` | already matched by a knowledge-base signature | already understood; useful as confirmation that the action fired a known signature |
| `hidden` | matches a `hidden_keys` entry you added | your own pruning |

`rows()` and `count()` default to retained-only (`include_noise=False`,
`include_kb_known=False`, `include_hidden=False`), ordered by timestamp then id.
Widen deliberately with the flags, and use `search=` for a substring filter.

### Pruning noise, reversibly

The interesting lines are usually buried in per-run chatter that the baseline
happened to miss — a timer that fires every few minutes, a daemon logging its
heartbeat. Hide them:

```python
results.hide(message, process)        # hides every row with that exact pair
results.hidden_keys()                 # [(message, process), …]
results.unhide(message, process)      # fully reversible
```

Hiding is stored in the database, never destructive, and always undoable — which
is why it is safe to be aggressive. Work top-down: hide an obviously periodic line,
re-read the counts, repeat, until what remains plausibly belongs to the action.

### Exporting

```python
n = results.export_csv(Path("attributed.csv"))                      # retained + kb_known
n = results.export_csv(Path("everything.csv"), include_noise=True)
```

The header and column order match `run_diff`'s own CSV, so the export drops into
the same downstream tooling. `include_kb_known` defaults to `True` and
`include_noise` to `False`; hidden rows are never exported — the export reflects
your current pruning.

---

## Getting a clean result

- **Use a dedicated test device**, signed out of accounts you do not control and
  with as few background apps as possible.
- **Perform exactly one action**, and nothing else. Do not check notifications, do
  not answer a message, do not let the screen wake for something unrelated.
- **Keep the still pause.** It is what turns connection chatter into baseline noise
  instead of a false positive. Only use `--still 0` when you know the device was
  already quiet.
- **Act promptly after the baseline.** The longer the gap, the more unrelated
  activity accumulates in the action window.
- **Repeat the run.** A line that appears in two independent runs of the same
  action is a candidate; a line that appears once is a coincidence. This is the
  single most effective filter.
- **Vary one thing at a time** if you are comparing variants of an action.
- **Note the iOS version.** Log messages are version-specific; a signature derived
  here may not apply to another build.

Once a line is confirmed across runs, write it up as a knowledge-base signature so
future extractions annotate it automatically — see
[../formats/knowledge-base.md](../formats/knowledge-base.md).

---

## See also

- [Case workflow](case-workflow.md) · [Validation](validation.md)
- [../formats/identify-database.md](../formats/identify-database.md) — the diff database schema
- [../library/recipes.md](../library/recipes.md) · [../gui.md](../gui.md)
