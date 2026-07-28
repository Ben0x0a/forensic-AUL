# Progress, errors and logging

How a long operation reports its progress, what it raises when it refuses, and how
its diagnostics reach your logs. All three follow the same principle: **the library
never owns the console.** It emits events and raises exceptions; the host decides
what the user sees.

---

## Progress

### The protocol

Two names, both exported from the top level:

```python
from forensic_aul import ProgressEvent, ProgressSink
```

```python
@dataclass(frozen=True)
class ProgressEvent:
    overall: float          # 0.0 … 1.0 across all phases (monotonically rising)
    phase: str              # name of the current phase
    phase_fraction: float   # 0.0 … 1.0 within the current phase
    detail: str = ""        # short human detail, e.g. "12/56" or a file name

ProgressSink = Callable[[ProgressEvent], None]
```

A **sink** is just a callable that consumes events. Pass one as the `progress=`
keyword; `None` (the default) means "no progress wanted" and makes every internal
reporter call a cheap no-op.

Two operations accept `progress=` today: `run_extract` and
`run_identify_workflow`.

```python
from forensic_aul import run_extract, tty_bar_sink

run_extract(src, Path("case.db"), case_number="C1", progress=tty_bar_sink())
```

### The three ready-made sinks

| Sink | Signature | Behaviour |
|---|---|---|
| `tty_bar_sink` | `(stream: TextIO \| None = None, width: int = 30) -> ProgressSink \| None` | A live one-line terminal bar written to `stream` (default `sys.stderr`). **Returns `None` when the stream is not a TTY** — deliberately, so a carriage-return bar can never corrupt piped output or interleave with the forensic log file. Because `None` is a valid sink value, `progress=tty_bar_sink()` is always safe. |
| `logging_progress_sink` | `(logger: logging.Logger, every_percent: int = 5) -> ProgressSink` | Emits an INFO line each time overall progress crosses another `every_percent` step. The right choice for non-interactive / audited runs: progress lands in the operational log instead of a transient bar. |
| `callback_progress_sink` | `(fn: Callable[[str], None], every_percent: int = 10) -> ProgressSink` | Hands one formatted string per emitted step to a plain callable — `"progress  40%  parse  12/56"`. An adapter for hosts that already have their own log function (a GUI status setter, a plugin framework's `logfunc`) and should not have to understand `ProgressEvent`. |

```python
import logging
from forensic_aul import callback_progress_sink, logging_progress_sink, run_extract

log = logging.getLogger("mytool")
run_extract(src, db, progress=logging_progress_sink(log, every_percent=10))

# or, for a host with its own logging function:
run_extract(src, db, progress=callback_progress_sink(logfunc))
```

Both threshold sinks emit the very first event (start), then each crossing, and
always at 100 %.

### Writing your own sink

A sink is a one-argument callable — anything works: a function, a bound method, a
`lambda`, a Qt signal emitter.

```python
def sink(event):
    ui.set_progress(int(event.overall * 100))
    ui.set_label(f"{event.phase}: {event.detail}")

run_extract(src, db, progress=sink)
```

Two guarantees you can rely on:

- **`overall` rises monotonically** and reaches `1.0` exactly once, at the end
  (the reporter forces it, so a skipped phase never leaves the bar short).
- **A misbehaving sink never breaks the operation it observes.** Exceptions raised
  inside a sink are caught and logged at DEBUG. Progress is cosmetic; evidence
  processing is not.

If your sink touches a UI, remember it is called from the worker thread/process
that is doing the work — marshal to the UI thread yourself (this is exactly what
the GUI's workers do, see [../gui.md](../gui.md)).

### Phase weighting

An operation declares its phases with **relative weights** once, so the overall bar
covers the *entire* run rather than just its longest loop. Weights are ratios —
only their proportions matter. A step with no natural sub-progress (a single
monolithic SQL statement) simply jumps 0 → 1 inside its phase, and its weight keeps
the overall bar moving sensibly.

`run_extract` phases:

| Phase | Weight | Covers |
|---|---|---|
| `prepare` | 0.08 | source preparation + hashing + timesync + string cache + oversize scan |
| `parse` | 0.55 | the main parse pass, weighted by tracev3 bytes |
| `ordering` | 0.17 | assigning the forensic ordering |
| `index` | 0.13 | building the deferred indexes |
| `fts` | 0.07 | the deferred FTS rebuild (only with `fast_fts=True`) |

`run_identify_workflow` phases:

| Phase | Weight |
|---|---|
| `connect` | 0.02 |
| `still` | 0.04 |
| `baseline` | 0.12 |
| `wait` | 0.02 |
| `action` | 0.12 |
| `extract-baseline` | 0.26 |
| `extract-action` | 0.26 |
| `annotate` | 0.04 |
| `diff` | 0.12 |

The extract phases dominate the identify run because parsing is by far the slowest
step; `wait` and `annotate` keep a small non-zero weight because they can
legitimately take a moment. Each nested `run_extract`'s own 0…1 progress advances
the corresponding phase, so one sink sees a single smooth 0…100 % across the whole
workflow.

Treat the phase *names* as human-facing detail, not as an API to branch on — they
can change as pipelines evolve. `overall` is the stable part.

---

## Errors

### The hierarchy

```
Exception
└── ForensicAULError                     ← catch this
    ├── SourceError            (also ValueError)
    ├── InvalidDatabaseError   (also ValueError)
    ├── KnowledgeBaseError     (also ValueError)
    └── AcquisitionError
        └── AcquisitionAborted
```

**Every error the library raises on purpose derives from `ForensicAULError`.** One
handler covers "the library rejected the input / could not do the work", while
genuine bugs (`AttributeError`, `sqlite3` internals, …) still propagate loudly.

```python
from forensic_aul import ForensicAULError, query_logs, run_extract

try:
    res  = run_extract(src, db, case_number="C1")
    rows = list(query_logs(res.db_path, subsystem="com.apple.locationd"))
except ForensicAULError as exc:
    print(f"forensic_aul rejected the request: {exc}")
```

| Exception | Raised when |
|---|---|
| `SourceError` | an evidence source could not be detected, validated or prepared (`prepare_source`, and `run_extract` by extension) |
| `InvalidDatabaseError` | the path exists but is not an analysis database (not SQLite, or no `logs` table). From the path-based readers: `query_logs`, `count_logs`, `fetch_logs`, `fetch_context`, `LogStore`, `run_export`, `summarise`, `annotate_database`, `verify_database`. `IdentifyResults` raises it for a file that is not a *diff* database (no `identified_logs` table). |
| `KnowledgeBaseError` | `load_kb` found a malformed or invalid knowledge base |
| `AcquisitionError` | `acquire` / `run_identify_workflow` failed to connect, collect, or write |
| `AcquisitionAborted` | the `confirm` hook returned `False`, or a workflow callback aborted. A subclass of `AcquisitionError`, so catch it *first* if you want to treat "the operator said no" differently from a failure. |

### Backward compatibility with builtins

Each concrete error also subclasses the builtin type the code historically raised —
`SourceError`, `InvalidDatabaseError` and `KnowledgeBaseError` are `ValueError`s.
Existing `except ValueError` code keeps working; the hierarchy only *adds* a common
base.

Builtin exceptions keep their conventional meaning and are **not** part of
`ForensicAULError`:

| Builtin | Meaning here |
|---|---|
| `FileNotFoundError` | a path that must exist does not |
| `FileExistsError` | `run_extract` without `overwrite=True` on an existing `db_path` |
| `ImportError` | the optional `pymobiledevice3` is not installed |
| `ValueError` | a malformed filter value; an annotation filter on a never-annotated database; `message_match` without a full-text index; `run_diff` on an empty baseline |

So a thorough handler usually looks like:

```python
try:
    ...
except AcquisitionAborted:
    ...                       # operator declined — not a failure
except ForensicAULError as exc:
    ...                       # bad input / unusable evidence
except (FileNotFoundError, FileExistsError, ImportError) as exc:
    ...                       # environment / path problems
```

### Errors that are deliberately *not* raised

Two behaviours are worth knowing because they show up in results rather than in
exceptions:

- **Best-effort steps never lose evidence.** After a device collection, hashing and
  report-writing failures are logged as warnings, not raised — the archive is
  already on disk and must survive.
- **Parse resilience.** A corrupt chunk inside a tracev3 costs a `parse_errors`
  increment and a warning, never the extract. Rows the database refuses are counted
  in `ExtractResult.write_errors` and logged loudly. A non-zero `write_errors`
  means the store is *knowingly* incomplete — never silently — so check it.

Likewise, `ExtractResult.source_files_changed` being non-zero means some source
file changed underneath the run: the data parsed from it is suspect. Check these
three counters after every extract.

---

## Logging

**The library configures nothing.** Import-time is side-effect free: no handlers,
no level, no output. Everything the library says goes to standard `logging`
loggers named after the module:

```python
logging.getLogger("forensic_aul.ops.extraction.extract")
logging.getLogger("forensic_aul.ops.identify.workflow")
```

So the host application is in full control:

```python
import logging

logging.basicConfig(level=logging.INFO)                     # everything
logging.getLogger("forensic_aul").setLevel(logging.WARNING) # quiet the library
logging.getLogger("forensic_aul").addHandler(my_handler)    # route it elsewhere
```

Conventions inside the library:

- **INFO** — the operational narrative an audit trail should keep (phase
  boundaries, counts, decisions such as "reusing existing analysis database").
- **WARNING** — a recoverable degradation the analyst must know about (a corrupt
  chunk, a hashing step that failed, a read-only database that could not be
  upgraded).
- **ERROR** — data was lost or a result is knowingly incomplete (a refused row, an
  apparently import-unsafe entry point producing an empty database).
- **DEBUG** — internals, including anything a progress sink threw.

The CLI (`launcher/`) additionally configures a case-scoped forensic log file
alongside the output database, whose hash is sealed into the case metadata — that
is application-layer behaviour, not something the library does to you. If you embed
the library, you own the audit trail.

---

## See also

- [Recipes](recipes.md)
- [Library overview](index.md)
- [`forensic_aul/README.md`](../../forensic_aul/README.md) — per-symbol reference
