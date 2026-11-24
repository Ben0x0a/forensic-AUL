# The desktop GUI

forensic_AUL ships a PySide6 desktop application (**FAUL**) over the same core
library the CLI uses. It is a front-end and nothing more: every screen collects
input, calls a `forensic_aul` operation, and renders the result. No analysis logic
lives in `gui/`.

> **Status: in progress.** The core library and CLI are the mature surfaces. The
> GUI implements the V1 screen set described below; later roadmap screens are
> present in the sidebar but deliberately **disabled**, tagged with the version
> they are planned for. Anything not listed as working here is not implemented.

---

## Install and launch

The GUI is an optional extra:

```bash
uv sync --extra gui          # or: uv pip install -e ".[gui]"
```

Launch it by running the front door with no subcommand:

```bash
python faul.py               # no arguments → GUI
python faul.py extract …     # a subcommand → CLI (see cli/)
```

If PySide6 is not installed, the launcher logs an actionable error and exits with
code 1 rather than dumping an `ImportError` traceback.

`Ctrl+C` in the launching terminal quits the app cleanly. (Qt's event loop runs in
C++ and never returns to the interpreter, so the launcher ticks a no-op timer a
few times a second to give the Python SIGINT handler a chance to run. A *wedged*
main thread still needs an OS kill.)

---

## The shell

A window with the operating system's own titlebar (`gui/views/shell.py`), sized
1180×800 by default with a 980×640 minimum. A custom macOS-style titlebar was
removed: it looked foreign on Windows and Linux and re-implemented the move,
resize and snap the OS already provides.

- **Titlebar** — native; its title carries a breadcrumb:
  `FAUL · forensic-aul — <screen>`.
- **Left sidebar** (fixed 220 px) — three sections: `PIPELINE`, `REFERENCE`,
  `SYSTEM` (the Preferences submenu). Disabled entries are greyed with a tooltip
  naming the version that will bring them.
- **Screen stack** — one screen at a time, in a `QStackedWidget`.
- **Log panel** — a docked, resizable panel at the bottom
  (`gui/widgets/log_panel.py`). It is a plain logging handler attached through
  `app/logging_config.py`, so the library's own INFO/WARNING/ERROR lines are
  visible live while an operation runs; its DEBUG button asks the same module to
  lower the root level (the widget does not configure logging itself).

There is a single dark theme (`gui/theme.py` builds the stylesheet); there is no
light/dark switch.

---

## Screens that exist today

| Sidebar | Screen class | Module | What it does |
|---|---|---|---|
| 1 · Acquire | `AcquireScreen` | `gui/views/screens_pipeline.py` | Scans for connected devices and collects a `.faul` from one, via `forensic_aul.ops.acquisition.acquire`. Records the run in the recents store and can hand its output straight to Extract ("Continue"). |
| 2 · Extract | `ExtractScreen` | `gui/views/screens_pipeline.py` | Parses an archive into SQLite via `run_extract`, with an inline progress bar and terminal actions. Carries a compact case-metadata panel (case number / IMEI), and auto-fills those fields from a `.faul`'s acquisition sidecar when present. A jobs dropdown is built from the host's physical core count. |
| 3 · Exploit | `ExploitScreen` | `gui/views/screen_exploit.py` | A two-tab viewer over an analysis database: **Overview** (facts from `summarise`) and **Analysis** (a paged log table over a held-open `LogStore`, with time and annotation filters, an FTS-backed keyword search, a soft row cap, and a "view context" action). |
| 4 · Export | `ExportScreen` | `gui/views/screens_data.py` | Filtered export to CSV / JSON / JSONL via `run_export` + `LogFilter`, off the GUI thread. Opened from Exploit, it arrives with that database and its Analysis filters (see [Navigation](#navigation-between-screens)). |
| · Verify hash | `VerifyHashScreen` | `gui/views/screens_data.py` | Recomputes a file's digest (SHA-256 / SHA-1 / MD5) and compares it with an expected value, keeping a session table of results. |
| · Identify | `IdentifyHub` | `gui/views/screen_identify_hub.py` | A tabbed hub with two children: **Run** (`IdentifyScreen`, `screens_identify.py`) — the interactive baseline → action → diff wizard; and **Results** (`IdentifyResultsScreen`, `screen_identify_results.py`) — browse, filter, hide and CSV-export a diff database through `IdentifyResults`. A run also writes `<prefix>-identified.csv` (the `[identify] write_csv` setting, on by default) and, when repeated, `<prefix>-repeat.csv` with the ranking — the files to analyse in a spreadsheet or script; the archives and extracts go to the run's `intermediate/` subfolder. |
| System · Settings | `SettingsScreen` | `gui/views/screens_prefs.py` | Workstation preferences (recents, timestamp rendering, context size, row cap, knowledge base, default Extract jobs — see [Settings](#settings-and-recent-cases)) plus an About panel with the version and platform. |

### Views and controllers

Every screen that calls the library is split in two:

- **The view** (`gui/views/`) builds widgets, forwards the analyst's input and
  renders what it is told to. It calls no library operation.
- **The controller** (`gui/controllers/`) validates the input, calls the
  `forensic_aul` operation (through the view's `run_task` when it is slow), and
  tells the view what to show. Controllers are plain Python objects, testable
  without driving widgets.

| View | Controller |
|---|---|
| `AcquireScreen`, `ExtractScreen` | `pipeline.AcquireController`, `pipeline.ExtractController` |
| `ExploitScreen` | `exploit.ExploitController` (+ the table's row sources) |
| `ExportScreen`, `VerifyHashScreen` | `data.ExportController`, `data.VerifyHashController` |
| `IdentifyScreen` | `identify.IdentifyController` |
| `IdentifyResultsScreen` | `identify_results.IdentifyResultsController` |
| `SignatureDialog` | `signature.SignatureController` |

The rule is enforced by `tests/unit/test_layering.py`: modules under
`gui/views/` and `gui/widgets/` may import from `forensic_aul` only a short list
of data types and constants (`LogFilter`, `Match`, `SignatureDraft`,
`__version__`, `default_kb_dir`, `physical_cpu_count`). `SettingsScreen` has no
controller: it edits the settings store and calls no library operation.

WHY: a view that calls the library mixes three jobs (layout, decisions, I/O),
cannot be tested without a window, and is where errors used to be phrased
inconsistently. Failures now reach the controller as exception objects and are
phrased once, by type, in `gui/controllers/__init__.py` (`phrase_failure`).

Exploit's and Identify Results' table reads stay on the GUI thread (they are
index-assisted counts and pages measured in milliseconds); annotation, export,
hashing, extraction, acquisition and identify run on a worker.

### Navigation between screens

Screens never reach into each other. A screen is given the shell's `navigate`
callback (`bind_navigator`) and calls it with a **destination**: a bare screen
id to switch screens, or a typed payload (`gui/navigation.py`) that names its
own target screen and is delivered to that screen's `receive`:

| Payload | Target | Sent by |
|---|---|---|
| `ExtractFrom(source, case)` | Extract | Acquire's "Continue" — the archive and the case metadata already typed |
| `OpenDatabase(db)` | Exploit | Extract's "Open in Exploit" |
| `ExportFrom(db, filters)` | Export | Exploit's "Export…" (its Analysis filters) and Extract's "Export" |
| `ShowIdentifyResults(db)` | Identify (Results tab) | the Identify wizard's "View results" |

```mermaid
sequenceDiagram
    participant X as ExploitScreen
    participant S as Shell (MainWindow.navigate)
    participant E as ExportScreen
    X->>S: navigate(ExportFrom(db, filters))
    S->>S: target_of(payload) = "export"; switch screen
    S->>E: receive(payload)
    E->>E: controller fills the form; lists filters the form cannot show
```

On Export, filters the form has an input for (process, subsystem, level,
message LIKE, last) fill those inputs; the others (time bounds, keyword search,
category, annotation filters) are listed under the form with a **Clear** button.
They are applied to the export only while listed — never invisibly.

WHY typed payloads rather than a dictionary or a shared "current database"
object: a misspelled dictionary key used to be ignored without a word, and a
shared object would change Export behind the analyst's back whenever another
screen opened a database. A payload is checked when it is built, goes only
where it names, and a screen that receives one it does not take raises
`TypeError` instead of dropping it.

### Greyed out / planned

These appear in the sidebar but are **disabled**, tagged with their target
version:

| Entry | Section | Planned for |
|---|---|---|
| Knowledge base | REFERENCE | v4 |
| KB match debug | Preferences | v4 |
| Update KB | Preferences | v3 |
| Lint KB | Preferences | v4 |
| Validate FAUL | Preferences | v2 |

Until then, use the CLI for those: `python faul.py kb …` and
`python faul.py validate-tool …` (see [workflows/validation.md](workflows/validation.md)).

---

## Threading model

`run_extract` can take minutes on a real archive. Running it on the GUI thread
would freeze the window, so blocking core calls go to a worker thread.

`gui/workers/base.py` provides the whole mechanism:

- **`Worker(fn, *args, **kwargs)`** — a `QObject` that runs one callable off-thread
  and emits `finished(object)` with its return value, `failed(object)` with the
  exception itself (so the controller can phrase it by type), or
  `cancelled(object)` when the operation raised `OperationCancelled`. It never
  lets an exception escape into the thread; unexpected failures are logged and
  additionally captured as a crash report (`app.diagnostics`).
- **`start_worker(owner, worker, on_finished, on_failed=None, on_cancelled=None)`** — moves the worker
  onto a fresh `QThread`, wires `started → run`, connects the callbacks, tears
  everything down on either outcome, and returns the thread. The thread is parented
  to `owner` so Qt keeps it alive; the worker stays un-parented (Qt forbids a
  parent on another thread).

This is Qt's recommended `QObject` + `moveToThread` pattern rather than a `QThread`
subclass, which means cross-thread `finished`/`failed` signals are delivered as
queued connections on the GUI thread automatically — no manual marshalling.

**The threading invariant: widgets are never touched from a worker thread.**
Worker → GUI progress travels only through the view's queued `emit_progress`
signal (the library's `ProgressSink` events feed it; see
[library/progress-and-errors.md](library/progress-and-errors.md)). GUI → worker
control uses `threading.Event` objects only — the Identify wizard's two operator
pauses ("keep still" countdown, "perform the action" wait) are bridged with a Skip
event, a Continue event and an aborted flag, and the countdown ticks ride the
progress detail label rather than poking a widget.

Controllers are plain objects, not `QObject`s: the callbacks they hand to the
view's `run_task` host are re-emitted from the view (a main-thread `QObject`), so
Qt has already delivered them on the GUI thread by the time they run.

A main-thread crash handler is installed before the UI is built
(`app.diagnostics.install_excepthook`); worker-thread crashes are captured
separately in `Worker.run`.

---

## Settings and recent cases

Both stores live in `app_data/` next to `faul.py` (git-ignored) and are display-only.

**`SettingsStore`** (`gui/settings_store.py`) → `settings.json` in that directory.
A small `QObject` that emits `changed(key, value)` so any screen can react live.
Known keys and defaults:

| Key | Default | Meaning |
|---|---|---|
| `recentDb` | `True` | show the recent-databases list atop pipeline steps |
| `recentsLimit` | `5` | entries each recents list keeps |
| `tz` | `"utc"` | timestamp rendering — `"utc"` / `"local"` / `"raw"` |
| `contextSize` | `20` | rows either side of a line in "view context" |
| `rowCap` | `5000` | most rows the analysis table loads at once |
| `kbPath` | `""` | knowledge base to annotate with (empty = the shipped one) |
| `extractJobs` | `0` | default parser jobs on Extract (0 = one per core) |

Every key has a consumer. A preference that changes nothing is worse than no
preference, because it tells the analyst the tool behaves in a way it does not —
`reduceMotion` was removed for exactly that reason, and `tz` was wired up rather
than removed (see `format_timestamp` in `forensic_aul/engine/utils/time.py`).

`tz` is **display only**. Stored and exported timestamps are always UTC so a case
stays portable between examiners; the preference changes what the Exploit table
and record drawer render, nothing else.

Integer keys are read through `get_int`, which coerces and clamps to a bounded
range — values arrive from a JSON file a user can hand-edit, and a string where an
int belongs must not reach a spin box. Unknown keys are ignored on load, so a
stray file cannot inject state. The store never raises on I/O problems: a missing
or corrupt file falls back to defaults, because a forensic tool must still open
when its non-essential preferences file is unreadable.

**`RecentStore`** (`gui/recent_store.py`) → `recents.json` in that directory.
Per-category lists (most recent first, de-duplicated, capped by the
`recentsLimit` preference) of paths the user actually acquired / extracted / exported. Nothing is
fabricated — a forensic tool showing invented case rows would be misleading — and
display is gated by the `recentDb` preference.

> **Forensic boundary:** preferences and recents are workstation-local. They are
> never written into a case database or its audit trail.

---

## Maturity notes

Honest limits as the code stands:

- The GUI is **V1 of a five-version roadmap**. Knowledge-base management, KB match
  debugging, KB updates/linting, and the in-GUI FAUL validation are not
  implemented — they are the greyed entries above.
- Acquire and Identify need the optional `acquire` extra (`pymobiledevice3`) and a
  USB-connected iOS device; without it those runs fail the same way the library
  does (an `ImportError` surfaced in the result panel).
- Exploit's reads run on the GUI thread. They are index-assisted, and a soft row
  cap plus a banner tell the analyst to narrow the filter, but a very large
  database can still feel sluggish there. Keyword search is FTS-index-backed or
  absent — there is deliberately no silent `LIKE` fallback, so the search box is
  disabled on a database extracted with `fts=False`.
- Acquire and Extract are cancellable: a **Cancel** button sits beside the
  running-state button, and closing the window or pressing Ctrl+C in the
  launching terminal asks the same question. Cancelling is cooperative — the
  current file finishes and the database closes cleanly — so it takes a moment
  rather than being instant, and the window stays responsive while it drains.
  A cancelled extract leaves `<name>.sqlite.partial`, never a file at the output
  path. The Identify wizard's pauses remain its own interactive control points.

For anything scripted, repeatable, or headless, prefer the CLI or the library —
they are the stable surfaces.

---

## See also

- [CLI reference](cli/index.md)
- [Library overview](library/index.md) and [recipes](library/recipes.md)
- [Progress and errors](library/progress-and-errors.md) — what feeds the GUI's bars
- [Case workflow](workflows/case-workflow.md)
- [Identify workflow](workflows/identify-action.md)
