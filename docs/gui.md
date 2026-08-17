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

A frameless, macOS-styled window (`gui/views/shell.py`), sized 1180×800 by default
with a 980×640 minimum:

- **Titlebar** — draggable, with functional traffic-light controls; double-click
  toggles maximise. Shows a breadcrumb: `FAUL · forensic-aul — <screen>`.
- **Left sidebar** (fixed 220 px) — three sections: `PIPELINE`, `REFERENCE`,
  `SYSTEM` (the Preferences submenu). Disabled entries are greyed with a tooltip
  naming the version that will bring them.
- **Screen stack** — one screen at a time, in a `QStackedWidget`.
- **Log panel** — a docked, resizable panel at the bottom, attached to the root
  logger (`gui/widgets/log_panel.py`), so the library's own INFO/WARNING/ERROR
  lines are visible live while an operation runs.
- **Resize** — a corner `QSizeGrip` preserves native resizing despite the frameless
  window.

There is a single dark theme (`gui/theme.py` builds the stylesheet); there is no
light/dark switch.

---

## Screens that exist today

| Sidebar | Screen class | Module | What it does |
|---|---|---|---|
| 1 · Acquire | `AcquireScreen` | `gui/views/screens_pipeline.py` | Scans for connected devices and collects a `.faul` from one, via `forensic_aul.ops.acquisition.acquire`. Records the run in the recents store and can hand its output straight to Extract ("Continue"). |
| 2 · Extract | `ExtractScreen` | `gui/views/screens_pipeline.py` | Parses an archive into SQLite via `run_extract`, with an inline progress bar and terminal actions. Carries a compact case-metadata panel (case number / IMEI), and auto-fills those fields from a `.faul`'s acquisition sidecar when present. A jobs dropdown is built from the host's physical core count. |
| 3 · Exploit | `ExploitScreen` | `gui/views/screen_exploit.py` | A two-tab viewer over an analysis database: **Overview** (facts from `summarise`) and **Analysis** (a paged log table over a held-open `LogStore`, with time and annotation filters, an FTS-backed keyword search, a soft row cap, and a "view context" action). |
| 4 · Export | `ExportScreen` | `gui/views/screens_data.py` | Filtered export to CSV / JSON / JSONL via `run_export` + `ExportFilters`. |
| · Verify hash | `VerifyHashScreen` | `gui/views/screens_data.py` | Recomputes a file's digest (SHA-256 / SHA-1 / MD5) and compares it with an expected value, keeping a session table of results. |
| · Identify | `IdentifyHub` | `gui/views/screen_identify_hub.py` | A tabbed hub with two children: **Run** (`IdentifyScreen`, `screens_identify.py`) — the interactive baseline → action → diff wizard; and **Results** (`IdentifyResultsScreen`, `screen_identify_results.py`) — browse, filter, hide and CSV-export a diff database through `IdentifyResults`. |
| System · Settings | `SettingsScreen` | `gui/views/screens_prefs.py` | Workstation display preferences (recent-database list, timezone rendering, reduce-motion) plus an About panel with the version and platform. |

Two conventions run through the views:

- **Views hold widgets only.** Acquire, Extract and the Identify wizard delegate to
  a controller (`gui/controllers/pipeline.py`, `gui/controllers/identify.py`) and
  import no `forensic_aul.ops` themselves.
- **Light data screens skip the controller.** Export, Verify hash, Exploit and
  Identify Results run their reads inline on the GUI thread — the reads are
  index-assisted counts/pages measured in milliseconds — and surface errors in a
  result panel rather than raising.

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
  and emits `finished(object)` with its return value, or `failed(str)` with a
  formatted traceback. It never lets an exception escape into the thread; failures
  are logged and additionally captured as a crash report (`app.diagnostics`).
  Purpose-built workers may subclass `QObject` directly as long as they expose the
  same two signals.
- **`start_worker(owner, worker, on_finished, on_failed=None)`** — moves the worker
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

Both stores live under `~/.config/faul/` and are display-only.

**`SettingsStore`** (`gui/settings_store.py`) → `~/.config/faul/settings.json`.
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

**`RecentStore`** (`gui/recent_store.py`) → `~/.config/faul/recents.json`.
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
- Long operations are cancellable only where the underlying operation offers it;
  the Identify wizard's pauses are the interactive control points.
- The window is frameless by design and styled for macOS; it runs on other
  platforms but that is where it looks intended.

For anything scripted, repeatable, or headless, prefer the CLI or the library —
they are the stable surfaces.

---

## See also

- [CLI reference](cli/index.md)
- [Library overview](library/index.md) and [recipes](library/recipes.md)
- [Progress and errors](library/progress-and-errors.md) — what feeds the GUI's bars
- [Case workflow](workflows/case-workflow.md)
- [Identify workflow](workflows/identify-action.md)
