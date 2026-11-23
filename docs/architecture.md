# Architecture

forensic_AUL is split into four layers with a strict one-way dependency rule:

```
faul.py  →  launcher/ · gui/  →  app/  →  forensic_aul/
                                             ops/  →  engine/  →  config · errors · outcomes
```

Nothing points back the other way, and there are no import cycles among the
first-party packages. Only `forensic_aul/` is published as a wheel; everything
above it is clone-and-run application code.

- Library API reference: [library/index.md](library/index.md)
- CLI reference: [cli/extract.md](cli/extract.md) and its siblings
- Output schema: [formats/database-schema.md](formats/database-schema.md)

---

## Dependency diagram

```mermaid
flowchart TD
    faul["faul.py<br/>(clone-&-run entry point)"]
    faul --> cli["launcher/cli.py<br/>(argparse dispatcher)"]
    cli -->|no subcommand| gui["gui/<br/>(PySide6 shell)"]
    cli --> cmds["launcher/cmds/*_cmd.py<br/>(one module per subcommand)"]
    cmds --> app
    gui --> app
    gui --> lib
    cmds --> lib

    app["app/<br/>extract_session · logging_config · diagnostics"] --> lib

    subgraph lib["forensic_aul/ — the installable library"]
        direction TB
        ops["ops/<br/>acquisition · extraction · annotation · knowledge_base<br/>export · identify · query · summary · verify"]
        engine["engine/<br/>parser · database · models · utils · integrity · faul_format · ios_builds"]
        base["config.py · errors.py · outcomes.py"]
        testing["testing/<br/>runtime validation vs Apple's tools"]
        ops --> engine
        ops --> base
        engine --> base
        testing --> ops
    end
```

The GUI depends on `app/` (crash reporting) *and* directly on the library's
public API; it never imports `launcher/`. `launcher/cli.py` is the only module
that knows about both the CLI commands and the GUI entry point.

**The frontends use only the public API**: `forensic_aul` itself (its
`__all__`), `forensic_aul.reports` (the `format_*` text renderers) and, for the
`validate-tool` command only, `forensic_aul.validation`. Never an internal module —
so an internal move cannot break the CLI or the GUI, and a third-party tool relies
on exactly what they rely on. `tests/unit/test_layering.py` enforces it, with
the other layer rules (the library never imports a frontend; the engine imports
only itself; no cycles; a brick never chains another — that is
`ops/workflows`).

---

## Layer responsibilities

### `faul.py` — entry point

A ~30-line launcher. It puts the repository root on `sys.path` (so `launcher`,
`gui` and `forensic_aul` resolve regardless of the caller's working directory)
and calls `launcher.cli.main()`. No logic of its own.

### `launcher/` — CLI shell

`launcher/cli.py` is a **thin dispatcher**. It builds the argparse tree by
importing each module listed in `_COMMAND_MODULES` and calling that module's
`add_subcommand(sub)`, then routes the parsed namespace to the module's
`run(args)`. With no subcommand it imports `launcher.gui` and boots the GUI.
Just before dispatch it installs the crash handler from `app.diagnostics`.

Registered commands and their handler modules, in registration order — which is
the workflow order, and therefore also the order `faul.py --help` prints:

| Command | Handler module |
|---|---|
| `acquire` | `launcher/cmds/acquire_cmd.py` |
| `extract` | `launcher/cmds/extract_cmd.py` |
| `summary` | `launcher/cmds/summary_cmd.py` |
| `kb` | `launcher/cmds/kb_cmd.py` |
| `annotate` | `launcher/cmds/annotate_cmd.py` |
| `export` | `launcher/cmds/export_cmd.py` |
| `verify-hash` | `launcher/cmds/verify_hash_cmd.py` |
| `identify` (both modes, incl. `--diff`) | `launcher/cmds/identify_cmd.py` |
| `validate-tool` | `launcher/cmds/validate_tool_cmd.py` |
| `redact-errors` | `launcher/cmds/redact_errors_cmd.py` |

The handler module filenames deliberately keep their original stems; only the
public subcommand names changed.

Each `*_cmd.py` owns only CLI concerns: flag definitions, mapping flags onto the
library's option objects, terminal prompts, and mapping exceptions to exit codes.
`launcher/gui.py` owns the `QApplication` lifecycle so the widget layer stays
import-light and testable without an event loop.

### `gui/` — PySide6 desktop shell

Optional (`uv sync --extra gui`). Layout:

| Path | Responsibility |
|---|---|
| `gui/app.py` | Builds the main window; routes application logging into the log panel. |
| `gui/views/shell.py` | `MainWindow`: frameless window, sidebar, stacked screens, docked log panel. |
| `gui/views/screens_*.py`, `screen_*.py` | Views only — widget construction, input getters, display methods. |
| `gui/controllers/` | Application logic for every screen that calls the library: validation, the library calls (off-thread when slow), result routing. |
| `gui/navigation.py` | Typed navigation payloads (`OpenDatabase`, `ExtractFrom`, `ExportFrom`, `ShowIdentifyResults`) and the `Screen` protocol the shell binds. |
| `gui/workers/` | `Worker` + `start_worker` — moves a blocking core call onto a `QThread`. |
| `gui/widgets/` | Reusable primitives (`LogTablePanel`, `PathPicker`, `LogPanel`, `DevicePicker`, …). |
| `gui/theme.py` | Design tokens interpolated into an application-wide Qt Style Sheet. |
| `gui/settings_store.py`, `gui/recent_store.py` | Display preferences and real recently-used paths, persisted in the application data directory (`app/paths.py`). |

Two conventions are enforced in the code:

- **Views call no library operation.** Every view delegates to a controller;
  `gui/views/` and `gui/widgets/` may import only a short list of `forensic_aul`
  data types (checked by `tests/unit/test_layering.py`). See
  [gui.md](gui.md#views-and-controllers).
- **Widgets are never touched from a worker thread.** Worker→GUI traffic goes
  through queued Qt signals; GUI→worker control uses `threading.Event` only.

### `app/` — orchestration

Application infrastructure that is neither forensic domain logic nor a UI
concern. It may import `forensic_aul.*`; it never imports the shells, and the
library never imports it.

| Module | Responsibility |
|---|---|
| `app/paths.py` | `APP_ROOT` (the folder holding `faul.py`) and `app_data_dir()` — `app_data/` next to the app (git-ignored) for settings, recents and crash reports, so the operator can see, copy and delete what the tool writes. Standard library only. |
| `app/settings.py` | The layered settings: option-dataclass defaults < `app_data/faul.toml` < `FAUL_*` environment; each command (and GUI screen) applies its own flags on top. An allowlist of settable keys; unknown or invalid entries are refused. See [Settings](configuration.md). |
| `app/logging_config.py` | The one place the frontends configure logging: console logging (`dictConfig`, UTC, detailed with `-v`) and attaching a frontend's own handler (the GUI log panel). The library never configures logging — it only adds a `NullHandler`; its one exception is the opt-in audit log below. |
| `app/extract_session.py` | The CLI's evidence extract: console verbosity, `run_extract` with `audit_log=True`, and the outcome → exit code (0 / 1 / 130) with a crash report on an unexpected failure. Used by both `extract` and `acquire --extract`. |
| `app/diagnostics/` | Forensic crash and bug reports: the type and value of every variable in every frame, classified `safe` / `sensitive`, kept in full plaintext locally; `write_shared_copy` produces the redacted copy that may leave the machine. **Standard library only** — domain types are recognised by *name*, never imported, so it still works when a domain import is what crashed. |

`app/diagnostics/` is a package of bricks, each layer importing only the layers above it:

| Brick | Responsibility |
|---|---|
| `schema.py` | The report format (schema id, kinds, `safe` / `sensitive`) and the one sensitivity vocabulary + `classify`, shared by capture and redaction. |
| `config.py` | `CrashConfig` (report folder, capture caps), read at call time so the folder can be redirected. |
| `capture.py` | Builds a report in memory: walks a traceback (crash) or every live thread (bug), summarising each value within fixed bounds. |
| `redact.py` | The shareable copy: sensitive values → type + SHA-256 placeholder, paths anonymised, known literals scrubbed from every string. |
| `render.py` | The Markdown view, which doubles as a bug template. |
| `store.py` | Every file rule: naming per kind, the one writer, listing, finding, the `*.shared.*` copy. |
| `hooks.py` | The guarded entry points: `install_excepthook`, `capture_exception`, `write_crash_report`, `write_bug_report`. They never raise. |

Why redaction is separate from the capture: the local report keeps full plaintext on
the operator's own machine; only the copy that leaves the machine is redacted, and
the operator reviews it first.

### `forensic_aul/` — the library

Importable on its own, with **no import-time side effects**. The package root
re-exports the whole public surface (`run_extract`, `run_export`, `query_logs`,
`annotate_database`, `prepare_source`, `verify_database`, `summarise`,
`acquire`, `run_diff`, the result dataclasses, the progress sinks…) so callers
depend on a stable surface rather than internal module paths.

#### `forensic_aul/ops/` — the operations

Each subpackage is one operation the tool can perform, and every one follows the
same shape: a main module (pure — data in, data out) plus a `report` module of
`format_*(outcome) -> str` functions.

| Package | Responsibility |
|---|---|
| `ops/acquisition/` | Collect a `.logarchive` from a USB-connected iOS device via the optional `pymobiledevice3` dependency (`device.py` = discovery/metadata, `acquire.py` = the operation, `report.py` = the acquisition sidecar). |
| `ops/extraction/` | The acquisition → SQLite pipeline: `source.py`/`sources/` (input normalisation), `timesync_setup.py`, `oversize_pass.py` (pass 1), `tracev3_parse.py` (pass 2 inner loop), `entry_builder.py` (Firehose → `LogEntry`), `workers.py` (multiprocessing), `shutdown_log.py`, `discovery.py`, `options.py` (`ExtractOptions`, `CaseInfo` and the evidence rule), `audit.py` (the opt-in forensic operational log and its seal, on every exit path), and `extract.py` (`run_extract`). |
| `ops/knowledge_base/` | Load (`loader.py`), model (`models.py`) and lint (`lint.py`) the YAML signature library; `default_kb_dir()` locates the shipped one (`forensic_aul/knowledge_base/`, package data). |
| `ops/annotation/` | Run a loaded knowledge base against `logs`, writing `log_annotations` and `extracted_values`. Every signature pre-filters on indexed columns before any regex runs. |
| `ops/query/` | The stable read surface — `query_logs` (streamed), `LogStore` (held-open store for paging UIs), `count_logs`/`fetch_logs`, `fetch_context`, plus the one row filter `LogFilter` and `LogRow` model, on top of `engine/database/reader.py`. |
| `ops/export/` | Filtered export to CSV / JSON / JSONL through a writer registry; knowledge-base aware (extracted values become columns or nested objects). |
| `ops/identify/` | Action attribution: `diff.py` (`run_diff`), `results.py` (read/annotate a diff DB). |
| `ops/workflows/` | Orchestration — the only ops modules that chain other bricks: `identify.py` (the full interactive baseline → action → diff sequence, operator interaction injected as callbacks) and `identify_options.py`. A brick imports another brick only for its data (`models`/`options`), enforced by `tests/unit/test_layering.py`. |
| `ops/summary/` | The text rendering of a database's summary (`report.py`); the statistics themselves are part of the store (`engine/database/summary.py`). |
| `ops/verify/` | Chain-of-custody re-verification: re-hash the logarchive (global + per file) and the operational log, compare against the digests stored at extract time. |

#### `forensic_aul/engine/` — the operation-agnostic backend

Nothing here knows about CLI commands, prompting, or human presentation.

| Module / package | Responsibility |
|---|---|
| `engine/parser/` | Apple Unified Log binary parsing — `reader` (the single source of all `struct.unpack` calls), `tracev3`, `header`, `catalog`, `chunkset`, `firehose`, `oversize`, `statedump`, `uuidtext`, `dsc`, `timesync`, `format_string`, `message`, `decoder_tables`, `string_cache`. See [concepts/unified-logs.md](concepts/unified-logs.md). |
| `engine/models/` | Dataclasses mirroring the Rust `macos-unifiedlogs` structs field-for-field: `chunks`, `firehose`, `strings`, `timesync`, `dumps`, `log_entry`. All re-exported from the package root. |
| `engine/database/` | `schema.py` (tables, pragmas, the `v_logs` view), `writer.py` (`BatchWriter` — lookup-table management + batched `executemany`), `ordering.py` (`assign_ordering`), `access.py` (the one validated path→connection gate), and the read side: `reader.py` (filters → SQL → rows, shared by query, export and identify), `summary.py` + `summary_cache.py` (the statistics the store keeps about itself, refreshed by extract and annotate). Every SQL over the logs schema outside a brick's own output tables lives here (S7). |
| `engine/utils/` | `time.py` (mach → wall-clock via timesync anchors), `progress.py` (the UI-agnostic progress standard), `system.py` (physical cores / RAM → the auto `--jobs` budget), `files.py`. |
| `engine/integrity.py` | `compute_sha256`, `hash_logarchive`, `seal_log_file`, `verify_source_files`. |
| `engine/faul_format.py` | Single source of truth for the `.faul` container — constants, `pack_faul`, the O(1) `is_faul` detector, and the readers. See [formats/faul-format.md](formats/faul-format.md). |
| `engine/ios_builds.py` | Best-effort, deliberately partial build-code → marketing-version table. Unknown builds return `None` rather than a guess. |

#### `forensic_aul/config.py`, `errors.py`, `outcomes.py`

- **`config.py`** — tunable operational defaults only (batch size, WAL
  auto-checkpoint pages, ordering batch/cache sizes, jobs auto-cap and memory
  model, hash chunk size, parser safety limits, log formats). Binary-format
  magic numbers deliberately stay in their parser modules; schema constants stay
  in `schema.py`.
- **`errors.py`** — `ForensicAULError` is the base of every purposeful library
  error, so one `except ForensicAULError` catches them all. `SourceError` and
  `InvalidDatabaseError` also subclass `ValueError` for backward compatibility.
- **`outcomes.py`** — the frozen result dataclasses returned by the top-level
  operations (`ExtractResult`, `AcquireResult`, `AnnotateResult`, `DiffResult`,
  `IdentifyResult`, `ExportResult`), kept in their own module so orchestration
  code can import them without a cycle.

#### `forensic_aul/validation/`

A shipped **runtime feature**, not the test suite: device log capture, an Apple
`log show` reference exporter, and comparators (`comparator.py`,
`merge_compare.py`, `archive_compare.py`, `ndjson_*`, `pipeline.py`,
`platform.py`). It backs the `validate-tool` command. The project's own pytest suite
lives in `tests/` at the repository root and is **not** shipped.

---

## Boundaries the code enforces

**Report modules are pure `format → str`.** Every op subpackage exposes a
`report` module whose functions build and return strings and never print. The
caller — a CLI handler, a GUI screen, a test — decides when and where to emit
them. This is what lets both frontends share one rendering.

**All prompting and pacing is frontend-bound.** Operations never ask questions
and never wait. Where a flow is interactive, the interaction is injected as
callbacks: `acquire` takes a *confirm* callback; `run_identify_workflow` takes
`confirm` / `wait_still` / `wait_for_action` / `status` — the workflow owns the
sequence, the frontend owns the pacing.

**Progress is a sink, not a UI.** `ProgressReporter` declares weighted phases and
forwards a `ProgressEvent` to a `Callable[[ProgressEvent], None]`. `None` means
"no progress wanted" and every call becomes a no-op, so ops need no
`if progress is not None` guards. Three sinks ship with the library
(`tty_bar_sink`, `logging_progress_sink`, `callback_progress_sink`); the GUI
supplies its own.

**Errors are raised, exit codes are not.** Library operations raise
(`SourceError`, `AcquisitionError`, `InvalidDatabaseError`, `ValueError`…); the
CLI handler maps them to process exit status and user messages.

**Optional dependencies are imported lazily.** `pymobiledevice3` is only touched
when acquisition actually runs, so every other command works without it. PySide6
is only imported on the GUI path.

**Workers never open the database.** Parser worker processes resolve all DB ids
from maps prepared in the main process and return `LogEntry` batches to a single
writer. The read-only string cache is loaded from disk inside each worker rather
than pickled across, so the design works under both `spawn` and `fork`.

---

## What ships in the wheel

`pyproject.toml` restricts the distribution to `forensic_aul*`:

```toml
[tool.setuptools.packages.find]
include = ["forensic_aul*"]
```

| Component | Shipped in the wheel | Notes |
|---|---|---|
| `forensic_aul/` (incl. `testing/`) | Yes | Plus the PEP 561 `py.typed` marker. |
| `faul.py`, `launcher/`, `gui/`, `app/` | No | Clone-and-run application layer. |
| `tests/`, `scripts/`, `benchmark/` | No | Development only. |
| `forensic_aul/knowledge_base/` (YAML tree) | Yes (package data) | The shipped KB, read via `importlib.resources`; `annotate`/`kb`/`identify` accept `--kb PATH`. |

Runtime dependencies are `lz4` and `PyYAML`. Optional extras: `gui` (PySide6),
`acquire` (pymobiledevice3), `dev` (pytest). Supported Python is 3.11–3.14.

See [getting-started.md](getting-started.md) for installation and
[library/index.md](library/index.md) for using the package as a library.
