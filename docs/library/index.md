# Using forensic_AUL as a library

`forensic_aul` is the installable core of the project. The CLI (`launcher/`) and the
GUI (`gui/`) are thin front-ends over it — anything they do, your own code can do
by importing the package.

This page is the orientation: how to install, what guarantees you get, and the
mental model. For the **per-symbol API reference** (every exported name, its exact
signature and behaviour) see [`forensic_aul/README.md`](../../forensic_aul/README.md).

- [Recipes](recipes.md) — runnable, task-oriented examples.
- [Progress and errors](progress-and-errors.md) — the progress sink protocol, the
  exception hierarchy, logging conventions.

---

## Install

```bash
uv pip install -e .                 # core library only
uv pip install -e ".[acquire]"      # + USB device acquisition (pymobiledevice3)
uv pip install -e ".[gui]"          # + the PySide6 GUI (see ../gui.md)
uv sync --extra acquire             # same extra, managing the project venv
```

Runtime dependencies of the core are just `lz4` and `PyYAML`. Supported Python is
`>=3.11,<3.15` (declared in `pyproject.toml`).

The distribution ships only `forensic_aul*` — the application layer (`launcher/`,
`gui/`, `faul.py`) is deliberately clone-and-run and is not packaged. A `py.typed`
marker is included, so mypy/pyright/IDEs pick up the library's annotations.

```python
import forensic_aul
forensic_aul.__version__      # "0.1.0"
```

---

## Import-safety guarantees

**Importing the package has no side effects.** No logging is configured, no files
are touched, nothing is printed. That is a deliberate contract so the library can
be embedded in another tool (an iLEAPP-style plugin, a service, a notebook) without
fighting it for the root logger or the console.

Two consequences for you as a caller:

1. **You configure logging.** The library only ever calls
   `logging.getLogger("forensic_aul.…")`. Without a handler you see nothing — see
   [progress-and-errors.md](progress-and-errors.md).
2. **`jobs > 1` needs an import-safe entry point.** `run_extract(..., jobs=N)` with
   `N > 1` uses **spawn-based multiprocessing**: every worker re-imports your entry
   module. If your script starts the extract at import time, each worker restarts
   the whole run. The classic symptom is a run that "succeeds" with an *empty*
   database (the run flags this with an ERROR log line).

   ```python
   # extract_case.py
   from pathlib import Path
   from forensic_aul import run_extract

   def main() -> None:
       run_extract(Path("acquisition.tar.gz"), Path("case.db"), jobs=8)

   if __name__ == "__main__":      # required for jobs > 1
       main()
   ```

   Code that only runs inside functions (a plugin, a web handler, a library) is
   already import-safe and needs nothing extra. `jobs=1` — the library default —
   parses in-process and has no such requirement.

---

## The mental model

Every operation is a plain function that takes paths and returns a frozen result
dataclass. Nothing is hidden in objects or global state, so you can stop, resume,
or re-run any step independently.

```
             ┌──────────────┐
 evidence →  │ prepare_source│ →  PreparedSource   (optional: inspect/hash first)
             └──────────────┘
                     ↓
             ┌──────────────┐
             │ run_extract  │ →  ExtractResult     (SQLite analysis database)
             └──────────────┘
                     ↓
             ┌──────────────────────────┐
             │ load_kb + annotate_database│ → AnnotateResult   (re-runnable at will)
             └──────────────────────────┘
                     ↓
      ┌──────────────┴───────────────┐
      ↓                              ↓
 query_logs / fetch_logs        run_export      (rows in memory | CSV/JSON/JSONL)
      (read)                      (write)
```

Alongside that main line:

| Step | Function | Notes |
|---|---|---|
| Collect from a device | `acquire` | needs the `acquire` extra; returns a `.faul` container |
| Attribute an action | `run_diff` / `run_identify_workflow` | see [../workflows/identify-action.md](../workflows/identify-action.md) |
| Read a diff database | `IdentifyResults` | browse, hide noise, export CSV |
| Describe a database | `summarise` | read-only `Summary` |
| Re-check chain of custody | `verify_database` | `VerifyResult.ok` |
| Hash evidence | `compute_sha256`, `hash_logarchive` | |

Three properties are worth internalising:

- **Parse once, reuse.** Extraction is by far the expensive step. `open_or_extract`
  encodes the "reuse the database if it is already there" pattern.
- **Annotation is a separate, repeatable pass.** `annotate_database` is path-based,
  so improving the knowledge base means re-annotating, never re-extracting.
- **Operations never print or prompt.** All interaction is injected: `progress=` for
  progress, `confirm=` / `wait_for_action=` for operator prompts, `status=` for
  human-readable lines. Front-ends supply those; the library does no I/O of its own
  beyond writing its declared outputs and logging.

---

## Reading rows back

Two read surfaces carry a compatibility promise; everything else about the schema
is internal (see [../formats/database-schema.md](../formats/database-schema.md)).

1. **`query_logs` / `fetch_logs` / `fetch_context` / `LogStore`** — Python objects
   (`LogRow`) with the same filter vocabulary as export.
2. **The `v_logs` SQL view** — for consumers that prefer raw SQL. Its columns are
   only ever appended to.

See [recipes.md](recipes.md) for both.

---

## Versioning and stability policy

> **Public API = the names in `forensic_aul.__all__`.** Everything else under
> `forensic_aul.*` is an internal implementation detail and may move or change
> without notice.

Practical rules:

- Import from the top level (`from forensic_aul import run_extract`), never from
  the internal module path (`forensic_aul.ops.extraction.extract`). The sub-package
  layout is documented in `forensic_aul/README.md` to make the architecture
  readable, not to be imported against.
- Result dataclasses are frozen and gain fields additively; read them by name.
- The `v_logs` view only ever gains columns; the normalised tables behind it may
  change shape.
- The project is at `0.1.0` and pre-1.0: the surface above is what is being
  stabilised, but it is not frozen yet. Pin the version if you depend on it.

---

## Where to go next

- [Recipes](recipes.md) — copy-pasteable examples for each task.
- [Progress and errors](progress-and-errors.md) — sinks, exceptions, logging.
- [`forensic_aul/README.md`](../../forensic_aul/README.md) — the canonical
  per-symbol API reference table.
- [../architecture.md](../architecture.md) — how `engine/` and `ops/` fit together.
- [../concepts/forensic-model.md](../concepts/forensic-model.md) — why the ordering,
  hashing and integrity choices are what they are.
