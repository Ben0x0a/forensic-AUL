<p align="center">
  <img src="gui/assets/faul-wordmark.png" alt="forensic_AUL" width="500">
</p>

# forensic_AUL

A digital-forensics tool that parses **Apple Unified Logs** into a normalised,
queryable **SQLite** database, preserving the byte-level provenance and the true
event timeline needed for forensic analysis. It is a Python port of the Rust
[`macos-unifiedlogs`](https://github.com/mandiant/macos-UnifiedLogs) reference
(Mandiant, Apache-2.0 — see [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)).

- **Status:** core library + CLI are functional; a PySide6 GUI is in progress
  (paused) and reuses the same core.
- **Python:** 3.11–3.14 (`uv` recommended; dev default 3.12). Runtime deps: `lz4`, `PyYAML`.

📖 **[Full documentation →](docs/README.md)**

---

## Install

```bash
uv venv --python 3.12          # creates .venv/
source .venv/bin/activate      # Windows: .venv\Scripts\activate
uv pip install -e ".[dev]"
python faul.py --help
```

The core install is deliberately light. Add extras for what you need:

| Extra | Adds | Install |
|---|---|---|
| `gui` | the PySide6 desktop GUI | `uv sync --extra gui` |
| `acquire` | USB iOS-device acquisition (`acquire`, `identify`, `validate-tool --from-device`) | `uv sync --extra acquire` |
| `dev` | the pytest test suite | `uv sync --extra dev` |

The repository is **clone-&-run**: `faul.py` is the entry point; only the
`forensic_aul/` package is published as a wheel (`launcher/` and `gui/` are app
glue). All commands below assume the virtual environment is **activated** —
otherwise prefix them with `.venv/bin/python`.

See [Getting started](docs/getting-started.md) for a guided first run.

## Quick start

```bash
faul.py extract evidence.faul -o case.db --case-number CASE-2024-001 --imei 35…
faul.py summary case.db
faul.py export  case.db -o report.csv --last 24h
```

`extract` accepts a `.logarchive` directory, a sysdiagnose `.tar.gz`, a `.faul`
container, a full-file-system `.zip`, or the two loose `diagnostics` / `uuidtext`
folders — detected by **content, not file extension**. See
[Evidence sources](docs/concepts/sources.md).

## Commands

In workflow order:

| Command | Purpose | Docs |
|---|---|---|
| `acquire` | Collect a `.faul` from a USB-connected iOS device | [→](docs/cli/acquire.md) |
| `extract` | Parse an acquisition into a SQLite database | [→](docs/cli/extract.md) |
| `summary` | High-level overview of an extracted database | [→](docs/cli/summary.md) |
| `kb` | Inspect and lint the YAML knowledge base | [→](docs/cli/kb.md) |
| `annotate` | Apply knowledge-base signatures to a database | [→](docs/cli/annotate.md) |
| `export` | Filtered export to CSV / JSON / JSONL | [→](docs/cli/export.md) |
| `verify-hash` | Re-verify the chain of custody of a database | [→](docs/cli/verify-hash.md) |
| `identify` | Attribute log lines to a user action (interactive, or `--diff` on two captures) | [→](docs/cli/identify.md) |
| `validate-tool` | Self-check against Apple's `log show` / `log collect` | [→](docs/cli/validate-tool.md) |
| `redact-errors` | Turn a local crash report into a redacted bug report | [→](docs/cli/redact-errors.md) |

This is also the order `faul.py --help` prints them in. Every flag, default and
exit code is documented in the [CLI reference](docs/cli/index.md).

## What makes it forensic

- **The timeline cannot be silently re-sorted.** Rows carry both `source_order`
  (physical position in their tracev3 file) and `event_order` (the merged
  timeline, ordered by the *monotonic* mach clock). A backwards jump in
  wall-clock time therefore stays visible as a **time-shift / clock-tampering**
  signal instead of being sorted away.
- **Every timestamp is reproducible.** Each row keeps `timestamp_mach`, its
  timesync anchor (with byte offsets), and `boot_uuid`, so any wall-clock value
  can be recomputed by hand from the evidence.
- **Chain of custody, per file.** The whole archive is fingerprinted before and
  re-verified after the run, and every parsed file gets a SHA-256 before and
  after — so a file that changed mid-run is flagged individually without
  discarding the rest.
- **Evidence is only ever opened read-only**, and a `.faul` container keeps the
  acquisition sidecar *inside* the evidence so the two can never be separated.

Details in the [forensic model](docs/concepts/forensic-model.md) and the
[database schema](docs/formats/database-schema.md).

## Using it as a library

`forensic_aul` is importable on its own, with **no import-time side effects**:

```python
from forensic_aul import run_extract, query_logs

result = run_extract("evidence.logarchive", "case.db", case_number="C1", imei="35…")
for row in query_logs(result.db_path, process="locationd", last="1h"):
    print(row.timestamp_iso, row.message)
```

- [Library overview](docs/library/index.md) · [Recipes](docs/library/recipes.md)
- [API reference](forensic_aul/README.md) — every public symbol

## Documentation

| | |
|---|---|
| [Getting started](docs/getting-started.md) | Install and first run |
| [CLI reference](docs/cli/index.md) | All commands and flags |
| [Concepts](docs/concepts/unified-logs.md) | Unified logs, sources, forensic model |
| [Workflows](docs/workflows/index.md) | Case handling, action attribution, validation |
| [Formats](docs/formats/index.md) | DB schema, `.faul`, sidecar, knowledge base, exports |
| [Library](docs/library/index.md) | Using `forensic_aul` from Python |
| [GUI](docs/gui.md) | The PySide6 desktop app |
| [Architecture](docs/architecture.md) | How the codebase is layered |

## Tests

```bash
python -m pytest tests/ -q          # fast suite (integration auto-excluded)
python -m pytest -q -m integration  # opt-in: full extraction, needs tests/data
./scripts/test_matrix.sh            # fast suite on Python 3.11–3.14 (via uv)
```

Integration tests do a full real extraction taking minutes, so they are
**excluded by default**. CI (`.github/workflows/ci.yml`) runs the fast suite on
3.11–3.14 on every push; builds are reproducible from the committed `uv.lock`.

> Not to be confused with the **`validate-tool`** command, which is a shipped runtime
> feature that checks an *acquisition* against Apple's own tools — see
> [Validation](docs/workflows/validation.md). `tests/` tests the code;
> `forensic_aul/validation/` tests the evidence.

## Development & AI use

Generative AI was used in this project mainly to assist during the coding phase.
The original ideas and the overall structure are the owner's, and all core logic
has been reviewed. Even so, mistakes or bugs may have slipped past proof-reading —
please report anything unexpected.

Coding standards, documentation conventions, and the plan/commit workflow live in
the author's `coding-rules` skill.

## License

Copyright (C) 2026 Ben0x0a

forensic_AUL is free software: you can redistribute it and/or modify it under the
terms of the **GNU General Public License** as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version. It is distributed in the hope that it will be useful, but **WITHOUT ANY
WARRANTY**; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the [`LICENSE`](LICENSE) file (GPL-3.0-or-later) for the
full text, or <https://www.gnu.org/licenses/>.

This project ports and adapts the Mandiant **`macos-unifiedlogs`** library
(Apache-2.0). That code is compatible with GPLv3, and its notices are retained in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) and
[`licenses/macos-UnifiedLogs-LICENSE`](licenses/macos-UnifiedLogs-LICENSE).
