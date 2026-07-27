# Getting started

This page takes you from a clean checkout to a first extracted, summarised and
exported case database.

---

## 1. Prerequisites

| Requirement | Detail |
|---|---|
| Python | **3.11 – 3.14** (`requires-python = ">=3.11,<3.15"`). The dev default is 3.12. |
| [uv](https://docs.astral.sh/uv/) | Recommended for creating the venv and installing. `pip` + `venv` also work. |
| Runtime dependencies | `lz4` and `PyYAML` only — installed automatically. |
| Disk | An extraction writes a SQLite database that is typically the same order of magnitude as the source archive (larger with the FTS index, smaller with `--no-fts`). |

macOS, Linux and Windows are all supported for parsing. Two features are
platform-bound:

- `acquire`, `identify` — need a USB-connected iOS device and the `acquire`
  extra (`pymobiledevice3`); cross-platform, no root.
- `validate-tool --from-device` and automatic reference generation — need **macOS**
  (Apple's `log show` / `log collect`), and `log collect` additionally needs
  **root**. See [`docs/cli/validate-tool.md`](cli/validate-tool.md).

---

## 2. Install

```bash
git clone <repo-url> forensic_AUL
cd forensic_AUL

uv venv --python 3.12          # creates .venv/
source .venv/bin/activate      # Windows: .venv\Scripts\activate
uv pip install -e ".[dev]"

python faul.py --help
```

The repository is **clone-&-run**: `faul.py` at the repo root is the entry
point. Only the `forensic_aul/` package is published as a wheel; `launcher/`,
`app/` and `gui/` are the application layer beside it (see
[`docs/architecture.md`](architecture.md)).

### Optional extras

The core install is deliberately light. Extras are declared in `pyproject.toml`:

| Extra | Adds | Pulls in | Install |
|---|---|---|---|
| `gui` | the PySide6 desktop GUI | `PySide6>=6.6` | `uv sync --extra gui` |
| `acquire` | USB iOS acquisition — the `acquire` command, `identify`, and `validate-tool --from-device` | `pymobiledevice3>=4.0` | `uv sync --extra acquire` |
| `dev` | the pytest test suite | `pytest>=8`, `pytest-cov` | `uv sync --extra dev` |

Install several at once with `uv sync --all-extras`, or with pip-style syntax:
`uv pip install -e ".[gui,acquire,dev]"`.

None of the extras are needed to parse an acquisition you already have on disk.
Without the `acquire` extra, `faul.py acquire` exits with code `1` and a message
telling you to install `pymobiledevice3`; without `gui`, launching the GUI exits
with code `1` and a message telling you to install `PySide6`.

### Activating the virtual environment

Every example in this documentation assumes the venv is **activated**, so
`python` is the venv interpreter:

```bash
source .venv/bin/activate       # Windows: .venv\Scripts\activate
python faul.py --help
```

Without activation, prefix commands with the interpreter path instead:

```bash
.venv/bin/python faul.py --help
```

---

## 3. First run

### 3.1 Extract

Point `extract` at any supported acquisition. The type is detected from the
archive's **content**, not its extension: a `.logarchive` directory, a
sysdiagnose `.tar.gz`, a `.faul` container, or a full-file-system `.zip`.

```bash
python faul.py extract /path/to/evidence.logarchive \
    -o cases/case.db \
    --case-number CASE-2024-001 \
    --imei 350000000000000
```

`-o/--output`, `--case-number` and `--imei` are required (a `.faul` source can
supply the last two from its embedded sidecar). Full reference:
[`docs/cli/extract.md`](cli/extract.md).

### 3.2 Summary

Before exporting anything, see what actually landed in the database:

```bash
python faul.py summary cases/case.db
```

This prints case metadata, the covered time window, top processes / subsystems /
levels, annotation counts and a temporal histogram. See
[`docs/cli/summary.md`](cli/summary.md).

### 3.3 Export

Then pull out the slice you care about:

```bash
python faul.py export cases/case.db -o out/report.csv \
    --process locationd --last 24h
```

The format is inferred from the output suffix (`.csv`, `.json`, `.jsonl`) unless
`--format` is given. See [`docs/cli/export.md`](cli/export.md).

---

## 4. Where the outputs go

| Artefact | Location |
|---|---|
| **Analysis database** | Exactly the path given to `-o/--output`. Parent directories are created if missing. |
| **Operational log** | `<case_number>-AUL-<imei>.log`, written **in the same directory as the output database**. Filesystem-unsafe characters in the case number / IMEI become underscores. |
| **Export files** | The path given to `export -o`. |
| **Crash reports** | `~/.config/faul/crash_reports/` — see [`docs/cli/redact-errors.md`](cli/redact-errors.md). |

The operational log is opened in **append** mode (successive runs for the same
case accumulate; no run is ever lost), always records at `INFO`, and is **sealed**
at the end of every extract session — its SHA-256 is stored in `case_metadata`,
so `verify-hash` can later prove it was not altered. Console output is `INFO` by
default and `DEBUG` with the global `-v/--verbose` flag; the file handler stays
at `INFO` regardless.

---

## 5. Launching the GUI

Running the entry point with **no subcommand** boots the PySide6 GUI:

```bash
python faul.py
```

It requires the `gui` extra. See [`docs/gui.md`](gui.md).

---

## 6. Where to go next

- [CLI overview](cli/index.md) — every command, its purpose, and the global flags.
- [Architecture](architecture.md) — how the layers fit together.
- Concepts: [unified logs](concepts/unified-logs.md) ·
  [sources](concepts/sources.md) · [the forensic model](concepts/forensic-model.md)
- Formats: [database schema](formats/database-schema.md) ·
  [`.faul` container](formats/faul-format.md) ·
  [knowledge base](formats/knowledge-base.md) ·
  [export formats](formats/export-formats.md) ·
  [acquisition sidecar](formats/acquisition-sidecar.md)
- [Using `forensic_aul` as a library](library/index.md)
- [Workflows](workflows/) — end-to-end recipes.
