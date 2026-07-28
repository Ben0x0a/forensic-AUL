# forensic_AUL documentation

Full documentation for **forensic_AUL** — a digital-forensics tool that parses
Apple Unified Logs into a normalised, queryable SQLite database while preserving
byte-level provenance and the true event timeline.

New here? Start with **[Getting started](getting-started.md)**, then follow the
[case workflow](workflows/case-workflow.md).

---

## Start here

| Page | For |
|---|---|
| [Getting started](getting-started.md) | Install, first extraction, first export |
| [CLI reference](cli/index.md) | Every command, flag and exit code |
| [Architecture](architecture.md) | How the codebase is layered |

## Concepts

Background needed to interpret the output correctly.

| Page | Covers |
|---|---|
| [Apple Unified Logs](concepts/unified-logs.md) | tracev3 containers, firehose entries, DSC/UUIDText strings, timesync, format-string resolution |
| [Evidence sources](concepts/sources.md) | The five accepted acquisition types, content-based detection, normalisation, work dirs |
| [Forensic model](concepts/forensic-model.md) | Mach vs wall clock, `source_order` / `event_order`, time-shift visibility, chain of custody, integrity modes |

## Commands

In workflow order:

| Page | Command |
|---|---|
| [acquire](cli/acquire.md) | Collect a `.faul` from a USB-connected iOS device |
| [extract](cli/extract.md) | Acquisition → SQLite |
| [summary](cli/summary.md) | Overview of an extracted database |
| [kb](cli/kb.md) | Inspect and lint the knowledge base |
| [annotate](cli/annotate.md) | Apply knowledge-base signatures |
| [export](cli/export.md) | Filtered CSV / JSON / JSONL export |
| [verify-hash](cli/verify-hash.md) | Re-verify chain of custody |
| [identify](cli/identify.md) | Attribute log lines to a user action (interactive, or `--diff` on two captures) |
| [validate-tool](cli/validate-tool.md) | Self-check against Apple's own tools (L1 / L2 / L3) |
| [redact-errors](cli/redact-errors.md) | Turn a crash report into a redacted bug report |

## Workflows

| Page | Covers |
|---|---|
| [Case workflow](workflows/case-workflow.md) | Acquire → extract → summary → annotate → export → verify-hash |
| [Action attribution](workflows/identify-action.md) | Baseline / action / diff, and how to read the result |
| [Validation](workflows/validation.md) | Proving equivalence with Apple's `log show` and `log collect` |

## Formats

| Page | Describes |
|---|---|
| [Index](formats/index.md) | All formats at a glance |
| [Database schema](formats/database-schema.md) | The analysis database `extract` produces |
| [`.faul` container](formats/faul-format.md) | The portable evidence container |
| [Acquisition sidecar](formats/acquisition-sidecar.md) | The traceability JSON written by `acquire` |
| [Knowledge base](formats/knowledge-base.md) | Signature YAML schema and the label vocabulary |
| [Export formats](formats/export-formats.md) | CSV / JSON / JSONL column contract |
| [Identify database](formats/identify-database.md) | The diff database produced by `identify` |

## Library

`forensic_aul` is importable on its own, with no CLI and no import-time side effects.

| Page | Covers |
|---|---|
| [Overview](library/index.md) | Install, stability policy, the mental model |
| [Recipes](library/recipes.md) | Runnable examples for every common task |
| [Progress & errors](library/progress-and-errors.md) | Progress sinks, exception hierarchy, logging |
| [API reference](../forensic_aul/README.md) | Per-symbol reference for everything in `__all__` |

## GUI

| Page | Covers |
|---|---|
| [Desktop GUI](gui.md) | Installing and launching the PySide6 app, the screens that exist today, current maturity |

---

## Conventions

- Every page documents the behaviour of the **current source**, not of a release.
  Where a flag's default matters forensically, it is stated explicitly.
- Command examples assume an **activated virtual environment**; without one,
  prefix them with the interpreter path (`.venv/bin/python faul.py …`).
- `docs/internal/` is maintainer-only and **not tracked in git**.
