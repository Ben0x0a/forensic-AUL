# `redact-errors`

List local crash reports, or redact one into a shareable bug report.

## Synopsis

```bash
faul.py redact-errors [--dir DIR]                # list
faul.py redact-errors ID_OR_PATH [--dir DIR]     # redact for sharing
```

## What it does

When FAUL hits an unexpected error — in the CLI, the GUI, or an extract session —
it writes a **crash report** capturing the traceback plus the type and value of
every variable in every stack frame. That is usually enough to diagnose a bug
without reproducing it.

Because this is a forensic tool, each captured variable is split into a **`safe`**
and a **`sensitive`** section. Device identifiers, log message content, extracted
values, case identifiers and evidence paths all go to `sensitive`. The local
report keeps the real values, and **nothing leaves your machine automatically**.

There are two modes:

- **no argument** — list the raw crash reports in the crash directory, newest
  first, with their size. Already-redacted `*.shared.json` files are excluded
  from the listing.
- **`ID_OR_PATH`** — write a redacted, shareable pair beside the source file:
  `<name>.shared.json` and `<name>.shared.md`. Every sensitive value is replaced
  by a type + SHA-256 placeholder and paths are anonymised. The Markdown file
  doubles as a fillable bug template (steps to reproduce, expected vs actual).

---

## Options

| Flag | Default | Meaning |
|---|---|---|
| `ID_OR_PATH` | none (→ list mode) | A crash-report file to redact. Accepts a full path, a bare filename, or the file stem (`.json` is appended). |
| `--dir DIR` | `~/.config/faul/crash_reports` | Crash-report directory. |

Raw files are named `faul_crash_*.json`. Resolution tries, in order: the value as
a path, `<crash-dir>/<value>`, then `<crash-dir>/<value>.json`.

---

## Examples

```bash
# What crash reports do I have?
faul.py redact-errors

# Redact one for a bug filing (any of these forms work)
faul.py redact-errors faul_crash_20260726_101112.json
faul.py redact-errors faul_crash_20260726_101112
faul.py redact-errors ~/.config/faul/crash_reports/faul_crash_20260726_101112.json

# A crash directory somewhere else
faul.py redact-errors --dir /Volumes/EVID/crash_reports
faul.py redact-errors faul_crash_20260726_101112 --dir /Volumes/EVID/crash_reports
```

---

## Outputs

| File | Contents |
|---|---|
| `<name>.shared.json` | the redacted data, machine-readable |
| `<name>.shared.md` | the same, rendered as Markdown with a bug template |

Both are written **next to the source file** (not into the current directory) and
encoded as UTF-8 with a BOM.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Files listed (including when there are none), or the redacted pair was written. |
| `1` | The named crash file could not be found, or could not be read / parsed as JSON. |

---

## Common pitfalls

- **Review the ⚠ Sensitive sections before attaching anything.** Redaction is
  thorough, but the tool cannot know what your case considers sensitive; the
  Markdown flags those sections precisely so you can check them.
- **Never send the raw `faul_crash_*.json`.** It contains real values by design.
  Only the `*.shared.*` pair is safe to share.
- **An empty listing exits `0`.** "No crash reports found" is not an error.
- **Listing output goes through the logger**, so it obeys the console handler
  like any other output.
- **A file is only written when an error was actually captured.** A failure a
  command handles itself (an invocation error, a bad path) is not a crash and
  produces nothing here.

---

## See also

- [CLI overview](index.md)
- [Architecture](../architecture.md) — where the crash handler is installed
