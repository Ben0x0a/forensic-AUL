# `verify-hash`

Verify the chain of custody of an extracted SQLite database.

## Synopsis

```bash
faul.py verify-hash DATABASE [--logarchive DIR] [--log-file FILE] [--skip-files]
```

## What it does

`verify-hash` re-computes the hashes recorded at extraction time and compares them
against what is stored in the database:

- the **global content SHA-256** of the logarchive material;
- the **per-file SHA-256** of every registered source file (`source_files`) —
  tracev3, uuidtext, dsc, timesync, `shutdown.log`;
- the SHA-256 of the **sealed operational log file**.

The paths come from `case_metadata` unless overridden. Nothing is written; the
evidence and the database are only read.

Use it **before disclosure or handover** to prove that neither the evidence nor
the audit log has been altered since extraction.

---

## Options

| Flag | Default | Meaning |
|---|---|---|
| `DATABASE` | **required** | SQLite database produced by `extract`. |
| `--logarchive DIR` | read from `case_metadata` | Override the path to the `.logarchive`. Supply only if the evidence has moved since extraction. |
| `--log-file FILE` | read from `case_metadata` | Override the path to the operational log file. Supply only if it has moved. |
| `--skip-files` | off | Skip the per-file verification; only re-hash the logarchive globally. Much faster on large archives, but a single altered file inside an otherwise identical tree is then only visible through the global hash, and a mismatch can no longer be attributed to a content change vs a renamed file (see [Reading a global-hash mismatch](#reading-a-global-hash-mismatch)). |

---

## Examples

```bash
# Standard verification, paths from case_metadata
faul.py verify-hash cases/case.db

# The evidence was moved to an external drive
faul.py verify-hash cases/case.db --logarchive /Volumes/EVID/case.logarchive

# The database and its log were archived together elsewhere
faul.py verify-hash cases/case.db \
    --logarchive /Volumes/EVID/case.logarchive \
    --log-file   /Volumes/EVID/CASE-2024-001-AUL-350000000000000.log

# Quick global-hash-only pass
faul.py verify-hash cases/case.db --skip-files

# Use in a script
faul.py verify-hash cases/case.db || echo "CHAIN OF CUSTODY BROKEN"
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | All checks passed. |
| `1` | At least one mismatch or missing file. The report names exactly what failed. |
| `2` | Invocation error — the database or a required path could not be read (`FileNotFoundError`), or the database is not a valid analysis database (`ValueError`). |

The distinction matters in scripts: `1` means "the evidence does not match",
`2` means "the check could not be performed at all".

---

## Common pitfalls

- **A database extracted with `--integrity fingerprint` or `--integrity off` has
  no evidence hashes to verify.** Those modes are triage-only; only
  `--integrity full` (the default) produces a fully verifiable database.
- **Exit `2` is not a pass.** Always distinguish it from `0`.
- **Only supply the overrides when files have actually moved.** Pointing
  `--logarchive` at a *different* archive will of course fail, which is the point.
- **A live acquisition re-collected later will not match.** The recorded hashes
  attest to the archive that was extracted, not to the device.
- **`--skip-files` weakens the result.** For a handover, run the full check.
- **The operational log is append-mode.** Running another extract session with
  the same case number + IMEI into the same directory appends to that log and
  changes its hash — re-seal by re-running, or verify against the sealed value
  from the run you are attesting to.

---

## See also

- [`extract`](extract.md) — where the hashes are recorded and the log is sealed
- [`validate-tool`](validate-tool.md) — a different question: is the *parse* correct?
- [Forensic model](../concepts/forensic-model.md) ·
  [Database schema](../formats/database-schema.md) ·
  [Acquisition sidecar](../formats/acquisition-sidecar.md)

## Reading a global-hash mismatch

The global hash covers each file's **relative path** and its **content digest**,
so a mismatch means one of the two moved. `verify-hash` says which, using the
per-file results to tell them apart:

| What it reports | What it means |
|---|---|
| `N file(s) changed content` | a recorded file's bytes differ — a real content change |
| `content is intact but N recorded file(s) are no longer at their recorded path` | something was renamed, moved or removed inside the archive |
| `every recorded file's content matches, so the difference is in file paths/names, or in a file the extract did not record` | no recorded content changed; the archive's *shape* did (note that `hash_logarchive` covers every file in the tree, while `source_files` records only the ones that were parsed) |
| `re-run without --skip-files …` | the per-file evidence that separates these cases was not gathered |

**Moving a case does not break verification.** Paths are relative to the
logarchive root, so relocating or copying the whole archive leaves the hash
unchanged. `verify-hash` finds the archive through the absolute path stored at
extract time, so after a move point it at the new location:

```bash
faul verify-hash case.db --logarchive /new/location/case.logarchive
```

## An interrupted extract cannot be verified

An extract that does not finish leaves `<name>.sqlite.partial` rather than
`<name>.sqlite` — the final name exists only when a run completed. `verify-hash`
refuses a partial, as every reader does: its ordering, indexes and full-text
index may be missing, so anything read from it would silently under-report.

A partial is not an extract. Re-run it.
