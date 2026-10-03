# The case workflow, end to end

The path from evidence in hand to a defensible export. Commands are shown for the
CLI (`python faul.py …`); the library equivalents are in
[../library/recipes.md](../library/recipes.md), and the GUI mirrors the same steps
in its sidebar (see [../gui.md](../gui.md)).

```
acquire ──┐
          ├─→ extract ─→ summary ─→ annotate ─→ export
receive ──┘                              └────→ verify-hash
```

---

## 0. Before you touch anything

Decide and write down, up front:

- the **case number** and, if applicable, the **exhibit reference** — they are
  recorded in the database's case metadata and in the operational log filename;
- the **analyst** name and any **notes** justifying the acquisition;
- where the working copy lives, and that the original stays untouched.

The commands that record case metadata — `acquire`, `extract` and `identify` —
all accept `--case-number`, `-e/--exhibit-number`, `--analyst` and `--notes`.
Fill them in — they are what turns a database into an exhibit.

---

## 1. Acquire, or receive

### Acquire from a device

```bash
python faul.py acquire --list                       # what is connected?
python faul.py acquire --case-number CASE-2024-001 \
    --analyst "A. Analyst" --exhibit-number "ITEM-3" \
    --output-dir /evidence
```

Requires the optional `acquire` extra (`pymobiledevice3`) and a paired,
USB-connected iOS device. The default output is a single portable **`.faul`
container** — the logarchive *plus* its acquisition sidecar in one file, named
`<case>-<imei|udid>-<UTC>.faul` — so the provenance record can never be separated
from the evidence. `--raw` produces the legacy loose layout instead (a
`.logarchive` directory plus a separate `.acquisition.json`).

Useful flags: `--udid` to pick a device, `--start-time` to bound how far back to
collect, `--size-limit` / `--age-limit`, `--yes` to skip the confirmation prompt,
and `--extract` to chain straight into step 2.

**Check:** the printed SHA-256 and file count. Record them.

### Receive evidence from elsewhere

forensic_AUL detects the container **by content, not by extension**:

| You have | Pass it as |
|---|---|
| a `.faul` container | the path |
| a `.logarchive` directory | the path |
| a sysdiagnose `.tar.gz` | the path |
| a full-file-system `.zip` | the path |
| already-uncompressed `private/var/db/{diagnostics,uuidtext}` | `--diagnostics DIR --uuidtext DIR` |

See [../concepts/sources.md](../concepts/sources.md).

**Chain-of-custody hygiene:** hash what you received *before* you process it, and
compare against whatever the provider stated. Work from a copy; never let a tool
write into the original evidence directory.

---

## 2. Extract

```bash
python faul.py extract /evidence/CASE-2024-001-…​.faul case.db \
    --case-number CASE-2024-001 --imei 35… \
    --analyst "A. Analyst" --exhibit-number "ITEM-3"
```

Case number and IMEI are required — unless the source is a `.faul`, whose sidecar
supplies them automatically.

What happens: the source is normalised, **every file is SHA-256 hashed**, the
tracev3 data is parsed, rows are written to SQLite, the forensic ordering is
assigned, indexes are built, and at the end **every source file is re-hashed** to
prove nothing changed underneath the run.

Flags worth knowing:

| Flag | Why |
|---|---|
| `--integrity full` (default) | the complete chain-of-custody attestation. `fingerprint` / `off` are **triage only** — the database then records no evidence hashes |
| `--overwrite` | required to write into an existing database; without it the run refuses, because merging two acquisitions into one file silently is unacceptable |
| `--jobs N` | parser process budget (default: auto, capped at the physical core count). The result is identical for any N |
| `--no-fts` | skip the full-text index — markedly smaller and faster, at the cost of keyword search |
| `--work-dir DIR` | for archive sources, keep the unpacked logarchive instead of using a temp dir (a non-empty work root is refused — add `--reset-work-dir` to clear it) |
| `--fast-write`, `--fast` | faster, less crash-durable — disposable, re-runnable extractions only |

**Check before moving on:**

- the reported **entry count** and **time range** — do they match the device and
  the period you expected?
- **parse errors** — a few are normal on real evidence (a corrupt chunk costs a
  counter, never the run); a flood is a signal;
- **write errors** — should be `0`. Non-zero means the database is *knowingly*
  incomplete; investigate the ERROR lines;
- **source files changed** — should be `0`. Non-zero means a source file changed
  during the run, and anything parsed from it is suspect.

Alongside the database, the run writes an operational **log file**
(`<case>-AUL-<imei>.log`) in the same directory, in append mode, whose hash is
sealed into the case metadata. Keep it with the database — it is the audit trail.

---

## 3. Summary — sanity-check the extraction

```bash
python faul.py summary case.db
python faul.py summary case.db --top 20 --buckets 60
```

Read it as a plausibility check, not a finding:

- device model, iOS build/version, case number, IMEI — do they match the exhibit?
- total entries and the time range — does the coverage span the period of interest,
  or did the device rotate its logs away?
- the temporal histogram — a gap can be a powered-off device, a rotation boundary,
  or a truncated acquisition. Know which before you rely on the absence of data.
- top processes / subsystems / levels — a first orientation on what this device
  was doing.

---

## 4. Annotate against the knowledge base

Annotation applies YAML **signatures** — known log patterns with an action label,
tags and optional extracted named values — to the extracted rows.

```bash
python faul.py annotate case.db                        # default: ./knowledge_base
python faul.py annotate case.db --kb /path/to/kb
python faul.py annotate case.db --tag network          # restrict by tag
python faul.py annotate case.db --signature some_id    # restrict by id
```

This is a **separate, repeatable pass**. When the knowledge base improves, re-run
`annotate` — you never re-extract. The knowledge-base version is recorded in the
database, so a finding can be traced back to the exact signature set that produced
it.

Inspect the knowledge base itself with `python faul.py kb list|show|validate|labels|stats`.
See [../formats/knowledge-base.md](../formats/knowledge-base.md).

**Check:** the per-signature match counts. Zero matches everywhere usually means
the signature set does not cover this iOS version, not that nothing happened.

---

## 5. Analyse

Query with the CLI export filters, or interactively in the GUI's Exploit screen,
or programmatically with `query_logs` / `LogStore`
([../library/recipes.md](../library/recipes.md)).

The filter vocabulary is the same everywhere: time bounds (`--from`, `--to`,
`--last`), log columns (`--process`, `--subsystem`, `--level`, `--like`), and
annotations (`--signature`, `--action`, `--tag`, `--annotated-only`).

Two habits that pay off:

- **Read context on the forensic ordering, not the clock.** `fetch_context` (and
  the GUI's "view context") walks `event_order`, so a shifted device clock cannot
  reorder what you see around a line.
- **Match dynamic messages on the composed message.** Some entries carry no format
  string, or a bare `%{public}s`; for those, filter on the message text rather
  than the template.

To attribute log lines to a *specific user action*, use the identify workflow —
[identify-action.md](identify-action.md).

---

## 6. Export

```bash
python faul.py export case.db -o report.csv --level Error --level Fault --last 7d
python faul.py export case.db -o findings.json --annotated-only
python faul.py export case.db -o rows.jsonl --format jsonl --no-fields
```

Format is inferred from the suffix (`.csv` / `.json` / `.jsonl`) unless
`--format` says otherwise. Extracted-value columns (one per label) are included by
default; `--no-fields` drops them. See
[../formats/export-formats.md](../formats/export-formats.md).

Export the *filtered* view you will actually cite, and record the exact filter set
you used — it is part of the method.

---

## 7. Verify — the chain of custody, re-checked

```bash
python faul.py verify-hash case.db
python faul.py verify-hash case.db --logarchive /evidence/original.logarchive
python faul.py verify-hash case.db --skip-files          # global hash only
```

`verify-hash` recomputes the hashes stored in the database's case metadata: the source
material and the operational log file, plus the per-file digests unless
`--skip-files`. It reports passed/failed counts and an overall verdict.

Run it:

- immediately after extraction (a baseline that the outputs are internally
  consistent);
- before producing a report;
- whenever evidence has been moved, copied, or handed over.

A failure is not a formality — it means the material behind your conclusions is
not the material that was hashed.

To go further and prove the *parser itself* agrees with Apple's own tooling, run
the self-check: [validation.md](validation.md).

---

## Chain-of-custody hygiene, condensed

1. **Fill in the case fields.** `--case-number`, `--exhibit-number`, `--analyst`,
   `--notes` on every command that takes them.
2. **Keep `--integrity full`.** `fingerprint` and `off` exist for triage speed and
   record *no* evidence hashes. Never use them for work you will report.
3. **Never write into the original.** Work from a copy; use `--work-dir` if you
   want the unpacked archive kept somewhere you chose.
4. **Never re-extract into an existing database.** The refusal without
   `--overwrite` exists precisely to stop two acquisitions silently merging.
5. **Keep the trio together:** the source (or its `.faul`), the database, and the
   `<case>-AUL-<imei>.log` operational log whose hash is sealed in the metadata.
6. **Prefer the `.faul` container** when moving evidence: the acquisition sidecar
   travels inside it and cannot be separated.
7. **Check the counters after every extract:** parse errors, write errors, and
   source files changed.
8. **Record the tool version** (`python faul.py --version`) and the knowledge-base
   version used for annotation, alongside your findings.
9. **Re-verify before you report**, and keep the `validate-tool --report` output if the
   method itself may be questioned.

---

## See also

- [Identify workflow](identify-action.md) · [Validation](validation.md)
- [CLI reference](../cli/index.md) · [GUI](../gui.md)
- [Library recipes](../library/recipes.md)
- [../getting-started.md](../getting-started.md)
- [../concepts/forensic-model.md](../concepts/forensic-model.md)
