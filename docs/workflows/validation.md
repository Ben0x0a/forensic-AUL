# Validation: proving the tool is telling the truth

A forensic parser is only useful if you can demonstrate that what it produced
matches what the device actually recorded. forensic_AUL ships a **runtime
self-check** — the `validate-tool` command — that compares its own output against
Apple's own tooling, and compares its own acquisition against Apple's own
acquisition.

```bash
python faul.py validate-tool --help
```

> **This is not the test suite.** `validate-tool` is a runtime QA feature that runs
> against *your* evidence on *your* machine; its implementation lives in
> `forensic_aul/validation/`. The project's pytest suite lives in the repo-root
> `tests/` and is a developer concern (`pytest`, or `pytest -m integration` for
> the slow full-extraction tests). The command is deliberately named `validate-tool`
> rather than `test` so the two never read as the same thing.

---

## The three layers

Each layer proves a different link in the chain, and each has different platform
requirements.

| Layer | Question it answers | What it compares | Needs |
|---|---|---|---|
| **L1 — parser fidelity** | Did we decode the logs the same way Apple does? | our SQLite database vs Apple `log show --style ndjson` | a reference ndjson (generated on macOS; usable anywhere) |
| **L2 — acquisition fidelity** | Did our collection copy the same device files Apple's does? | two `.logarchive` directories, file by file | nothing — cross-platform, parser-free, no root |
| **L3 — full native** | Both of the above, on one device, in one run | acquire the same device both ways, then run L2 + L1 | macOS **and** root, plus a paired iOS device |

The layers are independent. L2 can fail while L1 passes (the acquisition drifted
but both parsers agree on what was collected), and vice versa. L3 simply runs L2
and L1 back-to-back on the same device and reports both.

The command logs its environment probe on every run —
`macOS=… log-tool=… root=…` — so a refusal is always explainable.

---

## L1 — parser vs Apple `log show`

**What it proves.** For every record Apple's `log show` emits from an archive,
our database contains the corresponding row, with matching identity and content.

**How it compares.** The reference ndjson and the database are both sorted by the
match key `(bootUUID, machTimestamp, threadID)` and walked in lockstep by a
streaming sort-merge, so a multi-day store compares in flat memory (never more than
one record per side plus bounded samples). Matched pairs are then compared on the
message (exact, then normalised — trimmed, lower-cased, whitespace-collapsed), the
raw format-string template, and the structural fields (pid, tid, subsystem,
category, …).

**Pass criterion.** *Every reference record must be present in the database.*
Raise the tolerance explicitly with `--allow-missing N` (a count, not a
percentage). Extra rows on our side are reported but do not fail the run — our
extractor emits at every level, which is also why the reference is generated with
`--info --debug --signpost`.

Some Apple event types are deliberately out of scope on both sides:
`timesyncEvent` (metadata markers) and `stateEvent` (statedump) are skipped by the
loader, since they are not log entries in our schema.

### Running L1

On macOS, a logarchive alone is enough — the reference is generated for you:

```bash
python faul.py validate-tool /evidence/system_logs.logarchive
```

Anywhere, with an explicit reference:

```bash
python faul.py validate-tool /evidence/system_logs.logarchive ref.ndjson
python faul.py validate-tool case.db ref.ndjson          # skip the extract, diff only
```

Re-generate the reference for a database you already have (macOS):

```bash
python faul.py validate-tool case.db --regen-ref /evidence/system_logs.logarchive
```

Useful options:

| Option | Effect |
|---|---|
| `--report FILE` | write the comparison report to a text file as well as stdout |
| `--samples N` | mismatch samples per category (default 20) |
| `--allow-missing N` | tolerate N missing reference records (default 0) |
| `--ndjson-output FILE` | export the DB as ndjson with Apple's field names, for a side-by-side diff |
| `--log-show-args "…"` | override the `log show` flags (default `--info --debug --signpost`) |
| `--db-output PATH` | where the auto-extract writes its database |
| `--keep-db` / `--no-keep-db` | keep the extracted database (default: keep) |
| `--keep-ref` / `--no-keep-ref` | keep the auto-generated reference (default: discard) |
| `--case-number`, `--imei` | metadata for the auto-extract (defaults `VALIDATE` / an all-zero placeholder IMEI) |

An `--ndjson-output` export is the one path that loads the database into RAM; the
comparison itself always stays streaming.

### Generating a reference on a Mac for use elsewhere

`log show` only exists on macOS, so that is where a reference must be born — but
the resulting file is just ndjson and travels anywhere. On the Mac:

```bash
log show --style ndjson --info --debug --signpost /evidence/system_logs.logarchive > ref.ndjson
```

(That is exactly the command the CLI prints when you ask for an auto-generated
reference off macOS.) Or let the tool keep the one it generates:

```bash
python faul.py validate-tool /evidence/system_logs.logarchive --keep-ref
```

Then, on Linux or Windows, validate against it:

```bash
python faul.py validate-tool case.db ref.ndjson --report validation.txt
```

The archive and the reference must correspond to each other — a reference
generated from a different archive will show up as mass "missing" records.

---

## L2 — acquisition fidelity

**What it proves.** That two acquisition methods — typically our
`pymobiledevice3`-based `acquire` and Apple's `log collect` — copied the *same
bytes* off the device. It is **parser-free**: it never calls `run_extract`, so it
validates the acquisition without assuming the parser is correct.

**How it compares.** Only the on-device log-data files matter (`*.tracev3`,
`*.timesync`, `dsc/*`, `uuidtext/**`); the archive wrapper (`Info.plist` and
friends) differs by construction and is ignored. Each file gets a verdict:

| Verdict | Meaning |
|---|---|
| `identical` | same SHA-256 — sealed/rotated files, the bulk of the archive |
| `append` | one is a byte-prefix of the other — the live tail grew between the two collections on a running device; **expected** |
| `diverged` | contents differ and neither is a prefix — a file was rewritten; a **real** acquisition discrepancy |
| `only_a` / `only_b` | present in one archive only — a new current file is expected under rotation; a vanished file is flagged |

**Pass criterion.** No `diverged` files. Everything is hashed on disk in a stream,
so a multi-gigabyte archive costs flat memory.

```bash
python faul.py validate-tool --acquisition /evidence/from_pmd3.logarchive /evidence/from_log_collect.logarchive
python faul.py validate-tool --acquisition A.logarchive B.logarchive --report acq-check.txt
```

Cross-platform, no device needed, no root needed — the two archives just have to
be on disk.

---

## L3 — full native, one device, one run

**What it proves.** End to end, on a live device: that our userspace acquisition
matches Apple's native one (L2), *and* that our parser matches Apple's on the
metadata-complete archive (L1).

**How it runs.** The same device is acquired twice, back-to-back to minimise
live-log drift (whatever tail grows between the two collections is absorbed by
L2's append verdict):

1. `acquire` via `pymobiledevice3` (userspace, loose `.logarchive` — no `.faul`
   wrapper);
2. `log collect --device-udid …` via Apple's tool;
3. **L2** on the two archives;
4. **L1** on the `log collect` archive (chosen because it is the
   metadata-complete one): `log show` reference → our extract → sort-merge compare.

The run reports both verdicts and exits non-zero unless *both* pass.

**Requirements.** macOS (for `log collect` / `log show`), **root** (`log collect
--device-udid` demands it), and a device that has been paired — i.e. "Trust this
computer" was accepted. Without pairing, `log collect` fails and its stderr is
surfaced verbatim.

```bash
python faul.py validate-tool                       # macOS: lists connected devices
sudo python faul.py validate-tool --from-device    # auto-picks when one device is connected
sudo python faul.py validate-tool --from-device "Test iPhone" --collect-last 1h
```

`--collect-last DURATION` bounds *both* collections (`1h`, `30m`, …) — strongly
recommended: it keeps the capture small and fast and minimises drift between the
two acquisitions.

If you are not on macOS, or not root, the command refuses with the alternative
spelled out: run `validate-tool --acquisition A B` for the acquisition check and supply
a reference ndjson for the parser check.

---

## Choosing a layer

| Situation | Run |
|---|---|
| "Does your parser agree with Apple?" (a report, a court question) | L1 with `--report` |
| Working on Linux/Windows | L1 against a Mac-generated reference; L2 on two archives |
| "Is your USB collection as good as Apple's?" | L2 |
| A full, self-contained demonstration on a test device | L3 (macOS + root) |
| Regression-checking a code change | the pytest suite (`pytest`, `pytest -m integration`) |

Keep the `--report` output with the case file: it is a dated, reproducible record
that the tool was checked against the vendor's own implementation on this evidence.

---

## See also

- [Case workflow](case-workflow.md) — where validation sits in a real case
- [Identify workflow](identify-action.md)
- [CLI reference](../cli/index.md)
- [../concepts/forensic-model.md](../concepts/forensic-model.md)
