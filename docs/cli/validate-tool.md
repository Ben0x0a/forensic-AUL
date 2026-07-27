# `validate-tool`

Validate FAUL against Apple's own tooling — the built-in self-check.

> `validate-tool` is a **runtime feature for end users**, not the project's pytest
> suite. It is deliberately not called `test`, and the `-tool` suffix says what
> it validates: `tests/` at the repository root tests *the code*, while
> `forensic_aul/validation/` (which `validate-tool` drives) lets you test *the tool
> itself* against Apple's reference output on your own acquisition.
>
> Not to be confused with `kb validate`, which lints the YAML knowledge base —
> that sub-action keeps its name (see [`kb`](kb.md)).

## Synopsis

```bash
# L1 — parser fidelity
faul.py validate-tool SOURCE [REFERENCE_NDJSON]

# L2 — acquisition fidelity (parser-free)
faul.py validate-tool --acquisition ARCHIVE_A ARCHIVE_B

# L3 — full native pipeline (macOS + root)
sudo faul.py validate-tool --from-device [NAME_OR_UDID]

# no arguments: list devices (macOS) / point at --help
faul.py validate-tool
```

## What it does

FAUL replaces two Apple tools — `log collect` (acquisition) and `log show`
(parsing) — so it validates both, on three layers.

### L1 — parser fidelity

Extracts a logarchive with FAUL and compares the result to Apple's
`log show --style ndjson` ground truth, streaming both sides through a
**flat-memory sort-merge** join so a multi-day store validates without
exhausting RAM.

**Pass criterion: every reference record must be present in the database.**
Relax it with `--allow-missing N` (a count, not a percentage).

### L2 — acquisition fidelity

`--acquisition A B` compares two logarchives **file by file**: SHA-256 each, then
byte-check any that differ. A file passes if it is identical **or an append**
(the live log tail grew between the two collections); a **rewrite** fails it.

This proves two acquisition methods (e.g. pymobiledevice3 vs `log collect`)
copied identical device files. It never runs the parser, so it is independent of
FAUL's correctness — and it is **cross-platform, needs no reference and no
root**.

### L3 — full native pipeline

`--from-device` acquires the **same device both ways** back-to-back (minimising
live-log drift), then runs L2 on the pair and L1 on the metadata-complete
`log collect` archive. This is the headline "are we equivalent to Apple
end-to-end" check. It passes only if **both** L2 and L1 pass.

---

## Platform and privilege requirements

| Capability | Needs |
|---|---|
| `log show` (reference generation) | **macOS**, no root |
| `log collect --device-udid` (L3 acquisition) | **macOS and root** (`sudo`) |
| pymobiledevice3 acquisition (L3, `acquire` extra) | cross-platform, userspace |
| L1 comparison against a supplied reference | cross-platform |
| L2 `--acquisition` | cross-platform, no root |

`validate-tool` logs the capabilities it detected at startup and **refuses
unavailable modes with guidance** rather than failing obscurely:

- `--from-device` off macOS → error naming `--acquisition` and the
  supply-a-reference alternative;
- `--from-device` without root → error telling you to use `sudo`, and noting
  that pymobiledevice3's `acquire` is the userspace alternative;
- a bare logarchive with no reference off macOS → error printing the exact
  `log show` command to run on a Mac.

Off macOS, generate the reference once on a Mac and carry it with you:

```bash
log show --style ndjson --info --debug --signpost <archive> > ref.ndjson
```

---

## Source forms

The mode is selected by the **shape of the arguments** — the run is otherwise
non-interactive.

| Invocation | Mode |
|---|---|
| `validate-tool` | macOS: list connected devices; elsewhere: point at `--help` |
| `validate-tool --acquisition A B` | **L2** — checked first; needs no device and no `log` |
| `validate-tool --from-device [NAME_OR_UDID]` | **L3** — collect → show → extract → diff |
| `validate-tool <logarchive>` | **L1**, reference auto-generated (macOS only) |
| `validate-tool <logarchive> <ref.ndjson>` | **L1**, cross-platform |
| `validate-tool <db.sqlite> <ref.ndjson>` | **L1**, diff only, cross-platform |
| `validate-tool <db.sqlite> --regen-ref <logarchive>` | **L1**, reference re-made (macOS only) |

A `SOURCE` is recognised as a **logarchive** when it is a directory containing a
`Persist/` or `timesync/` subdirectory, and as a **database** when it is a file
with a `.db`, `.sqlite` or `.sqlite3` suffix. Anything else is rejected.

---

## Options

### Positional

| Argument | Default | Meaning |
|---|---|---|
| `SOURCE` | none | A logarchive directory, a SQLite database from `extract`, or omitted with `--from-device` / `--acquisition`. |
| `REFERENCE_NDJSON` | none | Apple `log show --style ndjson` reference; auto-generated on macOS when omitted. |

### Acquisition

| Flag | Default | Meaning |
|---|---|---|
| `--from-device [NAME_OR_UDID]` | not set; bare flag = `""` (auto-pick) | **macOS + root.** Run the L3 pipeline against the named device. Pass nothing to auto-pick when exactly one device is connected. |
| `--regen-ref LOGARCHIVE` | `None` | **macOS.** Force regeneration of the reference ndjson from this logarchive. Useful when `SOURCE` is an existing database. |
| `--acquisition ARCHIVE_A ARCHIVE_B` | `None` | **L2.** Compare two logarchives file-by-file (SHA-256 + append-check). Parser-free, cross-platform, no root. Takes exactly two paths. |

### Reporting

| Flag | Default | Meaning |
|---|---|---|
| `--report REPORT_FILE` | `None` | Also write the comparison report to this text file (parent dirs created). Applies to both L1 and L2. |
| `--ndjson-output NDJSON_FILE` | `None` | Export the database records as ndjson using Apple field names, sorted by `machTimestamp`, for a side-by-side diff. **This is the one path that loads the database into RAM**; the comparison itself stays streaming. |
| `--samples N` | `20` | Maximum mismatch samples shown per category. |

### Pass criterion

| Flag | Default | Meaning |
|---|---|---|
| `--allow-missing N` | `0` | Maximum number of reference records allowed to be missing from the database while still passing. |

### Reference generation

| Flag | Default | Meaning |
|---|---|---|
| `--log-show-args ARGS` | `--info --debug --signpost` | Override the flags passed to `log show`, as a single quoted string (split with `shlex`). |
| `--collect-last DURATION` | `None` | For `--from-device` (L3): bound **both** device collections to this window (`1h`, `30m`) — keeps the capture small and fast, and the drift minimal. |

### Artefacts

| Flag | Default | Meaning |
|---|---|---|
| `--db-output DB_PATH` | a temp dir | When extracting, write the database here (parent dirs created). |
| `--keep-db` / `--no-keep-db` | **keep** | Keep the extracted database after the run. Kept files live on even when they sit inside a temp dir. |
| `--keep-ref` / `--no-keep-ref` | **discard** | Keep the auto-generated reference ndjson after the run. |
| `--case-number CASE` | `VALIDATE` | Case number recorded on any auto-extraction. |
| `--imei IMEI` | `000000000000000` | IMEI recorded on any auto-extraction. A synthetic all-zero placeholder, deliberately **not** Luhn-valid. |

---

## Examples

```bash
# L1 on macOS: everything auto-generated from one archive
faul.py validate-tool evidence.logarchive

# L1 anywhere, with a reference made earlier on a Mac
faul.py validate-tool evidence.logarchive ref.ndjson

# L1 against an already-extracted database, keeping a full report
faul.py validate-tool cases/case.db ref.ndjson --report out/validate.txt --samples 100

# L1 tolerating a handful of missing records
faul.py validate-tool cases/case.db ref.ndjson --allow-missing 5

# Regenerate the reference for an existing database (macOS)
faul.py validate-tool cases/case.db --regen-ref evidence.logarchive --keep-ref

# Side-by-side ndjson for manual diffing
faul.py validate-tool cases/case.db ref.ndjson --ndjson-output out/faul.ndjson

# L2: did two acquisition methods copy the same files?
faul.py validate-tool --acquisition pmd3.logarchive collect.logarchive \
    --report out/acquisition.txt

# L3: the full end-to-end equivalence check, last hour only
sudo faul.py validate-tool --from-device --collect-last 1h --db-output out/l3.db

# L3 against a named device
sudo faul.py validate-tool --from-device 00008030-0011… --collect-last 30m

# Non-default log show flags
faul.py validate-tool evidence.logarchive --log-show-args "--info --debug"
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | **PASS.** L1: every reference record present (within `--allow-missing`). L2: the two acquisitions copied identical files (appends aside). L3: both L2 and L1 passed. Also `0` for the no-argument device listing on macOS when devices were found. |
| `1` | **FAIL or invocation error** — records missing beyond the allowance; diverged files in L2; either layer failing in L3; `--from-device` off macOS or without root; a missing / unreadable reference; an uninterpretable `SOURCE`; `--acquisition` paths that are not directories; no devices connected; or nothing to do off macOS. |

There is no separate code for "could not run" versus "did not pass" — read the
log output, which always states `PASS:` or `FAIL:` explicitly.

---

## Common pitfalls

- **`--from-device` needs `sudo` on macOS.** Apple's `log collect --device-udid`
  requires root; the error message says so, and points at `acquire` as the
  userspace alternative.
- **Off macOS you must supply the reference.** There is no way to generate
  `log show` output on Linux or Windows.
- **`--acquisition` is checked before everything else**, so a stray `SOURCE`
  alongside it is ignored.
- **The default `--allow-missing 0` is strict**, and correctly so: any missing
  reference record is a parser gap worth understanding before you relax it.
- **`--keep-ref` defaults to off, `--keep-db` defaults to on.** After a run you
  usually still have the database but not the reference.
- **`--ndjson-output` loads the database into memory.** Avoid it on very large
  archives unless you need the side-by-side dump.
- **Live drift is expected in L3.** The two collections happen back-to-back, and
  L2's append-check absorbs the tail that grew between them; a *rewrite* is what
  fails.
- **`--log-show-args` replaces the defaults entirely** — it does not append to
  `--info --debug --signpost`. Dropping `--debug` shrinks the reference and can
  make a real gap look like a pass.
- **`validate-tool` is not [`verify-hash`](verify-hash.md).** `validate-tool` asks
  "is the parse correct?"; `verify-hash` asks "has the evidence changed since extraction?".

---

## See also

- [`extract`](extract.md) — the parser under test
- [`acquire`](acquire.md) — the userspace acquisition path compared in L2
- [`verify-hash`](verify-hash.md) — chain of custody, a different question
- [Unified logs](../concepts/unified-logs.md) ·
  [Forensic model](../concepts/forensic-model.md) ·
  [Sources](../concepts/sources.md)
