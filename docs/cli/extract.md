# `extract`

Parse a unified-log acquisition into a normalised SQLite database.

## Synopsis

```bash
faul.py extract INPUT -o OUTPUT_DB --case-number CASE --imei IMEI [options]

faul.py extract -o OUTPUT_DB \
    --diagnostics DIR --uuidtext DIR \
    --case-number CASE --imei IMEI [options]
```

## What it does

`extract` reads a unified-log source and writes every Firehose log entry into a
normalised SQLite database, together with the lookups (processes, subsystems,
categories, libraries, format strings), the timesync anchors used to convert
mach time to wall clock, the shutdown events, and a full chain-of-custody
record.

Broad shape of a run (see [`docs/architecture.md`](../architecture.md) for the
detail):

1. **Prepare source** — normalise the input to a logarchive layout, take the
   archive fingerprint and per-file SHA-256, read `SystemVersion.plist` /
   `Info.plist` / the `.faul` sidecar.
2. **Schema + pragmas** — create the tables; indexes are deferred to the end.
3. **Timesync** — merge the `.timesync` files and pre-insert the anchors.
4. **String cache** — load `UUIDText` + `DSC` shared caches.
5. **Pass 1** — oversize-record scan.
6. **Pass 2** — parse the `tracev3` files, serially or across `jobs-1` worker
   processes.
7. **Ordering** — assign `source_order` and `event_order` in one pass, so the
   result is identical for any `--jobs`.
8. **Indexes**, then **FTS finalise** (when `--fast-fts`), then `shutdown.log`.
9. **Finalise** `case_metadata` and re-verify the archive fingerprint.

Only the required `-o/--output` decides where the database goes; the evidence is
opened **read-only** throughout.

Alongside the database, the command writes and then **seals** an operational log
— see [Outputs](#outputs).

---

## Inputs

The positional `INPUT` is auto-detected **by content (magic bytes), not by file
extension**:

| Input | What it is | What is used |
|---|---|---|
| `*.logarchive/` directory | `log collect` / pymobiledevice3 output | used in place |
| `*.tar.gz` | a **sysdiagnose** bundle | its self-contained `system_logs.logarchive/` |
| `*.faul` | a **portable container** produced by [`acquire`](acquire.md) | the bundled logarchive; its embedded sidecar auto-fills the case fields |
| `*.zip` | a **full file system (FFS)** acquisition | `…/private/var/db/diagnostics/` + `…/private/var/db/uuidtext/`, under any root folder |

`.faul` and FFS `.zip` are both zips, so detection reads the archive content: a
`.faul` carries a `faul/manifest.json` marker and that handler is probed first.
See [`docs/concepts/sources.md`](../concepts/sources.md) and
[`docs/formats/faul-format.md`](../formats/faul-format.md).

### Loose-directories mode

When the two unified-log folders are already uncompressed on disk, pass them
directly with `--diagnostics` + `--uuidtext` and **omit** the positional `INPUT`:

```bash
faul.py extract -o case.db \
    --diagnostics path/to/private/var/db/diagnostics \
    --uuidtext   path/to/private/var/db/uuidtext \
    --case-number CASE-2024-001 --imei 350000000000000
```

The two folders are merged into a logarchive layout by **hard link** (zero-copy);
the originals are only read. Hard links need the work dir and the sources on the
**same filesystem** and are unsupported on a few filesystems (exFAT, some network
drives) — when a link cannot be made the file is **copied** instead, a `WARNING`
is logged, and the result is identical (it just costs disk and time). To force
zero-copy, put `--work-dir` on the same volume as the sources.

Archives and loose dirs are materialised into a **temporary directory**
(auto-cleaned) unless `--work-dir DIR` is given.

### A kept work root is never reused

Everything under the work root is hashed and parsed as part of the acquisition.
A root left behind by an earlier run would therefore contribute *its* files to
the next case — hashed into `content_sha256`, registered in `source_files`, and
parsed into `logs`, indistinguishable from the evidence actually under
examination.

So FAUL **refuses** to extract into a work root that already holds files:

```
Work root already exists and is not empty: /scratch/unpacked/sysdiagnose.tar.logarchive
(1284 entries). Re-using it would hash and parse those files as part of THIS
acquisition — evidence from a previous run would silently enter this case. Point
--work-dir at an empty directory, or pass --reset-work-dir to delete this root first.
```

This is not a rare collision. The root is named after the source's stem, so two
sysdiagnose archives from **different devices** that share a filename map to the
same root — and the loose-dirs source uses a *fixed* root name, so any two
loose-dirs runs sharing a `--work-dir` collide regardless of source.

`--reset-work-dir` deletes that root first (logging a `WARNING` that its previous
contents are not part of this acquisition). It removes only the
`<name>.logarchive` root FAUL created, never your `--work-dir` itself.

---

## Options

### Positional and required

| Flag | Default | Meaning |
|---|---|---|
| `INPUT` | none (optional positional) | A `.logarchive` directory, sysdiagnose `.tar.gz`, `.faul` container, or FFS `.zip`. Omit when using `--diagnostics`/`--uuidtext`. |
| `-o, --output OUTPUT_DB` | **required** | Path for the output SQLite database. Parent directories are created. |

### Case identifiers (required unless supplied by a `.faul` sidecar)

| Flag | Default | Meaning |
|---|---|---|
| `--case-number CASE` | `None` | Investigation / case reference (e.g. `CASE-2024-001`). Names the operational log file. Auto-filled from a `.faul` sidecar when omitted. |
| `--imei IMEI` | `None` | Device IMEI. Also names the operational log file. Auto-filled from a `.faul` sidecar when omitted. |

If, after sidecar resolution, either is still empty, the command errors out with
exit code `1`. An explicit flag always overrides the sidecar value.

### Optional case metadata

| Flag | Default | Meaning |
|---|---|---|
| `-e, --exhibit-number EXHIBIT` | `None` | Exhibit / item reference. Auto-filled from a `.faul` sidecar. |
| `--analyst NAME` | `None` | Analyst name. Auto-filled from a `.faul` sidecar. |
| `--notes TEXT` | `None` | Free-text notes. Auto-filled from a `.faul` sidecar. |

### Source handling

| Flag | Default | Meaning |
|---|---|---|
| `--diagnostics DIR` | `None` | Loose-dirs source: the uncompressed `private/var/db/diagnostics/` folder (Persist/Special/Signpost/timesync). Must be given together with `--uuidtext`, and instead of `INPUT`. |
| `--uuidtext DIR` | `None` | Loose-dirs source: the uncompressed `private/var/db/uuidtext/` folder (the 2-char dirs + `dsc/`). |
| `--work-dir DIR` | `None` (auto-cleaned temp dir) | For archive / loose-dirs sources: materialise the logarchive here and keep it. A work root that already holds files is refused — see [A kept work root is never reused](#a-kept-work-root-is-never-reused). |
| `--reset-work-dir` | off | Delete the work root inside `--work-dir` before extracting. Without it, a root left by a previous run is refused rather than reused. |
| `--integrity {full,fingerprint,off}` | `full` | Source hashing mode. `full` = complete chain-of-custody attestation (per-file SHA-256 + end-of-run re-verification). `fingerprint` = only a cheap head+size+tail archive fingerprint. `off` = no hashing at all. **Non-`full` modes are triage-only: the database then records no evidence hashes**, and `verify-hash` has nothing to check. |
| `--overwrite` | off | Replace `OUTPUT` if it already exists. Without it, extracting into an existing database is refused (it would merge two acquisitions). |

### Performance

| Flag | Default | Meaning |
|---|---|---|
| `--batch-size N` | `100000` (`forensic_aul.config.BATCH_SIZE`) | Log entries per DB commit batch. Higher → fewer commit syncs, more RAM. |
| `-j, --jobs N` | auto | Total process budget for parsing: `N-1` parser workers + 1 writer. Auto = the smaller of `min(physical cores, 8)` and a memory ceiling of `(RAM − 4 GiB) / 0.30 GiB`, never below 1. `--jobs 1` disables multiprocessing. Each worker holds its own ~150–250 MB string cache. **The result is byte-identical regardless of `N`.** |
| `--fast-fts` / `--no-fast-fts` | **on** | Build the FTS index once at the end instead of maintaining it per row. Same final database, far less write I/O on large acquisitions. Trade-off: an interrupted run leaves full-text search empty until rebuilt, and the final rebuild has a higher memory peak. `--no-fast-fts` keeps a partial run searchable. |
| `--fts` / `--no-fts` | **on** | Build the FTS5 index over `logs.message` at all. The inverted index is the single largest addition to the database; `--no-fts` skips it entirely (message search then falls back to a `LIKE` scan) for a markedly smaller, faster extract. |
| `--fast-write` | off | `PRAGMA synchronous=OFF`. The default (`NORMAL` + WAL) never corrupts the database; `--fast-write` is faster but **can** corrupt it on an OS crash or power loss. Disposable, re-runnable extractions only. |
| `--keep-raw` | off | Store the per-entry `raw_data` JSON (the decoded `FirehoseItemInfo` list) for byte-level traceability. Off by default: it is often the fattest column and costs CPU on every entry. All resolved fields are kept regardless. |
| `--fast` | off | Shortcut for `--fast-fts` **and** `--fast-write` together. Implies both caveats. |

Note that `--fast-fts` is already the default, so `--fast` effectively only adds
`--fast-write`.

---

## Examples

```bash
# A logarchive directory
faul.py extract evidence.logarchive -o cases/case.db \
    --case-number CASE-2024-001 --imei 350000000000000

# A sysdiagnose bundle, keeping the unpacked logarchive for later inspection
faul.py extract sysdiagnose_2024.tar.gz -o cases/case.db \
    --work-dir /scratch/unpacked \
    --case-number CASE-2024-001 --imei 350000000000000 \
    --analyst "J. Doe" --exhibit-number ITEM-3

# A .faul container — case fields come from the embedded sidecar
faul.py extract CASE-2024-001-35000…-2024_06_01_10_00_00Z.faul -o cases/case.db

# A full-file-system zip, single-process, no full-text index
faul.py extract ffs_dump.zip -o cases/case.db --jobs 1 --no-fts \
    --case-number CASE-2024-001 --imei 350000000000000

# Loose diagnostics + uuidtext folders
faul.py extract -o cases/case.db \
    --diagnostics dump/private/var/db/diagnostics \
    --uuidtext   dump/private/var/db/uuidtext \
    --case-number CASE-2024-001 --imei 350000000000000

# Fast, disposable triage run
faul.py extract evidence.logarchive -o /tmp/triage.db --fast --integrity off \
    --overwrite --case-number TRIAGE --imei 000000000000000
```

---

## Interrupting a run

`extract` writes to `<OUTPUT>.partial` and renames it to `OUTPUT` only when the
run completes. **A file at the output path therefore means a finished extract —
always.** No code has to run for an interrupted one to be marked, so a cancel, a
crash, a power loss and a `kill -9` all leave the same evidence: a `.partial`.

Press **Ctrl+C** to stop a run. The first one cancels cooperatively — the current
file finishes, the database is closed cleanly and the audit log is sealed — and
`extract` exits **130**. A second Ctrl+C is left to Python's default handler, so
an unresponsive run can still be interrupted the usual way.

The partial database records what happened:

| Where | What it says |
|---|---|
| the filename | `.partial` — never promoted, so it cannot be mistaken for an extract |
| `case_metadata.extract_status` | `cancelled` (or `running` if the process died without a chance to write) |
| `case_metadata.extract_ended_at` | when it stopped |
| `extract_phases` | which phases completed and which one it died in |
| `source_files.parse_completed_at` | which source files were fully parsed |

Every reader refuses a partial, `verify-hash` included. There is no resume and no
inspection flag: a cancelled run is a discarded run. Re-run the extract.

## Outputs

| Artefact | Path |
|---|---|
| Analysis database | exactly `-o/--output` |
| Operational log | `<case_number>-AUL-<imei>.log` in the **same directory as the database** |

The operational log is opened in **append** mode, always written at `INFO`, and
**sealed** on every exit path (success, failure, Ctrl-C): its SHA-256 is stored
in `case_metadata` so [`verify-hash`](verify-hash.md) can prove it was not altered.
Filesystem-unsafe characters (`\ / : * ? " < > |`) in the case number or IMEI
become underscores.

A live progress bar is drawn on an interactive terminal; when output is piped or
redirected the bar is a no-op and the per-phase `INFO` log lines remain the
recorded trail.

For the resulting tables and columns, see
[`docs/formats/database-schema.md`](../formats/database-schema.md).

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Extraction completed and the log was sealed. |
| `1` | Invocation error (both `INPUT` and `--diagnostics/--uuidtext` given; only one of the two loose dirs given; a loose dir that is not a directory; unrecognised source type; missing `--case-number`/`--imei`; `OUTPUT` exists and is not a regular file) **or** an unhandled failure during the run (a crash report is written and the log is still sealed). |
| `130` | Interrupted with Ctrl-C (SIGINT). The log is sealed before exiting; the database contains whatever was committed. |

---

## Common pitfalls

- **`-o` is mandatory in every mode.** There is no implicit `<input>.db`.
- **`--case-number` / `--imei` are not cosmetic** — they name the operational
  log file. Two runs with the same pair append to the same log, by design.
- **Extracting into an existing database is refused** unless `--overwrite` is
  given; merging two acquisitions into one database is never what you want.
- **`--integrity fingerprint|off` silently removes the evidence hashes.** Use it
  only for triage; a database extracted that way cannot be meaningfully verified.
- **`--fast-write` can corrupt the database** on power loss. Never use it for
  the run that produces the deliverable.
- **An interrupted run with the default `--fast-fts` leaves full-text search
  empty** (the rest of the data is complete). Re-run, or use `--no-fast-fts` if
  interruptions are likely.
- **Loose-dirs mode on exFAT / network drives falls back to copying** — watch
  for the `WARNING` and the extra disk usage.
- **`--jobs` changes speed, never results.** If output differs between two
  `--jobs` values, that is a bug worth reporting.

---

## See also

- [`acquire`](acquire.md) — produce the `.faul` this command consumes
- [`summary`](summary.md) — first look at the resulting database
- [`verify-hash`](verify-hash.md) — re-check the chain of custody later
- [`validate-tool`](validate-tool.md) — prove the parse matches Apple's `log show`
- [Sources](../concepts/sources.md) · [Unified logs](../concepts/unified-logs.md) ·
  [Forensic model](../concepts/forensic-model.md)
- [Database schema](../formats/database-schema.md) ·
  [`.faul` format](../formats/faul-format.md)
