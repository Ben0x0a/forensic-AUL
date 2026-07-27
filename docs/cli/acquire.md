# `acquire`

Collect a `.faul` (logarchive + traceability sidecar) from a USB-connected iOS
device.

## Synopsis

```bash
faul.py acquire --list
faul.py acquire --case-number CASE [options]
faul.py acquire --case-number CASE --extract --db case.db
faul.py acquire --case-number CASE --raw
```

## What it does

`acquire` connects to an iOS device over USB using **pymobiledevice3**, reads the
device metadata (IMEI, serial number, SIM cards, …) **from the device itself**,
shows it for confirmation, then collects a `.logarchive`.

The logarchive and its traceability sidecar (per-file SHA-256 manifest, device
facts, case identifiers, collection parameters) are packed into a single
portable **`.faul`** container named `<case>-<imei|udid>-<UTC>.faul`. Because the
sidecar travels *inside* the container it can never be separated from the
evidence, and [`extract`](extract.md) auto-fills the case fields from it.

The `.faul` is a **stored** (uncompressed) zip, so `extract` unpacks it with one
sequential copy — no decompression cost. See
[`docs/formats/faul-format.md`](../formats/faul-format.md) and
[`docs/formats/acquisition-sidecar.md`](../formats/acquisition-sidecar.md).

Device-sourced fields (IMEI, serial, …) **cannot be overridden** — they are
always read from the device.

### Requirements

Needs the optional `acquire` extra:

```bash
uv sync --extra acquire        # or: uv pip install -e ".[acquire]"
```

Without it the command exits with code `1` and a message telling you to install
`pymobiledevice3`. Acquisition is cross-platform and runs in **userspace** — no
root required. The device must be unlocked and trusted by the host.

---

## Options

### Device selection

| Flag | Default | Meaning |
|---|---|---|
| `-l, --list` | off | List connected devices and exit — no acquisition, no `--case-number` needed. |
| `--udid UDID` | first connected device | Connect to this specific device UDID. |

### Case identifiers (recorded in the acquisition report)

| Flag | Default | Meaning |
|---|---|---|
| `--case-number CASE` | `None` | Investigation / case reference. **Required unless `--list`.** |
| `-e, --exhibit-number EXHIBIT` | `None` | Exhibit / item reference. |
| `--analyst NAME` | `None` | Analyst name. |
| `--notes TEXT` | `None` | Free-text notes. |

### Acquisition options

| Flag | Default | Meaning |
|---|---|---|
| `-o, --output-dir DIR` | **required** (except with `--list`) | Where the `.faul` (or, with `--raw`, the `.logarchive` and report) is written. |
| `--start-time TIME` | `None` (all available logs) | Collect logs from this point on. Accepts an ISO 8601 datetime (`2024-01-15T12:00:00`) or a relative offset (`1h`, `24h`, `7d`). |
| `--size-limit BYTES` | `None` | Maximum logarchive size, in bytes. |
| `--age-limit DAYS` | `None` | Maximum log age, in days. |
| `-y, --yes` | off | Skip the confirmation prompt shown after the device summary. |
| `--raw` | off | Produce the **legacy loose layout** — a `.logarchive` directory plus a separate `.acquisition.json` sidecar file — instead of a single `.faul`. Use when a downstream tool needs a plain logarchive. |

### Post-acquisition

| Flag | Default | Meaning |
|---|---|---|
| `--extract` | off | Immediately run an extract session on the acquired logarchive. |
| `--db DB_PATH` | `<logarchive>.db`, next to the archive | Output database for `--extract`. |
| `--batch-size N` | `100000` (`forensic_aul.config.BATCH_SIZE`) | Batch size for the `--extract` step — the same default as `extract`. |

---

## The confirmation prompt

After connecting, `acquire` prints the device table and asks:

```
  Proceed with log acquisition? [y/N]
```

Anything other than `y`/`yes` aborts. If the IMEI could not be read (Wi-Fi-only
devices, restricted configuration profiles) a warning is printed first, and the
acquisition still proceeds if you confirm. `--yes` skips the prompt entirely.
`Ctrl-C` or EOF at the prompt aborts cleanly.

---

## Examples

```bash
# See what is plugged in
faul.py acquire --list

# Standard acquisition into ./evidence
faul.py acquire --case-number CASE-2024-001 --output-dir ./evidence \
    --analyst "J. Doe" --exhibit-number ITEM-3

# Bound the collection to the last 24 hours of logs
faul.py acquire --case-number CASE-2024-001 --start-time 24h

# Specific device, unattended
faul.py acquire --case-number CASE-2024-001 --udid 00008030-0011… --yes

# Acquire and extract in one step
faul.py acquire --case-number CASE-2024-001 --extract --db ./evidence/case.db

# Legacy loose layout for a downstream tool
faul.py acquire --case-number CASE-2024-001 --raw
```

---

## Outputs

| Mode | Written |
|---|---|
| default | `<output-dir>/<case>-<imei\|udid>-<UTC>.faul` |
| `--raw` | `<output-dir>/…​.logarchive/` **and** a separate `.acquisition.json` sidecar |
| `--extract` | additionally the database at `--db` (or `<logarchive>.db`) and its sealed operational log beside it |

The `--extract` step runs through the **same sealed-log extract session** as the
standalone [`extract`](extract.md) command, so an acquired-then-extracted
database gets an identically sealed, tamper-evident operational log. Note that
this internal step always runs with `overwrite=True` — an existing database at
`--db` is replaced without asking.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Acquisition (and optional extract) completed — **or** the operator declined at the confirmation prompt ("Aborted."). |
| `1` | `--case-number` missing without `--list`; `pymobiledevice3` not installed; device enumeration failed; acquisition failed; or an unexpected error (a crash report is written). |

When `--extract` is used and the extract session fails, `acquire` returns the
extract session's code (`1`, or `130` on Ctrl-C) instead of its own.

---

## Common pitfalls

- **A clean abort returns `0`, not a non-zero code.** In scripts, check for the
  produced file rather than relying on the exit status to detect a refusal.
- **`--case-number` is required unless `--list`** — the error message points you
  at `--list` if you only wanted to enumerate devices.
- **`--start-time` doubles as a relative window** (`1h`, `7d`) and as an absolute
  ISO datetime; `--size-limit` is in **bytes**, `--age-limit` in **days**.
- **A missing IMEI is only a warning.** The container then falls back to the UDID
  in its name, and `extract` may need an explicit `--imei`.
- **`--raw` splits evidence from its sidecar.** Prefer the default `.faul` unless
  a downstream tool genuinely requires a loose logarchive.
- **`--extract`'s `--batch-size` matches `extract`'s** — both default to
  `100000` (`forensic_aul.config.BATCH_SIZE`).
- **`--extract` overwrites** any existing database at `--db`.
- Acquisition is a **live capture**: the device keeps logging while you collect,
  so two back-to-back acquisitions will differ by an appended tail. That is
  exactly what [`validate-tool --acquisition`](validate-tool.md) tolerates.

---

## See also

- [`extract`](extract.md) — consume the `.faul`
- [`identify`](identify.md) — baseline / action acquisition workflow
- [`validate-tool`](validate-tool.md) — L2 acquisition-fidelity check
- [`.faul` container format](../formats/faul-format.md) ·
  [acquisition sidecar](../formats/acquisition-sidecar.md)
- [Sources](../concepts/sources.md) · [Forensic model](../concepts/forensic-model.md)
