# The `.faul` portable-evidence container

A `.faul` bundles an acquired `.logarchive` together with its
[acquisition sidecar](acquisition-sidecar.md) so the two travel as a single,
portable file that can never be separated. It is what [`acquire`](../cli/acquire.md)
produces by default and a first-class [`extract`](../cli/extract.md) source.

Format logic lives in one module: `forensic_aul/engine/faul_format.py`
(`pack_faul`, `is_faul`, `read_manifest`, `read_sidecar`, `extract_logarchive`).
The extract-side handler is `forensic_aul/ops/extraction/sources/faul.py`.

## Layout

A `.faul` is a **stored** (uncompressed, `ZIP_STORED`) zip. All paths are
relative to the zip root:

```
faul/manifest.json                     ← marker + version + pointers
<name>.logarchive/…                    ← the full logarchive tree
<name>.logarchive.acquisition.json     ← the acquisition sidecar (optional)
```

- `<name>` is the acquisition stem, e.g. `CASE-2024-001-<imei>-<UTC>`
  (`<case>-<imei|udid[:8]>-%Y_%m_%d_%H_%M_%SZ`, each token sanitised to
  `[A-Za-z0-9_-]`).
- The sidecar entry is present only when the container was packed with one; a
  `.faul` with no sidecar is valid.
- Only **regular files** are packed — symlinks are skipped, since a logarchive
  holds only regular files and following one could pull in data from outside the
  evidence.
- Entries are written in a deterministic order (manifest first, then the sidecar,
  then the tree walked with sorted filenames), so identical input produces
  identical container bytes.

### `faul/manifest.json`

```json
{
  "format": "faul",
  "format_version": 1,
  "logarchive": "<name>.logarchive",
  "sidecar": "<name>.logarchive.acquisition.json"
}
```

| Field | Type | Meaning |
|---|---|---|
| `format` | string | Always `"faul"` |
| `format_version` | int | Currently `1`; bumped only on a breaking layout change |
| `logarchive` | string | Directory prefix of the logarchive tree inside the zip |
| `sidecar` | string \| null | Sidecar entry name, `null` when none was bundled |

A reader refuses (does not half-read) a container whose `format_version` is
**greater** than the build's `FORMAT_VERSION`: `read_manifest` logs a warning and
returns `None`, so every downstream call fails loudly instead of silently
mis-parsing.

## Why these choices

- **Stored, not compressed.** Extraction is a pure sequential byte copy — no
  decompression CPU, friendly to network drives, and reproducible container bytes
  for identical input. Logarchive material (`tracev3`) is already dense, so
  compression would buy little for a real cost on every `extract`.
- **A manifest at a fixed path.** A `.faul` shares its magic bytes
  (`PK\x03\x04`) with a full-file-system `.zip`. Detection therefore reads the
  archive's *content*: the presence of `faul/manifest.json` in the central
  directory is the cheap, unambiguous discriminator. The `.faul` source handler
  is probed **before** the FFS handler for exactly this reason.
- **Sidecar inside the container.** Chain-of-custody metadata cannot drift away
  from the evidence, and `extract` auto-fills case fields (`--case-number`,
  `--imei`, `--exhibit-number`, `--analyst`, `--notes`) from it — an explicit flag still
  overrides the embedded value. See
  [acquisition sidecar](acquisition-sidecar.md#how-extract-auto-fills-case-fields-from-it).

## Writing (`pack_faul`)

`acquire` collects the logarchive into a local temp directory, hashes it, builds
the sidecar dict, and packs both into the `.faul` written to the output directory.

The pack is **atomic**: the archive is built in a sibling `*.tmp` file and then
`os.replace`-d into place, and the temp file is removed on any failure — so an
interrupted pack never leaves a truncated `.faul` that could later be mistaken for
a valid container. A `.faul` that cannot be written raises `AcquisitionError`
(collection already succeeded at that point).

## Detection (`is_faul`)

O(1) and never raises:

1. read the first four bytes and compare against `PK\x03\x04`;
2. open the zip's central directory and test for `faul/manifest.json` in
   `namelist()`.

An unreadable or non-zip file is simply "not a `.faul`". Detection is by content,
never by extension.

In the source registry the handlers are probed in `priority` order — logarchive
(10), sysdiagnose (20), **faul (30)**, filesystem/FFS (40) — so a `.faul` is
recognised before the generic zip handler sees it.

## Reading

| Function | Behaviour |
|---|---|
| `read_manifest(path)` | Parsed manifest, or `None` if absent/unreadable/too new |
| `read_sidecar(path)` | The embedded sidecar dict, or `None` (best-effort: no sidecar, foreign or unreadable all yield `None`, so auto-fill just leaves fields untouched) |
| `extract_logarchive(path, dest_root)` | Extracts the tree, returns the number of files written |

`extract_logarchive` strips the container's `<name>.logarchive/` prefix so
*dest_root* itself becomes the logarchive — the shape the parser expects. Each
entry is streamed with `shutil.copyfileobj` (never buffering a whole tracev3).

Two hard failures, both `ValueError`:

- the container has no readable manifest, or its manifest names no logarchive;
- the container holds no entries under the logarchive prefix.

**Zip-slip guard:** every destination is resolved and confirmed to stay under
*dest_root*; an entry that escapes raises `ValueError`. A `.faul` is still
untrusted input once it leaves the acquiring host.

## Performance model (extract)

`extract` unpacks the bundled logarchive into a **temp dir** (auto-cleaned, or
kept with `--work-dir`) in one sequential pass, then parses it exactly as a plain
`.logarchive` directory — identical to how sysdiagnose / FFS sources are handled.
This is a single, uniform scenario for both local and network drives (no dynamic
branching). It adds one I/O copy pass versus parsing a bare `.logarchive`
directory in place; that is the deliberate trade for portability.

The shared `prepare_archive` flow applies: quick archive fingerprint (unless
`--integrity off`) → work root → unpack → per-file hashing per the integrity mode
→ `PreparedSource`, with the embedded sidecar surfaced on `PreparedSource.sidecar`.
A `.faul` bundles a plain logarchive (no `SystemVersion.plist`), so the iOS version
is left unresolved here and `extract` falls back to the tracev3 build code, exactly
as for a bare `.logarchive` directory.

An end-to-end test (`tests/integration/test_source_extract.py::
test_extract_from_faul_matches_logarchive`) asserts that extracting a `.faul`
produces a **byte-identical row count** to extracting the same logarchive
directory directly.

## Producing the legacy loose layout

`acquire --raw` (CLI-only) writes the old layout instead of a `.faul`: a
`<name>.logarchive` directory plus a separate `<name>.logarchive.acquisition.json`
sidecar file. The GUI always produces a `.faul`. In the library this is
`acquire(..., pack=False)`, and `AcquireResult.report_path` then points at the
loose sidecar (it is `None` when the sidecar is embedded).

## See also

- [Acquisition sidecar](acquisition-sidecar.md) — the JSON travelling inside
- [`acquire` CLI](../cli/acquire.md), [`extract` CLI](../cli/extract.md)
- [Sources](../concepts/sources.md) — the other accepted evidence shapes
