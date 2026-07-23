# The `.faul` portable-evidence container

A `.faul` bundles an acquired `.logarchive` together with its acquisition
**sidecar** so the two travel as a single, portable file that can never be
separated. It is what `acquire` produces by default and a first-class `extract`
source.

Format logic lives in one module: `forensic_aul/engine/faul_format.py`
(`pack_faul`, `is_faul`, `read_manifest`, `read_sidecar`, `extract_logarchive`).

## Layout

A `.faul` is a **stored** (uncompressed, `ZIP_STORED`) zip. All paths are
relative to the zip root:

```
faul/manifest.json                     ← marker + version + pointers
<name>.logarchive/…                    ← the full logarchive tree
<name>.logarchive.acquisition.json     ← the acquisition sidecar (optional)
```

- `<name>` is the acquisition stem, e.g. `CASE-2024-001-<imei>-<UTC>`.
- The sidecar entry is present only when the container was packed with one; a
  `.faul` with no sidecar is valid.

### `faul/manifest.json`

```json
{
  "format": "faul",
  "format_version": 1,
  "logarchive": "<name>.logarchive",
  "sidecar": "<name>.logarchive.acquisition.json"
}
```

`sidecar` is `null` when none was bundled. `format_version` is a single integer;
a reader refuses (does not half-read) a container whose version is **greater**
than the build's `FORMAT_VERSION`.

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
  `--imei`, `--exhibit`, `--analyst`, `--notes`) from it — an explicit flag still
  overrides the embedded value.

## Performance model (extract)

`extract` unpacks the bundled logarchive into a **temp dir** (auto-cleaned, or
kept with `--work-dir`) in one sequential pass, then parses it exactly as a plain
`.logarchive` directory — identical to how sysdiagnose / FFS sources are handled.
This is a single, uniform scenario for both local and network drives (no dynamic
branching). It adds one I/O copy pass versus parsing a bare `.logarchive`
directory in place; that is the deliberate trade for portability.

An end-to-end test (`tests/integration/test_source_extract.py::
test_extract_from_faul_matches_logarchive`) asserts that extracting a `.faul`
produces a **byte-identical row count** to extracting the same logarchive
directory directly.

## Producing the legacy loose layout

`acquire --raw` (CLI-only) writes the old layout instead of a `.faul`: a
`<name>.logarchive` directory plus a separate `<name>.logarchive.acquisition.json`
sidecar file. The GUI always produces a `.faul`.
