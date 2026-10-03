# Knowledge base format

The knowledge base (KB) is a directory of YAML files describing *signatures*:
rules that recognise a known behaviour in the logs, label it with a human-readable
action, and optionally pull named values out of the message. It is applied to an
analysis database by [`annotate`](../cli/annotate.md) and linted by
[`kb validate`](../cli/kb.md).

Source: `forensic_aul/ops/knowledge_base/{models,loader,lint,writer}.py`,
`forensic_aul/ops/annotation/matcher.py`, and the shipped `knowledge_base/`.

## Directory layout

```
knowledge_base/
├── VERSION              # required — a non-empty version string (e.g. 0.2.0)
├── labels.yaml          # optional — controlled vocabulary of extracted labels
└── signatures/          # required — at least one .yaml / .yml file
    └── example.yaml
```

Loading rules (`load_kb`):

- `VERSION` must exist and be non-empty; its stripped contents become
  `KnowledgeBase.version`.
- `signatures/` is walked **recursively** (`rglob`), `*.yaml` first then `*.yml`,
  each group sorted. At least one file must be found.
- An empty YAML document is skipped; otherwise the top level must be a mapping
  with a `signatures` key holding a list.
- A duplicate signature `id` anywhere in the tree is a hard error.

Every failure raises `KnowledgeBaseError` (a subclass of `ValueError`) with the
KB-relative file path and the item index, e.g.
`signatures/wifi.yaml [#2]: match: unknown keys: ['proces']`.

## Versioning and the SHA-256 digest

`KnowledgeBase.sha256` is a rolling SHA-256 built in this order:

1. the `VERSION` string, then a `\x00` separator;
2. if `labels.yaml` exists: the literal `labels.yaml`, `\x00`, its raw bytes, `\x00`;
3. for each signature file in load order: its KB-relative POSIX path, `\x00`, its
   raw bytes, `\x00`.

So a version bump alone, a vocabulary edit, a signature edit, **and** a file
rename all change the digest. On annotate, `kb_version` and `kb_sha256` are stored
on every `kb_signatures` row together with `applied_at` — that triple is what makes
an annotation run reproducible and auditable. See
[database schema](database-schema.md#annotation-tables-created-by-annotate).

## Signature schema

Each list item under `signatures:` is one rule. **Unknown top-level keys are
rejected** (typos surface immediately).

| Key | Type | Required | Meaning |
|---|---|---|---|
| `id` | string | yes | Unique identifier. Must match `^[a-z0-9][a-z0-9._-]*$` (lowercase, dot/dash/underscore) |
| `action` | string | yes | The behaviour asserted, in plain language — stored in `kb_signatures.action` and filterable with `export --action` |
| `description` | string | no (default `""`) | Longer explanation |
| `interpretation` | string | no (default `""`) | What an analyst may conclude from a match — `action` is only a title |
| `caveats` | string | no (default `""`) | Known false positives / conditions where the conclusion does not hold |
| `match` | mapping | yes | The matching specification (below) |
| `extract-regex` / `extract_regex` | string | no | One regex whose **named groups** become extracted labels |
| `extract-fields` / `extract_fields` | mapping | no | `label → regex`, one regex per value |
| `confidence` | string | no (default `medium`) | `low` \| `medium` \| `high` |
| `platform` | string | no (default `ios`) | Free-text platform tag |
| `ios_min` | string | no | Lower iOS bound (recorded, not enforced by the matcher) |
| `ios_max` | string | no | Upper iOS bound (recorded, not enforced by the matcher) |
| `references` | list of strings | no | Provenance / research notes |
| `tags` | list of strings | no | Free-form tags; stored as a JSON list and filterable with `--tag` |
| `author` | string | no (default `""`) | Who wrote the rule |
| `created` | string | no (default `""`) | ISO date the rule was authored, `YYYY-MM-DD` (loosely shape-checked, not calendar-validated) |
| `version` | string | no (default `""`) | Per-signature semver, independent of the KB-wide `VERSION` |
| `status` | string | no (default `validated`) | `draft` \| `validated` \| `deprecated` — a signature's review state |

Both spellings (`extract-regex` / `extract_regex`, `extract-fields` /
`extract_fields`) are accepted; **the hyphenated form is canonical** and is what
the shipped KB and the writer (see below) both use — prefer `extract-fields` /
`extract-regex` for new signatures.

### `match`

**Unknown keys inside `match` are rejected too.**

| Key | Type | Meaning |
|---|---|---|
| `format_str` | string | Exact match on the invariant format-string template |
| `format_str_any` | list of strings | Match any one of several templates |
| `dynamic` | bool | Target lines with no usable format string |
| `process` | string | Exact process name |
| `subsystem` | string | Exact subsystem |
| `category` | string | Exact category |
| `log_level` | string | One of `Default`, `Info`, `Debug`, `Error`, `Fault` |
| `event_type` | string | One of `Log`, `Activity`, `Trace`, `Signpost`, `Loss`, `Statedump`, `Simpledump` (`engine/database/schema.py:EVENT_TYPE_NAMES`) |
| `library` | string | Exact match on the library path (`libraries.name`) |
| `message_regex` | string | Post-filter regex applied to the **rendered** message |

Validation rules:

- **Exactly one** of `format_str`, `format_str_any`, `dynamic: true` must be
  present — no more, no fewer.
- `dynamic: true` **requires** `message_regex` (there would be no anchor otherwise).
- `log_level` must be one of the five names above.
- `event_type` must be one of the seven names above.
- `message_regex` must compile.

### Matching semantics

`matcher.py` builds one indexed candidate query per signature, then applies the
regex post-filter in Python:

1. **Format-string anchor.** `format_str` and `format_str_any` are resolved to
   `format_strs.id` values. If none of them exists in this database, the signature
   matches nothing and returns immediately (0 hits, no scan). With `dynamic: true`
   no `format_str_id` constraint is added at all.
2. **Indexed refinements.** `process`, `subsystem`, `category` are resolved to
   their lookup ids; a name absent from the database again short-circuits to 0.
   These become `AND`-ed equality predicates on indexed columns.
3. **Residual refinement.** `log_level`, `event_type`, and `library` are resolved
   to their lookup ids (`log_levels`, `event_types`, `libraries`) and added as
   non-indexed predicates over the already-narrow candidate set. `library` is the
   odd one out: `libraries` is keyed `UNIQUE(name, uuid)` — the same path can
   appear under several UUIDs (e.g. across OS builds) — so a `library` match
   resolves to *every* matching id and uses `library_id IN (…)`, not a single `=`.
4. **Safety guard.** If a signature produces *no* WHERE clause at all (a `dynamic`
   signature with no process/subsystem/category/log_level/event_type/library
   refinement), the matcher logs a warning and refuses to run it rather than
   scanning the whole table.
5. **`message_regex`** is then evaluated with `re.search` (not `fullmatch`) on each
   candidate's `message`; a NULL message never matches.

All conditions are AND-combined. There is no OR across different keys — use
`format_str_any` for alternative templates, or write several signatures.

Every match inserts a `log_annotations` row. The `kb_signatures` row is created
lazily, on the first hit, so a signature with zero matches leaves no trace in the
database (its count is still reported by the CLI).

### Value extraction

Two complementary mechanisms; when both are present their results are **merged**,
`extract-regex` groups first, then `extract-fields` entries in declaration order.

- `extract-regex` — one `re.search` on the message. Every named group that
  matched (`value is not None`) contributes a `(group name, value)` pair. Groups
  that did not participate are omitted, not stored as empty rows. The regex
  **must contain at least one named group**, else the KB fails to load.
- `extract-fields` — each `label: regex` is searched independently. The value is
  taken from, in order of preference: a named group equal to the label, else
  group 1, else the whole match (`group(0)`). A regex that does not match
  contributes nothing.

Each resulting pair becomes a row in `extracted_values` attached to that
annotation, and a column in the CSV export (see
[export formats](export-formats.md#extracted-value-columns)).

Signatures that extract values are inserted one annotation at a time (the rowid is
needed to attach values); signatures without extraction use a faster batched path.

## `labels.yaml` — the controlled vocabulary

Optional. Top level must be a mapping with a `labels` key, which may be either a
mapping of `name → description` or a plain list of names.

```yaml
labels:
  ssid:          "Wi-Fi network name (SSID)"
  bssid:         "Wi-Fi access-point MAC address (BSSID)"
  bundle_id:     "Application bundle identifier"
```

The shipped vocabulary groups labels into network/Wi-Fi (`ssid`, `bssid`,
`ip_address`, `host`, `url`, `port`), app/process (`bundle_id`, `app_name`,
`process_name`, `pid`), identity (`account`, `device_name`) and files/errors
(`file_path`, `error_code`).

The point is consistency: one canonical `ssid`, never `wifi` / `WiFi` /
`wifi_name`, so the exported columns line up across signatures.

## `kb validate` linting

`lint_labels()` computes each signature's emitted labels — the named groups of
`extract_regex` first, then the `extract_fields` keys, de-duplicated — and warns
for any that is not in the vocabulary. If the KB has no `labels.yaml` (or it is
empty), linting is skipped entirely.

Suggestions are produced without any dependency:

1. an exact case-insensitive hit maps back to the canonical spelling
   (`SSID` → `ssid`);
2. otherwise `difflib.get_close_matches` with a cutoff of `0.6` proposes the
   closest allowed label (`bundleid` → `bundle_id`);
3. if nothing is close enough, the warning carries no suggestion.

Warnings are **advisory** — an unknown label still annotates fine. Resolve one by
either renaming the group in the signature or adding the label to `labels.yaml`
(which also changes the KB digest, as it should).

## Worked example

`knowledge_base/signatures/wifi.yaml`:

```yaml
signatures:
  - id: net.wifi_associate
    action: "Wi-Fi association with access point"
    description: "Device associated with a Wi-Fi BSSID."
    confidence: medium
    platform: ios
    ios_min: "14.0"
    match:
      format_str_any:
        - "Associated to %@ with bssid %@"
        - "Associating with %@ (bssid %@)"
      subsystem: com.apple.wifi
    # One regex, two named groups → two labels on the same annotation.
    extract-regex: 'to (?P<ssid>\S+) with bssid (?P<bssid>[0-9a-fA-F:]{17})'
    references:
      - "Observed on iOS 17.4 — wifid logs"
    tags: [network, wifi]
```

What happens when `annotate` runs it:

1. `format_strs` is queried for the two templates; the ids found become the
   candidate pre-filter, `AND`-ed with `subsystem_id` for `com.apple.wifi`.
2. There is no `message_regex`, so every candidate is a match.
3. On the first match a `kb_signatures` row is written with `signature_id =
   net.wifi_associate`, `action`, `description`, `confidence = medium`,
   `tags = ["network","wifi"]`, `source_file = signatures/wifi.yaml`, plus the KB
   `version`, `sha256` and this run's `applied_at`.
4. Each match gets a `log_annotations` row, and the `extract-regex` search adds up
   to two `extracted_values` rows (`ssid`, `bssid`).
5. `match_count` on the `kb_signatures` row is updated at the end.
6. `export --format csv` then emits `bssid` and `ssid` columns (sorted) alongside
   `matched_signatures = net.wifi_associate`.

The `extract-fields` alternative, for values that sit apart in the message:

```yaml
    extract-fields:
      bundle_id: '(?P<bundle_id>[\w.\-]+)'
      error_code: 'error=(-?\d+)'
```

## Writing signatures programmatically

`forensic_aul/ops/knowledge_base/writer.py` emits house-style YAML for signatures
built in memory — e.g. by a GUI "new signature" dialog — rather than typed by
hand. It is a template-string emitter, not a generic YAML serialiser: it
reproduces `example.yaml`'s exact layout (two-space indent, block scalars for
multi-line prose, single-quoted regexes, `tags: [a, b]` flow style) and omits
every field left at its `Signature` default.

- `SignatureDraft` (in `models.py`, beside `Signature`/`Match`) holds everything
  needed to emit one signature. Its own default `status` is `"draft"` — unlike
  `Signature`'s default of `"validated"` — so an interactively-created signature
  is written out as `status: draft` unless the caller sets it otherwise.
- `render_signature(draft) -> str` renders the draft to a complete YAML file
  (the `signatures:` wrapper included).
- `write_signature(kb_dir, draft) -> Path` writes `<kb_dir>/signatures/<id>.yaml`
  (one signature per file), refusing to overwrite an existing file. It then
  reloads the whole KB via `load_kb` — the same validation every hand-written
  signature goes through — and **deletes the file it just wrote if that
  reload fails**, so an invalid signature (a bad regex, two match anchors, a
  duplicate id, …) can never be left on disk.

## Authoring checklist

1. Find the invariant format string (`v_logs.format_string` / `logs.format_strs`)
   rather than the rendered text — it is stable across executions.
2. Give the signature exactly one anchor, and add `process` / `subsystem` /
   `category` refinements: they are the indexed pre-filter that keeps annotation
   fast. A `dynamic` signature **must** carry at least one of them.
3. Name extracted labels from `labels.yaml`; add new ones there deliberately.
4. Run `kb validate` — it loads the KB (catching every schema error) and reports
   label warnings with suggestions.
5. Bump `VERSION` when the meaning of the KB changes; the digest changes either
   way, and both are recorded on each annotation.

## See also

- [`kb` CLI](../cli/kb.md) and [`annotate` CLI](../cli/annotate.md)
- [Database schema](database-schema.md) — `kb_signatures`, `log_annotations`, `extracted_values`
- [Export formats](export-formats.md) — how labels become columns
