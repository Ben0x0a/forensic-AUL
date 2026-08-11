"""Emit knowledge-base signatures as house-style YAML.

Nothing else in the codebase writes KB YAML (``yaml.dump``/``safe_dump`` is used
nowhere; ``yaml`` is imported only by ``loader.py`` for ``safe_load``). The
shipped signatures use hyphenated keys, block scalars for multi-line prose and
single-quoted regexes — a generic ``yaml.safe_dump`` would flatten all of that
onto one messy line per field. This module is therefore a template-string
emitter, not a serialiser: it mirrors the exact layout of
``knowledge_base/signatures/example.yaml`` field by field.

Defines : ``render_signature`` (draft → YAML text) and ``write_signature``
          (render + persist + validate-by-reload, with rollback on failure).
Used by : a GUI "new signature" dialog (built separately — this module is its
          programmatic API), and ``tests/unit/test_kb_writer.py``.
Uses    : forensic_aul.ops.knowledge_base.models (SignatureDraft, Match),
          forensic_aul.ops.knowledge_base.loader (KnowledgeBaseError, load_kb —
          the single source of truth for signature validity).
"""

from __future__ import annotations

import re
from pathlib import Path

from forensic_aul.ops.knowledge_base.loader import KnowledgeBaseError, load_kb
from forensic_aul.ops.knowledge_base.models import Match, SignatureDraft

# A value renders as a bare (unquoted) YAML scalar only when it looks like a
# plain identifier — starting with a letter or underscore, so it can never be
# mistaken for a YAML implicit int/float/date (those start with a digit or
# '-'). Anything else (spaces, colons, punctuation, a leading digit) falls
# back to a double-quoted scalar instead, so an unusual value never produces
# broken or misinterpreted YAML.
_SAFE_BARE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]*$")
_YAML_RESERVED_WORDS = {"true", "false", "null", "yes", "no", "~"}


# ── Scalar/collection rendering helpers ─────────────────────────────────────

def _dq(value: str) -> str:
    """Render *value* as a double-quoted YAML scalar (house style for prose:
    action, single-line description/interpretation/caveats, references, …).

    Escapes backslash and the quote character; a literal newline or tab is
    escaped too so this helper is safe for any string, even though in practice
    multi-line values are routed through ``_block`` instead.
    """
    out = value.replace("\\", "\\\\").replace('"', '\\"')
    out = out.replace("\n", "\\n").replace("\t", "\\t")
    return f'"{out}"'


def _sq(value: str) -> str:
    """Render *value* as a single-quoted YAML scalar (house style for regexes:
    extract-regex, extract-fields values, match.message_regex).

    Single-quoted YAML treats backslash as a literal character — the only
    escape is a doubled `''` for an embedded single quote — so a regex's own
    backslashes (`\\d`, `\\.`, …) survive byte-identical with no re-escaping.
    """
    return "'" + value.replace("'", "''") + "'"


def _bare_or_dq(value: str) -> str:
    """Bare scalar for a simple identifier (process/subsystem/category/tag
    names, matching the shipped KB's style); double-quoted otherwise."""
    if _SAFE_BARE_RE.fullmatch(value) and value.lower() not in _YAML_RESERVED_WORDS:
        return value
    return _dq(value)


def _flow_list(items: tuple[str, ...]) -> str:
    """`[a, b]` inline flow style (house style for `tags`)."""
    return "[" + ", ".join(_bare_or_dq(v) for v in items) + "]"


def _block(value: str, indent: str) -> str:
    """Literal block scalar (`|-`, STRIP chomping) for a multi-line value.

    WHY strip (`|-`) rather than the shipped KB's plain `|` (clip): clip
    chomping always appends exactly one trailing newline on reload — fine for
    a hand-authored file nobody diffs byte-for-byte, but it would silently
    turn "a\\nb" into "a\\nb\\n" on the round trip `render → write → load_kb`
    that ``write_signature`` and the writer's tests rely on. Strip chomping
    reproduces the draft's string exactly, with no appended newline.
    """
    lines = value.split("\n")
    body = "\n".join(f"{indent}{line}" if line else "" for line in lines)
    return f"|-\n{body}"


def _emit_text(lines: list[str], key: str, value: str, key_indent: str) -> None:
    """Append a `key: value` line for an optional prose field, omitted at its
    default of `""`; multi-line values use a block scalar, single-line ones a
    double-quoted scalar.
    """
    if not value:
        return
    if "\n" in value:
        lines.append(f"{key_indent}{key}: {_block(value, key_indent + '  ')}")
    else:
        lines.append(f"{key_indent}{key}: {_dq(value)}")


# ── match: → house-style lines ───────────────────────────────────────────────

def _render_match(match: Match) -> list[str]:
    out: list[str] = []
    # Anchor (exactly one is set on a valid Match — render whichever is present;
    # load_kb enforces the "exactly one" rule on reload, not this function).
    if match.format_str is not None:
        out.append(f"      format_str: {_dq(match.format_str)}")
    if match.format_str_any:
        out.append("      format_str_any:")
        out.extend(f"        - {_dq(f)}" for f in match.format_str_any)
    if match.dynamic:
        out.append("      dynamic: true")

    if match.process is not None:
        out.append(f"      process: {_bare_or_dq(match.process)}")
    if match.subsystem is not None:
        out.append(f"      subsystem: {_bare_or_dq(match.subsystem)}")
    if match.category is not None:
        out.append(f"      category: {_bare_or_dq(match.category)}")
    if match.log_level is not None:
        out.append(f"      log_level: {match.log_level}")
    if match.event_type is not None:
        out.append(f"      event_type: {match.event_type}")
    if match.library is not None:
        out.append(f"      library: {_dq(match.library)}")
    if match.message_regex is not None:
        out.append(f"      message_regex: {_sq(match.message_regex)}")
    return out


# ── Public API ────────────────────────────────────────────────────────────────

def render_signature(draft: SignatureDraft) -> str:
    """Render *draft* as a complete, house-style KB YAML file (one signature).

    Field order and quoting follow ``knowledge_base/signatures/example.yaml``:
    two-space indent, block scalars for multi-line prose, single-quoted
    regexes, `tags: [a, b]` flow style. Every field left at its `Signature`
    default is omitted, exactly as in a hand-authored file.
    """
    lines: list[str] = ["signatures:", f"  - id: {draft.id}"]
    lines.append(f"    action: {_dq(draft.action)}")

    _emit_text(lines, "description", draft.description, "    ")
    _emit_text(lines, "interpretation", draft.interpretation, "    ")
    _emit_text(lines, "caveats", draft.caveats, "    ")

    if draft.confidence != "medium":
        lines.append(f"    confidence: {draft.confidence}")
    if draft.platform != "ios":
        lines.append(f"    platform: {draft.platform}")
    if draft.ios_min is not None:
        lines.append(f"    ios_min: {_dq(draft.ios_min)}")
    if draft.ios_max is not None:
        lines.append(f"    ios_max: {_dq(draft.ios_max)}")

    lines.append("    match:")
    lines.extend(_render_match(draft.match))

    # extract-regex / extract-fields: hyphenated form only — it is the
    # canonical spelling for newly-authored signatures (see
    # docs/formats/knowledge-base.md); the loader still accepts both.
    if draft.extract_regex:
        lines.append(f"    extract-regex: {_sq(draft.extract_regex)}")
    if draft.extract_fields:
        lines.append("    extract-fields:")
        lines.extend(f"      {name}: {_sq(pattern)}" for name, pattern in draft.extract_fields)

    if draft.references:
        lines.append("    references:")
        lines.extend(f"      - {_dq(r)}" for r in draft.references)
    if draft.tags:
        lines.append(f"    tags: {_flow_list(draft.tags)}")

    if draft.author:
        lines.append(f"    author: {_dq(draft.author)}")
    if draft.created:
        lines.append(f"    created: {_dq(draft.created)}")
    if draft.version:
        lines.append(f"    version: {_dq(draft.version)}")
    # "validated" is the Signature schema default (existing hand-authored
    # signatures with no `status` key are read as validated); only an
    # explicit non-default status needs to be written out.
    if draft.status != "validated":
        lines.append(f"    status: {draft.status}")

    return "\n".join(lines) + "\n"


def write_signature(kb_dir: Path, draft: SignatureDraft) -> Path:
    """Render *draft* and persist it as ``<kb_dir>/signatures/<draft.id>.yaml``.

    One signature per file. Refuses to overwrite an existing file. After
    writing, the whole KB is reloaded via ``load_kb`` — the single source of
    truth for signature validity (match anchor rule, regex compileability,
    duplicate ids, unknown keys, …) — so the new file is checked in full KB
    context, not just in isolation.

    Raises:
        KnowledgeBaseError: a file already exists at the target path, or the
            written signature fails to load — in the latter case the file is
            deleted before the error propagates, so an invalid signature can
            never be left on disk (see the WHY comment below).
    """
    sigs_dir = Path(kb_dir) / "signatures"
    sigs_dir.mkdir(parents=True, exist_ok=True)
    out_path = sigs_dir / f"{draft.id}.yaml"
    if out_path.exists():
        raise KnowledgeBaseError(f"signature file already exists: {out_path}")

    content = render_signature(draft)
    # BOM so the file matches the project's file-output convention; load_kb
    # round-trips a BOM-prefixed file fine (yaml.safe_load strips a leading
    # U+FEFF even when the caller decoded with plain "utf-8").
    out_path.write_text(content, encoding="utf-8-sig")

    try:
        load_kb(kb_dir)
    except KnowledgeBaseError:
        # WHY: a signature that renders but fails to reload (e.g. two match
        # anchors, an uncompilable regex, a duplicate id) must not linger on
        # disk — an unvalidated file in signatures/ would silently corrupt the
        # next `load_kb` call for every other caller of this KB.
        out_path.unlink()
        raise

    return out_path
