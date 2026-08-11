"""Load and validate the YAML knowledge base.

Defines : ``load_kb`` (public entry point), ``KnowledgeBaseError``, and the
          hand-written per-field validation behind it (no pydantic/jsonschema).
Used by : forensic_aul.ops.annotation.matcher, forensic_aul.ops.knowledge_base.
          {lint,writer}, the ``kb`` CLI commands (launcher/cmds/kb_cmd.py).
Uses    : forensic_aul.ops.knowledge_base.models (Match/Signature/KnowledgeBase),
          forensic_aul.engine.database.schema (EVENT_TYPE_NAMES, for
          match.event_type validation), yaml.safe_load.
"""

from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path

import yaml

from forensic_aul.engine.database.schema import EVENT_TYPE_NAMES
from forensic_aul.errors import ForensicAULError
from forensic_aul.ops.knowledge_base.models import KnowledgeBase, Match, Signature

log = logging.getLogger(__name__)


_VALID_LOG_LEVELS = {"Default", "Info", "Debug", "Error", "Fault"}
_VALID_EVENT_TYPES = set(EVENT_TYPE_NAMES)
_VALID_CONFIDENCE = {"low", "medium", "high"}
_VALID_STATUS = {"draft", "validated", "deprecated"}
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
# Loose ISO date shape check (YYYY-MM-DD) — not a full calendar validation, just
# enough to catch an obviously malformed `created` value at load time.
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class KnowledgeBaseError(ForensicAULError, ValueError):
    """Raised when a YAML signature file is invalid.

    Subclasses ``ValueError`` for backward compatibility with existing
    ``except ValueError`` call sites (see forensic_aul/errors.py).
    """


# ── Public API ────────────────────────────────────────────────────────────────

def load_kb(root: Path | str) -> KnowledgeBase:
    """Load every YAML under *root*/signatures/ into a KnowledgeBase.

    *root* is the directory containing the ``VERSION`` file and a
    ``signatures/`` subdirectory of YAML files.
    """
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        raise KnowledgeBaseError(f"Knowledge base root is not a directory: {root_path}")

    version_file = root_path / "VERSION"
    if not version_file.is_file():
        raise KnowledgeBaseError(f"Missing VERSION file: {version_file}")
    version = version_file.read_text(encoding="utf-8").strip()
    if not version:
        raise KnowledgeBaseError(f"VERSION file is empty: {version_file}")

    sigs_dir = root_path / "signatures"
    if not sigs_dir.is_dir():
        raise KnowledgeBaseError(f"Missing signatures/ directory under {root_path}")

    yaml_files = sorted(sigs_dir.rglob("*.yaml")) + sorted(sigs_dir.rglob("*.yml"))
    if not yaml_files:
        raise KnowledgeBaseError(f"No YAML signature files found under {sigs_dir}")

    # Optional controlled vocabulary of allowed extracted-value labels.
    labels, labels_bytes = _load_labels(root_path)

    signatures: list[Signature] = []
    seen_ids: dict[str, str] = {}  # id → file (for duplicate detection)
    rolling = hashlib.sha256()

    # Hash VERSION too so that a version bump alone changes the digest.
    rolling.update(version.encode("utf-8"))
    rolling.update(b"\x00")

    # Hash the vocabulary so a labels.yaml change alters the KB digest.
    if labels_bytes is not None:
        rolling.update(b"labels.yaml\x00")
        rolling.update(labels_bytes)
        rolling.update(b"\x00")

    for yf in yaml_files:
        rel = yf.relative_to(root_path).as_posix()
        rolling.update(rel.encode("utf-8"))
        rolling.update(b"\x00")
        rolling.update(yf.read_bytes())
        rolling.update(b"\x00")

        try:
            data = yaml.safe_load(yf.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise KnowledgeBaseError(f"{rel}: YAML parse error: {exc}") from exc

        if data is None:
            continue
        if not isinstance(data, dict) or "signatures" not in data:
            raise KnowledgeBaseError(f"{rel}: top-level must be a mapping with a 'signatures' key")
        items = data["signatures"]
        if not isinstance(items, list):
            raise KnowledgeBaseError(f"{rel}: 'signatures' must be a list")

        for idx, raw in enumerate(items):
            try:
                sig = _build_signature(raw, source_file=rel)
            except KnowledgeBaseError as exc:
                raise KnowledgeBaseError(f"{rel} [#{idx}]: {exc}") from None

            if sig.id in seen_ids:
                raise KnowledgeBaseError(
                    f"{rel}: duplicate signature id {sig.id!r} (also defined in {seen_ids[sig.id]})"
                )
            seen_ids[sig.id] = rel
            signatures.append(sig)

    log.info(f"Loaded {len(signatures)} signatures + {len(labels)} allowed label(s) from {sigs_dir} (KB version {version})")
    return KnowledgeBase(
        version=version,
        sha256=rolling.hexdigest(),
        signatures=tuple(signatures),
        root=str(root_path),
        labels=labels,
    )


def _load_labels(root: Path) -> tuple[tuple[tuple[str, str], ...], bytes | None]:
    """Load the optional ``labels.yaml`` controlled vocabulary.

    Returns ``((name, description) pairs, raw_bytes)``; an absent file yields
    ``((), None)`` (label linting is then skipped). ``labels:`` may be a mapping
    of name → description, or a plain list of names.
    """
    labels_file = root / "labels.yaml"
    if not labels_file.is_file():
        return (), None

    raw_bytes = labels_file.read_bytes()
    try:
        data = yaml.safe_load(raw_bytes.decode("utf-8"))
    except yaml.YAMLError as exc:
        raise KnowledgeBaseError(f"labels.yaml: YAML parse error: {exc}") from exc
    if data is None:
        return (), raw_bytes
    if not isinstance(data, dict) or "labels" not in data:
        raise KnowledgeBaseError("labels.yaml: top-level must be a mapping with a 'labels' key")

    raw_labels = data["labels"]
    pairs: list[tuple[str, str]] = []
    if isinstance(raw_labels, dict):
        for name, desc in raw_labels.items():
            if not isinstance(name, str) or not name:
                raise KnowledgeBaseError(f"labels.yaml: label name must be a non-empty string, got {name!r}")
            pairs.append((name, str(desc) if desc is not None else ""))
    elif isinstance(raw_labels, list):
        for name in raw_labels:
            if not isinstance(name, str) or not name:
                raise KnowledgeBaseError(f"labels.yaml: label must be a non-empty string, got {name!r}")
            pairs.append((name, ""))
    else:
        raise KnowledgeBaseError("labels.yaml: 'labels' must be a mapping or a list")
    return tuple(pairs), raw_bytes


# ── Validation ────────────────────────────────────────────────────────────────

def _build_signature(raw: object, *, source_file: str) -> Signature:
    if not isinstance(raw, dict):
        raise KnowledgeBaseError("signature must be a mapping")

    sig_id = _require_str(raw, "id")
    if not _ID_RE.fullmatch(sig_id):
        raise KnowledgeBaseError(
            f"id {sig_id!r} must match {_ID_RE.pattern} (lowercase, dot/dash/underscore)"
        )

    action = _require_str(raw, "action")
    description = _opt_str(raw, "description", default="")
    interpretation = _opt_str(raw, "interpretation", default="")
    caveats = _opt_str(raw, "caveats", default="")
    confidence = _opt_str(raw, "confidence", default="medium")
    if confidence not in _VALID_CONFIDENCE:
        raise KnowledgeBaseError(
            f"confidence {confidence!r} must be one of {sorted(_VALID_CONFIDENCE)}"
        )
    platform = _opt_str(raw, "platform", default="ios")

    author = _opt_str(raw, "author", default="")
    created = _opt_str(raw, "created", default="")
    if created and not _DATE_RE.fullmatch(created):
        raise KnowledgeBaseError(f"created {created!r} must be an ISO date (YYYY-MM-DD)")
    sig_version = _opt_str(raw, "version", default="")
    status = _opt_str(raw, "status", default="validated")
    if status not in _VALID_STATUS:
        raise KnowledgeBaseError(f"status {status!r} must be one of {sorted(_VALID_STATUS)}")

    match = _build_match(raw.get("match"))

    # extract_regex: a single regex whose NAMED groups become extracted labels.
    extract_regex = raw.get("extract-regex") or raw.get("extract_regex")
    if extract_regex is not None:
        if not isinstance(extract_regex, str):
            raise KnowledgeBaseError("extract-regex must be a string regex")
        try:
            compiled = re.compile(extract_regex)
        except re.error as exc:
            raise KnowledgeBaseError(f"extract-regex invalid regex: {exc}") from None
        if not compiled.groupindex:
            raise KnowledgeBaseError(
                "extract-regex must contain at least one named group, e.g. (?P<ssid>...)"
            )

    extract_fields: list[tuple[str, str]] = []
    ef = raw.get("extract-fields") or raw.get("extract_fields")
    if ef is not None:
        if not isinstance(ef, dict):
            raise KnowledgeBaseError("extract-fields must be a mapping of name → regex")
        for name, pattern in ef.items():
            if not isinstance(name, str) or not name:
                raise KnowledgeBaseError(f"extract-fields key must be a non-empty string, got {name!r}")
            if not isinstance(pattern, str):
                raise KnowledgeBaseError(f"extract-fields[{name}] must be a string regex")
            try:
                re.compile(pattern)
            except re.error as exc:
                raise KnowledgeBaseError(f"extract-fields[{name}] invalid regex: {exc}") from None
            extract_fields.append((name, pattern))

    refs = _opt_str_list(raw, "references")
    tags = _opt_str_list(raw, "tags")
    ios_min = _opt_str(raw, "ios_min", default=None)
    ios_max = _opt_str(raw, "ios_max", default=None)

    # Pre-compile hot-path regexes for the matcher.
    compiled_msg = re.compile(match.message_regex) if match.message_regex else None
    compiled_er = re.compile(extract_regex) if extract_regex else None
    compiled_ef = tuple((n, re.compile(p)) for n, p in extract_fields)

    # Reject unknown top-level keys to surface typos early.
    known_keys = {
        "id", "action", "description", "interpretation", "caveats",
        "confidence", "platform", "ios_min", "ios_max", "match",
        "extract-regex", "extract_regex", "extract-fields", "extract_fields",
        "references", "tags", "author", "created", "version", "status",
    }
    unknown = set(raw) - known_keys
    if unknown:
        raise KnowledgeBaseError(f"unknown keys: {sorted(unknown)}")

    return Signature(
        id=sig_id,
        action=action,
        description=description,
        match=match,
        interpretation=interpretation,
        caveats=caveats,
        extract_regex=extract_regex,
        extract_fields=tuple(extract_fields),
        confidence=confidence,
        platform=platform,
        ios_min=ios_min,
        ios_max=ios_max,
        references=tuple(refs),
        tags=tuple(tags),
        source_file=source_file,
        author=author,
        created=created,
        version=sig_version,
        status=status,
        _compiled_message_regex=compiled_msg,
        _compiled_extract_regex=compiled_er,
        _compiled_extract_fields=compiled_ef,
    )


def _build_match(raw: object) -> Match:
    if not isinstance(raw, dict):
        raise KnowledgeBaseError("match must be a mapping")

    fmt = raw.get("format_str")
    fmt_any_raw = raw.get("format_str_any")
    dynamic = bool(raw.get("dynamic", False))
    msg_regex = raw.get("message_regex")

    if fmt is not None and not isinstance(fmt, str):
        raise KnowledgeBaseError("match.format_str must be a string")
    if fmt_any_raw is not None:
        if not isinstance(fmt_any_raw, list) or not all(isinstance(x, str) for x in fmt_any_raw):
            raise KnowledgeBaseError("match.format_str_any must be a list of strings")
        fmt_any = tuple(fmt_any_raw)
    else:
        fmt_any = ()

    if msg_regex is not None:
        if not isinstance(msg_regex, str):
            raise KnowledgeBaseError("match.message_regex must be a string")
        try:
            re.compile(msg_regex)
        except re.error as exc:
            raise KnowledgeBaseError(f"match.message_regex invalid: {exc}") from None

    # Anchor rule: exactly one of {format_str, format_str_any, dynamic}.
    anchors = [bool(fmt), bool(fmt_any), dynamic]
    if sum(anchors) != 1:
        raise KnowledgeBaseError(
            "match must contain exactly one of: format_str, format_str_any, dynamic: true"
        )
    if dynamic and not msg_regex:
        raise KnowledgeBaseError("match.dynamic requires match.message_regex")

    log_level = _opt_str_field(raw, "log_level")
    if log_level is not None and log_level not in _VALID_LOG_LEVELS:
        raise KnowledgeBaseError(
            f"match.log_level {log_level!r} must be one of {sorted(_VALID_LOG_LEVELS)}"
        )

    event_type = _opt_str_field(raw, "event_type")
    if event_type is not None and event_type not in _VALID_EVENT_TYPES:
        raise KnowledgeBaseError(
            f"match.event_type {event_type!r} must be one of {sorted(_VALID_EVENT_TYPES)}"
        )

    library = _opt_str_field(raw, "library")

    known = {
        "format_str", "format_str_any", "dynamic",
        "process", "subsystem", "category", "log_level", "event_type", "library",
        "message_regex",
    }
    unknown = set(raw) - known
    if unknown:
        raise KnowledgeBaseError(f"match: unknown keys: {sorted(unknown)}")

    return Match(
        format_str=fmt,
        format_str_any=fmt_any,
        dynamic=dynamic,
        process=_opt_str_field(raw, "process"),
        subsystem=_opt_str_field(raw, "subsystem"),
        category=_opt_str_field(raw, "category"),
        log_level=log_level,
        event_type=event_type,
        library=library,
        message_regex=msg_regex,
    )


# ── Tiny YAML helpers ─────────────────────────────────────────────────────────

def _require_str(d: dict, key: str) -> str:
    v = d.get(key)
    if not isinstance(v, str) or not v:
        raise KnowledgeBaseError(f"{key!r} is required and must be a non-empty string")
    return v


def _opt_str(d: dict, key: str, default):
    v = d.get(key, default)
    if v is None:
        return None
    if not isinstance(v, str):
        raise KnowledgeBaseError(f"{key!r} must be a string")
    return v


def _opt_str_field(d: dict, key: str):
    v = d.get(key)
    if v is None:
        return None
    if not isinstance(v, str):
        raise KnowledgeBaseError(f"{key!r} must be a string")
    return v


def _opt_str_list(d: dict, key: str) -> list[str]:
    v = d.get(key)
    if v is None:
        return []
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise KnowledgeBaseError(f"{key!r} must be a list of strings")
    return list(v)
