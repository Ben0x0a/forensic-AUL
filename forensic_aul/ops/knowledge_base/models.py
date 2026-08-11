"""Dataclasses for the knowledge-base signatures.

Defines : ``Match``, ``Signature``, ``KnowledgeBase`` (the loaded, validated KB)
          and ``SignatureDraft`` (an in-memory signature awaiting emission by the
          writer — see ``forensic_aul.ops.knowledge_base.writer``).
Used by : forensic_aul.ops.knowledge_base.{loader,writer,lint},
          forensic_aul.ops.annotation.matcher.
Uses    : the standard library only (dataclasses, re).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Match:
    """The matching specification of a signature.

    Validation rule (enforced by the loader, not here): exactly one of
    `format_str`, `format_str_any`, or `dynamic` must be present. The
    indexed refinements (process, subsystem, …) are AND'ed on top.
    """
    # Format-string anchors (one of the three required).
    format_str: str | None = None
    format_str_any: tuple[str, ...] = ()
    dynamic: bool = False               # signature targets dynamic-format lines

    # Indexed pre-filters (all optional).
    process:    str | None = None
    subsystem:  str | None = None
    category:   str | None = None
    log_level:  str | None = None       # Default/Info/Debug/Error/Fault
    event_type: str | None = None       # Log/Activity/Trace/Signpost/Loss/Statedump/Simpledump
    library:    str | None = None       # exact match on the library path

    # Optional post-filter on the rendered message.
    message_regex: str | None = None


@dataclass(frozen=True)
class Signature:
    id:           str
    action:       str
    description:  str
    match:        Match
    # What the match means to an analyst — `action` is only a title.
    interpretation: str = ""   # what one may conclude from this line
    caveats:        str = ""   # known false positives / when the conclusion doesn't hold
    # Two complementary ways to pull named values out of a matched message; the
    # extracted (label → value) pairs from both are merged. Use whichever reads
    # cleaner for a given signature (or both):
    #   - extract_regex : ONE regex whose NAMED groups become labels — best when
    #     several values sit in one message (e.g. SSID + BSSID on a Wi-Fi line).
    #   - extract_fields : a label → regex map, one regex per value — best when
    #     the values are independent.
    extract_regex:  str | None = None
    extract_fields: tuple[tuple[str, str], ...] = ()  # (label, regex) pairs
    confidence:   str = "medium"        # low | medium | high
    platform:     str = "ios"
    ios_min:      str | None = None
    ios_max:      str | None = None
    references:   tuple[str, ...] = ()
    tags:         tuple[str, ...] = ()
    source_file:  str = ""               # YAML file the signature came from
    # Provenance: who wrote the rule and whether it has been reviewed.
    author:       str = ""
    created:      str = ""              # ISO date, "YYYY-MM-DD"
    version:      str = ""              # per-signature semver
    status:       str = "validated"     # draft | validated | deprecated

    # Pre-compiled regexes — populated by the loader for hot-path use.
    _compiled_message_regex: re.Pattern | None = field(default=None, compare=False)
    _compiled_extract_regex: re.Pattern | None = field(default=None, compare=False)
    _compiled_extract_fields: tuple[tuple[str, re.Pattern], ...] = field(
        default=(), compare=False,
    )


@dataclass(frozen=True)
class SignatureDraft:
    """An in-memory signature awaiting emission as YAML.

    Mirrors the authorable (non-compiled, non-source_file) fields of
    ``Signature``. Built programmatically — e.g. by a GUI "new signature"
    dialog — and handed to ``writer.render_signature`` /
    ``writer.write_signature``, which turn it into house-style YAML and
    validate it by round-tripping through ``load_kb``.
    """
    id:             str
    action:         str
    match:          Match
    description:    str = ""
    interpretation: str = ""
    caveats:        str = ""
    extract_regex:  str | None = None
    extract_fields: tuple[tuple[str, str], ...] = ()
    confidence:     str = "medium"
    platform:       str = "ios"
    ios_min:        str | None = None
    ios_max:        str | None = None
    references:     tuple[str, ...] = ()
    tags:           tuple[str, ...] = ()
    author:         str = ""
    created:        str = ""
    version:        str = ""
    # Interactively-created signatures default to "draft" (unlike the loaded
    # Signature model, whose default of "validated" preserves the meaning of
    # existing hand-authored signatures that predate this field).
    status:         str = "draft"


@dataclass(frozen=True)
class KnowledgeBase:
    """Loaded, validated set of signatures plus traceability metadata."""
    version:    str                 # semver from knowledge_base/VERSION
    sha256:     str                 # rolling hash of all YAML contents
    signatures: tuple[Signature, ...]
    root:       str                 # absolute path to the KB root
    # Controlled vocabulary of allowed extracted-value labels, as ordered
    # (name, description) pairs from labels.yaml. Empty when no vocabulary file
    # is present (label linting is then skipped).
    labels:     tuple[tuple[str, str], ...] = ()

    def allowed_label_names(self) -> frozenset[str]:
        """The set of allowed label names (for membership checks in linting)."""
        return frozenset(name for name, _desc in self.labels)
