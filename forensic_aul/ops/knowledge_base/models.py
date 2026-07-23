"""Dataclasses for the knowledge-base signatures."""

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

    # Optional post-filter on the rendered message.
    message_regex: str | None = None


@dataclass(frozen=True)
class Signature:
    id:           str
    action:       str
    description:  str
    match:        Match
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

    # Pre-compiled regexes — populated by the loader for hot-path use.
    _compiled_message_regex: re.Pattern | None = field(default=None, compare=False)
    _compiled_extract_regex: re.Pattern | None = field(default=None, compare=False)
    _compiled_extract_fields: tuple[tuple[str, re.Pattern], ...] = field(
        default=(), compare=False,
    )


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
