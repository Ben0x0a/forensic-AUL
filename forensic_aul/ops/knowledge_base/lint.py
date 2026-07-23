"""Lint a knowledge base against its controlled label vocabulary.

The labels a signature produces are the NAMED groups of its ``extract_regex`` and
the keys of its ``extract_fields`` — each becomes a row in ``extracted_values``
and a column in the export. To keep those consistent across signatures (one
canonical ``ssid``, never ``wifi`` / ``WiFi`` / ``wifi_name``) a KB may ship a
``labels.yaml`` vocabulary; this module flags any label a signature uses that is
not in it, and — using stdlib ``difflib`` (no dependency) — proposes the closest
allowed label when the unknown one looks like a typo or case/format variant
(``SSID`` → ``ssid``, ``bundleid`` → ``bundle_id``).

Warnings are advisory: an unknown label still annotates fine. ``kb validate``
surfaces them so the author can either rename the group or add the label.

Used by : launcher/cmds/kb_cmd.py (the ``kb validate`` action).
Uses    : the standard library only (difflib).
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass

from forensic_aul.ops.knowledge_base.models import KnowledgeBase, Signature

# Similarity threshold for suggesting an existing label. 0.6 catches case/format
# variants and small typos without proposing unrelated words.
_SUGGEST_CUTOFF = 0.6


@dataclass(frozen=True)
class LabelWarning:
    """One signature label that is not in the controlled vocabulary."""

    signature_id: str
    source_file: str
    label: str
    suggestion: str | None   # closest allowed label, or None if nothing is close

    def message(self) -> str:
        hint = f" — did you mean '{self.suggestion}'?" if self.suggestion else ""
        return (
            f"{self.source_file}: signature {self.signature_id!r} uses label "
            f"'{self.label}' which is not in labels.yaml{hint}"
        )


def signature_labels(sig: Signature) -> list[str]:
    """Return the (ordered, de-duplicated) labels a signature emits.

    Named groups of ``extract_regex`` first, then ``extract_fields`` keys.
    """
    out: list[str] = []
    seen: set[str] = set()
    if sig._compiled_extract_regex is not None:
        for name in sig._compiled_extract_regex.groupindex:
            if name not in seen:
                seen.add(name)
                out.append(name)
    for name, _pat in sig.extract_fields:
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


def lint_labels(kb: KnowledgeBase) -> list[LabelWarning]:
    """Return warnings for signature labels absent from the KB vocabulary.

    Returns an empty list when the KB has no ``labels.yaml`` (vocabulary opt-in).
    """
    allowed = kb.allowed_label_names()
    if not allowed:
        return []

    # Match case-INSENSITIVELY so the common variants (ssid / SSID / WiFi) are
    # caught — difflib is case-sensitive, so 'SSID' vs 'ssid' would otherwise
    # score zero. Map each lowercased form back to its canonical spelling.
    canonical_by_lower = {name.lower(): name for name in sorted(allowed)}
    warnings: list[LabelWarning] = []
    for sig in kb.signatures:
        for label in signature_labels(sig):
            if label in allowed:
                continue
            low = label.lower()
            if low in canonical_by_lower:
                suggestion: str | None = canonical_by_lower[low]
            else:
                close = difflib.get_close_matches(
                    low, list(canonical_by_lower), n=1, cutoff=_SUGGEST_CUTOFF
                )
                suggestion = canonical_by_lower[close[0]] if close else None
            warnings.append(LabelWarning(
                signature_id=sig.id,
                source_file=sig.source_file,
                label=label,
                suggestion=suggestion,
            ))
    return warnings
