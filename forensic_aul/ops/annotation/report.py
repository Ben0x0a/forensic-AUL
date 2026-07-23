"""Render annotation run output as text.

Pure formatting — returns strings, never prints.
"""

from __future__ import annotations

from forensic_aul.outcomes import AnnotateResult


def format_header(database, kb) -> str:
    """Pre-run context line block (what is about to be annotated)."""
    return "\n".join([
        f"  DB         : {database}",
        f"  KB         : {kb.root} (version {kb.version})",
        f"  Signatures : {len(kb.signatures)} loaded",
    ])


def format_annotate_result(result: AnnotateResult) -> str:
    """Post-run summary of an annotation pass."""
    out = [
        f"  Annotation complete: {result.total_matches} match(es) "
        f"across {result.signatures_matched} signature(s)"
    ]
    if result.total_matches == 0 and result.counts:
        out.append("  (No matches — verify your KB targets the right OS/build.)")
    return "\n".join(out)
