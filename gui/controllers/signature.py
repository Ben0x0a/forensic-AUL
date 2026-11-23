"""Controller for the signature dialog: turn a form into a knowledge-base file.

Defines : SignatureController (preview, problems that would stop a save, a match
          test against the rows on screen, the write) and ``suggest_id``.
Used by : gui.views.dialog_signature (the dialog builds the draft from its form
          and shows what this returns).
Uses    : forensic_aul (render_signature, write_signature, SignatureDraft,
          KnowledgeBaseError, default_kb_dir).

WHY a controller (G6): the rules (the id format, an existing file, the pattern
compiling, the write and its rollback) are the knowledge base's, not the
widgets'. Phase 5 moves them into one library machinery shared with the CLI; the
dialog will not change then.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from forensic_aul import (
    KnowledgeBaseError,
    SignatureDraft,
    default_kb_dir,
    render_signature,
    write_signature,
)

# The loader's own id rule, mirrored so a bad id is rejected as it is typed
# instead of at save time. Kept identical to loader._ID_RE.
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


class SignatureController:
    """The knowledge-base side of the signature dialog."""

    def __init__(self, kb_dir: Path | None = None) -> None:
        self.kb_dir = kb_dir or default_kb_dir()

    @staticmethod
    def preview(draft: SignatureDraft) -> str:
        """The YAML the draft would write (a half-typed draft still previews)."""
        try:
            return render_signature(draft)
        except (ValueError, TypeError, KnowledgeBaseError) as exc:
            return f"# incomplete: {exc}"

    def problems(self, *, sig_id: str, action: str, regex: str) -> list[str]:
        """What would stop a save, first problem first (empty: ready)."""
        found: list[str] = []
        if not sig_id:
            found.append("an id is required")
        elif not _ID_RE.fullmatch(sig_id):
            found.append("id must be lowercase letters, digits, dot, dash or underscore")
        elif (self.kb_dir / "signatures" / f"{sig_id}.yaml").exists():
            found.append(f"signatures/{sig_id}.yaml already exists")
        if not action:
            found.append("an action is required")
        if not regex:
            found.append("a message pattern is required")
        else:
            try:
                re.compile(regex)
            except re.error as exc:
                found.append(f"pattern does not compile: {exc}")
        return found

    @staticmethod
    def test(regex: str, rows: list[Mapping[str, Any]]) -> str:
        """How many of the rows on screen the pattern matches, as a sentence.

        Deliberately only the loaded rows: a sanity check the analyst can reason
        about ("does it still match the line I picked, and how many of its
        neighbours?"), not a claim about the whole database — which would need a
        scan and would be misleading, since the KB is applied at annotate time
        against different candidate sets.
        """
        try:
            pattern = re.compile(regex)
        except re.error as exc:
            return f"Pattern does not compile: {exc}"
        if not rows:
            return "No rows loaded to test against."
        hits = sum(1 for row in rows if pattern.search(str(row.get("message") or "")))
        return f"Matches {hits:,} of the {len(rows):,} rows on screen (not the whole database)."

    def save(self, draft: SignatureDraft) -> tuple[Path | None, str]:
        """Write the signature: ``(path, "")``, or ``(None, why)`` — the write has
        already rolled back, so the form can be corrected and saved again."""
        try:
            return write_signature(self.kb_dir, draft), ""
        except (KnowledgeBaseError, OSError) as exc:
            return None, str(exc)


def suggest_id(row: Mapping[str, Any]) -> str:
    """A plausible starting id derived from the row's process, e.g. "wifid.event".

    Only a suggestion — the analyst renames it. An empty process yields an empty
    field rather than a misleading default.
    """
    process = str(row.get("process") or "").strip()
    if not process:
        return ""
    slug = re.sub(r"[^a-z0-9]+", "_", process.lower()).strip("_")
    return f"{slug}.event" if slug else ""
