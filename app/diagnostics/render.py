"""Render a diagnostic report (full or redacted) as a human-readable Markdown page.

Defines : ``render_markdown`` — a scannable summary that doubles as a fileable bug
          template (placeholder sections at the end).
Used by : app.diagnostics.store (the local ``.md`` twin and the shared ``.md`` copy).
Uses    : app.diagnostics.schema (bucket labels, kinds) and the standard library.
"""

from __future__ import annotations

import json
from typing import Any

from app.diagnostics.schema import KIND_BUG, SAFE, SENSITIVE, TOOL_NAME

# ── Markdown rendering ─────────────────────────────────────────────────────────

def _one_line(summary: Any) -> str:
    """A short, single-line description of a summarised local for the Markdown view."""
    if isinstance(summary, dict):
        if summary.get("redacted"):
            return f"`[redacted: {summary.get('type', '?')} · {str(summary.get('sha256', ''))[:12]}]`"
        typ = summary.get("type", "object")
        if "path" in summary:
            return f"`{typ}` → `{summary['path']}`"
        if "repr" in summary:
            return f"`{typ}` {summary['repr']}"
        hints = summary.get("len", summary.get("_pending_len"))
        return f"`{typ}`" + (f" (len={hints})" if hints is not None else "")
    return f"`{summary!r}`"


def _metadata_rows(safe_meta: dict[str, Any]) -> list[str]:
    keys = ("tool", "tool_version", "python_version", "platform", "git_commit", "context")
    rows: list[str] = []
    for key in keys:
        if key in safe_meta:
            value = safe_meta[key]
            rendered = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)
            rows.append(f"| {key} | {rendered} |")
    return rows


def _frame_lines(frame: dict[str, Any]) -> list[str]:
    """One frame rendered as a heading, its source line, and its two locals lists."""
    lines = [
        f"### `{frame.get('function', '?')}` — "
        f"{frame.get('file', '?')}:{frame.get('lineno', '?')}"
    ]
    if frame.get("code"):
        lines.append(f"> `{frame['code']}`")
    locs = frame.get("locals", {})
    for label, bucket in (("_Safe:_", locs.get(SAFE, {})),
                          ("_⚠ Sensitive (review before sharing):_", locs.get(SENSITIVE, {}))):
        if bucket:
            lines.append("")
            lines.append(label)
            lines.extend(f"- `{name}` = {_one_line(summary)}" for name, summary in bucket.items())
    lines.append("")
    return lines


def render_markdown(report: dict[str, Any]) -> str:
    """A human-readable summary of a report (full or already-redacted). Doubles as a
    fileable bug template via the placeholder sections at the end.

    Renders BOTH kinds from the one schema: a crash report leads with the exception
    and its traceback, while a bug report — which has neither — leads straight into
    the live thread stacks. Frames carrying a ``thread`` label are grouped under it.
    """
    exc = report.get("exception") or {}
    meta = report.get("metadata", {})
    safe_meta = meta.get(SAFE, {}) if isinstance(meta, dict) else {}
    is_bug = report.get("kind") == KIND_BUG or not exc

    lines: list[str] = []
    lines.append(f"# {TOOL_NAME} {'bug' if is_bug else 'crash'} report")
    lines.append("")
    if is_bug:
        lines.append("Filed by the operator — no exception was raised. The stacks below are "
                     "the tool's live state at the moment the report was requested.")
    else:
        lines.append(f"**{exc.get('type', 'Exception')}**: {exc.get('message', '')}")
    lines.append("")

    lines.append("## Environment")
    lines.append("")
    lines.append("| field | value |")
    lines.append("| --- | --- |")
    lines.extend(_metadata_rows(safe_meta))
    lines.append("")

    if report.get("traceback"):
        lines.append("## Traceback")
        lines.append("")
        lines.append("```")
        lines.append(str(report["traceback"]).rstrip())
        lines.append("```")
        lines.append("")

    lines.append("## Live thread stacks & variables" if is_bug
                 else "## Stack frames & variables")
    lines.append("")
    current_thread: str | None = None
    for frame in report.get("frames", []):
        thread = frame.get("thread")
        if thread is not None and thread != current_thread:
            lines.append(f"## Thread — {thread}")
            lines.append("")
            current_thread = thread
        lines.extend(_frame_lines(frame))

    lines.append("---")
    lines.append("")
    lines.append("> ⚠ **Before sharing this report**, confirm every value in the "
                 "_Sensitive_ sections above is redacted or acceptable to disclose.")
    lines.append("")
    lines.append("## Steps to reproduce")
    lines.append("")
    lines.append("<!-- What were you doing when it went wrong? -->")
    lines.append("")
    lines.append("## Expected vs actual")
    lines.append("")
    lines.append("<!-- What did you expect to happen, and what happened instead? -->")
    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("<!-- Anything else that might help. -->")
    lines.append("")
    return "\n".join(lines)
