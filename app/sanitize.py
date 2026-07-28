"""Turn a full (plaintext) crash report into shareable artefacts: a redacted JSON
twin and a human-readable Markdown summary.

Defines : ``redact_report`` (replace every sensitive value with a type + sha256
          placeholder and anonymise filesystem paths) and ``render_markdown``
          (a scannable summary that doubles as a fileable bug template).
Used by : launcher.cmds.redact_errors_cmd (produces the shareable copies) and
          app.diagnostics (renders the local Markdown twin at crash time).
Uses    : app.diagnostics (the sensitivity vocabulary) and the standard library.

WHY redaction lives here, not in the capture: the local report keeps FULL
PLAINTEXT on the operator's own machine (maximum debug value, and the operator
may choose to re-include a specific value); only the copy that leaves the machine
is redacted, and the operator reviews it first.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import sysconfig
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.diagnostics import (
    SAFE,
    SENSITIVE,
    SENSITIVE_TYPE_NAMES,
    is_sensitive_key,
)

# ── path anonymisation ─────────────────────────────────────────────────────────
# Filesystem paths leak the examiner's username and directory layout. A path under
# the project renders relative to the repo root (so a frame reads as
# "app/extract_session.py"); a stdlib / site-packages path keeps its module path
# under a symbolic root ("<stdlib>/json/__init__.py"); anything else under home
# renders as "~/…".
#
# WHY parent.parent: this file is <repo>/app/sanitize.py, so parent.parent is the
# repo root. (This is the anchor mATLAS's diagnostics got subtly wrong — its module
# sat one level deeper than its comment assumed, rooting relative paths too deep.)

try:
    _PROJECT_ROOT: Path | None = Path(__file__).resolve().parent.parent
except Exception:  # noqa: BLE001 - root discovery is best-effort; None disables project-relative.
    _PROJECT_ROOT = None

try:
    _HOME: Path | None = Path.home()
except Exception:  # noqa: BLE001
    _HOME = None


def _interpreter_roots() -> list[tuple[Path, str]]:
    """(root, label) pairs for the stdlib / installed-package trees.

    WHY: a traceback usually crosses out of our code into the stdlib or a dependency.
    Those paths are under neither the repo nor home, so the bare-basename fallback
    reduced them to useless names like "__init__.py" — losing which module actually
    raised. Longest root first so site-packages (often nested under the stdlib
    prefix) wins over the stdlib itself.
    """
    roots: list[tuple[Path, str]] = []
    for key, label in (("purelib", "<site-packages>"), ("platlib", "<site-packages>"),
                       ("stdlib", "<stdlib>"), ("platstdlib", "<stdlib>")):
        try:
            roots.append((Path(sysconfig.get_paths()[key]).resolve(), label))
        except Exception:  # noqa: BLE001 - a missing scheme key is simply skipped.
            continue
    return sorted(roots, key=lambda r: len(str(r[0])), reverse=True)


_INTERPRETER_ROOTS = _interpreter_roots()


def anonymise_path(path_str: str) -> str:
    """Render one path relative to the repo root; else under a symbolic ``<stdlib>``
    / ``<site-packages>`` root; else ``~/…`` under home; else the bare basename."""
    if not path_str:
        return path_str
    try:
        path = Path(path_str)
    except Exception:  # noqa: BLE001 - a non-path value is returned unchanged.
        return path_str
    if _PROJECT_ROOT is not None:
        try:
            return path.relative_to(_PROJECT_ROOT).as_posix()
        except (ValueError, TypeError):
            pass
    for root, label in _INTERPRETER_ROOTS:
        try:
            return f"{label}/{path.relative_to(root).as_posix()}"
        except (ValueError, TypeError):
            continue
    if _HOME is not None:
        try:
            return "~/" + path.relative_to(_HOME).as_posix()
        except (ValueError, TypeError):
            pass
    return path.name


def anonymise_text(text: str) -> str:
    """For text that may EMBED paths (traceback, exception message): drop the repo
    root prefix, then collapse the home root to ``~``."""
    if not text:
        return text
    if _PROJECT_ROOT is not None:
        root = str(_PROJECT_ROOT)
        text = text.replace(root + os.sep, "").replace(root, ".")
    if _HOME is not None:
        text = text.replace(str(_HOME), "~")
    return text


# ── redaction ──────────────────────────────────────────────────────────────────

def _sha256(value: Any) -> str:
    """Stable sha256 of a summarised value — correlatable across reports, not the
    plaintext."""
    try:
        payload = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    except Exception:  # noqa: BLE001 - fall back to str() for anything unserialisable.
        payload = str(value)
    return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()


def _bare_type(summary: Any) -> str:
    """The bare class name from a summary's module-qualified ``type`` field."""
    if isinstance(summary, dict):
        return str(summary.get("type", "?")).rsplit(".", 1)[-1]
    return type(summary).__name__


def _redact(value: Any) -> dict[str, Any]:
    """Replace a value with a non-reversible placeholder that still correlates."""
    return {"redacted": True, "type": _bare_type(value), "sha256": _sha256(value)}


def _is_sensitive_summary(summary: Any) -> bool:
    """A summarised node is sensitive if it carries a known PII-bearing type, or is
    a filesystem-path summary."""
    if not isinstance(summary, dict):
        return False
    if _bare_type(summary) in SENSITIVE_TYPE_NAMES:
        return True
    return "path" in summary and summary.get("type", "").lower().endswith("path")


def _scan(name: str | None, summary: Any) -> Any:
    """Recursively redact anything sensitive-by-name or sensitive-by-type that rode
    along inside an otherwise-safe container."""
    if is_sensitive_key(name) or _is_sensitive_summary(summary):
        return _redact(summary)
    if isinstance(summary, dict):
        out = dict(summary)
        # Named children live under "items" (from a dict) or "attrs" (from an object).
        for holder in ("items", "attrs"):
            child = out.get(holder)
            if isinstance(child, dict):
                out[holder] = {k: _scan(k, v) for k, v in child.items()}
            elif isinstance(child, list):  # a sequence's items have no names
                out[holder] = [_scan(None, v) for v in child]
        return out
    return summary


_REDACTED_MARK = "<redacted>"
# A floor on literal length before we scrub it from free text: long enough that a
# path / identifier is scrubbed, short enough tokens (e.g. "1") never corrupt prose.
_MIN_LITERAL_LEN = 4


@lru_cache(maxsize=4096)
def _boundary_re(literal: str) -> re.Pattern[str]:
    """Match *literal* only as a whole identifier/path component, never mid-word.

    WHY not a plain ``str.replace``: ``sys.argv`` is sensitive, so every subcommand
    name ("extract", "validate", "acquire"…) becomes a scrub literal — and each is a
    substring of real module and function names. A raw replace turned a shared
    traceback into ``app/<redacted>_session.py … run_<redacted>_session``, corrupting
    the very artefact ``faul report`` exists to produce. Word boundaries keep the
    genuine occurrences (a path, an id, a standalone token) scrubbed while leaving
    identifiers that merely CONTAIN the token intact.
    """
    return re.compile(rf"(?<![0-9A-Za-z_]){re.escape(literal)}(?![0-9A-Za-z_])")


def _collect_literals(node: Any, out: set[str]) -> None:
    """Gather the raw sensitive value strings (paths, ids, leaf attrs) so their exact
    occurrences can also be scrubbed from the traceback / message free text."""
    if isinstance(node, str):
        if len(node) >= _MIN_LITERAL_LEN:
            out.add(node)
        return
    if isinstance(node, dict):
        for key in ("path", "preview"):
            if isinstance(node.get(key), str) and len(node[key]) >= _MIN_LITERAL_LEN:
                out.add(node[key])
        for holder in ("items", "attrs"):
            child = node.get(holder)
            if isinstance(child, dict):
                for value in child.values():
                    _collect_literals(value, out)
            elif isinstance(child, list):
                for value in child:
                    _collect_literals(value, out)
        return
    if isinstance(node, list):
        for value in node:
            _collect_literals(value, out)


def _sensitive_literals(report: dict[str, Any]) -> list[str]:
    out: set[str] = set()
    for frame in report.get("frames", []):
        for summary in frame.get("locals", {}).get(SENSITIVE, {}).values():
            _collect_literals(summary, out)
    for value in report.get("metadata", {}).get(SENSITIVE, {}).values():
        _collect_literals(value, out)
    # ``exception.args`` belongs to no bucket, yet a Path handed straight to `raise`
    # can be the ONLY structured occurrence of an evidence location — and the same
    # value is then repeated as free text in the message and the traceback. Harvest
    # it so all three get scrubbed together. Only sensitive-by-type args qualify: a
    # plain string arg IS the message, and taking it whole would scrub every copy of
    # the message out of the report.
    exc = report.get("exception")
    if isinstance(exc, dict):
        for arg in exc.get("args") or []:
            if _is_sensitive_summary(arg):
                _collect_literals(arg, out)
    # Longest first so a value is scrubbed before any shorter value nested in it.
    return sorted(out, key=len, reverse=True)


def _scrub(text: str, literals: list[str]) -> str:
    for literal in literals:
        if literal in text:
            text = _boundary_re(literal).sub(_REDACTED_MARK, text)
    return text


def _sanitise_text_tree(node: Any, literals: list[str]) -> Any:
    """Anonymise, then scrub, EVERY string value in the report.

    WHY a blanket walk instead of a per-field list: the fields carrying free text
    are not a closed set. ``exception.args`` holds the very same message string as
    ``exception.message`` (and ``__notes__`` holds more of it), so anonymising only
    the fields we happened to think of left the operator's home directory and case
    name in plain sight inside the artefact ``redact-errors`` exists to make safe.
    Applying the same rule to every string cannot miss a field added later. Dict
    keys (variable names) are left untouched.
    """
    if isinstance(node, str):
        return _scrub(anonymise_text(node), literals)
    if isinstance(node, dict):
        return {key: _sanitise_text_tree(value, literals) for key, value in node.items()}
    if isinstance(node, list):
        return [_sanitise_text_tree(value, literals) for value in node]
    return node


def redact_report(report: dict[str, Any]) -> dict[str, Any]:
    """Return a shareable copy: every ``sensitive`` bucket redacted wholesale, every
    ``safe`` bucket re-scanned for nested sensitive values, all paths anonymised, and
    every known-sensitive literal scrubbed from every string in the report.
    The input report is not modified."""
    # Collect literals BEFORE the buckets are replaced by placeholders.
    literals = _sensitive_literals(report)
    red = copy.deepcopy(report)

    # ``exception.args`` is free-form and belongs to no bucket, yet a `raise` can
    # put a Path or a DeviceInfo straight into it. Scan it like a safe bucket so a
    # sensitive-by-TYPE argument is replaced by a placeholder; its free TEXT is
    # handled by the blanket pass at the end.
    exc = red.get("exception")
    if isinstance(exc, dict) and isinstance(exc.get("args"), list):
        exc["args"] = [_scan(None, arg) for arg in exc["args"]]

    for frame in red.get("frames", []):
        frame["file"] = anonymise_path(str(frame.get("file", "")))
        locs = frame.get("locals", {})
        if isinstance(locs.get(SENSITIVE), dict):
            locs[SENSITIVE] = {k: _redact(v) for k, v in locs[SENSITIVE].items()}
        if isinstance(locs.get(SAFE), dict):
            locs[SAFE] = {k: _scan(k, v) for k, v in locs[SAFE].items()}

    meta = red.get("metadata", {})
    if isinstance(meta.get(SENSITIVE), dict):
        meta[SENSITIVE] = {k: _redact(v) for k, v in meta[SENSITIVE].items()}
    if isinstance(meta.get(SAFE), dict):
        meta[SAFE] = {k: _scan(k, v) for k, v in meta[SAFE].items()}

    # Final pass: anonymise the paths embedded in every remaining string (traceback,
    # exception message and args, source lines, safe-bucket text) and scrub every
    # known-sensitive literal, so neither can survive in a field we did not
    # anticipate. See _sanitise_text_tree.
    return _sanitise_text_tree(red, literals)


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


def render_markdown(report: dict[str, Any]) -> str:
    """A human-readable summary of a report (full or already-redacted). Doubles as a
    fileable bug template via the placeholder sections at the end."""
    exc = report.get("exception", {})
    meta = report.get("metadata", {})
    safe_meta = meta.get(SAFE, {}) if isinstance(meta, dict) else {}

    lines: list[str] = []
    lines.append("# forensic_AUL crash report")
    lines.append("")
    lines.append(f"**{exc.get('type', 'Exception')}**: {exc.get('message', '')}")
    lines.append("")

    lines.append("## Environment")
    lines.append("")
    lines.append("| field | value |")
    lines.append("| --- | --- |")
    lines.extend(_metadata_rows(safe_meta))
    lines.append("")

    lines.append("## Traceback")
    lines.append("")
    lines.append("```")
    lines.append(str(report.get("traceback", "")).rstrip())
    lines.append("```")
    lines.append("")

    lines.append("## Stack frames & variables")
    lines.append("")
    for frame in report.get("frames", []):
        lines.append(f"### `{frame.get('function', '?')}` — {frame.get('file', '?')}:{frame.get('lineno', '?')}")
        if frame.get("code"):
            lines.append(f"> `{frame['code']}`")
        locs = frame.get("locals", {})
        safe_locals = locs.get(SAFE, {})
        sens_locals = locs.get(SENSITIVE, {})
        if safe_locals:
            lines.append("")
            lines.append("_Safe:_")
            for name, summary in safe_locals.items():
                lines.append(f"- `{name}` = {_one_line(summary)}")
        if sens_locals:
            lines.append("")
            lines.append("_⚠ Sensitive (review before sharing):_")
            for name, summary in sens_locals.items():
                lines.append(f"- `{name}` = {_one_line(summary)}")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("> ⚠ **Before sharing this report**, confirm every value in the "
                 "_Sensitive_ sections above is redacted or acceptable to disclose.")
    lines.append("")
    lines.append("## Steps to reproduce")
    lines.append("")
    lines.append("<!-- What were you doing when it crashed? -->")
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
