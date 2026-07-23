"""Render knowledge-base views (list / show / validate / labels / stats) as text.

Pure formatting — every function returns a string and never prints. The CLI
handler selects/filters signatures and computes lint warnings, then emits what
these functions build; a GUI can reuse the same renderings.
"""

from __future__ import annotations

import json


def format_signature_list_json(signatures) -> str:
    """Machine-readable JSON list of *signatures*."""
    return json.dumps([
        {
            "id": s.id,
            "action": s.action,
            "process": s.match.process,
            "subsystem": s.match.subsystem,
            "tags": list(s.tags),
            "confidence": s.confidence,
            "source_file": s.source_file,
        }
        for s in signatures
    ], ensure_ascii=False, indent=2)


def format_signature_list(kb, signatures) -> str:
    """Human-readable table of *signatures* (a filtered subset of *kb*)."""
    out = [
        f"  KB version : {kb.version}",
        f"  KB SHA-256 : {kb.sha256}",
        f"  Signatures : {len(signatures)} / {len(kb.signatures)}",
        "",
        f"  {'ID':<32}  {'PROCESS':<22}  {'CONF':<6}  ACTION",
        f"  {'-' * 32}  {'-' * 22}  {'-' * 6}  ------",
    ]
    for s in signatures:
        out.append(f"  {s.id:<32}  {(s.match.process or '-'):<22}  "
                   f"{s.confidence:<6}  {s.action}")
    return "\n".join(out)


def format_signature(target) -> str:
    """Full definition of one signature."""
    m = target.match
    out = [
        f"id          : {target.id}",
        f"action      : {target.action}",
        f"description : {target.description or '(none)'}",
        f"confidence  : {target.confidence}",
        f"platform    : {target.platform}",
    ]
    if target.ios_min:
        out.append(f"ios_min     : {target.ios_min}")
    if target.ios_max:
        out.append(f"ios_max     : {target.ios_max}")
    out.append(f"source_file : {target.source_file}")
    out.append(f"tags        : {', '.join(target.tags) or '(none)'}")
    out.append("")
    out.append("match:")
    if m.format_str:
        out.append(f"  format_str    : {m.format_str!r}")
    if m.format_str_any:
        out.append("  format_str_any:")
        out.extend(f"    - {f!r}" for f in m.format_str_any)
    if m.dynamic:
        out.append("  dynamic       : true")
    for k, v in (("process", m.process), ("subsystem", m.subsystem),
                 ("category", m.category), ("log_level", m.log_level)):
        if v is not None:
            out.append(f"  {k:<14}: {v}")
    if m.message_regex:
        out.append(f"  message_regex : {m.message_regex!r}")

    if target.extract_regex:
        out.append("")
        out.append(f"extract-regex : {target.extract_regex}")
    if target.extract_fields:
        out.append("")
        out.append("extract-fields:")
        out.extend(f"  {name}: {pat}" for name, pat in target.extract_fields)
    if target.references:
        out.append("")
        out.append("references:")
        out.extend(f"  - {r}" for r in target.references)
    return "\n".join(out)


def format_validation(kb, warnings) -> str:
    """Validation result for an already-loaded *kb* plus advisory label *warnings*."""
    out = [
        f"  OK — {len(kb.signatures)} signature(s) loaded from {kb.root}",
        f"  KB version : {kb.version}",
        f"  KB SHA-256 : {kb.sha256}",
    ]
    if not kb.labels:
        out.append("  Labels     : no labels.yaml — label checks skipped")
    elif warnings:
        out.append("")
        out.append(f"  {len(warnings)} label warning(s):")
        out.extend(f"    - {w.message()}" for w in warnings)
        out.append("")
        out.append("  Resolve each by renaming the group/field, or adding the label to labels.yaml.")
    else:
        out.append(f"  Labels     : OK — all extracted labels are in the {len(kb.labels)}-entry vocabulary")
    return "\n".join(out)


def format_labels(kb) -> str:
    """The controlled label vocabulary."""
    if not kb.labels:
        return "  No labels.yaml vocabulary found."
    out = [f"  Controlled label vocabulary ({len(kb.labels)} entries):", ""]
    width = max(len(name) for name, _ in kb.labels)
    for name, desc in kb.labels:
        out.append(f"    {name:<{width}}  {desc}" if desc else f"    {name}")
    return "\n".join(out)


def format_stats(kb) -> str:
    """KB-wide counts: by confidence, by source file, by tag."""
    by_tag: dict[str, int] = {}
    by_conf: dict[str, int] = {}
    by_file: dict[str, int] = {}
    for s in kb.signatures:
        by_conf[s.confidence] = by_conf.get(s.confidence, 0) + 1
        by_file[s.source_file] = by_file.get(s.source_file, 0) + 1
        for t in s.tags:
            by_tag[t] = by_tag.get(t, 0) + 1

    out = [
        f"  Total signatures : {len(kb.signatures)}",
        f"  KB version       : {kb.version}",
        f"  KB SHA-256       : {kb.sha256}",
        "",
        "  By confidence:",
    ]
    for k in ("high", "medium", "low"):
        if k in by_conf:
            out.append(f"    {k:<7} {by_conf[k]}")
    out.append("")
    out.append("  By source file:")
    out.extend(f"    {n:>4}  {f}" for f, n in sorted(by_file.items()))
    if by_tag:
        out.append("")
        out.append("  By tag:")
        out.extend(f"    {n:>4}  {t}"
                   for t, n in sorted(by_tag.items(), key=lambda x: (-x[1], x[0])))
    return "\n".join(out)
