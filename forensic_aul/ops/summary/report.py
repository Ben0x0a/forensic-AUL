"""Render a :class:`~forensic_aul.ops.summary.summary.Summary` as text.

Pure formatting: every function builds and returns a string and never prints.
The CLI handler (and the GUI) decide when and where to emit it. This keeps the
core I/O-free and lets both frontends share one rendering.
"""

from __future__ import annotations

from datetime import datetime, timezone

from forensic_aul.ops.summary.summary import Summary


def format_summary(s: Summary) -> str:
    """Return the full human-readable summary report for *s*."""
    out: list[str] = []
    out.append(f"  Case          : {s.case_number or '(none)'}")
    out.append(f"  IMEI          : {s.imei or '(none)'}")
    if s.ios_model or s.ios_build_version or s.ios_version:
        ver = f" ({s.ios_version})" if s.ios_version else ""
        out.append(f"  Device        : {s.ios_model or '?'}  build {s.ios_build_version or '?'}{ver}")
    out.append(f"  Time range    : {s.log_start_time}  →  {s.log_end_time}  "
               f"({_human_duration(s.range_seconds)})")
    out.append(f"  Total entries : {s.total_entries:,}")
    if s.has_kb:
        pct = (s.annotated_count / s.total_entries * 100) if s.total_entries else 0
        kbv = ", ".join(s.kb_versions) if s.kb_versions else "—"
        out.append(f"  Annotated     : {s.annotated_count:,} ({pct:.2f}%)  "
                   f"across {s.signature_count} signature(s), KB {kbv}")
    out.append("")

    if s.total_entries == 0:
        out.append("  (logs table is empty)")
        return "\n".join(out)

    out.extend(_format_top("Top processes", s.top_processes))
    out.extend(_format_top("Top subsystems", s.top_subsystems))
    out.extend(_format_top("Log levels", s.log_levels))

    if s.annotated_actions:
        out.append("  Annotated actions (by count):")
        width = max(len(a.action) for a in s.annotated_actions)
        for a in s.annotated_actions:
            out.append(f"    {a.count:>6,}  {a.action:<{width}}   ({a.signature_id})")
        out.append("")

    out.extend(_format_histogram(s))
    return "\n".join(out)


def _format_top(title: str, entries) -> list[str]:
    if not entries:
        return []
    width = max(len(str(e.name) or "") for e in entries)
    lines = [f"  {title}:"]
    for e in entries:
        lines.append(f"    {e.count:>10,}  {e.name or '(none)':<{width}}")
    lines.append("")
    return lines


def _format_histogram(s: Summary) -> list[str]:
    max_total = max((b.total for b in s.histogram), default=0)
    if max_total == 0:
        return []

    width = 50
    blocks = "▁▂▃▄▅▆▇█"
    lines = [
        f"  Temporal distribution  (bucket = {_human_duration(s.histogram_bucket_ns / 1e9)}, "
        f"max = {max_total:,}/bucket):"
    ]
    for b in s.histogram:
        ts = datetime.fromtimestamp(b.start_unix_ns / 1_000_000_000, tz=timezone.utc)
        ratio = b.total / max_total if max_total else 0
        bar_len = int(round(ratio * width))
        if s.has_kb and b.total:
            ann_len = int(round((b.annotated / max_total) * width))
            bar = "▓" * ann_len + "█" * max(0, bar_len - ann_len)
        else:
            bar = "█" * bar_len
        if bar_len == 0 and b.total > 0:
            bar = blocks[min(int(ratio * len(blocks) * width), len(blocks) - 1)]
        bar = bar + " " * (width - len(bar))
        lines.append(f"    {ts.strftime('%Y-%m-%d %H:%M:%S')}  {bar}  {b.total:,}")
    lines.append("")
    if s.has_kb and any(b.annotated for b in s.histogram):
        lines.append("    Legend: ▓ annotated  █ total")
        lines.append("")
    return lines


def _human_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        return f"{seconds/60:.1f}m"
    if seconds < 86400:
        return f"{seconds/3600:.1f}h"
    return f"{seconds/86400:.1f}d"
