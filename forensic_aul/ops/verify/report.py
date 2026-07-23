"""Render a :class:`~forensic_aul.ops.verify.verify.VerifyResult` as text.

Pure formatting — returns a string, never prints. The CLI handler decides the
process exit code from ``result.ok``; this module only renders.
"""

from __future__ import annotations

from forensic_aul.ops.verify.verify import VerifyResult

_MARK = {"ok": "[ OK ]", "fail": "[FAIL]", "skip": "[skip]"}


def format_verify(result: VerifyResult) -> str:
    """Return the full chain-of-custody verification report for *result*."""
    out = [
        f"  Case      : {result.case_number}",
        f"  IMEI      : {result.imei}",
        f"  DB        : {result.database.resolve()}",
        "",
    ]

    for c in result.checks:
        line = f"  {_MARK.get(c.status, '[ ?? ]')} {c.label}"
        if c.actual and c.status == "ok":
            line += f" matches ({c.actual})"
        elif c.detail:
            line += f" — {c.detail}"
        out.append(line)
        if c.status == "fail" and c.stored is not None:
            out.append(f"         stored : {c.stored}")
            out.append(f"         actual : {c.actual}")

    pf = result.per_file
    if pf is not None:
        extra = ""
        if pf.missing_hash:
            extra += f"  ({pf.missing_hash} no stored hash)"
        if pf.missing_file:
            extra += f"  ({pf.missing_file} missing on disk)"
        out.append(f"  Per-file  : {pf.matched}/{pf.total} matched{extra}")
        if pf.mismatches:
            out.append("  [FAIL] mismatched files:")
            for m in pf.mismatches[:10]:
                out.append(f"         - {m.path}")
                out.append(f"             stored: {m.stored}")
                out.append(f"             actual: {m.actual}")
            if len(pf.mismatches) > 10:
                out.append(f"         … and {len(pf.mismatches) - 10} more")

    out.append("")
    out.append(f"  Summary: {result.passed} passed, {result.failed} failed")
    return "\n".join(out)
