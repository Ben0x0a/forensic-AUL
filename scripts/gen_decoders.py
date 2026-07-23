#!/usr/bin/env python3
"""Generate Python value→name decoder tables from the Mandiant Rust library.

Defines : a code generator that reads the os_log decoders straight from the
          **upstream** Mandiant *macos-unifiedlogs* repository on GitHub
          (``src/decoders/``) and emits
          ``forensic_aul/engine/parser/decoder_tables.py`` — a pure data module
          mapping each os_log annotation *type* (e.g. ``odtypes:ODError``,
          ``location:CLSubHarvesterIdentifier``) to its ``{raw_value: name}``
          lookup table. Only *pure* ``match "k" => "v"`` tables are ported;
          decoders that parse bytes (sockaddr, IPv4/6, DNS headers, timestamps)
          are real code and are skipped — they stay in hand-written Python.
Used by : developers / CI (``.github/workflows/decoder-tables.yml``) to keep the
          generated tables in sync with the upstream source. Run with no
          arguments to (re)write the module; ``--check`` exits non-zero if the
          on-disk module is stale (for CI). ``--ref`` pins a branch/tag/commit
          (default ``main``) for a reproducible generation.
Uses    : the upstream Mandiant macos-unifiedlogs source fetched over HTTPS
          (Apache-2.0). Nothing is vendored in this repo; attribution is embedded
          in the generated module header, in ``THIRD_PARTY_NOTICES.md``, and the
          licence text is kept at ``licenses/macos-UnifiedLogs-LICENSE``.

WHY a generator rather than hand-copied tables: the upstream tables grow as new
macOS versions add decoders; regenerating keeps them current and auditable (the
diff shows exactly what changed) instead of drifting silently. WHY fetch upstream
rather than vendor the crate: the source of truth stays a single URL, so a
regeneration always reflects the live upstream without carrying a copy here.

Network: stdlib ``urllib`` only. Set ``GITHUB_TOKEN`` to raise the anonymous
GitHub API rate limit (used automatically by CI).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

# ── Upstream source (Mandiant macos-unifiedlogs, Apache-2.0) ─────────────────────
_UPSTREAM_REPO = "mandiant/macos-UnifiedLogs"
_DEFAULT_REF = "main"
_DECODERS_PATH = "src/decoders"  # directory holding the per-type decoder .rs files
_DISPATCH_NAME = "decoder.rs"  # the file with the type→function dispatch table
_CARGO_PATH = "Cargo.toml"  # read for the upstream crate version (header only)

_API_BASE = "https://api.github.com"
_RAW_BASE = "https://raw.githubusercontent.com"

# ── Output location (relative to the repo root: this file's parent's parent) ─────
_REPO_ROOT = Path(__file__).resolve().parent.parent
_OUTPUT_FILE = _REPO_ROOT / "forensic_aul" / "engine" / "parser" / "decoder_tables.py"

# ── Rust-parsing regexes ────────────────────────────────────────────────────────
# Dispatch arm:  ... contains("TYPE") { [Ok(] func( ...
#   \s also matches the newline between the `{` and the function call.
_DISPATCH_RE = re.compile(
    r'contains\("([^"]+)"\)\s*\{\s*(?:Ok\(\s*)?([a-z_][a-zA-Z0-9_]*)\s*\('
)
# A match arm of pure string→string form, allowing `"a" | "b" => "v"` alternation.
# Anchored at line start (after indent) so commented-out `//"x" => ...` lines are
# skipped (they begin with `/`, not `"`).
_ARM_RE = re.compile(
    r'^\s*((?:"[^"]*"\s*\|\s*)*"[^"]*")\s*=>\s*"([^"]*)"',
    re.MULTILINE,
)
_QUOTED_RE = re.compile(r'"([^"]*)"')


class UpstreamError(RuntimeError):
    """A failure fetching the upstream source (network, HTTP, or rate limit)."""


def _http_get(url: str, *, accept: str = "application/vnd.github.raw") -> str:
    """GET *url* from GitHub and return the body text, or raise ``UpstreamError``.

    Sends a User-Agent (required by the GitHub API) and, when ``GITHUB_TOKEN`` is
    set, an Authorization header to lift the anonymous rate limit.
    """
    headers = {"User-Agent": "forensic-aul-gen-decoders", "Accept": accept}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:  # noqa: PERF203 — one-shot, clarity over speed
        detail = ""
        if exc.code == 403 and "rate limit" in (exc.headers.get("x-ratelimit-remaining") or ""):
            detail = " (GitHub API rate limit — set GITHUB_TOKEN)"
        raise UpstreamError(f"HTTP {exc.code} for {url}{detail}") from exc
    except urllib.error.URLError as exc:
        raise UpstreamError(f"network error for {url}: {exc.reason}") from exc


def _raw_url(path: str, ref: str) -> str:
    return f"{_RAW_BASE}/{_UPSTREAM_REPO}/{ref}/{path}"


def _list_decoder_files(ref: str) -> list[str]:
    """Return the ``*.rs`` file names under the upstream ``src/decoders/`` at *ref*.

    Uses the GitHub contents API so newly added decoder files are picked up
    automatically rather than being pinned to a hard-coded list.
    """
    url = f"{_API_BASE}/repos/{_UPSTREAM_REPO}/contents/{_DECODERS_PATH}?ref={ref}"
    entries = json.loads(_http_get(url, accept="application/vnd.github+json"))
    names = [e["name"] for e in entries if e.get("type") == "file" and e["name"].endswith(".rs")]
    if _DISPATCH_NAME not in names:
        raise UpstreamError(
            f"dispatch file {_DISPATCH_NAME!r} not found under {_DECODERS_PATH}/ at {ref}"
        )
    return sorted(names)


def _upstream_version(ref: str) -> str:
    """Best-effort read of the upstream crate version for the attribution header."""
    try:
        text = _http_get(_raw_url(_CARGO_PATH, ref))
    except UpstreamError:
        return "unknown"
    m = re.search(r'^\s*version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    return m.group(1) if m else "unknown"


def _function_body(source: str, func_name: str) -> str | None:
    """Return the brace-balanced body of ``fn func_name`` in *source*, or None.

    HOW: locate ``fn <name>``, then scan forward from its first ``{`` counting
    braces until the matching close. WHY brace-counting rather than a regex: Rust
    bodies nest braces (match arms, error structs), so a naive ``{...}`` regex
    would stop at the first inner ``}``.
    """
    m = re.search(r'\bfn\s+' + re.escape(func_name) + r'\b', source)
    if not m:
        return None
    start = source.find("{", m.end())
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(source)):
        c = source[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return source[start : i + 1]
    return None


def _extract_table(body: str) -> dict[str, str]:
    """Extract the pure ``{key: value}`` string→string arms from a function body."""
    table: dict[str, str] = {}
    for left, value in _ARM_RE.findall(body):
        for key in _QUOTED_RE.findall(left):
            # First definition wins; upstream never duplicates keys, but be safe.
            table.setdefault(key, value)
    return table


def build_tables(ref: str) -> dict[str, dict[str, str]]:
    """Map each lowercased annotation type to its ported value→name table.

    Fetches every ``src/decoders/*.rs`` from the upstream repo at *ref*, then maps
    each dispatched annotation type to its ported table. Types whose decoder is not
    a pure string→string table (byte parsers, etc.) yield an empty table and are
    omitted — they remain hand-written in Python.
    """
    names = _list_decoder_files(ref)
    sources = {name: _http_get(_raw_url(f"{_DECODERS_PATH}/{name}", ref)) for name in names}

    dispatch_src = sources[_DISPATCH_NAME]
    all_src = "\n".join(sources[name] for name in names)

    tables: dict[str, dict[str, str]] = {}
    for ann_type, func_name in _DISPATCH_RE.findall(dispatch_src):
        body = _function_body(all_src, func_name)
        if body is None:
            continue
        table = _extract_table(body)
        if table:  # skip byte-parser decoders (no pure arms)
            tables[ann_type.lower()] = table
    return dict(sorted(tables.items()))


def render_module(tables: dict[str, dict[str, str]], version: str) -> str:
    """Render the generated ``decoder_tables.py`` source text (deterministic)."""
    lines: list[str] = []
    lines.append('"""os_log annotation value→name decoder tables (AUTO-GENERATED).')
    lines.append("")
    lines.append("DO NOT EDIT BY HAND. Regenerate with `python scripts/gen_decoders.py`.")
    lines.append("")
    lines.append("Ported from the Mandiant *macos-unifiedlogs* Rust library")
    lines.append(f"(version {version}, Apache-2.0): https://github.com/mandiant/macos-UnifiedLogs")
    lines.append("Only pure value→name lookup tables are ported here; byte-parsing decoders")
    lines.append("(sockaddr, IPv4/6, DNS headers, timestamps) remain hand-written in message.py.")
    lines.append("See THIRD_PARTY_NOTICES.md for the full attribution and licence.")
    lines.append('"""')
    lines.append("")
    lines.append("from __future__ import annotations")
    lines.append("")
    lines.append("# annotation type (lowercased) → {raw value: decoded name}")
    lines.append("DECODER_TABLES: dict[str, dict[str, str]] = {")
    for ann_type, table in tables.items():
        lines.append(f"    {ann_type!r}: {{")
        for key, value in table.items():
            lines.append(f"        {key!r}: {value!r},")
        lines.append("    },")
    lines.append("}")
    lines.append("")
    lines.append("")
    lines.append("def decode(decoder_type: str, raw: str) -> str | None:")
    lines.append('    """Return the decoded name for *raw* under *decoder_type*, or None.')
    lines.append("")
    lines.append("    *decoder_type* must be lowercased (callers pass the stripped annotation")
    lines.append("    type from message._annotation_type). None means 'no table / no match',")
    lines.append("    so the caller can fall back to the raw value.")
    lines.append('    """')
    lines.append("    table = DECODER_TABLES.get(decoder_type)")
    lines.append("    if table is None:")
    lines.append("        return None")
    lines.append("    return table.get(raw)")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if the on-disk module differs from freshly generated output.",
    )
    parser.add_argument(
        "--ref",
        default=_DEFAULT_REF,
        help=f"Upstream branch/tag/commit to generate from (default: {_DEFAULT_REF}).",
    )
    args = parser.parse_args()

    try:
        tables = build_tables(args.ref)
        version = _upstream_version(args.ref)
    except UpstreamError as exc:
        print(f"error: could not fetch upstream decoders: {exc}", file=sys.stderr)
        return 2

    rendered = render_module(tables, version)
    n_tables = len(tables)
    n_entries = sum(len(t) for t in tables.values())

    if args.check:
        current = _OUTPUT_FILE.read_text(encoding="utf-8") if _OUTPUT_FILE.exists() else ""
        if current != rendered:
            print(
                f"decoder_tables.py is STALE — run `python scripts/gen_decoders.py` "
                f"({n_tables} tables, {n_entries} entries from upstream {args.ref}).",
                file=sys.stderr,
            )
            return 1
        print(f"decoder_tables.py is up to date ({n_tables} tables, {n_entries} entries).")
        return 0

    _OUTPUT_FILE.write_text(rendered, encoding="utf-8")
    print(f"Wrote {_OUTPUT_FILE.relative_to(_REPO_ROOT)}: {n_tables} tables, {n_entries} entries.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
