"""Format Apple Unified Log messages from Firehose format strings and item data.

Apple's log format strings are printf-like with extensions:
  - %{public}s / %{private}s  — visibility annotations (already resolved upstream)
  - %{uuid_t}.16P             — 16-byte UUID
  - %{bool}d                  — boolean ("true"/"false")
  - %{errno}d                 — errno code name (best-effort)
  - %{time_t}d                — unix timestamp
  - %{network:in_addr}d       — IPv4 address
  - %{network:in6_addr}...    — IPv6 address
  - %%                        — literal percent

Items in FirehoseItemData.item_info are consumed sequentially, one per
non-%% format specifier found in the format string.

Reference: macos-UnifiedLogs/src/message.rs, macos-UnifiedLogs/src/unified_log.rs
"""

from __future__ import annotations

import errno
import logging
import os
import re
from datetime import datetime, timezone
from functools import lru_cache

from forensic_aul.engine.models import FirehoseItemData, FirehoseItemInfo

log = logging.getLogger(__name__)

# Value→name decoder tables auto-generated from the Mandiant Rust library
# (scripts/gen_decoders.py → engine/parser/decoder_tables.py). The import is
# guarded so the parser still works if the generated module is absent (e.g. a
# fresh checkout before the generator has run) — it just falls back to raw values.
try:
    from forensic_aul.engine.parser.decoder_tables import decode as _decode_from_table
except ImportError:  # pragma: no cover - generated module not present
    def _decode_from_table(decoder_type: str, raw: str) -> str | None:
        return None

# ---------------------------------------------------------------------------
# Regex that matches a single printf-style format specifier.
#
# Group 1 (optional): annotation in braces  e.g.  {public}  {uuid_t}
# Group 2 (optional): format flags / width / precision / length modifier
# Group 3:            conversion character
#
# The full pattern is anchored to a literal '%'.
# ---------------------------------------------------------------------------
_SPEC_RE = re.compile(
    r"%"
    r"(?:\{([^}]*)\})?"                           # optional {annotation}
    r"([-+ #0]*\d*(?:\.\d+)?(?:hh?|ll?|[qztLwI]|I32|I64)?)?"  # flags/width/prec/length
    r"([cmCdiouxXeEfgGaAnpsSZP@%])"               # conversion character
)

# Item types that represent sensitive/private data — already redacted upstream
_PRIVATE_MSG = "<private>"

# One parsed format specifier: (start, end, annotation, fmt_modifier, conv).
# `start`/`end` are byte offsets into the format string so the caller can slice
# out the literal runs between specifiers.
_Spec = tuple[int, int, str, str, str]


@lru_cache(maxsize=65_536)
def _parse_specs(format_string: str) -> tuple[_Spec, ...]:
    """Tokenise *format_string* into its printf specifiers, with memoisation.

    HOW: runs ``_SPEC_RE`` once over the string and freezes the match groups into
    a tuple of ``(start, end, annotation, fmt_modifier, conv)``.
    WHY cached: a tiny set of format-string *templates* recurs across millions of
    log entries (only the substituted values differ), so tokenising each template
    once and reusing the parse removes the regex scan from the per-entry hot path.
    The cache is per-process — under multiprocessing each worker keeps its own,
    which is exactly what we want (no cross-process sharing needed). The key is the
    immutable format string and the result is immutable, so the cache is safe.
    """
    return tuple(
        (m.start(), m.end(), m.group(1) or "", m.group(2) or "", m.group(3))
        for m in _SPEC_RE.finditer(format_string)
    )

# Epoch for time_t formatting (used for %{time_t}d)
# We just emit the integer value; callers can format if needed.


def format_message(
    format_string: str,
    item_data: FirehoseItemData,
) -> str:
    """Substitute format specifiers in *format_string* with resolved item values.

    Items in *item_data.item_info* are consumed left-to-right, one per
    non-`%%` specifier.

    Returns the assembled message string.
    """
    if not format_string:
        return ""

    items: list[FirehoseItemInfo] = item_data.item_info
    item_idx = 0
    result_parts: list[str] = []
    last_end = 0

    # Tokenisation is memoised per template (see _parse_specs); only the value
    # substitution below runs per entry.
    for start, end, annotation, fmt_modifier, conv in _parse_specs(format_string):
        # Append literal text before this specifier
        result_parts.append(format_string[last_end:start])
        last_end = end

        # %% — literal percent, no item consumed
        if conv == "%":
            result_parts.append("%")
            continue

        # Consume next item
        if item_idx >= len(items):
            log.debug(
                "format_message: no item for specifier at pos %d in %r",
                start, format_string,
            )
            result_parts.append(format_string[start:end])  # leave specifier as-is
            continue

        item = items[item_idx]
        item_idx += 1

        value_str = _render_item(item, annotation, fmt_modifier, conv)
        result_parts.append(value_str)

    # Append any trailing literal text
    result_parts.append(format_string[last_end:])

    return "".join(result_parts)


# ---------------------------------------------------------------------------
# Internal rendering helpers
# ---------------------------------------------------------------------------

# os_log privacy / masking qualifiers. Apple packs the brace content of a
# specifier as a comma-separated list mixing one of these with an optional
# decoder *type*, e.g. ``%{public, location:CLSubHarvesterIdentifier}d``. These
# tokens are NOT decoder types — they must be stripped before dispatch.
_PRIVACY_TOKENS = frozenset({"public", "private", "sensitive", "mask.hash", "mask.none"})


def _annotation_type(annotation: str) -> str:
    """Extract the decoder-type token from a (possibly compound) os_log annotation.

    HOW: the annotation is a comma-separated list (e.g. ``"public, time_t"`` or
    ``"private, location:_CLClientManagerStateTrackerState"``); return the first
    lowercased part that is not a privacy/masking qualifier, or ``""`` if the
    annotation carries only privacy qualifiers (or is empty).
    WHY: dispatching on the *raw* brace content meant a ``public,``/``private,``
    prefix made even supported types (uuid_t, time_t, …) fall through to the
    "unknown annotation" placeholder and spam the debug log — see the
    CLSubHarvesterIdentifier case. Splitting first fixes that whole class.
    """
    for part in annotation.split(","):
        tok = part.strip().lower()
        if tok and tok not in _PRIVACY_TOKENS:
            return tok
    return ""


def _render_item(
    item: FirehoseItemInfo,
    annotation: str,
    fmt_modifier: str,
    conv: str,
) -> str:
    """Render a single FirehoseItemInfo as a string for the given format specifier."""
    raw = item.message_strings

    # Already-redacted private items
    if raw == _PRIVATE_MSG:
        return _PRIVATE_MSG

    # Strip privacy qualifiers, then dispatch on the decoder type.
    decoder_type = _annotation_type(annotation)

    if decoder_type in ("uuid_t", "uuid"):
        return _render_uuid(raw)

    if decoder_type == "bool":
        return _render_bool(raw)

    if decoder_type in ("errno", "darwin.errno"):
        return _render_errno(raw)

    if decoder_type in ("time_t", "timeval", "timespec"):
        return _render_time_t(raw)

    if decoder_type in ("network:in_addr", "in_addr"):
        return _render_in_addr(raw)

    if decoder_type in ("network:in6_addr", "in6_addr"):
        return _render_in6_addr(raw)

    if decoder_type == "":
        # Only privacy qualifiers (or none) — standard printf on the resolved string.
        return _apply_printf(raw, fmt_modifier, conv)

    # Auto-generated value→name lookup tables ported from the Mandiant Rust
    # library (see engine/parser/decoder_tables.py and scripts/gen_decoders.py).
    decoded = _decode_from_table(decoder_type, raw)
    if decoded is not None:
        return decoded

    # Unknown annotation — surface as placeholder so we don't silently lose data.
    log.debug("format_message: unknown annotation %r, value=%r", annotation, raw)
    return f"<decoded:{annotation}:{raw}>"


def _apply_printf(raw: str, fmt_modifier: str, conv: str) -> str:
    """Apply basic printf conversion to the pre-resolved string *raw*.

    For string conversions (%s, %S, %@) return as-is.
    For integer/float conversions attempt to parse *raw* and re-format
    using the full specifier (flags + width + precision + conv), so that
    format strings like "%-10d" or "%08x" render correctly.
    """
    if conv in ("s", "S", "@", "Z"):
        return raw

    if conv in ("c", "C"):
        # character — raw is already a single-char string from upstream
        return raw

    # Integer conversions
    if conv in ("d", "i", "o", "u", "x", "X"):
        try:
            int_val = int(raw, 0)
        except (ValueError, TypeError):
            return raw
        spec = f"%{fmt_modifier}{conv}"
        try:
            return spec % int_val
        except (ValueError, TypeError):
            return raw

    # Floating-point conversions
    if conv in ("e", "E", "f", "g", "G", "a", "A"):
        try:
            float_val = float(raw)
        except (ValueError, TypeError):
            return raw
        spec = f"%{fmt_modifier}{conv}"
        try:
            return spec % float_val
        except (ValueError, TypeError):
            return raw

    # Pointer
    if conv in ("p", "P"):
        try:
            int_val = int(raw, 0)
            return f"0x{int_val:x}"
        except (ValueError, TypeError):
            return raw

    # Fallback — return as-is
    return raw


def _render_uuid(raw: str) -> str:
    """Format a UUID string.  *raw* is expected to be a 32-char hex string or
    already hyphenated 8-4-4-4-12 form.
    """
    s = raw.replace("-", "").upper()
    if len(s) != 32:
        return raw
    return f"{s[0:8]}-{s[8:12]}-{s[12:16]}-{s[16:20]}-{s[20:32]}"


def _render_bool(raw: str) -> str:
    """Render an integer value as 'true' or 'false'."""
    try:
        return "true" if int(raw, 0) != 0 else "false"
    except (ValueError, TypeError):
        return raw


@lru_cache(maxsize=256)
def _render_errno(raw: str) -> str:
    """Render an errno value as 'NAME: description' where possible.

    Cached: the errno domain is tiny and fixed, so the same *raw* values recur
    constantly across entries; memoising avoids re-parsing + strerror each time.
    """
    try:
        code = int(raw, 0)
    except (ValueError, TypeError):
        return raw
    name = errno.errorcode.get(code, str(code))
    # os.strerror maps the code to its system description; the errno module has
    # no strerror (that was a latent bug — it raised AttributeError for every
    # %{errno}d message). os.strerror raises ValueError for out-of-range codes.
    try:
        desc = os.strerror(code)
    except (ValueError, OverflowError):
        return name
    return f"{name}: {desc}"


def _render_time_t(raw: str) -> str:
    """Render a unix timestamp as an ISO-8601 UTC string (best-effort)."""
    try:
        ts = int(raw, 0)
    except (ValueError, TypeError):
        return raw
    try:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return raw
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _render_in_addr(raw: str) -> str:
    """Render a 32-bit integer as a dotted-quad IPv4 address."""
    try:
        val = int(raw, 0)
        b = val.to_bytes(4, "big")
    except (ValueError, TypeError, OverflowError):
        return raw
    return f"{b[0]}.{b[1]}.{b[2]}.{b[3]}"


def _render_in6_addr(raw: str) -> str:
    """Render a 128-bit integer (as hex string) as an IPv6 address.

    Apple sometimes prefixes IPv6 hex strings with ``0x`` and embeds dashes
    coming from a hex dump renderer; we strip those prefixes/separators
    rather than ``replace("0x", "")``, which would corrupt a string that
    legitimately contains the substring ``0x`` later on.
    """
    try:
        s = raw.removeprefix("0x").removeprefix("0X").replace("-", "")
        val = int(s, 16)
        b = val.to_bytes(16, "big")
    except (ValueError, TypeError, OverflowError):
        return raw
    groups = [f"{b[i]:02x}{b[i + 1]:02x}" for i in range(0, 16, 2)]
    return ":".join(groups)
