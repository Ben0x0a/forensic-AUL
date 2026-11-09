"""os_log annotation value→name decoder tables (AUTO-GENERATED).

DO NOT EDIT BY HAND. Regenerate with `python scripts/gen_decoders.py`.

Ported from the Mandiant *macos-unifiedlogs* Rust library
(version 0.8.0, Apache-2.0): https://github.com/mandiant/macos-UnifiedLogs
Only pure value→name lookup tables are ported here; byte-parsing decoders
(sockaddr, IPv4/6, DNS headers, timestamps) remain hand-written in message.py.
See THIRD_PARTY_NOTICES.md for the full attribution and licence.
"""

from __future__ import annotations

# annotation type (lowercased) → {raw value: decoded name}
DECODER_TABLES: dict[str, dict[str, str]] = {
}


def decode(decoder_type: str, raw: str) -> str | None:
    """Return the decoded name for *raw* under *decoder_type*, or None.

    *decoder_type* must be lowercased (callers pass the stripped annotation
    type from message._annotation_type). None means 'no table / no match',
    so the caller can fall back to the raw value.
    """
    table = DECODER_TABLES.get(decoder_type)
    if table is None:
        return None
    return table.get(raw)
