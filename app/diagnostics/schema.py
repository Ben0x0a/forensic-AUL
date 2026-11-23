"""The diagnostic-report format and the sensitivity vocabulary — the package's leaf.

Defines : the report identity (``REPORT_SCHEMA``, ``TOOL_NAME``, ``KIND_CRASH`` /
          ``KIND_BUG``), the two bucket labels (``SAFE`` / ``SENSITIVE``), the
          sensitivity vocabulary (``SENSITIVE_TYPE_NAMES``, ``SENSITIVE_FIELD_TOKENS``,
          ``SECRET_TOKENS``) and the classifier built on it (``classify``,
          ``is_sensitive_key``, ``is_sensitive_type``, ``type_names``).
Used by : every other module of app.diagnostics — capture (splits locals into the
          buckets), redact (re-scans them for the shared copy), render (labels the
          sections), store (file names per kind).
Uses    : the standard library only, and imports nothing else of the package — so
          every brick can depend on it without a cycle.

WHY one vocabulary for capture AND redaction: the capture decides what is sensitive
and the redaction removes it. If they used two lists, a token added to one would be
captured as safe, or never redacted.
"""

from __future__ import annotations

from pathlib import PurePath
from typing import Any

# Bumped when the report structure changes so a downstream reader can branch on it.
# /2 added ``kind`` and the optional per-frame ``thread`` label (bug reports).
REPORT_SCHEMA = "faul.diagnostic-report/2"
TOOL_NAME = "forensic_AUL"

# Report kinds. One schema covers both; ``kind`` is how a reader tells them apart.
KIND_CRASH = "crash"
KIND_BUG = "bug"

# Sensitivity bucket labels — the two sections the operator reviews before sharing.
SAFE = "safe"
SENSITIVE = "sensitive"

# WHY a forensic-specific classifier (not name-substring-only redaction): this
# tool's PII lives in well-TYPED fields (a DeviceInfo's imei, a LogEntry's message,
# extracted_values) whose variable names need not match any keyword. So a value is
# sensitive if its TYPE, its NAME, or its being a filesystem path says so.

# Domain types whose instances are sensitive as a whole. Matched by bare class name
# against the value's MRO (so subclasses count) — never imported. Reference homes:
# forensic_aul/device_info.py, ops/extraction/options.py, engine/models/log_entry.py,
# ops/query/reader.py.
SENSITIVE_TYPE_NAMES = frozenset(
    {"DeviceInfo", "SimInfo", "CaseInfo", "LogEntry", "LogRow", "MessageData"}
)

# Case-insensitive substrings; a variable / attribute / dict-key whose name
# contains any of these is sensitive. Over-redaction here is acceptable — a false
# positive costs a hashed value, a false negative leaks PII.
SENSITIVE_FIELD_TOKENS = frozenset(
    {
        "imei", "udid", "serial", "meid", "ecid", "iccid", "imsi", "phone",
        "_mac", "device_name", "case_number", "exhibit", "analyst", "notes",
        "message", "ssid", "latitude", "longitude",
    }
)

# Generic secret tokens (kept separate so the intent reads clearly).
SECRET_TOKENS = frozenset(
    {
        "password", "passwd", "pwd", "passphrase", "secret", "token",
        "credential", "api_key", "apikey", "private_key",
    }
)


def is_sensitive_key(name: str | None) -> bool:
    """True when a variable/key name matches a sensitive field or secret token."""
    if not name:
        return False
    lowered = name.lower()
    return any(t in lowered for t in SENSITIVE_FIELD_TOKENS) or any(
        t in lowered for t in SECRET_TOKENS
    )


def type_names(value: Any) -> tuple[str, ...]:
    """Every class name in the value's MRO (best-effort) — for name-based matching."""
    try:
        return tuple(base.__name__ for base in type(value).__mro__)
    except Exception:  # noqa: BLE001 - exotic metaclasses must not crash the probe.
        return ()


def is_sensitive_type(value: Any) -> bool:
    """True when the value's type (or any base) is a known sensitive domain type."""
    return any(name in SENSITIVE_TYPE_NAMES for name in type_names(value))


def classify(name: str | None, value: Any) -> str:
    """Return ``SENSITIVE`` or ``SAFE`` for a captured variable.

    Sensitive if the NAME matches a token, the VALUE is a filesystem path
    (evidence/output location), or the TYPE is a known PII-bearing domain type.
    """
    if is_sensitive_key(name):
        return SENSITIVE
    if isinstance(value, PurePath):
        return SENSITIVE
    if is_sensitive_type(value):
        return SENSITIVE
    return SAFE
