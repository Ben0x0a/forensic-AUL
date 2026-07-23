"""Write a tamper-evident acquisition report next to the logarchive.

The report is a human-readable JSON file named
``<logarchive_name>.acquisition.json``.

Structure
---------
{
  "forensic_aul_version": "0.1.0",
  "report_format_version": 1,

  "case": {                         ← entered manually by the operator
    "case_number": "...",
    "exhibit": "...",
    "analyst": "...",
    "notes": "..."
  },

  "acquisition": {                  ← generated automatically
    "timestamp_utc": "2024-01-15T12:34:56Z",
    "logarchive_path": "...",
    "logarchive_sha256": "...",
    "file_count": 42
  },

  "device": { ... }                 ← all DeviceInfo fields (never editable)
}

The file itself is NOT hashed (it would be a chicken-and-egg problem), but
the logarchive SHA-256 inside it provides the forensic anchor.  Operators
should sign or hash this file externally if chain-of-custody requires it.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from forensic_aul import __version__
from forensic_aul.ops.acquisition.device import DeviceInfo

log = logging.getLogger(__name__)

_REPORT_FORMAT_VERSION = 1

# Suffix appended (not substituted) to the logarchive name to form the report
# filename, e.g. ``foo.logarchive`` → ``foo.logarchive.acquisition.json``. Single
# source of truth for the sidecar naming, shared by the writer and the lookups
# below (consumed by the GUI's Extract / Verify-hash sidecar auto-fill).
ACQUISITION_REPORT_SUFFIX = ".acquisition.json"


def sidecar_path_for(source_path: Path) -> Path:
    """Return the acquisition-report path that would sit beside *source_path*."""
    return source_path.parent / (source_path.name + ACQUISITION_REPORT_SUFFIX)


def load_sidecar_for(source_path: Path) -> dict | None:
    """Load the acquisition report for *source_path*, or None if absent/unreadable.

    Two shapes are handled transparently, so a single call auto-fills case fields
    from either an acquire output:
      - a ``.faul`` container carries its sidecar **inside** the archive;
      - a loose ``.logarchive`` (legacy layout) has a neighbouring
        ``<name>.acquisition.json`` file.

    Best-effort: a missing or malformed sidecar returns None rather than raising,
    so callers (e.g. GUI auto-fill) can treat "no sidecar" and "bad sidecar" alike
    and simply leave their fields untouched.
    """
    source_path = Path(source_path)
    # A .faul embeds its sidecar; read it from within the container.
    from forensic_aul.engine import faul_format
    if faul_format.is_faul(source_path):
        return faul_format.read_sidecar(source_path)

    path = sidecar_path_for(source_path)
    if not path.is_file():
        return None
    try:
        return load_acquisition_report(path)
    except (OSError, ValueError):
        return None


def build_report_dict(
    logarchive_path: Path,
    device: DeviceInfo,
    *,
    case_number: str,
    exhibit: str | None,
    analyst: str | None,
    notes: str | None,
    logarchive_sha256: str,
    file_count: int = 0,
    file_hashes: dict[str, str] | None = None,
) -> dict:
    """Build the acquisition-report dict (no I/O).

    Shared by :func:`write_acquisition_report` (loose-layout sidecar file) and the
    ``.faul`` packer, which embeds the same dict inside the container. All device
    fields come from *device* and are **never overridable**.

    *file_hashes* (the ``{relative_path: sha256}`` map from ``hash_logarchive``)
    is recorded per file under ``acquisition.file_hashes`` so each file can be
    integrity-checked independently later. ``file_count`` defaults to
    ``len(file_hashes)`` when the map is given.
    """
    if file_hashes is not None and not file_count:
        file_count = len(file_hashes)
    return {
        "forensic_aul_version": __version__,
        "report_format_version": _REPORT_FORMAT_VERSION,

        "case": {
            "case_number":  case_number,
            "exhibit":      exhibit  or "",
            "analyst":      analyst  or "",
            "notes":        notes    or "",
        },

        "acquisition": {
            "timestamp_utc":    datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "logarchive_path":  str(logarchive_path.resolve()),
            "logarchive_sha256": logarchive_sha256,
            "file_count":       file_count,
            # Per-file SHA-256 ({relative_path: digest}) for independent
            # integrity checks; omitted (None) if hashing was unavailable.
            "file_hashes":      file_hashes if file_hashes else None,
        },

        "device": device.to_dict(),
    }


def write_acquisition_report(
    logarchive_path: Path,
    device: DeviceInfo,
    *,
    case_number: str,
    exhibit: str | None,
    analyst: str | None,
    notes: str | None,
    logarchive_sha256: str,
    file_count: int = 0,
    file_hashes: dict[str, str] | None = None,
) -> Path:
    """Write the acquisition report next to *logarchive_path* and return its path.

    The report is placed beside the logarchive with the suffix
    ``.acquisition.json`` (legacy loose layout; the ``.faul`` packer embeds the
    same dict instead). See :func:`build_report_dict` for the payload.
    """
    report = build_report_dict(
        logarchive_path, device,
        case_number=case_number, exhibit=exhibit, analyst=analyst, notes=notes,
        logarchive_sha256=logarchive_sha256, file_count=file_count, file_hashes=file_hashes,
    )
    # Append (do not replace) — `Path.with_suffix` would strip ".logarchive".
    report_path = sidecar_path_for(logarchive_path)

    # Atomic write: a partial file would be a forensic disaster.
    tmp_path = report_path.with_suffix(report_path.suffix + ".tmp")
    payload = json.dumps(report, indent=2, ensure_ascii=False)
    try:
        tmp_path.write_text(payload, encoding="utf-8")
        os.replace(tmp_path, report_path)
        log.info(f"Acquisition report written: {report_path}")
    except OSError:
        log.exception("Could not write acquisition report")
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass
        raise

    return report_path


def load_acquisition_report(report_path: Path) -> dict:
    """Load and return a previously written acquisition report."""
    return json.loads(report_path.read_text(encoding="utf-8"))


# ── stdout rendering ──────────────────────────────────────────────────────────

def format_acquire_result(result) -> str:  # result: forensic_aul.outcomes.AcquireResult
    """Human-readable summary of a completed acquisition (pure format → str)."""
    out = [f"  Done — .faul container written to: {result.logarchive_path}"]
    if result.logarchive_sha256:
        out.append(f"  SHA-256 (logarchive) : {result.logarchive_sha256}")
    # The acquisition sidecar travels inside the .faul (no separate report file);
    # a non-None report_path means the legacy loose layout was used.
    if result.report_path is not None:
        out.append(f"  Acquisition report   : {result.report_path}")
    else:
        out.append("  Acquisition sidecar  : embedded in the .faul container")
    return "\n".join(out)
