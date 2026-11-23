"""The operator's case identifiers — a leaf data module.

Defines : ``CaseInfo`` (case number, IMEI, exhibit, analyst, notes) and
          ``EVIDENCE_REQUIRED_FIELDS`` (the rule an evidence extract enforces,
          ``CaseInfo.missing_for_evidence``).
Used by : forensic_aul.ops.extraction (run_extract, the audit log),
          forensic_aul.ops.acquisition (the sidecar), forensic_aul.ops.workflows,
          the frontends (re-exported from forensic_aul).
Uses    : the standard library only.

WHY a leaf at the package root (like device_info.py): acquisition, extraction and
the workflows all need it; living inside one of those bricks made the others
import that brick.
"""

from __future__ import annotations

from dataclasses import dataclass


# The CaseInfo fields an evidence extract cannot run without: they name the audit
# log and identify the exhibit. Only PRESENCE is checked — never the IMEI's format:
# a Wi-Fi-only iPad has no IMEI, and the examiner must still be able to record one.
EVIDENCE_REQUIRED_FIELDS: tuple[str, ...] = ("case_number", "imei")


@dataclass(frozen=True)
class CaseInfo:
    """Operator-supplied case identifiers recorded in ``case_metadata``."""

    case_number: str | None = None
    imei: str | None = None
    exhibit_number: str | None = None
    analyst_name: str | None = None
    notes: str | None = None

    def missing_for_evidence(self) -> tuple[str, ...]:
        """The required field names that are empty — ``()`` when complete.

        The one definition of the rule; the CLI and the GUI only phrase the result.
        """
        return tuple(
            name for name in EVIDENCE_REQUIRED_FIELDS
            if not (getattr(self, name) or "").strip()
        )
