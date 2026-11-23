"""Option container for the identify workflow.

Defines : ``IdentifyOptions`` (device, still pause, outputs, and how the two
          captures are extracted) and ``IDENTIFY_EXTRACT`` (identify's extract
          defaults). Built once by a frontend and passed through untouched.
Used by : forensic_aul.ops.workflows.identify (``run_identify_workflow``), the CLI
          ``identify`` command and the GUI Identify screen (re-exported from
          forensic_aul).
Uses    : forensic_aul.ops.extraction.options (ExtractOptions).
"""

from __future__ import annotations

from dataclasses import dataclass

from forensic_aul.ops.extraction.options import ExtractOptions

# Said by every frontend before an identify run. WHY advice and not a check: if
# the device locks anyway, its lock/unlock lines are plainly visible in the
# result, and the unlock may be the very action studied. Consumed by:
# launcher/cmds/identify_cmd.py, gui/views/screens_identify.py.
AUTO_LOCK_ADVICE = (
    "Disable Auto-Lock (Settings › Display & Brightness › Auto-Lock › Never) "
    "unless lock and unlock events are what you study."
)

# How both captures are extracted by default. WHY these differ from an evidence
# extract: identify is a research tool that runs two short extracts back to back —
# no full-text index (the diff never searches text), no source hashing (no chain
# of custody to attest), small batches (short captures).
IDENTIFY_EXTRACT = ExtractOptions(batch_size=1_000, fts=False, integrity="off")


@dataclass(frozen=True)
class IdentifyOptions:
    """The tunable behaviour of one ``run_identify_workflow`` call."""

    # The device. None = the only connected one.
    udid: str | None = None
    # Seconds the operator keeps the device still while the baseline captures a
    # quiet device (0 = no pause; the baseline is still taken).
    still_seconds: int = 60
    # Seconds of stillness after the operator's preparation (see the
    # ``prepare`` callback), so the background work it set off ends inside the
    # baseline rather than leaking into the action capture.
    settle_seconds: int = 10
    write_csv: bool = True          # also write <prefix>-identified.csv
    # Both extracts. ``integrity != "off"`` also hashes both archives and writes
    # their acquisition reports.
    extract: ExtractOptions = IDENTIFY_EXTRACT
