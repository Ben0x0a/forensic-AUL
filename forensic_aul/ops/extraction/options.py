"""Option and run-state containers for the extract pipeline.

Defines : ``ExtractOptions`` (the user-tunable knobs of ``run_extract``),
          ``CaseInfo`` (the operator-supplied case identifiers) — both public,
          built ONCE by a frontend and passed through untouched — and
          ``RunContext`` (the per-run state threaded through the pipeline
          stages instead of ~20 individual parameters).
Used by : forensic_aul.ops.extraction.extract (run_extract and its stages), and
          every caller of run_extract (re-exported from forensic_aul).

WHY objects and not keyword arguments: the same ~20 options used to be re-declared
at every layer (CLI → session → run_extract), and one layer forgetting to forward
one was a real bug. With one object, a new option is one field here plus one flag.
Uses    : forensic_aul.config (BATCH_SIZE default),
          forensic_aul.engine.utils.cancellation (CancelToken),
          forensic_aul.ops.extraction.source (PreparedSource),
          forensic_aul.engine.database.writer / engine.utils.progress (types).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from forensic_aul.config import BATCH_SIZE
from forensic_aul.engine.utils.cancellation import NEVER_CANCELLED, CancelToken

if TYPE_CHECKING:
    # Type-only: keeps this container module import-light (no writer/progress
    # machinery pulled in by consumers that only need the option dataclasses).
    from forensic_aul.engine.database.writer import BatchWriter
    from forensic_aul.engine.utils.progress import ProgressReporter
    from forensic_aul.ops.extraction.audit import AuditLog
    from forensic_aul.ops.extraction.source import PreparedSource


@dataclass(frozen=True)
class ExtractOptions:
    """The tunable behaviour of one ``run_extract`` call (see its docstring)."""

    batch_size: int = BATCH_SIZE
    # Defer the FTS rebuild to the end of the run. ON by default: it produces
    # the same final database with far less write amplification, and the only
    # cost is that an interrupted run leaves full-text search empty until
    # rebuilt. Only the CLI can turn it off (--no-fast-fts); the GUI does not
    # offer the choice, because there is no case where an analyst benefits
    # from the slower path but many where they would pick it by accident.
    fast_fts: bool = True
    fast_write: bool = False    # synchronous=OFF (speed over power-loss safety)
    fts: bool = True            # build the FTS5 full-text index at all
    keep_raw: bool = False      # persist logs.raw_data JSON
    # Total process budget: 1 = serial, in-process; N = N-1 parser workers + the
    # writer; 0 = auto (memory-aware, one per physical core — see run_extract).
    # Anything but 1 uses spawn-based multiprocessing: the caller must be import-safe.
    jobs: int = 1
    overwrite: bool = False     # replace an existing output database
    integrity: str = "full"     # source hashing mode (source.INTEGRITY_MODES)
    # Where archives / loose dirs are materialised: None = an auto-cleaned temp
    # dir; a path = kept. A kept dir that already holds files is refused unless
    # reset_work_dir (it would parse the previous run's evidence into this case).
    work_dir: Path | None = None
    reset_work_dir: bool = False
    # Write and seal the forensic operational log (<case>-AUL-<imei>.log beside the
    # database; see ops/extraction/audit.py). On for evidence extracts (CLI, GUI);
    # off by default, so a library caller and identify's scratch extracts need no
    # case identifiers. When on, CaseInfo.missing_for_evidence() must be empty.
    audit_log: bool = False


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


@dataclass
class RunContext:
    """Everything one extract run's stages share.

    Bundles the connection, the prepared source, the options and the progress
    reporter so the pipeline stages (`_run_parse`, `_finalise`, …) take one
    context instead of re-declaring ~20 forwarded parameters each. Mutable on
    purpose: ``writer`` and ``fts5_ok`` are filled in once the schema exists.
    """

    conn: sqlite3.Connection
    # The file actually being written: ``<final_db_path>.partial``. Everything in
    # the pipeline writes here, so an interrupted run is self-evidently partial
    # from its NAME alone — see run_extract's docstring.
    db_path: Path
    # Where db_path is renamed once, and only once, the run has succeeded. A file
    # at this name therefore MEANS a completed extract.
    final_db_path: Path
    prepared: "PreparedSource"
    case: CaseInfo
    opts: ExtractOptions
    reporter: "ProgressReporter"
    t0: float                            # monotonic start of the run
    cancel: CancelToken = NEVER_CANCELLED
    writer: "BatchWriter | None" = None  # set after the schema is initialised
    fts5_ok: bool = False                # set after init_schema probes FTS5
    # case_metadata rowid, known once step 3 has run. Held here so the cancel
    # path can mark the run cancelled without threading the id back out of the
    # stage that created it.
    metadata_id: int | None = None
    # ISO 8601 UTC time source preparation began — the one phase that runs before
    # the database exists, so it can only be entered in ``extract_phases``
    # retrospectively (see extract._record_prepare_phase).
    prepare_started_at: str = ""
    # extract_phases rowid of the phase currently in progress; None between
    # phases. A row left open is the record of where an interrupted run stopped.
    phase_id: int | None = None
    # The open audit log when ExtractOptions.audit_log is on; bound to the
    # case_metadata row as soon as it exists, so every exit path can seal it.
    audit: "AuditLog | None" = None
