"""Option and run-state containers for the extract pipeline.

Defines : ``ExtractOptions`` (the user-tunable knobs of ``run_extract``),
          ``CaseInfo`` (the operator-supplied case identifiers) and
          ``RunContext`` (the per-run state threaded through the pipeline
          stages instead of ~20 individual parameters).
Used by : forensic_aul.ops.extraction.extract (run_extract and its stages).
Uses    : forensic_aul.config (BATCH_SIZE default),
          forensic_aul.ops.extraction.source (PreparedSource),
          forensic_aul.engine.database.writer / engine.utils.progress (types).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from forensic_aul.config import BATCH_SIZE

if TYPE_CHECKING:
    # Type-only: keeps this container module import-light (no writer/progress
    # machinery pulled in by consumers that only need the option dataclasses).
    from forensic_aul.engine.database.writer import BatchWriter
    from forensic_aul.engine.utils.progress import ProgressReporter
    from forensic_aul.ops.extraction.source import PreparedSource


@dataclass(frozen=True)
class ExtractOptions:
    """The tunable behaviour of one ``run_extract`` call (see its docstring)."""

    batch_size: int = BATCH_SIZE
    fast_fts: bool = False      # defer the FTS rebuild to the end of the run
    fast_write: bool = False    # synchronous=OFF (speed over power-loss safety)
    fts: bool = True            # build the FTS5 full-text index at all
    keep_raw: bool = False      # persist logs.raw_data JSON
    jobs: int = 1               # total process budget (1 = serial, in-process)
    overwrite: bool = False     # replace an existing output database
    integrity: str = "full"     # source hashing mode (source.INTEGRITY_MODES)


@dataclass(frozen=True)
class CaseInfo:
    """Operator-supplied case identifiers recorded in ``case_metadata``."""

    case_number: str | None = None
    imei: str | None = None
    exhibit_number: str | None = None
    analyst_name: str | None = None
    notes: str | None = None


@dataclass
class RunContext:
    """Everything one extract run's stages share.

    Bundles the connection, the prepared source, the options and the progress
    reporter so the pipeline stages (`_run_parse`, `_finalise`, …) take one
    context instead of re-declaring ~20 forwarded parameters each. Mutable on
    purpose: ``writer`` and ``fts5_ok`` are filled in once the schema exists.
    """

    conn: sqlite3.Connection
    db_path: Path
    prepared: "PreparedSource"
    case: CaseInfo
    opts: ExtractOptions
    reporter: "ProgressReporter"
    t0: float                            # monotonic start of the run
    writer: "BatchWriter | None" = None  # set after the schema is initialised
    fts5_ok: bool = False                # set after init_schema probes FTS5
