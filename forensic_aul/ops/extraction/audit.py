"""The forensic operational log of one extract (the audit log) and its seal.

Defines : ``AuditLog`` (open the log file, remember which database row it belongs
          to, seal it), ``audit_log_path`` (``<case>-AUL-<imei>.log`` beside the
          database), and the file's format (``AUDIT_FORMAT``, ``AUDIT_DATEFMT``,
          ``UTCFormatter``).
Used by : forensic_aul.ops.extraction.extract (``run_extract`` with
          ``ExtractOptions(audit_log=True)`` — the CLI, the GUI and any third-party
          caller get the same sealed artefact).
Uses    : forensic_aul.engine.integrity (``seal_log_file``), forensic_aul._version,
          forensic_aul.ops.extraction.options (CaseInfo, ExtractOptions) and the
          standard library.

WHY in the library and not in a frontend: the sealed log is part of the evidence
an extract produces. When it lived in the app layer, the GUI never sealed one and
a library caller could not produce one at all.

WHY the handler goes on the ``forensic_aul`` logger and not on the root logger: the
sealed file must hold this tool's own record of the run. On the root logger, any
third-party library logging at INFO during the run would land in the evidence log.

WHY the level is lowered to INFO while the log is open: a host that never
configured logging leaves the effective level at WARNING, so the INFO records the
audit is made of would never be created. The previous level is restored on seal.
"""

from __future__ import annotations

import logging
import re
import sqlite3
import time
from collections.abc import Mapping
from pathlib import Path

from forensic_aul._version import __version__
from forensic_aul.engine.integrity import seal_log_file
from forensic_aul.case_info import CaseInfo
from forensic_aul.ops.extraction.options import ExtractOptions

log = logging.getLogger(__name__)

# The logger the audit handler is attached to: the library's root logger, so every
# library record of the run is captured and nothing else is.
_AUDITED_LOGGER_NAME = "forensic_aul"

# File format: no source location — a UTC timestamp, the level, a fixed source
# label and the message. Part of the artefact's contract: change it deliberately.
AUDIT_FORMAT: str = "%(asctime)s  %(levelname)-8s  Forensic AUL — %(message)s"
AUDIT_DATEFMT: str = "%Y-%m-%dT%H:%M:%SZ"

_UNSAFE_FILENAME_CHARS = re.compile(r'[\\/:*?"<>|]')


class UTCFormatter(logging.Formatter):
    """A formatter whose ``%(asctime)s`` is always UTC (forensic timestamps)."""

    converter = staticmethod(time.gmtime)


def audit_log_path(case: CaseInfo, db_path: Path) -> Path:
    """``<case>-AUL-<imei>.log`` beside the database (unsafe characters → ``_``)."""
    safe_case = _UNSAFE_FILENAME_CHARS.sub("_", case.case_number or "").strip("_ ")
    safe_imei = _UNSAFE_FILENAME_CHARS.sub("_", case.imei or "").strip("_ ")
    return db_path.parent / f"{safe_case}-AUL-{safe_imei}.log"


class AuditLog:
    """One open audit log: a file handler plus where its seal will be stored.

    Lifecycle: :meth:`open` → the pipeline calls :meth:`bind` once the
    ``case_metadata`` row exists (and again after the rename to the final name) →
    :meth:`seal` on every exit path.
    """

    def __init__(self, path: Path, handler: logging.Handler, previous_level: int) -> None:
        self.path = path
        self._handler = handler
        self._previous_level = previous_level
        self._db_path: Path | None = None
        self._metadata_id: int | None = None

    @classmethod
    def open(cls, case: CaseInfo, db_path: Path) -> AuditLog:
        """Start the audit log of one extract; the database folder is created.

        Append mode: successive runs of the same case accumulate in one file, so no
        run is ever lost. Always INFO, whatever the console verbosity.
        """
        db_path.parent.mkdir(parents=True, exist_ok=True)
        path = audit_log_path(case, db_path)
        handler = logging.FileHandler(path, mode="a", encoding="utf-8")
        handler.setLevel(logging.INFO)
        handler.setFormatter(UTCFormatter(fmt=AUDIT_FORMAT, datefmt=AUDIT_DATEFMT))
        audited = logging.getLogger(_AUDITED_LOGGER_NAME)
        previous_level = audited.level
        if audited.getEffectiveLevel() > logging.INFO:
            audited.setLevel(logging.INFO)
        audited.addHandler(handler)
        return cls(path, handler, previous_level)

    def banner(
        self,
        source: Path | str | Mapping[str, Path] | object,
        db_path: Path,
        case: CaseInfo,
        opts: ExtractOptions,
    ) -> None:
        """Write the session header: who, what, where, with which options."""
        if isinstance(source, Mapping):
            src = ", ".join(f"{k}={Path(v).resolve()}" for k, v in source.items())
        elif isinstance(source, (str, Path)):
            src = str(Path(source).resolve())
        else:  # a PreparedSource
            src = str(getattr(source, "original_path", source))
        jobs_desc = "serial" if opts.jobs <= 1 else f"{opts.jobs - 1} workers + 1 writer"
        log.info("=" * 72)
        log.info(f"AUL Parser {__version__} — extract session started")
        log.info(f"Log file   : {self.path}")
        log.info(f"Case       : {case.case_number}")
        log.info(f"IMEI       : {case.imei}")
        if case.exhibit_number:
            log.info(f"Exhibit    : {case.exhibit_number}")
        if case.analyst_name:
            log.info(f"Analyst    : {case.analyst_name}")
        log.info(f"Source     : {src}")
        if opts.work_dir:
            log.info(f"Work dir   : {opts.work_dir}  (kept)")
        log.info(f"Output DB  : {db_path.resolve()}")
        log.info(f"Batch size : {opts.batch_size}")
        log.info(f"Jobs       : {opts.jobs}  ({jobs_desc})")
        log.info("=" * 72)

    def bind(self, db_path: Path, metadata_id: int | None) -> None:
        """Record which database row the seal belongs in (called by the pipeline)."""
        self._db_path = db_path
        self._metadata_id = metadata_id

    def seal(self) -> str | None:
        """Close the handler, hash the log, store the digest in ``case_metadata``.

        Returns the digest, or ``None`` when the log could not be hashed. Never
        raises: it runs on failure paths, where a second error would mask the
        first. Closing the handler first flushes every byte, so the file is
        complete before it is hashed; the lines below are therefore console-only.
        """
        self._close()
        db_path, metadata_id = self._db_path, self._metadata_id
        # WHY the existence guard: seal_log_file opens db_path with sqlite3.connect,
        # which CREATES the file when absent — a file conjured at the final name
        # would fake a completed extract.
        if db_path is None or metadata_id is None or not db_path.exists():
            db_path, metadata_id = None, None
        try:
            digest = seal_log_file(db_path, self.path, metadata_id)
        except OSError as exc:
            log.error(f"Could not hash log file {self.path}: {exc}")
            return None
        except sqlite3.Error:
            log.exception("Failed to store the log hash in the database")
            return None
        log.info("Log file sealed")
        log.info(f"  Path   : {self.path}")
        log.info(f"  SHA-256: {digest}")
        if metadata_id is None:
            log.warning("No database row to hold the log hash — it is reported here only")
        else:
            log.info(f"Log file SHA-256 stored in {db_path.name} case_metadata (id={metadata_id})")
        return digest

    def _close(self) -> None:
        audited = logging.getLogger(_AUDITED_LOGGER_NAME)
        self._handler.flush()
        self._handler.close()
        audited.removeHandler(self._handler)
        audited.setLevel(self._previous_level)
