"""Common exception hierarchy for the library.

Defines : ``ForensicAULError`` — the base class every library-specific error
          derives from — and the shared concrete errors ``SourceError`` (input
          detection / preparation), ``InvalidDatabaseError`` (a path that is not
          an analysis database), ``IncompleteDatabaseError`` (one produced by a
          run that never finished), ``OutputExistsError`` (an output would be
          overwritten) and ``OperationCancelled`` (the operator stopped a long
          operation), ``CaseInfoError`` (case identifiers missing for an
          evidence extract), ``ExtractFailedError`` (an extract decoded
          nothing, for callers that cannot go on without data), the parser's
          ``FormatError`` family (``UnsupportedFormat``, ``CorruptRecord``,
          ``TruncatedRecord``) and ``PARSE_ERRORS`` (what bad input bytes can
          raise — the only thing a parse loop may catch and count). Operation-specific errors defined elsewhere
          (``AcquisitionError``, ``KnowledgeBaseError``) also derive from the
          base, so a consumer can catch everything the library raises with one
          ``except ForensicAULError``.
Used by : forensic_aul.ops.* (raise sites), forensic_aul/__init__.py (re-export),
          and external consumers (catch sites).
Uses    : the standard library only.

Backward compatibility: each concrete error that *replaced* a builtin raise ALSO
subclasses the builtin type the code historically raised (``ValueError`` for
``SourceError`` / ``InvalidDatabaseError``; ``AcquisitionError`` keeps its place
under ``Exception``). Existing ``except ValueError`` call sites therefore keep
working — the hierarchy only ADDS a catchable common base, it never changes what
an existing handler receives. ``OperationCancelled`` is the deliberate exception
to that pattern: it is new, it never replaced a builtin raise, and it must NOT be
caught by an ``except ValueError`` written for bad input (see its docstring).
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Type-only: errors.py is imported by everything (including the cancellation
    # primitive), so it must stay dependency-free at runtime.
    from pathlib import Path

    from forensic_aul.outcomes import ExtractResult


class ForensicAULError(Exception):
    """Base class for every error the forensic_aul library raises on purpose.

    Catch this to handle "the library rejected the input / could not do the
    work" uniformly, while genuine bugs (AttributeError, sqlite3 internals, …)
    still propagate loudly.
    """


class SourceError(ForensicAULError, ValueError):
    """An evidence source could not be detected, validated, or prepared.

    Raised by ``detect_source_type`` / ``prepare_source`` / ``prepare_loose_dirs``
    (historically a plain ``ValueError`` — still caught by ``except ValueError``).
    """


class InvalidDatabaseError(ForensicAULError, ValueError):
    """The given path is not a usable analysis database.

    Raised by the path-based readers (``query_logs``, ``run_export``,
    ``summarise``, …) when the file exists but is not a SQLite database or
    lacks the ``logs`` table a ``run_extract`` output always carries.
    """


class IncompleteDatabaseError(InvalidDatabaseError):
    """The database was produced by an extract that never completed.

    ``case_metadata.extract_status`` is still ``running`` (the run died or was
    killed) or ``cancelled`` (the operator stopped it). Such a store is real
    evidence as far as it goes, but it is **not** the complete parse of its
    source: ordering, indexes and the full-text index may be missing or partial,
    so a reader that treated it as finished would silently under-report.

    Opening one is therefore refused, and no CLI or GUI path lifts the refusal:
    the answer is to re-run the extract. The library kwarg
    ``open_analysis_database(..., allow_incomplete=True)`` is the only way in,
    kept so the guard stays testable.

    Subclasses ``InvalidDatabaseError`` so existing "cannot use this database"
    handlers keep working unchanged, while a caller that wants to offer the
    escape can catch this narrower type.
    """


class OutputExistsError(ForensicAULError, FileExistsError):
    """An output already exists and the call was not allowed to replace it.

    Raised by ``run_extract`` when the output database (or the ``.partial`` of an
    interrupted run) exists and ``overwrite`` is off — writing into it would merge
    two acquisitions into one file. Subclasses ``FileExistsError``, which is what
    it is, so a plain ``except FileExistsError`` still catches it. ``path`` is the
    output in the way, so a frontend can phrase its own advice.
    """

    def __init__(self, message: str, path: "Path | None" = None) -> None:
        super().__init__(message)
        self.path = path


class CaseInfoError(ForensicAULError, ValueError):
    """Case identifiers required for an evidence extract are missing.

    Raised by ``run_extract`` with ``ExtractOptions(audit_log=True)`` before any
    work starts. ``missing`` lists the absent ``CaseInfo`` field names, so a
    frontend can name them in its own words (a CLI flag, a form label).
    """

    def __init__(self, missing: tuple[str, ...]) -> None:
        super().__init__(f"required for an evidence extract: {', '.join(missing)}")
        self.missing = missing


class ExtractFailedError(ForensicAULError):
    """An extract finished with status ``FAILED``: nothing could be decoded.

    ``run_extract`` itself never raises it — its database is a genuine record of
    what could be read. A caller that cannot go on without data (identify, which
    would otherwise diff two empty databases) raises it to stop early. ``result``
    is the ``ExtractResult``; ``result.status_reasons`` say why.
    """

    def __init__(self, label: str, result: "ExtractResult") -> None:
        super().__init__(f"{label} extract decoded nothing — {'; '.join(result.status_reasons)}")
        self.result = result


class FormatError(ForensicAULError, ValueError):
    """Bytes that do not form the on-disk structure the parser expected."""


class UnsupportedFormat(FormatError):
    """A recognised structure in a variant this parser does not handle — an
    unknown compression algorithm, a new magic. The data may be fine; this
    version cannot read it (the signal that a newer OS changed the format)."""


class CorruptRecord(FormatError):
    """A record that is inconsistent with itself: a size or offset pointing
    outside its container, a count that cannot fit."""


class TruncatedRecord(CorruptRecord, EOFError):
    """The bytes ended before the record did. Raised by the binary reader; also an
    ``EOFError``, which is what it historically was."""


# What malformed INPUT can raise while it is parsed: the typed errors above, plus
# the shapes bad bytes take in Python code not (yet) raising them — a short read,
# a bad unpack, an index or key the data points at but that does not exist, an
# undecodable string. A parse loop catches exactly this tuple, counts a parse
# error and goes on. Anything else (AttributeError, TypeError, NameError, an
# assertion) is a bug in this tool and must reach the crash reporter instead of
# being counted as damage in the evidence (review finding S8).
PARSE_ERRORS: tuple[type[BaseException], ...] = (
    FormatError, EOFError, ValueError, IndexError, KeyError, OverflowError, struct.error,
)


class OperationCancelled(ForensicAULError):
    """A long-running operation was stopped at the operator's request.

    Raised by ``CancelToken.check()`` (see
    :mod:`forensic_aul.engine.utils.cancellation`) once cancellation has been
    requested. This is an *expected outcome*, not a failure: the caller should
    report what the partial artefact is, never a traceback.

    Three deliberate constraints, each one a trap:

    * It does **not** subclass ``ValueError``. Several GUI handlers catch
      ``ValueError`` around a core call (``gui/views/screen_exploit.py``); a
      cancellation caught there would be swallowed and reported as a bad input.
    * It does **not** subclass ``KeyboardInterrupt``. That would make it escape
      ``except Exception`` blocks that legitimately need to run their cleanup,
      and would conflate "the analyst pressed Cancel" with "the terminal sent
      SIGINT".
    * ``__init__`` takes a **message only**. The exception is raised inside
      worker processes and must survive being pickled back to the parent, which
      reconstructs it as ``OperationCancelled(*args)`` — an extra required
      argument would turn a cancellation into a confusing ``TypeError``.

    ``partial_db_path`` is therefore a plain attribute filled in by the main
    process (``run_extract``) once it knows where the ``.partial`` artefact
    lives, never a constructor argument.
    """

    # Where the interrupted run left its artefact; set in the main process, so
    # it is None on an instance that has just crossed a process boundary.
    partial_db_path: "Path | None" = None

    def __init__(self, message: str = "operation cancelled") -> None:
        super().__init__(message)
