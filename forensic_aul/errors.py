"""Common exception hierarchy for the library.

Defines : ``ForensicAULError`` — the base class every library-specific error
          derives from — and the shared concrete errors ``SourceError`` (input
          detection / preparation), ``InvalidDatabaseError`` (a path that is not
          an analysis database), ``IncompleteDatabaseError`` (one produced by a
          run that never finished) and ``OperationCancelled`` (the operator
          stopped a long operation). Operation-specific errors defined elsewhere
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

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Type-only: errors.py is imported by everything (including the cancellation
    # primitive), so it must stay dependency-free at runtime.
    from pathlib import Path


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
