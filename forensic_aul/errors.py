"""Common exception hierarchy for the library.

Defines : ``ForensicAULError`` — the base class every library-specific error
          derives from — and the shared concrete errors ``SourceError`` (input
          detection / preparation) and ``InvalidDatabaseError`` (a path that is
          not an analysis database). Operation-specific errors defined elsewhere
          (``AcquisitionError``, ``KnowledgeBaseError``) also derive from the
          base, so a consumer can catch everything the library raises with one
          ``except ForensicAULError``.
Used by : forensic_aul.ops.* (raise sites), forensic_aul/__init__.py (re-export),
          and external consumers (catch sites).
Uses    : the standard library only.

Backward compatibility: each concrete error ALSO subclasses the builtin type the
code historically raised (``ValueError`` here; ``AcquisitionError`` keeps its
place under ``Exception``). Existing ``except ValueError`` call sites therefore
keep working — the hierarchy only ADDS a catchable common base, it never changes
what an existing handler receives.
"""

from __future__ import annotations


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
