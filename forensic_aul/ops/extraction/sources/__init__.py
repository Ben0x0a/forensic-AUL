"""Input-source preparation for the extract pipeline (pluggable registry).

Normalises any supported evidence container into a directory laid out as a
``.logarchive`` (the layout the parser already understands) and records the
integrity hashes kept for chain of custody. Each container type is a
self-contained handler module in this package; this ``__init__`` holds the
registry and the two dispatch entry points:

  - :func:`detect_source_type` — classify a path (content-first, never by
    extension) by asking each registered :class:`SourceHandler` in priority order.
  - :func:`prepare_source` — normalise a path *or* the loose-dirs mapping into a
    :class:`PreparedSource`.

Registered handlers (probed in ``priority`` order — most specific first):

  =============  =========================================================
  LOGARCHIVE     a ``.logarchive`` directory (used in place, no copy)
  SYSDIAGNOSE    a ``.tar.gz`` with ``system_logs.logarchive/``
  FAUL           a ``.faul`` portable container (a zip carrying a marker)
  FILESYSTEM     a full-file-system ``.zip``
  =============  =========================================================

FAUL is probed before FILESYSTEM because both share the zip magic — the ``.faul``
handler inspects the archive's content (a ``faul/manifest.json`` marker) to tell
them apart. LOOSE_DIRS is given explicitly as a mapping and never auto-detected.

**Adding a source:** drop a module in this package exposing a ``HANDLER =
SourceHandler(...)`` (a ``matches(path)`` predicate + a ``prepare(...)`` returning
a :class:`PreparedSource`) and add it to :data:`_HANDLERS`. Everything else —
detection, preparation, and the "unrecognised source" error — follows.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from pathlib import Path

from forensic_aul.engine.utils.cancellation import NEVER_CANCELLED, CancelToken
from forensic_aul.errors import SourceError
from forensic_aul.ops.extraction.sources import (
    faul,
    filesystem,
    logarchive,
    loose_dirs,
    sysdiagnose,
)
from forensic_aul.ops.extraction.sources.base import (
    INTEGRITY_MODES,
    LOOSE_DIAGNOSTICS_KEY,
    LOOSE_UUIDTEXT_KEY,
    TEMP_DIR_PLACEHOLDER,
    ExtractOutcome,
    PreparedSource,
    SourceHandler,
    SourceType,
    check_integrity_mode,
)
from forensic_aul.ops.extraction.sources.loose_dirs import (
    find_loose_dirs,
    prepare_loose_dirs,
)

log = logging.getLogger(__name__)

# Detection registry, ordered by handler priority (lower = probed first). To add
# a source, append its module's HANDLER here (see the module docstring).
_HANDLERS: tuple[SourceHandler, ...] = tuple(
    sorted(
        (
            logarchive.HANDLER,
            sysdiagnose.HANDLER,
            faul.HANDLER,
            filesystem.HANDLER,
        ),
        key=lambda h: h.priority,
    )
)

__all__ = [
    "INTEGRITY_MODES",
    "LOOSE_DIAGNOSTICS_KEY",
    "LOOSE_UUIDTEXT_KEY",
    "TEMP_DIR_PLACEHOLDER",
    "ExtractOutcome",
    "PreparedSource",
    "SourceHandler",
    "SourceType",
    "detect_source_type",
    "find_loose_dirs",
    "prepare_loose_dirs",
    "prepare_source",
]


# ── Detection ─────────────────────────────────────────────────────────────────

def _handler_for(path: Path) -> SourceHandler:
    """Return the first registered handler whose ``matches`` accepts *path*.

    Raises:
        SourceError: the path does not exist or no handler recognises it.
    """
    if not path.exists():
        raise SourceError(f"Source does not exist: {path}")
    for handler in _HANDLERS:
        if handler.matches(path):
            return handler
    expected = ", ".join(h.describe for h in _HANDLERS)
    raise SourceError(f"Unrecognised source: {path} — expected {expected}.")


def detect_source_type(path: Path) -> SourceType:
    """Classify *path* as one of the supported single-path sources.

    Header-first / content-first — the file extension is never trusted on its own.

    Raises:
        SourceError: the path does not exist or is an unrecognised container.
    """
    return _handler_for(Path(path)).source_type


# ── Public entry point ──────────────────────────────────────────────────────────

def prepare_source(
    source: Path | str | Mapping[str, Path | str],
    *,
    work_dir: Path | None = None,
    integrity: str = "full",
    reset_work_dir: bool = False,
    cancel: CancelToken = NEVER_CANCELLED,
) -> PreparedSource:
    """Normalise *source* into a logarchive-laid-out directory ready for parsing.

    *source* is either a single path (auto-detected — a logarchive directory, a
    sysdiagnose tarball, a ``.faul`` container, or an FFS zip) or a mapping of two
    already-uncompressed folders ``{"diagnostics": dir, "uuidtext": dir}`` (see
    :data:`LOOSE_DIAGNOSTICS_KEY` / :data:`LOOSE_UUIDTEXT_KEY`), which is routed to
    :func:`prepare_loose_dirs`.

    For a logarchive directory the directory is used in place (no copy). Archive
    containers are extracted into *work_dir* (kept) or an auto-cleaned temp dir,
    and a quick tamper-evident fingerprint of the archive is captured before
    extraction.

    *integrity* selects how much hashing is done (see :data:`INTEGRITY_MODES`):
    ``"full"`` (default) hashes every file for chain of custody; ``"fingerprint"``
    keeps only the cheap archive fingerprint; ``"off"`` takes no attestation.

    A kept *work_dir* must not already hold a work root for this source: reusing
    one would fold the previous run's files into this acquisition. Set
    *reset_work_dir* to delete it first (see ``claim_work_root``).

    *cancel* makes preparation interruptible: it is checked per archive member
    while extracting and per file while hashing. A cancellation cleans up any
    temp work root before propagating, so nothing is left behind.

    Raises:
        SourceError: the source is unrecognised, lacks the expected content, is a
            mapping missing the required keys, *integrity* is not a valid mode, or
            the work root already exists with content and *reset_work_dir* is false.
        OperationCancelled: *cancel* was cancelled during preparation.
    """
    check_integrity_mode(integrity)
    if isinstance(source, Mapping):
        try:
            diagnostics = source[LOOSE_DIAGNOSTICS_KEY]
            uuidtext = source[LOOSE_UUIDTEXT_KEY]
        except KeyError as exc:
            raise SourceError(
                f"Loose-dirs source mapping needs keys {LOOSE_DIAGNOSTICS_KEY!r} "
                f"and {LOOSE_UUIDTEXT_KEY!r}; got {sorted(source)}"
            ) from exc
        return prepare_loose_dirs(
            Path(diagnostics), Path(uuidtext),
            work_dir=work_dir, integrity=integrity, reset_work_dir=reset_work_dir,
            cancel=cancel,
        )

    path = Path(source)
    handler = _handler_for(path)
    return handler.prepare(
        path, work_dir=work_dir, integrity=integrity, reset_work_dir=reset_work_dir,
        cancel=cancel,
    )
