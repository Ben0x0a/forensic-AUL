"""Build a `log show`-readable ``.logarchive`` from a non-logarchive acquisition.

Defines : ``build_logarchive(prepared_root, out_dir) -> Path`` and the
          ``Info.plist`` synthesis it needs (``build_info_plist``).
Used by : forensic_aul.validation.pipeline — so a sysdiagnose / FFS zip can be
          validated against Apple's own ``log show``, not just against our parser.
Uses    : forensic_aul.engine.parser (tracev3 header chunk) and the standard
          library. macOS-only in effect, though the build itself is portable.

WHY this exists
---------------
Validation compares our output against Apple's ``log show``. That only works when
``log show`` will *read* the evidence — and it refuses anything without a valid
``Info.plist``, which a sysdiagnose or a full-filesystem zip has no reason to
carry: the phone stores the log data, not the archive wrapper a Mac later wraps
around it. So the highest-value acquisitions were exactly the ones that could not
be checked against ground truth.

The log DATA in a zip is byte-identical to what a logarchive holds (the extraction
sources already normalise it into a logarchive-shaped directory). Only the wrapper
is missing, and the wrapper is derivable from the data itself — every value
``log show`` needs is in the tracev3 header chunks.

What ``log show`` requires (reference:
https://digital-forensics.polewczyk.fr/apple/unified-logs/info-plist/):

  OSArchiveVersion    int   5 for macOS 12–26 / iOS 15–26
  EndTimeRef          dict  the most recent event's time reference
  LiveMetadata        dict  {ContinuousTime, UUID} for logdata.LiveData.tracev3
  PersistMetadata     dict  {ContinuousTime, UUID} for Persist/
  SpecialMetadata     dict  {ContinuousTime, UUID} for Special/

``ContinuousTime`` is the mach continuous time in the header chunk of the relevant
tracev3; ``UUID`` is that header's boot UUID. Both are read through the existing
header parser rather than at the raw offsets the article quotes — the parser
already validates the chunk tags, so a layout change surfaces as a warning instead
of silently yielding a plausible-looking wrong integer.

FORENSIC NOTE: the built bundle is a DERIVED artefact for validation only. The
evidence files are copied verbatim and never modified; the only thing added is the
Info.plist wrapper. It is written to a temp/working directory, never beside the
evidence.
"""

from __future__ import annotations

import logging
import plistlib
import shutil
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

# The archive-format version `log show` expects. 5 covers macOS 12.x–26.x and
# iOS 15.x–26.x; older archives used 4, which current `log` still reads but which
# we never need to emit (we only ever build from a modern acquisition).
OS_ARCHIVE_VERSION = 5

# Where each metadata key takes its ContinuousTime/UUID from, relative to the
# archive root. A missing directory simply yields no entry — an acquisition need
# not contain every log stream.
_METADATA_SOURCES = {
    "PersistMetadata": "Persist",
    "SpecialMetadata": "Special",
    "SignpostMetadata": "Signpost",
}
_LIVE_DATA_NAME = "logdata.LiveData.tracev3"


@dataclass(frozen=True)
class _HeaderFacts:
    """The two values Info.plist needs from one tracev3 header chunk."""

    continuous_time: int
    boot_uuid: str


def read_header_facts(tracev3: Path) -> _HeaderFacts | None:
    """Continuous time + boot UUID from a tracev3's header chunk, or None.

    Guarded: a truncated or unexpected file yields None so the caller can fall
    back to another file rather than aborting the whole build.
    """
    try:
        from forensic_aul.engine.parser.header import parse_header_chunk
        from forensic_aul.engine.parser.reader import BinaryReader

        # The header chunk is the first chunk in the file, so the reader stops after
        # a few hundred bytes — a multi-GB tracev3 costs the same as a small one.
        with tracev3.open("rb") as fh:
            header = parse_header_chunk(BinaryReader(fh))
        return _HeaderFacts(header.continuous_time, header.boot_uuid)
    except Exception as exc:  # noqa: BLE001 - one unreadable file must not sink the build.
        log.debug("logarchive_build: no header facts from %s (%s)", tracev3.name, exc)
        return None


def _newest_tracev3(directory: Path) -> Path | None:
    """The most recent tracev3 in *directory* — the one whose header carries the
    latest continuous time, which is what the metadata keys are meant to describe.
    Chosen by name, since the AUL numbers these files in rotation order and mtime
    is not preserved through a zip acquisition."""
    files = sorted(p for p in directory.glob("*.tracev3") if p.is_file())
    return files[-1] if files else None


def _facts_for(root: Path, subdir: str) -> _HeaderFacts | None:
    directory = root / subdir
    if not directory.is_dir():
        return None
    newest = _newest_tracev3(directory)
    return read_header_facts(newest) if newest else None


def build_info_plist(root: Path) -> dict:
    """Synthesise the ``Info.plist`` payload for the logarchive laid out at *root*.

    Raises:
        ValueError: no tracev3 header could be read at all — without a boot UUID
            and a continuous time the plist would be a fiction, and ``log show``
            would either refuse it or (worse) accept it and report nonsense times.
    """
    facts = {key: _facts_for(root, sub) for key, sub in _METADATA_SOURCES.items()}
    live = read_header_facts(root / _LIVE_DATA_NAME) if (root / _LIVE_DATA_NAME).is_file() else None
    if live is not None:
        facts["LiveMetadata"] = live

    present = {key: value for key, value in facts.items() if value is not None}
    if not present:
        raise ValueError(
            f"no readable tracev3 header under {root} — cannot synthesise Info.plist"
        )

    # The newest continuous time across every stream is the archive's end-time
    # reference: it is the point `log show` treats as "now" for the capture.
    newest = max(present.values(), key=lambda f: f.continuous_time)

    info: dict = {
        "OSArchiveVersion": OS_ARCHIVE_VERSION,
        "EndTimeRef": {
            "ContinuousTime": newest.continuous_time,
            "UUID": newest.boot_uuid,
        },
        # Provenance: this wrapper was DERIVED, not acquired. An analyst opening the
        # bundle later must be able to tell it apart from a real `log collect`.
        "ArchiveIdentifier": "forensic-aul synthesised (validation only)",
    }
    for key, value in present.items():
        info[key] = {"ContinuousTime": value.continuous_time, "UUID": value.boot_uuid}
    return info


def build_logarchive(prepared_root: Path, out_dir: Path, *, name: str = "synthesised") -> Path:
    """Assemble ``out_dir/<name>.logarchive`` from an already-normalised source.

    *prepared_root* is a ``PreparedSource.logarchive_root`` — the extraction layer
    has already unpacked the acquisition into the logarchive shape (Persist/,
    Special/, timesync/, dsc/, the two-hex uuidtext dirs). This adds the one thing
    it cannot know how to write: the Info.plist wrapper.

    The evidence is COPIED, never moved or modified. Returns the bundle path.
    """
    prepared_root = Path(prepared_root)
    bundle = Path(out_dir) / f"{name}.logarchive"
    if bundle.exists():
        shutil.rmtree(bundle)

    # copytree rather than a symlink farm: `log show` resolves the bundle itself and
    # a link into a temp dir that later disappears would leave an archive that looks
    # valid and reads empty.
    shutil.copytree(prepared_root, bundle, symlinks=False)

    info = build_info_plist(bundle)
    (bundle / "Info.plist").write_bytes(plistlib.dumps(info, fmt=plistlib.FMT_XML))
    log.info(
        f"Built a validation logarchive at {bundle} "
        f"(OSArchiveVersion {OS_ARCHIVE_VERSION}, "
        f"{len([k for k in info if k.endswith('Metadata')])} log streams)"
    )
    return bundle
