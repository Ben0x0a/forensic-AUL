"""File-level acquisition-fidelity check (L2): pymobiledevice3 vs Apple ``log collect``.

Defines : ``compare_archives(a, b) -> ArchiveComparison`` and ``render_archive_report``.
Used by : forensic_aul.validation.pipeline (the ``validate --acquisition`` mode).
Uses    : forensic_aul.engine.integrity (per-file SHA-256) — nothing else; this
          check is **parser-free**, so it validates the *acquisition* without
          depending on ``run_extract`` being correct.

Both acquisition methods copy the same on-device log-data files verbatim
(``*.tracev3``, ``*.timesync``, ``dsc/*``, ``uuidtext/**``); only the archive
wrapper (e.g. ``Info.plist``) differs. So the two archives are compared file by
file.

The comparison is **order-significant**: *A* is the archive collected FIRST and
*B* the one collected SECOND, so the direction of a size change is itself
evidence and each direction gets its own verdict:

  same sha256              → identical (sealed/rotated files, the bulk)
  B = A + extra bytes      → append (the live tail grew between the two
                             collections on a running device) — expected
  A = B + extra bytes      → shrunk (B holds only a prefix of A: the store
                             dropped the tail between the collections, e.g. an
                             old-record purge on the live file) — legitimate on a
                             running device, but reported on its own so it is
                             never read as growth
  neither is a prefix      → diverged (a file was rewritten) — a real
                             acquisition discrepancy
  in only one archive      → only_a / only_b (rotation: a new current file is
                             expected; a vanished file is flagged)

Pass = no ``diverged`` files. Like rotation (``only_a``/``only_b``), a purge
(``shrunk``) is normal live-store behaviour, so it is surfaced for review rather
than failed. Everything is streamed/hashed on disk, so a multi-GB archive costs
flat memory.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from forensic_aul.config import HASH_CHUNK_SIZE
from forensic_aul.engine.integrity import hash_logarchive

log = logging.getLogger(__name__)

# On-device log-data files both acquisitions must copy identically (append aside).
# Everything else in the bundle is acquisition-tool wrapper/metadata.
_LOG_DATA_SUFFIXES = (".tracev3", ".timesync")
_LOG_DATA_DIRS = ("dsc/", "uuidtext/")

# Inside a .logarchive the uuidtext files are NOT under a ``uuidtext/`` prefix: the
# two-hex-char directories of ``private/var/db/uuidtext/`` are mirrored straight into
# the archive root (see ops/extraction/sources/loose_dirs.py), so they read as
# ``0A/1B2C3D…``. They carry every format string, so they must be compared, not
# dismissed as wrapper metadata.
_UUIDTEXT_ENTRY = re.compile(r"^[0-9A-Fa-f]{2}/[0-9A-Fa-f]+$")

# Verdicts. APPEND and SHRUNK are the two DIRECTIONS of the same prefix relation
# (see the module docstring): which archive holds the extra bytes is what tells a
# grown live tail apart from a purged one, so they must never share a label.
IDENTICAL = "identical"
APPEND = "append"
SHRUNK = "shrunk"
DIVERGED = "diverged"
ONLY_A = "only_a"
ONLY_B = "only_b"


def _is_log_data(rel: str) -> bool:
    return (
        rel.endswith(_LOG_DATA_SUFFIXES)
        or rel.startswith(_LOG_DATA_DIRS)
        or _UUIDTEXT_ENTRY.match(rel) is not None
    )


@dataclass
class FileVerdict:
    rel_path: str
    status: str
    size_a: int | None = None
    size_b: int | None = None


@dataclass
class ArchiveComparison:
    label_a: str
    label_b: str
    verdicts: list[FileVerdict] = field(default_factory=list)
    meta_files_a: int = 0   # non-log-data (wrapper) files, informational
    meta_files_b: int = 0

    def _count(self, status: str) -> int:
        return sum(1 for v in self.verdicts if v.status == status)

    @property
    def identical(self) -> int:
        return self._count(IDENTICAL)

    @property
    def append(self) -> int:
        return self._count(APPEND)

    @property
    def shrunk(self) -> list[FileVerdict]:
        return [v for v in self.verdicts if v.status == SHRUNK]

    @property
    def diverged(self) -> list[FileVerdict]:
        return [v for v in self.verdicts if v.status == DIVERGED]

    @property
    def only_a(self) -> list[FileVerdict]:
        return [v for v in self.verdicts if v.status == ONLY_A]

    @property
    def only_b(self) -> list[FileVerdict]:
        return [v for v in self.verdicts if v.status == ONLY_B]

    @property
    def passed(self) -> bool:
        """The acquisitions agree when no shared file was rewritten — i.e. every
        shared file is identical, or one is a byte-prefix of the other in either
        direction. A purge (shrunk) and a rotation (only_a/only_b) are normal
        live-store behaviour: both are listed in the report for review, neither
        fails the check. Only ``diverged`` — bytes that changed in place — is a
        real acquisition discrepancy."""
        return not self.diverged


def _safe_size(path: Path) -> int | None:
    try:
        return path.stat().st_size
    except OSError:
        return None


def _prefix_verdict(a: Path, b: Path) -> str | None:
    """Classify a differing pair by the DIRECTION of the prefix relation.

    ``APPEND`` when *b* is *a* plus extra bytes (the second collection saw more),
    ``SHRUNK`` when *a* is *b* plus extra bytes (the second collection saw less),
    and ``None`` when neither is a byte-prefix of the other — bytes changed in
    place, which is a rewrite, not a size change. Streamed in chunks (flat memory).

    WHY the direction matters: the caller passes the archives in acquisition
    order, so "which side is longer" is the difference between a live tail that
    grew and one that was purged away. Reporting both as "append" told the
    operator a file had GROWN when it had in fact lost its tail.
    """
    sa, sb = _safe_size(a), _safe_size(b)
    if sa is None or sb is None:
        return None
    b_is_longer = sa <= sb
    short, long = (a, b) if b_is_longer else (b, a)
    remaining = min(sa, sb)
    with short.open("rb") as fs, long.open("rb") as fl:
        while remaining > 0:
            want = min(HASH_CHUNK_SIZE, remaining)
            cs, cl = fs.read(want), fl.read(want)
            if cs != cl:
                return None
            if not cs:  # unexpected short read — treat as non-prefix
                return None
            remaining -= len(cs)
    # Equal sizes cannot reach here with equal content (the caller only calls this
    # for files whose SHA-256 differ), so b_is_longer means b genuinely grew.
    return APPEND if b_is_longer else SHRUNK


def compare_archives(
    archive_a: Path | str,
    archive_b: Path | str,
    *,
    label_a: str = "A",
    label_b: str = "B",
) -> ArchiveComparison:
    """Compare two logarchives at the file level (see the module docstring).

    Argument order is significant: *archive_a* must be the acquisition collected
    FIRST and *archive_b* the one collected SECOND, since the append/shrunk
    verdicts are read in that direction.
    """
    root_a, root_b = Path(archive_a), Path(archive_b)
    _, hashes_a = hash_logarchive(root_a)
    _, hashes_b = hash_logarchive(root_b)

    data_a = {p: h for p, h in hashes_a.items() if _is_log_data(p)}
    data_b = {p: h for p, h in hashes_b.items() if _is_log_data(p)}

    result = ArchiveComparison(
        label_a=label_a, label_b=label_b,
        meta_files_a=len(hashes_a) - len(data_a),
        meta_files_b=len(hashes_b) - len(data_b),
    )

    for rel in sorted(set(data_a) | set(data_b)):
        in_a, in_b = rel in data_a, rel in data_b
        pa, pb = root_a / rel, root_b / rel
        if in_a and in_b:
            if data_a[rel] == data_b[rel]:
                status = IDENTICAL
            else:
                status = _prefix_verdict(pa, pb) or DIVERGED
        else:
            status = ONLY_A if in_a else ONLY_B
        result.verdicts.append(FileVerdict(
            rel_path=rel, status=status,
            size_a=_safe_size(pa) if in_a else None,
            size_b=_safe_size(pb) if in_b else None,
        ))
    return result


def render_archive_report(cmp: ArchiveComparison) -> str:
    """Human-readable summary of an :class:`ArchiveComparison`."""
    lines: list[str] = []
    lines.append("═" * 72)
    lines.append("  forensic-aul — Acquisition comparison (file-level, parser-free)")
    lines.append("═" * 72)
    lines.append(f"  {cmp.label_a}  vs  {cmp.label_b}")
    lines.append("")
    lines.append(f"  identical      : {cmp.identical}")
    lines.append(f"  append-only    : {cmp.append}   (live tail grew between collections)")
    lines.append(f"  shrunk         : {len(cmp.shrunk)}   (tail lost — e.g. purged; review)")
    lines.append(f"  diverged       : {len(cmp.diverged)}   (rewritten — a real discrepancy)")
    lines.append(f"  only in {cmp.label_a:<6} : {len(cmp.only_a)}   (vanished — review)")
    lines.append(f"  only in {cmp.label_b:<6} : {len(cmp.only_b)}   (new/rotated — expected)")
    lines.append(f"  wrapper files  : {cmp.meta_files_a} / {cmp.meta_files_b}  (metadata, ignored)")
    lines.append("")
    for label, verdicts in (("DIVERGED", cmp.diverged), ("SHRUNK", cmp.shrunk),
                            (f"ONLY IN {cmp.label_a}", cmp.only_a)):
        if verdicts:
            lines.append(f"  {label}:")
            for v in verdicts[:20]:
                lines.append(f"    {v.rel_path}  (a={v.size_a} b={v.size_b})")
            lines.append("")
    lines.append(f"  RESULT: {'PASS' if cmp.passed else 'FAIL'} — "
                 f"{'no file was rewritten between the two acquisitions' if cmp.passed else f'{len(cmp.diverged)} file(s) diverged'}")
    lines.append("═" * 72)
    return "\n".join(lines)
