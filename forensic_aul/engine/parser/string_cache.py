"""Lazy cache of a logarchive's format-string tables (UUIDText + DSC).

``StringCacheProvider`` discovers and parses every UUIDText and DSC file under a
logarchive root, then answers the three lookups
(:meth:`get_uuidtext`, :meth:`get_dsc`, :meth:`get_file_id`) that
:func:`forensic_aul.engine.parser.format_string.resolve_format_string` needs.

It also bridges to the database: the main process calls
:meth:`register_source_files` to record each file in ``source_files`` and build
the uuid→file-id map, while worker processes only :meth:`load_content` and adopt
that map via :meth:`set_uuid_file_ids` — so a worker never needs a DB connection.
"""

from __future__ import annotations

import logging
from pathlib import Path

from forensic_aul.engine.database.writer import BatchWriter, register_source_file
from forensic_aul.engine.models import SharedCacheStrings, UUIDText
from forensic_aul.engine.parser.dsc import parse_dsc
from forensic_aul.engine.parser.uuidtext import parse_uuidtext
from forensic_aul.engine.utils.files import is_appledouble

log = logging.getLogger(__name__)


class StringCacheProvider:
    """Lazy-loading cache for UUIDText and DSC files.

    After `load()` the caches are read-only, safe for concurrent reads
    from multiple workers (no mutation during lookups).

    The provider also tracks which source_files.id corresponds to each UUID,
    so the extract pipeline can populate `format_src_file_id` per log entry.
    """

    def __init__(self, logarchive: Path) -> None:
        self._root = logarchive
        self._uuidtext: dict[str, UUIDText] = {}   # uuid (no dashes, upper) → UUIDText
        self._dsc: dict[str, SharedCacheStrings] = {}  # dsc_uuid → SharedCacheStrings
        # uuid (no dashes, upper) → source_files.id
        self._uuid_to_file_id: dict[str, int] = {}
        # uuid (upper) → source path, recorded by load_content() so the main
        # process can register source files (workers skip this — they receive
        # the uuid→file_id map instead). Kept separate per kind to preserve the
        # historical "all uuidtext, then all dsc" registration order.
        self._uuidtext_paths: dict[str, Path] = {}
        self._dsc_paths: dict[str, Path] = {}

    def load_content(self) -> None:
        """Parse all UUIDText and DSC files into the in-memory cache (no DB).

        Populates the format-string caches and records each file's path. Used by
        both the main process (which then calls :meth:`register_source_files`)
        and by worker processes (which instead receive the file-id map via
        :meth:`set_uuid_file_ids`), so a worker never needs a DB connection.
        """
        # UUIDText: stored as <2-char-dir>/<30-char-file> (no extension)
        for p in self._root.rglob("*"):
            if p.is_file() and len(p.parent.name) == 2 and len(p.stem) == 30 and not p.suffix:
                obj = parse_uuidtext(p)
                if obj:
                    key = obj.uuid.upper()
                    self._uuidtext[key] = obj
                    self._uuidtext_paths[key] = p

        # DSC: stored as *.dsc or inside a dsc/ directory (no extension).
        # Skip AppleDouble ``._*`` sidecars (e.g. ``._foo.dsc``) — not real DSCs.
        seen_dsc: set[str] = set()
        for p in list(self._root.rglob("*.dsc")) + _list_dsc_dir(self._root):
            if is_appledouble(p):
                continue
            obj = parse_dsc(p)
            if obj:
                key = obj.dsc_uuid.upper()
                if key not in seen_dsc:
                    self._dsc[key] = obj
                    self._dsc_paths[key] = p
                    seen_dsc.add(key)

    def register_source_files(
        self,
        writer: BatchWriter,
        logarchive_root: Path,
        file_hashes: dict[str, str],
    ) -> None:
        """Main process only: register every cached file and build the id map.

        Registration order (all UUIDText, then all DSC) matches the historical
        single-pass loader. Workers must NOT call this — they have no writer.
        """
        for key, p in self._uuidtext_paths.items():
            self._uuid_to_file_id[key] = register_source_file(
                writer, logarchive_root, p, "uuidtext", file_hashes
            )
        for key, p in self._dsc_paths.items():
            self._uuid_to_file_id[key] = register_source_file(
                writer, logarchive_root, p, "dsc", file_hashes
            )
        log.info(f"String cache loaded : {len(self._uuidtext_paths)} UUIDText  {len(self._dsc_paths)} DSC  ({len(self._uuidtext_paths) + len(self._dsc_paths)} total source_files registered)")

    def load(
        self,
        writer: BatchWriter,
        logarchive_root: Path,
        file_hashes: dict[str, str],
    ) -> None:
        """Main-process convenience: parse content then register source files."""
        self.load_content()
        self.register_source_files(writer, logarchive_root, file_hashes)

    def uuid_file_ids(self) -> dict[str, int]:
        """Return the uuid→source_files.id map (to hand to worker processes)."""
        return self._uuid_to_file_id

    def set_uuid_file_ids(self, mapping: dict[str, int]) -> None:
        """Worker-side: adopt the main process's uuid→file_id map after load_content()."""
        self._uuid_to_file_id = dict(mapping)

    def get_uuidtext(self, uuid: str) -> UUIDText | None:
        return self._uuidtext.get(uuid.upper().replace("-", ""))

    def get_dsc(self, uuid: str) -> SharedCacheStrings | None:
        return self._dsc.get(uuid.upper().replace("-", ""))

    def get_file_id(self, uuid: str) -> int | None:
        """Return the source_files.id for a UUIDText or DSC file by its UUID."""
        return self._uuid_to_file_id.get(uuid.upper().replace("-", ""))


def _list_dsc_dir(logarchive: Path) -> list[Path]:
    """Return files in the dsc/ subdirectory (DSC files without extension)."""
    dsc_dir = logarchive / "dsc"
    if dsc_dir.is_dir():
        return [p for p in dsc_dir.iterdir() if p.is_file()]
    return []
