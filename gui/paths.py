"""Filesystem locations the GUI needs, resolved once.

Defines : DEFAULT_KB_DIR — the knowledge base that ships with the repository.
Used by : gui.controllers.identify (loads it before an identify run),
          gui.views.screen_exploit (the Annotate button's default KB).
Uses    : pathlib only — deliberately import-light so any screen can use it.

WHY a module rather than a constant repeated per screen: two screens already
needed "the shipped knowledge base", and a second copy of the ``parents[2]``
walk is a silent trap — the correct number of parents depends on where the file
sits, so a copy that is moved is wrong in a way nothing catches.
"""

from __future__ import annotations

from pathlib import Path

# <repo>/gui/paths.py → parents[1] is the repository root, which holds
# knowledge_base/. The GUI is clone-and-run (it is excluded from packaging), so
# this layout is the one it always sees.
DEFAULT_KB_DIR = Path(__file__).resolve().parents[1] / "knowledge_base"
