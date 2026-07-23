#!/usr/bin/env python3
"""forensic-aul — clone-&-run entry point.

Usage:
    python faul.py                  # launch the GUI
    python faul.py <command> ...    # run a CLI subcommand (extract, acquire, ...)

Defines : the root launcher; delegates to launcher.cli.main(), which routes to a
          CLI subcommand or, with no arguments, boots the GUI.
Used by : the user / clone-&-run workflow (the app's front door).
Uses    : launcher.cli (CLI dispatch + GUI hand-off). Core logic lives in the
          importable, pip-installable `forensic_aul` package; `launcher/` and
          `gui/` are the application layer beside it.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Put the repo root (this file's directory) on sys.path so `launcher`, `gui`
# and `forensic_aul` resolve regardless of the caller's working directory.
# WHY: without this, `python /abs/path/faul.py` from elsewhere cannot import the
# sibling app packages.
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from launcher.cli import main  # noqa: E402

if __name__ == "__main__":
    main()
