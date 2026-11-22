"""Synthetic evidence builders shared by the test suite (no real device data).

Defines : synthetic_sysdiagnose — a minimal sysdiagnose tarball the real
          pipeline accepts (0 log entries).
Used by : tests/unit/test_cancellation.py, tests/unit/test_cli_extract.py,
          tests/unit/test_library_consumer.py.
Uses    : the standard library only, so it also works for a process that runs
          the installed wheel rather than the repository.
"""

from __future__ import annotations

import io
import tarfile
from pathlib import Path


def synthetic_sysdiagnose(directory: Path) -> Path:
    """Write ``sd.tar.gz`` into *directory* and return its path."""
    archive = directory / "sd.tar.gz"
    files = {
        "sysdiagnose_DEMO/system_logs.logarchive/timesync/0.timesync": b"",
        "sysdiagnose_DEMO/system_logs.logarchive/Info.plist": b"",
    }
    with tarfile.open(archive, "w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return archive
