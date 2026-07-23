"""Wrapper around Apple's ``log show --style ndjson``.

Used by the ``test`` subcommand to materialise a reference ndjson from a
logarchive directly. Apple's tool understands the format better than any
third-party parser, so it serves as the ground-truth oracle for our
extractor.

Output coverage
---------------
Default flags include ``--info`` and ``--debug`` because our parser emits
log entries at every level. Without those flags ``log show`` only prints
Default/Error/Fault, which inflates our "Extra (DB → ref)" counter for
no real reason. ``--signpost`` is included for parity even though recent
macOS versions emit signposts by default.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path

from forensic_aul.testing.platform import require_macos_log_tools

log = logging.getLogger(__name__)

DEFAULT_FLAGS: tuple[str, ...] = ("--info", "--debug", "--signpost")
"""Flags that align ``log show`` coverage with our extractor.

Use :data:`DEFAULT_FLAGS` as the ``flags`` argument to :func:`run` to keep
the ndjson and the DB at the same level of detail.
"""


def run(
    logarchive: Path,
    output_path: Path,
    *,
    flags: tuple[str, ...] = DEFAULT_FLAGS,
    timeout: int | None = None,
) -> Path:
    """Invoke ``log show --style ndjson`` against *logarchive*.

    The output (potentially very large — gigabytes) is streamed line by
    line to *output_path*; the binary's stdout is never buffered in
    Python memory.

    Returns *output_path* on success.
    Raises :class:`RuntimeError` if the binary is missing or exits non-zero.
    """
    require_macos_log_tools()
    if not logarchive.is_dir():
        raise FileNotFoundError(f"logarchive directory does not exist: {logarchive}")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        "/usr/bin/log",
        "show",
        "--style", "ndjson",
        *flags,
        str(logarchive),
    ]
    log.info(f'Running: {" ".join(cmd)}')
    log.info(f"  → output: {output_path}")

    # Stream stdout straight to disk via the OS — no Python buffering.
    with output_path.open("wb") as fh:
        try:
            completed = subprocess.run(  # noqa: S603 — fixed argv, no shell
                cmd,
                stdout=fh,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            raise RuntimeError(
                "Could not invoke /usr/bin/log — is this really macOS?"
            ) from exc

    if completed.returncode != 0:
        # Don't let a half-written ndjson linger on disk.
        try:
            output_path.unlink()
        except OSError:
            pass
        stderr = (completed.stderr or b"").decode("utf-8", errors="replace").strip()
        raise RuntimeError(
            f"`log show` exited with status {completed.returncode}: {stderr or '(no stderr)'}"
        )

    size_mb = output_path.stat().st_size / (1024 * 1024)
    log.info(f"`log show` produced {size_mb:.1f} MB of ndjson")
    return output_path


def _which_log() -> str | None:
    """Return the path to the ``log`` binary, or None if unavailable."""
    return shutil.which("log")
