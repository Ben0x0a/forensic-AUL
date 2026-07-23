"""Wrapper around Apple's ``log collect --device-udid``.

Acquires a fresh ``.logarchive`` directly from a connected iOS device on
macOS. The pymobiledevice3-based path stays in :mod:`forensic_aul.ops.acquisition`
for the ``acquire`` subcommand; this wrapper exists so the ``test``
subcommand can run the *full* native pipeline (collect → show → diff)
without depending on third-party Python code at acquisition time.

Note
----
``log collect`` requires that the host has paired with the device
(Apple Mobile Device Service handles trust). If the user has never
clicked "Trust this computer" on the phone, the command fails with a
non-zero exit code; we surface the stderr verbatim so the user can act.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from forensic_aul.testing.platform import require_macos_log_tools

log = logging.getLogger(__name__)


def run(
    udid: str,
    output_dir: Path,
    *,
    timeout: int | None = None,
) -> Path:
    """Run ``log collect --device-udid <udid> --output <output_dir>``.

    Returns the path to the produced ``.logarchive`` directory.

    *output_dir* must exist and be writable. The resulting archive is
    placed inside *output_dir* (Apple decides the file name, typically
    ``system_logs.logarchive``).
    """
    require_macos_log_tools()

    if not udid:
        raise ValueError("udid must be a non-empty string")
    if not output_dir.is_dir():
        raise FileNotFoundError(f"output directory does not exist: {output_dir}")

    cmd = [
        "/usr/bin/log",
        "collect",
        "--device-udid", udid,
        "--output", str(output_dir),
    ]
    log.info(f'Running: {" ".join(cmd)}')

    try:
        completed = subprocess.run(  # noqa: S603 — fixed argv, no shell
            cmd,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "Could not invoke /usr/bin/log — is this really macOS?"
        ) from exc

    if completed.returncode != 0:
        stderr = (completed.stderr or b"").decode("utf-8", errors="replace").strip()
        raise RuntimeError(
            f"`log collect` exited with status {completed.returncode}: "
            f"{stderr or '(no stderr — is the device trusted?)'}"
        )

    archives = sorted(output_dir.glob("*.logarchive"))
    if not archives:
        raise RuntimeError(
            f"`log collect` succeeded but produced no .logarchive in {output_dir}"
        )
    if len(archives) > 1:
        # Shouldn't happen with a fresh tempdir, but be defensive.
        log.warning(f"log collect produced {len(archives)} archives in {output_dir} — using the first: {archives[0]}")
    log.info(f"log collect produced: {archives[0]}")
    return archives[0]
