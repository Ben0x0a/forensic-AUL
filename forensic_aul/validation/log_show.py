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
macOS versions emit signposts by default. ``--loss`` because log show hides the
firehose loss records ("N messages dropped") by default, while we store them.

The full archive, not the declared window
-----------------------------------------
``log show`` only prints entries inside the window the archive's ``Info.plist``
declares (each log class's ``OldestTimeRef`` up to ``EndTimeRef``); entries
outside it are in the files and decode fine, but are hidden — and ``--start`` /
``--end`` cannot widen it. Our extractor keeps them (they are evidence), so a
reference of the declared window counted them as "extra" (+36% on an iOS 27
capture). ``full_window_view`` therefore builds a hard-linked view of the archive
whose ``Info.plist`` widens the window, and the reference is taken from it: on
the iOS 27 test capture, every one of its 143,045 entries is then in our
database. Measured facts the method rests on (2026-11-23, macOS 27):

* each edge must stay a consistent (continuous time, wall time) pair — moving
  only the continuous time loses the state events;
* symbolic links are not followed reliably by ``log show`` (it read 62,784 of
  143,158 lines), hence hard links (or a copy across volumes);
* moving the end edge 30 days or more loses every state event (1-7 days: none).
"""

from __future__ import annotations

import logging
import os
import plistlib
import shutil
import subprocess
from pathlib import Path

from forensic_aul.validation.platform import require_macos_log_tools

log = logging.getLogger(__name__)

DEFAULT_FLAGS: tuple[str, ...] = ("--info", "--debug", "--signpost", "--loss")
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


# How far past the declared end the widened window reaches. One day covers the
# gap between the end reference and the end of collection (seconds to minutes).
# WHY not "as far as possible": measured on macOS 27, moving the end 30 days or
# more makes log show drop every state event (1 to 7 days keeps them all).
_END_MARGIN_NS = 86_400 * 10**9


def full_window_view(logarchive: Path, dest: Path) -> Path:
    """Build *dest*: *logarchive* with its declared time window widened.

    Every file is hard-linked (no space used, nothing copied; a file on another
    volume is copied instead), except ``Info.plist``, written anew with each log
    class's ``OldestTimeRef`` moved back to its boot's start (continuous time 0)
    and ``EndTimeRef`` moved a day later — each as a consistent (continuous,
    wall) pair. The evidence itself is never written to.
    """
    def link_or_copy(src: str, dst: str) -> None:
        try:
            os.link(src, dst)
        except OSError:          # another volume, or links not supported
            shutil.copy2(src, dst)

    shutil.copytree(logarchive, dest, copy_function=link_or_copy, ignore=shutil.ignore_patterns("Info.plist"))
    with (logarchive / "Info.plist").open("rb") as fh:
        info = plistlib.load(fh)
    ns_per_tick = _ns_per_tick(logarchive, info)
    for value in info.values():
        ref = value.get("OldestTimeRef") if isinstance(value, dict) else None
        if ref:
            ref["WallTime"] -= int(ref["ContinuousTime"] * ns_per_tick)
            ref["ContinuousTime"] = 0
    end = info.get("EndTimeRef")
    if end:
        end["WallTime"] += _END_MARGIN_NS
        end["ContinuousTime"] += int(_END_MARGIN_NS / ns_per_tick)
    with (dest / "Info.plist").open("wb") as fh:
        plistlib.dump(info, fh)
    log.info(f"Reference over the full archive: declared window widened in {dest} "
             f"({ns_per_tick:.4f} ns per tick)")
    return dest


def _ns_per_tick(logarchive: Path, info: dict) -> float:
    """The device's mach timebase: from a tracev3 header (125/3 on Apple silicon,
    1 on Intel); else from the plist's two references on one boot; else 1."""
    from forensic_aul.engine.parser.format import CHUNK_TAG_HEADER
    from forensic_aul.engine.parser.header import parse_header_chunk
    from forensic_aul.engine.parser.reader import reader_from_bytes
    from forensic_aul.engine.parser.tracev3 import iter_chunks

    for path in sorted(logarchive.rglob("*.tracev3")):
        for raw in iter_chunks(path):
            if raw.tag == CHUNK_TAG_HEADER:
                hdr = parse_header_chunk(reader_from_bytes(raw.data))
                if hdr.mach_time_numerator and hdr.mach_time_denominator:
                    return hdr.mach_time_numerator / hdr.mach_time_denominator
            break
    end = info.get("EndTimeRef") or {}
    for value in info.values():
        ref = value.get("OldestTimeRef") if isinstance(value, dict) else None
        if ref and ref.get("UUID") == end.get("UUID") and end.get("ContinuousTime", 0) > ref["ContinuousTime"]:
            return (end["WallTime"] - ref["WallTime"]) / (end["ContinuousTime"] - ref["ContinuousTime"])
    log.warning("No mach timebase found — assuming 1 ns per tick (Intel)")
    return 1.0


def _which_log() -> str | None:
    """Return the path to the ``log`` binary, or None if unavailable."""
    return shutil.which("log")
