"""Tunables of the diagnostic reporter: where reports go and how much is captured.

Defines : ``CrashConfig`` (output folder + capture caps), ``DEFAULT_CONFIG`` (the
          shipped values) and ``resolve`` (an explicit config, else the default —
          read at CALL time).
Used by : app.diagnostics.capture (the caps), app.diagnostics.store (the folder),
          app.diagnostics.hooks (the ``enabled`` switch).
Uses    : app.paths (``app_data_dir``) — standard library only, like the reporter.

WHY ``resolve`` reads the default at call time (not as a default argument): a
default argument is frozen when the function is defined, so the folder could not be
redirected — by a test, or by a frontend — without passing a config everywhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from app.paths import app_data_dir


@dataclass(frozen=True)
class CrashConfig:
    """Size/behaviour knobs for one capture (defaults are the shipped values)."""

    enabled: bool = True
    crash_dir: Path = field(default_factory=lambda: app_data_dir() / "crash_reports")
    max_string_len: int = 2048    # longer str/bytes → preview + len + sha256
    max_items: int = 50           # max children summarised per dict/list/attrs
    max_depth: int = 4            # recursion cap; below it a container degrades to a repr
    max_frame_bytes: int = 65536  # 64 KiB budget per frame's locals


DEFAULT_CONFIG = CrashConfig()


def resolve(cfg: CrashConfig | None) -> CrashConfig:
    """*cfg* when given, else the module's current ``DEFAULT_CONFIG``."""
    return cfg if cfg is not None else DEFAULT_CONFIG
