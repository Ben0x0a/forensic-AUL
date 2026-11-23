"""Layered settings for the frontends: defaults < config file < FAUL_* environment < flags.

Defines : ``Settings`` (the option objects the frontends start from),
          ``load_settings`` (read ``app_data/faul.toml`` and the environment),
          ``SettingsError``, ``CONFIG_PATH`` and ``SETTABLE_KEYS`` (the documented
          surface: ``section.field`` names).
Used by : launcher/cli.py (loads once, hands it to every command as
          ``args.settings``), launcher/cmds/extract_cmd.py, acquire_cmd.py,
          identify_cmd.py, and the GUI controllers (gui/controllers/pipeline.py,
          gui/controllers/identify.py).
Uses    : forensic_aul (the option dataclasses, INTEGRITY_MODES), app.paths, and
          the standard library (tomllib, difflib, dataclasses, typing).

Precedence, lowest first — each layer replaces only the keys it names:

1. the option dataclasses' own defaults (ExtractOptions, AcquireOptions,
   IdentifyOptions) — the ONLY place a default value is written down, plus the
   app's one deliberate override (``jobs = 0``, "auto", see _DEFAULTS);
2. ``app_data/faul.toml`` next to the app, one table per section::

       [extract]
       jobs = 4
       integrity = "fingerprint"

       [identify]
       still_seconds = 30

       [identify.extract]
       batch_size = 5000

3. the environment: ``FAUL_<SECTION>_<FIELD>`` (``FAUL_EXTRACT_JOBS=4``,
   ``FAUL_IDENTIFY_EXTRACT_BATCH_SIZE=5000``);
4. command-line flags (applied by each command; a flag left out means "the
   settings decide").

WHY an allowlist (SETTABLE_KEYS) and not every dataclass field: some choices must
be made per run, never inherited from a file nobody looks at — ``overwrite``
(would replace an evidence database), ``audit_log`` (an evidence extract is the
frontend's decision), ``work_dir``, ``udid``. WHY unknown keys are refused: a typo
silently ignored ("jbos = 8") leaves the operator believing a setting applies.
"""

from __future__ import annotations

import difflib
import os
import tomllib
import typing
from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass, replace
from pathlib import Path
from typing import Any

from forensic_aul import INTEGRITY_MODES, AcquireOptions, ExtractOptions, IdentifyOptions

from app.paths import app_data_dir

CONFIG_PATH = app_data_dir() / "faul.toml"
_ENV_PREFIX = "FAUL_"


@dataclass(frozen=True)
class Settings:
    """The option objects a frontend starts from before applying its flags."""

    extract: ExtractOptions
    acquire: AcquireOptions
    identify: IdentifyOptions


# The app's defaults: the dataclasses' own, except ``jobs = 0`` ("auto": one
# parser per physical core, memory-aware — resolved by the frontend). WHY the
# library default stays 1: jobs > 1 needs an import-safe caller (spawn), which a
# frontend is and an arbitrary library caller may not be.
_DEFAULTS = Settings(
    extract=ExtractOptions(jobs=0),
    acquire=AcquireOptions(),
    identify=IdentifyOptions(extract=replace(IdentifyOptions().extract, jobs=0)),
)

# section → the fields that may be set from the file / environment. A dotted
# section is a nested option object (IdentifyOptions.extract).
_SETTABLE: dict[str, tuple[str, ...]] = {
    "extract": ("batch_size", "jobs", "fts", "fast_fts", "fast_write", "keep_raw", "integrity"),
    "acquire": ("pack", "size_limit", "age_limit"),
    "identify": ("still_seconds", "write_csv"),
    "identify.extract": ("batch_size", "jobs", "fts", "integrity"),
}
SETTABLE_KEYS: tuple[str, ...] = tuple(
    f"{section}.{name}" for section, names in _SETTABLE.items() for name in names
)

# Value rules beyond the type: (check, what a valid value is).
_RULES: dict[str, tuple[typing.Callable[[Any], bool], str]] = {
    "batch_size": (lambda v: v >= 1, "at least 1"),
    "jobs": (lambda v: v >= 0, "0 (auto) or more"),
    "still_seconds": (lambda v: v >= 0, "0 or more"),
    "size_limit": (lambda v: v is None or v > 0, "a positive number of bytes"),
    "age_limit": (lambda v: v is None or v > 0, "a positive number of days"),
    "integrity": (lambda v: v in INTEGRITY_MODES, f"one of {', '.join(INTEGRITY_MODES)}"),
}

_TRUE, _FALSE = {"1", "true", "yes", "on"}, {"0", "false", "no", "off"}


class SettingsError(ValueError):
    """The config file or a FAUL_* variable holds something unusable.

    ``problems`` lists every one found (all are reported at once, so fixing the
    file is one round trip, not one per error).
    """

    def __init__(self, problems: list[str]) -> None:
        super().__init__("invalid settings:\n  " + "\n  ".join(problems))
        self.problems = problems


def load_settings(
    path: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> Settings:
    """Defaults, then *path* (default ``CONFIG_PATH``; absent is fine), then *env*
    (default ``os.environ``). Raises :class:`SettingsError` on any bad entry."""
    path = CONFIG_PATH if path is None else path
    env = os.environ if env is None else env
    problems: list[str] = []
    values: dict[str, Any] = {}       # "section.field" → value, file then env
    values.update(_read_file(path, problems))
    values.update(_read_env(env, problems))
    settings = _apply(_DEFAULTS, values, problems)
    if problems:
        raise SettingsError(problems)
    return settings


# ── Readers: each yields "section.field" → raw value ─────────────────────────

def _read_file(path: Path, problems: list[str]) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        problems.append(f"{path}: {exc}")
        return {}
    out: dict[str, Any] = {}
    _flatten(data, "", out)
    for key in list(out):
        if key not in SETTABLE_KEYS:
            problems.append(f"{path}: unknown setting {key!r}{_suggest(key)}")
            del out[key]
    return out


def _flatten(table: Mapping[str, Any], prefix: str, out: dict[str, Any]) -> None:
    for name, value in table.items():
        key = f"{prefix}{name}"
        if isinstance(value, Mapping):
            _flatten(value, f"{key}.", out)
        else:
            out[key] = value


def _read_env(env: Mapping[str, str], problems: list[str]) -> dict[str, Any]:
    by_var = {_env_name(key): key for key in SETTABLE_KEYS}
    out: dict[str, Any] = {}
    for var, raw in env.items():
        if not var.startswith(_ENV_PREFIX):
            continue
        key = by_var.get(var)
        if key is None:
            hint = difflib.get_close_matches(var, by_var, n=1)
            problems.append(f"unknown environment variable {var}"
                            + (f" (did you mean {hint[0]}?)" if hint else ""))
            continue
        out[key] = _EnvText(raw)
    return out


def _env_name(key: str) -> str:
    return _ENV_PREFIX + key.upper().replace(".", "_")


class _EnvText(str):
    """A value read from the environment: text, to be converted to the field's type."""


def _suggest(key: str) -> str:
    hint = difflib.get_close_matches(key, SETTABLE_KEYS, n=1)
    return f" (did you mean {hint[0]!r}?)" if hint else ""


# ── Applying the values onto the defaults ────────────────────────────────────

def _apply(defaults: Settings, values: dict[str, Any], problems: list[str]) -> Settings:
    sections: dict[str, Any] = {}
    for section in ("extract", "acquire", "identify"):
        obj = getattr(defaults, section)
        nested = {f.name: getattr(obj, f.name) for f in fields(obj) if is_dataclass(getattr(obj, f.name))}
        for name, child in nested.items():
            nested[name] = _set_fields(child, f"{section}.{name}", values, problems)
        obj = replace(obj, **nested) if nested else obj
        sections[section] = _set_fields(obj, section, values, problems)
    return Settings(**sections)


def _set_fields(obj: Any, section: str, values: dict[str, Any], problems: list[str]) -> Any:
    hints = typing.get_type_hints(type(obj))
    changes: dict[str, Any] = {}
    for name in _SETTABLE.get(section, ()):
        key = f"{section}.{name}"
        if key not in values:
            continue
        try:
            value = _convert(values[key], hints[name])
        except ValueError as exc:
            problems.append(f"{key}: {exc}")
            continue
        rule = _RULES.get(name)
        if rule is not None and not rule[0](value):
            problems.append(f"{key}: {value!r} — expected {rule[1]}")
            continue
        changes[name] = value
    return replace(obj, **changes) if changes else obj


def _convert(raw: Any, hint: Any) -> Any:
    """*raw* (a TOML value, or text from the environment) → a value of *hint*."""
    args = typing.get_args(hint)
    optional = type(None) in args
    target = next((a for a in args if a is not type(None)), hint) if args else hint
    from_env = isinstance(raw, _EnvText)
    if optional and from_env and raw.strip().lower() in ("", "none"):
        return None
    if target is bool:
        if from_env and raw.strip().lower() in _TRUE | _FALSE:
            return raw.strip().lower() in _TRUE
        if not from_env and isinstance(raw, bool):
            return raw
        raise ValueError(f"{raw!r} — expected true or false")
    if target is int:
        if from_env:
            try:
                return int(raw.strip())
            except ValueError:
                raise ValueError(f"{raw!r} — expected a whole number") from None
        if isinstance(raw, int) and not isinstance(raw, bool):
            return raw
        raise ValueError(f"{raw!r} — expected a whole number")
    if target is str:
        if isinstance(raw, str):
            return str(raw)
        raise ValueError(f"{raw!r} — expected text")
    raise ValueError(f"unsupported setting type {hint!r}")  # pragma: no cover - allowlist bug
