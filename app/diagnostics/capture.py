"""Build a diagnostic report in memory: the type + value of every variable in every
stack frame — enough to debug a run without reproducing it. Writes nothing.

Defines : ``build_crash_report`` (walk a traceback) and ``build_bug_report`` (walk
          every live thread — there is no traceback when the tool *returns* a wrong
          answer), plus ``summarise`` (one value → a bounded, JSON-safe summary).
Used by : app.diagnostics.hooks (the guarded entry points that write the result).
Uses    : app.diagnostics.schema (report identity + ``classify``),
          app.diagnostics.config (``CrashConfig`` caps) and the standard library,
          plus a lazy, guarded read of ``forensic_aul.__version__``. Domain types are
          recognised by *name*, never imported — so the capture still works when a
          domain import is the very thing that crashed.

Design:
- Every value passes through ``summarise``, which NEVER dumps a whole DB connection
  / batch / cache (they are reduced to type + size) and caps string length, item
  count, recursion depth and per-frame bytes.
- Each captured variable is CLASSIFIED ``safe`` / ``sensitive`` so the report has two
  clearly separated sections. The capture keeps FULL PLAINTEXT (the operator's own
  machine); only the shareable copy is redacted — see app.diagnostics.redact.
- Both kinds produce the same schema, so one reader, one redaction pass and one
  renderer serve both; only ``kind`` and the absence of an exception differ.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import linecache
import logging
import os
import platform
import sys
import threading
import traceback
import types
from importlib import metadata as importlib_metadata
from pathlib import Path, PurePath
from typing import Any

from app.diagnostics.config import CrashConfig
from app.diagnostics.schema import (
    KIND_BUG,
    KIND_CRASH,
    REPORT_SCHEMA,
    SAFE,
    SENSITIVE,
    TOOL_NAME,
    classify,
    type_names,
)

log = logging.getLogger(__name__)

# Frames kept per thread in a bug report, innermost first. A module constant, not a
# CrashConfig knob: it bounds the REPORTER, not the tool, so it is not something an
# operator would ever tune — while a runaway recursion would otherwise dump
# thousands of near-identical frames.
_MAX_STACK_DEPTH = 60

# Packages whose installed version is worth recording for a repro (best-effort; a
# missing one is simply omitted).
_RECORDED_PACKAGES = ("forensic-aul", "PySide6", "pymobiledevice3")

# Large runtime objects that must be summarised (type + size), never walked. Matched
# by bare class name. Homes: sqlite3, engine/database/writer.py (BatchWriter),
# engine/parser/string_cache.py, ops/extraction/oversize_pass.py.
_LARGE_TYPE_NAMES = frozenset(
    {"Connection", "Cursor", "BatchWriter", "StringCacheProvider", "OversizeCache"}
)

# The package whose frames are the reporter's own (trimmed from a bug report).
_REPORTER_PACKAGE = __name__.rpartition(".")[0]


# ── safe primitives (must never raise: a broken __repr__ cannot crash the handler) ──

def _typename(value: Any) -> str:
    cls = type(value)
    module = getattr(cls, "__module__", "") or ""
    return cls.__qualname__ if module in ("builtins", "") else f"{module}.{cls.__qualname__}"


def _safe_repr(value: Any, limit: int) -> tuple[str | None, str | None]:
    """(repr-or-None, error-or-None). Truncates past ``limit`` with a residual marker."""
    try:
        text = repr(value)
    except Exception as exc:  # noqa: BLE001 - a value's __repr__ must not crash the handler.
        return None, f"{type(exc).__name__}: {exc}"
    if len(text) > limit:
        text = text[:limit] + f"…<+{len(text) - limit} chars>"
    return text, None


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_size(path: Any) -> int | None:
    """File size via a single stat (metadata only — never reads/hashes the file, so a
    512 GB acquisition costs nothing). None when it does not exist / is not stattable.

    Broad except: a PurePath (PurePosixPath is common in the source-preparation code)
    has no ``stat`` at all, and letting that AttributeError escape would sink the
    whole crash report in the very frames we most need captured."""
    try:
        return path.stat().st_size
    except Exception:  # noqa: BLE001 - a size probe must never crash the handler.
        return None


# ── the summariser (full plaintext; redaction happens later, in redact) ────────

def summarise(value: Any, cfg: CrashConfig, depth: int) -> Any:
    """One value → a bounded, JSON-serialisable summary. Never raises on a hostile
    value; recursion stops at *depth*."""
    # Scalars flow through verbatim — they are the point of "capture every variable".
    if value is None or isinstance(value, (bool, int, float)):
        return value

    # A filesystem-path value: keep type + size + the literal path (plaintext locally;
    # redact replaces it with type + hash for a shared copy).
    if isinstance(value, PurePath):
        return {"type": _typename(value), "path": str(value), "size_bytes": _safe_size(value)}

    if isinstance(value, str):
        if len(value) <= cfg.max_string_len:
            return value
        return {
            "type": "str", "len": len(value), "truncated": True,
            "preview": value[: cfg.max_string_len],
            "sha256": _sha256_bytes(value.encode("utf-8", "replace")),
        }

    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        return {
            "type": _typename(value), "len": len(raw), "sha256": _sha256_bytes(raw),
            "preview_hex": raw[:64].hex(), "truncated": len(raw) > 64,
        }

    # Large runtime objects (DB connection, batch writer, caches): type + size only.
    if any(name in _LARGE_TYPE_NAMES for name in type_names(value)):
        return _summarise_large(value)

    if isinstance(value, dict):
        return _summarise_mapping(value, cfg, depth)

    if isinstance(value, (list, tuple, set, frozenset)):
        return _summarise_sequence(value, cfg, depth)

    return _summarise_object(value, cfg, depth)


def _summarise_large(value: Any) -> dict[str, Any]:
    """A big object we deliberately do not walk: its type plus any cheap size hint."""
    out: dict[str, Any] = {"type": _typename(value), "not_dumped": True}
    # Best-effort size hint from common attributes, without materialising anything.
    for attr in ("_pending", "_cache"):
        container = getattr(value, attr, None)
        if container is not None:
            try:
                out[f"{attr}_len"] = len(container)
            except Exception:  # noqa: BLE001 - a size probe must never crash the handler.
                pass
    try:
        out["len"] = len(value)  # type: ignore[arg-type]
    except Exception:  # noqa: BLE001 - not everything is sized; that is fine.
        pass
    return out


def _shallow(value: Any, cfg: CrashConfig) -> dict[str, Any]:
    """Depth-exhausted fallback: type + truncated repr, no recursion."""
    text, err = _safe_repr(value, cfg.max_string_len)
    out: dict[str, Any] = {"type": _typename(value), "depth_exceeded": True}
    if err is not None:
        out["repr_error"] = err
    else:
        out["repr"] = text
    return out


def _summarise_mapping(value: dict, cfg: CrashConfig, depth: int) -> Any:
    if depth <= 0:
        return _shallow(value, cfg)
    items: dict[str, Any] = {}
    for i, (key, val) in enumerate(value.items()):
        if i >= cfg.max_items:
            break
        key_name = key if isinstance(key, str) else repr(key)
        items[str(key_name)] = summarise(val, cfg, depth - 1)
    out: dict[str, Any] = {"type": _typename(value), "len": len(value), "items": items}
    if len(value) > cfg.max_items:
        out["truncated"] = True
    return out


def _summarise_sequence(value: Any, cfg: CrashConfig, depth: int) -> Any:
    if depth <= 0:
        return _shallow(value, cfg)
    materialised = list(value)
    items = [summarise(item, cfg, depth - 1) for item in materialised[: cfg.max_items]]
    out: dict[str, Any] = {"type": _typename(value), "len": len(materialised), "items": items}
    if len(materialised) > cfg.max_items:
        out["truncated"] = True
    return out


def _summarise_object(value: Any, cfg: CrashConfig, depth: int) -> Any:
    """A dataclass / plain object: repr + a shallow view of its instance attributes."""
    text, err = _safe_repr(value, cfg.max_string_len)
    out: dict[str, Any] = {"type": _typename(value)}
    if err is not None:
        out["repr_error"] = err
    else:
        out["repr"] = text
    attrs = getattr(value, "__dict__", None)
    if isinstance(attrs, dict) and attrs and depth > 0:
        shown: dict[str, Any] = {}
        for i, (key, val) in enumerate(attrs.items()):
            if i >= cfg.max_items:
                out["attrs_truncated"] = True
                break
            shown[str(key)] = summarise(val, cfg, depth - 1)
        out["attrs"] = shown
    return out


# ── frame collection ───────────────────────────────────────────────────────────

def _sizeof(summary: Any) -> int:
    try:
        return len(json.dumps(summary, default=str, ensure_ascii=False))
    except Exception:  # noqa: BLE001 - a non-serialisable summary still has a str length.
        return len(str(summary))


# Frame locals that carry no debug value and only bloat the report: dunder names
# (``__name__``, ``__loader__``, …) and imported modules / functions / classes —
# common in a module-level frame. Actual data variables are always kept.
_NOISE_TYPES = (types.ModuleType, types.FunctionType, types.BuiltinFunctionType,
                types.MethodType, type)


def _is_noise(name: str, value: Any) -> bool:
    if name.startswith("__") and name.endswith("__"):
        return True
    return isinstance(value, _NOISE_TYPES)


def _frame_entry(frame: Any, lineno: int, cfg: CrashConfig) -> dict[str, Any]:
    """One report entry for one live frame: where it is, plus its locals summarised
    and split into ``safe`` / ``sensitive``. A per-frame byte budget stops one huge
    frame bloating the report. Shared by the traceback walk (crash) and the
    live-thread walk (bug), so both kinds produce identical frame records."""
    code = frame.f_code
    buckets: dict[str, dict[str, Any]] = {SAFE: {}, SENSITIVE: {}}
    used = 0
    truncated = False
    for var_name, value in list(frame.f_locals.items()):
        if _is_noise(var_name, value):
            continue
        summary = summarise(value, cfg, cfg.max_depth)
        size = _sizeof(summary)
        if used + size > cfg.max_frame_bytes:
            truncated = True
            break
        buckets[classify(var_name, value)][var_name] = summary
        used += size
    entry: dict[str, Any] = {
        "file": code.co_filename,
        "lineno": lineno,
        "function": code.co_name,
        "code": linecache.getline(code.co_filename, lineno).strip() or None,
        "locals": buckets,
    }
    if truncated:
        entry["locals_truncated"] = True
    return entry


def _collect_frames(tb: Any, cfg: CrashConfig) -> list[dict[str, Any]]:
    """One entry per traceback frame (outermost first, crash site last)."""
    return [_frame_entry(frame, lineno, cfg) for frame, lineno in traceback.walk_tb(tb)]


# ── live-thread stacks (the bug report, which has no traceback to walk) ─────────

def _is_reporter_frame(frame: Any) -> bool:
    """True when *frame* belongs to this package — i.e. it is the reporter's own
    (capture, hooks, …), not the application state the report is for."""
    try:
        module = frame.f_globals.get("__name__") or ""
    except Exception:  # noqa: BLE001 - an exotic frame must not crash the probe.
        return False
    return module == _REPORTER_PACKAGE or module.startswith(_REPORTER_PACKAGE + ".")


def _thread_chain(innermost: Any) -> list[tuple[Any, int]]:
    """A thread's frames, OUTERMOST first (matching the traceback order), with the
    reporter's own frames trimmed off the inner end and the depth capped.

    WHY trim rather than skip: the obvious guard — "if this stack contains one of my
    frames, skip the whole thread" — silently discards the calling thread, which is
    normally the most interesting one. It is also invisible: the report still looks
    valid, just with nothing in it. Only the frames INNER than the reporter are
    noise; every frame outside it is the application state we came for.
    """
    frame = innermost
    # The reporter's frames form a contiguous run at the INNER end of the calling
    # thread's stack (this package is what called sys._current_frames), so walking
    # outward past them removes exactly the reporter and nothing else.
    while frame is not None and _is_reporter_frame(frame):
        frame = frame.f_back
    chain: list[tuple[Any, int]] = []
    while frame is not None and len(chain) < _MAX_STACK_DEPTH:
        chain.append((frame, frame.f_lineno))
        frame = frame.f_back
    return list(reversed(chain))


def _collect_thread_frames(cfg: CrashConfig) -> list[dict[str, Any]]:
    """Every live thread's frames, the calling thread first, each entry labelled with
    its thread. Per-thread guarded: ``sys._current_frames`` is a snapshot, so a
    thread can finish while we walk it — losing one racing thread is acceptable,
    raising out of the reporter is not."""
    names = {t.ident: t.name for t in threading.enumerate()}
    current = threading.get_ident()
    snapshot = sys._current_frames()  # noqa: SLF001 - the only way to reach live stacks.
    # Calling thread first: it is the one the operator was interacting with.
    order = sorted(snapshot, key=lambda tid: (tid != current, names.get(tid, ""), tid))

    frames: list[dict[str, Any]] = []
    for tid in order:
        label = f"{names.get(tid, 'unknown')} (tid={tid})"
        try:
            for frame, lineno in _thread_chain(snapshot[tid]):
                entry = _frame_entry(frame, lineno, cfg)
                entry["thread"] = label
                frames.append(entry)
        except Exception:  # noqa: BLE001 - a vanished/racing thread must not sink the report.
            log.debug("Could not capture stack for thread %s", label, exc_info=True)
    return frames


# ── execution metadata ─────────────────────────────────────────────────────────

def _tool_version() -> str:
    """The library version, read lazily and guarded so a broken import still reports."""
    try:
        from forensic_aul import __version__
        return __version__
    except Exception:  # noqa: BLE001 - a failed domain import is itself a likely crash cause.
        return "unknown"


def _package_versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    for name in _RECORDED_PACKAGES:
        try:
            versions[name] = importlib_metadata.version(name)
        except Exception:  # noqa: BLE001 - an absent optional package is simply omitted.
            continue
    return versions


def _git_commit() -> str | None:
    """Best-effort short commit: read .git/HEAD from the CWD upward, no subprocess."""
    try:
        for directory in (Path.cwd(), *Path.cwd().parents):
            head = directory / ".git" / "HEAD"
            if not head.is_file():
                continue
            content = head.read_text(encoding="utf-8").strip()
            if content.startswith("ref:"):
                ref = directory / ".git" / content[4:].strip()
                return ref.read_text(encoding="utf-8").strip() if ref.is_file() else None
            return content  # detached HEAD stores the commit sha directly
    except Exception:  # noqa: BLE001 - provenance is best-effort, never fatal.
        return None
    return None


def _metadata(context: dict[str, Any] | None) -> dict[str, Any]:
    """Execution metadata, itself split into ``safe`` and ``sensitive`` sections.

    ``argv`` and ``cwd`` are sensitive (they carry evidence paths and case ids);
    the platform / version facts are safe.
    """
    now = dt.datetime.now(dt.timezone.utc)
    safe: dict[str, Any] = {
        "tool": TOOL_NAME,
        "tool_version": _tool_version(),
        "generated_at_utc": now.isoformat(),
        "generated_at_local": now.astimezone().isoformat(),
        "python_version": sys.version,
        "python_implementation": platform.python_implementation(),
        "pid": os.getpid(),
        "cpu_count": os.cpu_count(),
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "packages": _package_versions(),
        "git_commit": _git_commit(),
    }
    if context:
        safe["context"] = context
    sensitive: dict[str, Any] = {
        "argv": list(sys.argv),
        "cwd": str(Path.cwd()),
        "executable": sys.executable,
    }
    return {SAFE: safe, SENSITIVE: sensitive}


# ── the two report builders ────────────────────────────────────────────────────

def build_crash_report(
    exc_type: type[BaseException],
    exc: BaseException,
    tb: Any,
    cfg: CrashConfig,
    context: dict[str, Any] | None,
) -> dict[str, Any]:
    """A crash report for one exception: its frames come from the traceback."""
    return {
        "schema": REPORT_SCHEMA,
        "kind": KIND_CRASH,
        "tool": TOOL_NAME,
        "exception": {
            "type": _typename(exc),
            "message": str(exc),
            "args": [summarise(arg, cfg, 1) for arg in getattr(exc, "args", ())],
            "notes": [str(n) for n in (getattr(exc, "__notes__", []) or [])] or None,
        },
        "traceback": "".join(traceback.format_exception(exc_type, exc, tb)),
        "frames": _collect_frames(tb, cfg),
        "metadata": _metadata(context),
    }


def build_bug_report(cfg: CrashConfig, context: dict[str, Any] | None) -> dict[str, Any]:
    """The same structure as a crash report, minus the two things a bug report has
    no equivalent of. Keeping the keys present (as ``None``) rather than dropping
    them means one reader and one redaction pass handle both kinds unchanged."""
    return {
        "schema": REPORT_SCHEMA,
        "kind": KIND_BUG,
        "tool": TOOL_NAME,
        "exception": None,
        "traceback": None,
        "frames": _collect_thread_frames(cfg),
        "metadata": _metadata(context),
    }
