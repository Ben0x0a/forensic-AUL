"""Forensic diagnostic capture: write one structured report holding the type + value
of every variable in every stack frame — enough to debug a run without reproducing
it. Two kinds share one format:

* a **crash** report, written automatically when something raises;
* a **bug** report, written on demand when the tool *returns* but the answer is
  wrong — the harder failure, because there is no traceback and the state that
  explains it lives only in the running frames.

Defines : ``install_excepthook`` (global ``sys``/``threading`` hooks),
          ``capture_exception`` (call from an ``except`` block that swallows and
          returns a code), ``write_bug_report`` (operator-triggered, no exception),
          ``write_crash_report`` (the guarded writer), ``list_reports`` (find/count
          saved reports by kind), and the sensitivity vocabulary + ``classify``
          used to split captured variables into ``safe`` and ``sensitive`` buckets.
Used by : launcher.cli / launcher.gui (install the hooks at start-up), and the
          broad ``except`` handlers in app.extract_session and launcher.cmds.*.
          app.sanitize consumes the classification vocabulary; launcher.cmds.
          redact_errors_cmd reads the reports this module writes.
Uses    : the STANDARD LIBRARY ONLY (plus a lazy, guarded read of
          ``forensic_aul.__version__``). Domain types are recognised by *name*,
          never imported — so this module still loads and runs even when a
          domain import is the very thing that crashed.

Design:
- A global ``sys.excepthook`` (+ ``threading.excepthook``) receives the crash;
  ``capture_exception`` covers the paths that catch-log-and-``return 1`` and so
  never reach the hook. Both walk the traceback so every frame's ``f_locals`` is
  captured with no instrumentation sprinkled through the codebase.
- ``write_bug_report`` has no traceback to walk, so it walks EVERY LIVE THREAD
  instead (``sys._current_frames``). In a GUI the values that explain a wrong
  answer are usually in a worker thread, not the one that pressed the button.
- BOTH kinds emit the same schema through the same writer, so one reader and one
  redaction pass serve both; only ``kind`` and the absence of an exception differ.
- Every value passes through ``_summarise``, which NEVER dumps a whole DB
  connection / batch / cache (they are reduced to type + size) and caps string
  length, item count, recursion depth and per-frame bytes.
- Each captured variable is CLASSIFIED ``safe`` / ``sensitive`` so the report has
  two clearly separated sections. This is a forensic tool, so the capture keeps
  FULL PLAINTEXT locally (the operator's own machine); redaction and path
  anonymisation happen only when a shareable copy is produced — see app.sanitize.
- The handler is fully guarded: any internal failure degrades to a log line and
  returns ``None`` — it never masks the original exception, whose normal
  traceback still prints.
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
from dataclasses import dataclass
from importlib import metadata as importlib_metadata
from pathlib import Path, PurePath
from typing import Any

log = logging.getLogger(__name__)

# Bumped when the report structure changes so a downstream reader can branch on it.
# /2 added ``kind`` and the optional per-frame ``thread`` label (bug reports).
REPORT_SCHEMA = "faul.diagnostic-report/2"

# Report kinds. One schema covers both; ``kind`` is how a reader tells them apart.
KIND_CRASH = "crash"
KIND_BUG = "bug"

# Filename prefix per kind. They differ so a shell can COUNT one kind without the
# other: a control that decides between "open error reports" and "report bug…" must
# count crashes only — counting bug reports is self-fulfilling, since filing one
# would make the tool claim it had errored.
_FILENAME_PREFIX = {KIND_CRASH: "faul_crash_", KIND_BUG: "faul_bug_"}

# Sensitivity bucket labels — the two sections the operator reviews before sharing.
SAFE = "safe"
SENSITIVE = "sensitive"

# Frames kept per thread in a bug report, innermost first. A module constant, not a
# CrashConfig knob: it bounds the REPORTER, not the tool, so it is not something an
# operator would ever tune — while a runaway recursion would otherwise dump
# thousands of near-identical frames.
_MAX_STACK_DEPTH = 60


# ── configuration ─────────────────────────────────────────────────────────────
# App-layer tunables. Consumed by: this module (capture caps + output dir) and
# launcher.cmds.redact_errors_cmd (lists CRASH_REPORT_DIR). The app-data dir mirrors the
# convention already used by gui.settings_store / gui.recent_store.

_APP_DATA_DIR = Path.home() / ".config" / "faul"


@dataclass(frozen=True)
class CrashConfig:
    """Size/behaviour knobs for one crash capture (defaults are the shipped values)."""

    enabled: bool = True
    crash_dir: Path = _APP_DATA_DIR / "crash_reports"
    max_string_len: int = 2048   # longer str/bytes → preview + len + sha256
    max_items: int = 50          # max children summarised per dict/list/attrs
    max_depth: int = 4           # recursion cap; below it a container degrades to a repr
    max_frame_bytes: int = 65536  # 64 KiB budget per frame's locals


_DEFAULT_CONFIG = CrashConfig()

# Packages whose installed version is worth recording for a repro (best-effort; a
# missing one is simply omitted).
_RECORDED_PACKAGES = ("forensic-aul", "PySide6", "pymobiledevice3")


# ── sensitivity vocabulary + classifier ───────────────────────────────────────
# WHY a forensic-specific classifier (not mATLAS's name-substring-only redaction):
# this tool's PII lives in well-TYPED fields (a DeviceInfo's imei, a LogEntry's
# message, extracted_values) whose variable names need not match any keyword. So a
# value is sensitive if its TYPE, its NAME, or its being a filesystem path says so.

# Domain types whose instances are sensitive as a whole. Matched by bare class name
# against the value's MRO (so subclasses count) — never imported. Reference homes:
# ops/acquisition/device.py, ops/extraction/options.py, engine/models/log_entry.py,
# ops/query/reader.py.
SENSITIVE_TYPE_NAMES = frozenset(
    {"DeviceInfo", "SimInfo", "CaseInfo", "LogEntry", "LogRow", "MessageData"}
)

# Case-insensitive substrings; a variable / attribute / dict-key whose name
# contains any of these is sensitive. Over-redaction here is acceptable — a false
# positive costs a hashed value, a false negative leaks PII.
SENSITIVE_FIELD_TOKENS = frozenset(
    {
        "imei", "udid", "serial", "meid", "ecid", "iccid", "imsi", "phone",
        "_mac", "device_name", "case_number", "exhibit", "analyst", "notes",
        "message", "ssid", "latitude", "longitude",
    }
)

# Generic secret tokens (kept separate so the intent reads clearly).
SECRET_TOKENS = frozenset(
    {
        "password", "passwd", "pwd", "passphrase", "secret", "token",
        "credential", "api_key", "apikey", "private_key",
    }
)

# Large runtime objects that must be summarised (type + size), never walked. Matched
# by bare class name. Homes: sqlite3, engine/database/writer.py (BatchWriter),
# engine/parser/string_cache.py, ops/extraction/oversize_pass.py.
_LARGE_TYPE_NAMES = frozenset(
    {"Connection", "Cursor", "BatchWriter", "StringCacheProvider", "OversizeCache"}
)


def is_sensitive_key(name: str | None) -> bool:
    """True when a variable/key name matches a sensitive field or secret token."""
    if not name:
        return False
    lowered = name.lower()
    return any(t in lowered for t in SENSITIVE_FIELD_TOKENS) or any(
        t in lowered for t in SECRET_TOKENS
    )


def _type_names(value: Any) -> tuple[str, ...]:
    """Every class name in the value's MRO (best-effort) — for name-based matching."""
    try:
        return tuple(base.__name__ for base in type(value).__mro__)
    except Exception:  # noqa: BLE001 - exotic metaclasses must not crash the probe.
        return ()


def is_sensitive_type(value: Any) -> bool:
    """True when the value's type (or any base) is a known sensitive domain type."""
    return any(name in SENSITIVE_TYPE_NAMES for name in _type_names(value))


def classify(name: str | None, value: Any) -> str:
    """Return ``SENSITIVE`` or ``SAFE`` for a captured variable.

    Sensitive if the NAME matches a token, the VALUE is a filesystem path
    (evidence/output location), or the TYPE is a known PII-bearing domain type.
    """
    if is_sensitive_key(name):
        return SENSITIVE
    if isinstance(value, PurePath):
        return SENSITIVE
    if is_sensitive_type(value):
        return SENSITIVE
    return SAFE


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


# ── the summariser (full plaintext; redaction happens later in app.sanitize) ───

def _summarise(value: Any, cfg: CrashConfig, depth: int) -> Any:
    # Scalars flow through verbatim — they are the point of "capture every variable".
    if value is None or isinstance(value, (bool, int, float)):
        return value

    # A filesystem-path value: keep type + size + the literal path (plaintext locally;
    # app.sanitize replaces it with type + hash for a shared copy).
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
    if any(name in _LARGE_TYPE_NAMES for name in _type_names(value)):
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
        items[str(key_name)] = _summarise(val, cfg, depth - 1)
    out: dict[str, Any] = {"type": _typename(value), "len": len(value), "items": items}
    if len(value) > cfg.max_items:
        out["truncated"] = True
    return out


def _summarise_sequence(value: Any, cfg: CrashConfig, depth: int) -> Any:
    if depth <= 0:
        return _shallow(value, cfg)
    materialised = list(value)
    items = [_summarise(item, cfg, depth - 1) for item in materialised[: cfg.max_items]]
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
            shown[str(key)] = _summarise(val, cfg, depth - 1)
        out["attrs"] = shown
    return out


# ── frame + metadata collection ────────────────────────────────────────────────

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
        summary = _summarise(value, cfg, cfg.max_depth)
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
    """True when *frame* belongs to this module — i.e. it is the reporter's own."""
    try:
        return frame.f_globals.get("__name__") == __name__
    except Exception:  # noqa: BLE001 - an exotic frame must not crash the probe.
        return False


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
    # thread's stack (this module is what called sys._current_frames), so walking
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
        "tool": "forensic_AUL",
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


# ── report assembly + hooks ────────────────────────────────────────────────────

def _report_path(cfg: CrashConfig, kind: str) -> Path:
    """A filesystem-safe, collision-free path: kind-specific prefix (so one kind can
    be counted without the other); no colons in the timestamp; pid suffix; a numeric
    suffix only if a same-second same-pid file already exists (never overwrite an
    existing report)."""
    cfg.crash_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
    base = f"{_FILENAME_PREFIX[kind]}{stamp}_p{os.getpid()}"
    path = cfg.crash_dir / f"{base}.json"
    counter = 1
    while path.exists():
        path = cfg.crash_dir / f"{base}_{counter}.json"
        counter += 1
    return path


def _build_report(
    exc_type: type[BaseException],
    exc: BaseException,
    tb: Any,
    cfg: CrashConfig,
    context: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "schema": REPORT_SCHEMA,
        "kind": KIND_CRASH,
        "tool": "forensic_AUL",
        "exception": {
            "type": _typename(exc),
            "message": str(exc),
            "args": [_summarise(arg, cfg, 1) for arg in getattr(exc, "args", ())],
            "notes": [str(n) for n in (getattr(exc, "__notes__", []) or [])] or None,
        },
        "traceback": "".join(traceback.format_exception(exc_type, exc, tb)),
        "frames": _collect_frames(tb, cfg),
        "metadata": _metadata(context),
    }


def _build_bug_report(cfg: CrashConfig, context: dict[str, Any] | None) -> dict[str, Any]:
    """The same structure as a crash report, minus the two things a bug report has
    no equivalent of. Keeping the keys present (as ``None``) rather than dropping
    them means one reader and one redaction pass handle both kinds unchanged."""
    return {
        "schema": REPORT_SCHEMA,
        "kind": KIND_BUG,
        "tool": "forensic_AUL",
        "exception": None,
        "traceback": None,
        "frames": _collect_thread_frames(cfg),
        "metadata": _metadata(context),
    }


def _emit(report: dict[str, Any], cfg: CrashConfig, kind: str) -> Path | None:
    """Write one report (JSON + best-effort Markdown twin) and return the JSON path.

    The single writer for both kinds: whatever the JSON gains — an encoding, a
    naming rule, a twin — both kinds gain together and cannot drift apart.
    """
    path = _report_path(cfg, kind)
    # utf-8-sig so Windows tooling auto-detects the encoding (house rule).
    path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8-sig",
    )
    _write_markdown_twin(report, path)
    return path


def write_crash_report(
    exc_type: type[BaseException],
    exc: BaseException,
    tb: Any,
    *,
    context: dict[str, Any] | None = None,
    cfg: CrashConfig = _DEFAULT_CONFIG,
) -> Path | None:
    """Write one crash report (JSON, plus a best-effort human Markdown twin) and
    return the JSON path — or ``None`` if disabled/failed.

    Guaranteed non-throwing: any internal failure is logged and swallowed so the
    original exception is never masked.
    """
    try:
        if not cfg.enabled:
            return None
        path = _emit(_build_report(exc_type, exc, tb, cfg, context), cfg, KIND_CRASH)
        log.error(f"Crash report written to {path}")
        return path
    except Exception:  # noqa: BLE001 - the handler must never raise over the original error.
        log.exception("Failed to write crash report")
        return None


def write_bug_report(
    context: dict[str, Any] | None = None,
    *,
    cfg: CrashConfig = _DEFAULT_CONFIG,
) -> Path | None:
    """Capture the tool's CURRENT live state as a bug report and return the JSON
    path — or ``None`` if disabled/failed.

    For the failure a crash report can never catch: the tool ran to completion,
    exited cleanly, and produced a wrong answer. There is no exception and no
    traceback, so every live thread's frames are captured instead — in a GUI the
    values that explain the wrong answer are usually in a worker thread, not in the
    one that pressed the button.

    Guaranteed non-throwing, like its crash twin: an operator asking for help must
    never be punished with a second failure.
    """
    try:
        if not cfg.enabled:
            return None
        path = _emit(_build_bug_report(cfg, context), cfg, KIND_BUG)
        log.info(f"Bug report written to {path}")
        return path
    except Exception:  # noqa: BLE001 - reporting a bug must not itself raise.
        log.exception("Failed to write bug report")
        return None


def list_reports(
    crash_dir: Path | None = None,
    *,
    kind: str | None = None,
) -> list[Path]:
    """Saved reports, newest first. *kind* selects ``KIND_CRASH`` or ``KIND_BUG``;
    ``None`` returns both. The redacted ``*.shared.json`` copies are excluded.

    WHY the kind filter: a shell offering one control for "something is wrong" picks
    its caption from the number of ERROR reports. Counting bug reports there would
    be self-fulfilling — filing one would make the tool claim it had errored.
    """
    directory = crash_dir if crash_dir is not None else _DEFAULT_CONFIG.crash_dir
    if not directory.is_dir():
        return []
    prefixes = [_FILENAME_PREFIX[kind]] if kind else list(_FILENAME_PREFIX.values())
    found: list[tuple[float, Path]] = []
    for prefix in prefixes:
        for path in directory.glob(f"{prefix}*.json"):
            if path.name.endswith(".shared.json"):
                continue
            try:
                found.append((path.stat().st_mtime, path))
            except OSError:  # noqa: PERF203 - a report deleted mid-scan is simply skipped.
                continue
    return [p for _, p in sorted(found, reverse=True)]


def report_kind(path: Path) -> str:
    """``KIND_CRASH`` or ``KIND_BUG`` for a saved report, from its filename prefix.
    Kept here beside the prefix table so the naming rule has one owner."""
    return KIND_BUG if path.name.startswith(_FILENAME_PREFIX[KIND_BUG]) else KIND_CRASH


def _write_markdown_twin(report: dict[str, Any], json_path: Path) -> None:
    """Best-effort human-readable ``.md`` beside the JSON. Guarded: the JSON is the
    authoritative artefact, so a Markdown failure must not sink the report."""
    try:
        from app.sanitize import render_markdown
        md_path = json_path.with_suffix(".md")
        md_path.write_text(render_markdown(report), encoding="utf-8-sig")
    except Exception:  # noqa: BLE001 - the JSON already succeeded; the twin is a convenience.
        log.debug("Could not render Markdown crash twin", exc_info=True)


def capture_exception(
    context: dict[str, Any] | None = None,
    *,
    cfg: CrashConfig = _DEFAULT_CONFIG,
) -> Path | None:
    """Write a report for the exception currently being handled (``sys.exc_info``).

    For the broad ``except Exception:`` blocks that log-and-``return`` an exit
    code and so never reach ``sys.excepthook``. The active traceback still holds
    every frame down to the crash site, so all locals are captured.
    """
    exc_type, exc, tb = sys.exc_info()
    if exc is None or exc_type is None:
        return None
    return write_crash_report(exc_type, exc, tb, context=context, cfg=cfg)


_installed = False


def install_excepthook(context: dict[str, Any] | None = None) -> None:
    """Install the crash handler on ``sys.excepthook`` and ``threading.excepthook``,
    chaining the previous hooks so the normal stderr traceback still prints.
    Idempotent."""
    global _installed
    if _installed:
        return

    previous_sys_hook = sys.excepthook

    def _sys_hook(exc_type: type[BaseException], exc: BaseException, tb: Any) -> None:
        write_crash_report(exc_type, exc, tb, context=context)
        previous_sys_hook(exc_type, exc, tb)

    sys.excepthook = _sys_hook

    previous_thread_hook = threading.excepthook

    def _thread_hook(args: threading.ExceptHookArgs) -> None:
        thread_ctx = dict(context or {})
        if args.thread is not None:
            thread_ctx["thread"] = args.thread.name
        if args.exc_value is not None:
            write_crash_report(
                args.exc_type, args.exc_value, args.exc_traceback, context=thread_ctx
            )
        previous_thread_hook(args)

    threading.excepthook = _thread_hook
    _installed = True
