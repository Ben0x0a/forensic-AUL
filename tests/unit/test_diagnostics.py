"""Unit tests for the crash-report engine — app/diagnostics.py + app/sanitize.py.

Cover the three things that must not regress: (1) the sensitivity CLASSIFIER puts
PII (typed domain objects, named fields, filesystem paths) in the ``sensitive``
bucket and tuning knobs in ``safe``; (2) the SUMMARISER caps size and never raises,
even on a value with a hostile ``__repr__``; and (3) the SHARE path redacts every
planted secret — no plaintext PII survives ``redact_report``.

The domain types are recognised by NAME, so the tests use local stand-ins named
like the real ones (``DeviceInfo``, ``CaseInfo``, ``Connection``) — no library
import is needed, which is exactly the property that keeps the handler robust.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from app import diagnostics
from app.diagnostics import SAFE, SENSITIVE, CrashConfig, classify
from app.sanitize import anonymise_path, redact_report, render_markdown


# ── stand-ins for the real domain / runtime types (matched by class name) ──────

@dataclass
class CaseInfo:                       # matches SENSITIVE_TYPE_NAMES
    case_number: str
    imei: str
    notes: str


class Connection:                     # matches _LARGE_TYPE_NAMES (sqlite3.Connection)
    def __init__(self, rows: int) -> None:
        self._pending = list(range(rows))

    def __repr__(self) -> str:
        return "<sqlite Connection>"


class Hostile:
    """A value whose repr raises — the handler must survive it."""

    def __repr__(self) -> str:
        raise ValueError("repr exploded")


def _raise(exc: BaseException):
    """Raise inside a real frame so the traceback carries locals to capture."""
    try:
        raise exc
    except type(exc):
        import sys
        return sys.exc_info()


# ── classifier ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name", ["imei", "password", "notes", "device_name", "ssid"])
def test_classify_sensitive_by_name(name):
    assert classify(name, "whatever") == SENSITIVE


def test_classify_sensitive_by_type():
    case = CaseInfo(case_number="C1", imei="123", notes="x")
    assert classify("anything", case) == SENSITIVE


def test_classify_path_is_sensitive():
    assert classify("out", Path("/evidence/x.logarchive")) == SENSITIVE


@pytest.mark.parametrize("name,value", [("batch_size", 10_000), ("count", 3), ("ok", True)])
def test_classify_safe(name, value):
    assert classify(name, value) == SAFE


# ── summariser ─────────────────────────────────────────────────────────────────

def test_long_string_summarised_with_hash():
    cfg = CrashConfig(max_string_len=10)
    out = diagnostics._summarise("x" * 50, cfg, cfg.max_depth)
    assert out["truncated"] is True and out["len"] == 50 and "sha256" in out


def test_large_object_not_dumped():
    out = diagnostics._summarise(Connection(10_000), CrashConfig(), 4)
    assert out["not_dumped"] is True
    assert out["_pending_len"] == 10_000  # size hint, not the 10k rows themselves


def test_summariser_survives_hostile_repr():
    out = diagnostics._summarise(Hostile(), CrashConfig(), 4)
    assert "repr_error" in out  # captured, not raised


def test_noise_variables_are_dropped(tmp_path):
    exc_type, exc, tb = _raise(RuntimeError("boom"))
    report = diagnostics._build_report(exc_type, exc, tb, CrashConfig(), None)
    crash_frame = report["frames"][-1]["locals"]
    all_names = {*crash_frame[SAFE], *crash_frame[SENSITIVE]}
    assert "__name__" not in all_names  # dunders / modules / functions filtered out


# ── end-to-end write + two-section split ───────────────────────────────────────

def _write_sample(tmp_path: Path) -> Path:
    def crash():
        # These locals are deliberately "unused": they exist to be captured as
        # frame locals by the crash handler (hence the noqa).
        case = CaseInfo(case_number="CASE-42", imei="356938035643809", notes="private")  # noqa: F841
        conn = Connection(5)  # noqa: F841
        evidence = Path("/Users/someone/Evidence/phone.logarchive")
        secret_token = "hunter2"  # noqa: F841
        raise RuntimeError(f"failed on {evidence}")

    cfg = CrashConfig(crash_dir=tmp_path)
    try:
        crash()
    except Exception:  # noqa: BLE001
        return diagnostics.capture_exception({"entrypoint": "test"}, cfg=cfg)


def test_write_crash_report_splits_buckets(tmp_path):
    path = _write_sample(tmp_path)
    assert path is not None and path.exists()
    assert path.with_suffix(".md").exists()  # the human twin

    report = json.loads(path.read_text(encoding="utf-8-sig"))
    crash = report["frames"][-1]["locals"]
    assert "conn" in crash[SAFE]
    assert {"case", "evidence", "secret_token"} <= set(crash[SENSITIVE])


def test_capture_exception_without_active_exception_returns_none(tmp_path):
    assert diagnostics.capture_exception(cfg=CrashConfig(crash_dir=tmp_path)) is None


# ── redaction round-trip ───────────────────────────────────────────────────────

def test_redaction_removes_all_plaintext_pii(tmp_path):
    report = json.loads(_write_sample(tmp_path).read_text(encoding="utf-8-sig"))
    blob = json.dumps(redact_report(report))
    for planted in ("356938035643809", "hunter2", "someone", "CASE-42", "private"):
        assert planted not in blob, f"{planted!r} survived redaction"


def test_redaction_keeps_safe_values_and_marks_sensitive(tmp_path):
    report = json.loads(_write_sample(tmp_path).read_text(encoding="utf-8-sig"))
    red = redact_report(report)
    crash = red["frames"][-1]["locals"]
    assert crash[SAFE]["conn"]["not_dumped"] is True          # safe value intact
    assert crash[SENSITIVE]["case"]["redacted"] is True       # sensitive value hashed
    assert "sha256" in crash[SENSITIVE]["case"]


def test_render_markdown_has_template_sections(tmp_path):
    report = json.loads(_write_sample(tmp_path).read_text(encoding="utf-8-sig"))
    md = render_markdown(redact_report(report))
    for heading in ("## Steps to reproduce", "## Expected vs actual", "review before sharing"):
        assert heading in md


# ── path anonymisation (the repo-root anchor) ──────────────────────────────────

def test_anonymise_path_relative_to_repo_root():
    inside = str(Path(diagnostics.__file__).resolve())  # <repo>/app/diagnostics.py
    assert anonymise_path(inside) == "app/diagnostics.py"


def test_anonymise_path_home_fallback():
    home_file = str(Path.home() / "secret" / "note.txt")
    assert anonymise_path(home_file) == "~/secret/note.txt"
