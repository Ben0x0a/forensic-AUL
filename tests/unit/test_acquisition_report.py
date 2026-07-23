"""Unit tests for the acquisition-sidecar helpers in
forensic_aul.ops.acquisition.report.

Cover the shared lookup used by the GUI's Extract / Verify-hash auto-fill:
``sidecar_path_for`` (suffix is appended, never substituted) and
``load_sidecar_for`` (best-effort: returns None for an absent or malformed file,
never raises).
"""

from __future__ import annotations

import json

from forensic_aul.ops.acquisition.report import (
    ACQUISITION_REPORT_SUFFIX,
    load_sidecar_for,
    sidecar_path_for,
)


def test_sidecar_path_appends_suffix_keeping_logarchive_ext(tmp_path):
    arc = tmp_path / "foo.logarchive"
    expected = tmp_path / ("foo.logarchive" + ACQUISITION_REPORT_SUFFIX)
    # The .logarchive extension must be kept (append, not with_suffix replace).
    assert sidecar_path_for(arc) == expected
    assert sidecar_path_for(arc).name == "foo.logarchive.acquisition.json"


def test_load_sidecar_returns_dict_when_present(tmp_path):
    arc = tmp_path / "case.logarchive"
    arc.mkdir()
    payload = {"acquisition": {"logarchive_sha256": "a" * 64}}
    sidecar_path_for(arc).write_text(json.dumps(payload), encoding="utf-8")

    report = load_sidecar_for(arc)
    assert report is not None
    assert report["acquisition"]["logarchive_sha256"] == "a" * 64


def test_load_sidecar_returns_none_when_absent(tmp_path):
    assert load_sidecar_for(tmp_path / "nope.logarchive") is None


def test_load_sidecar_returns_none_on_malformed_json(tmp_path):
    arc = tmp_path / "bad.logarchive"
    arc.mkdir()
    sidecar_path_for(arc).write_text("{ not valid json", encoding="utf-8")
    # Best-effort: a corrupt sidecar must not raise — auto-fill simply skips it.
    assert load_sidecar_for(arc) is None
