"""The iOS build table (forensic_aul/engine/ios_builds.json) and its generator.

Guards the data file's shape (every entry a build code mapped to a dotted
version, so a bad regeneration cannot ship) and the generator's merge rules:
union, never drop an entry, refuse a contradictory mapping. No network.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

from forensic_aul.engine.ios_builds import load_build_table

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "update_ios_builds.py"


def _script():
    spec = importlib.util.spec_from_file_location("update_ios_builds", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_entry_is_a_build_code_and_a_version():
    table = load_build_table()
    assert table, "the shipped table must not be empty"
    for build, version in table.items():
        assert re.fullmatch(r"\d{2}[A-Z]\d{1,4}[a-z]?", build), build
        assert re.fullmatch(r"\d{2}(\.\d+){1,2}", version), (build, version)


def test_merge_is_a_union_that_keeps_existing_entries():
    merge = _script().merge
    assert merge({"21F90": "17.5.1"}, {"22B91": "18.1.1"}) == {
        "21F90": "17.5.1", "22B91": "18.1.1"}
    assert merge({"21F90": "17.5.1"}, {}) == {"21F90": "17.5.1"}


def test_merge_refuses_a_contradictory_mapping():
    module = _script()
    with pytest.raises(module.ConflictError, match="21F90"):
        module.merge({"21F90": "17.5.1"}, {"21F90": "17.5"})
