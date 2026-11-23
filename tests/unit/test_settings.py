"""Unit tests for app/settings.py — defaults < faul.toml < FAUL_* environment.

Covers : the precedence of the layers, the dataclasses as the only source of
         defaults (plus the app's jobs = 0 "auto"), nested sections, type and
         value checks, and that unknown keys / variables are refused with a hint.
Uses    : tmp_path config files and explicit env mappings (never os.environ).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.settings import SETTABLE_KEYS, SettingsError, load_settings
from forensic_aul import AcquireOptions, ExtractOptions, IdentifyOptions


def _config(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "faul.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_without_file_or_env_the_dataclass_defaults_apply(tmp_path):
    s = load_settings(tmp_path / "absent.toml", env={})
    assert s.extract == ExtractOptions(jobs=0)      # the app's one override: auto
    assert s.acquire == AcquireOptions()
    assert s.identify.still_seconds == IdentifyOptions().still_seconds
    assert s.identify.extract.batch_size == IdentifyOptions().extract.batch_size


def test_file_then_environment_each_replace_only_their_keys(tmp_path):
    path = _config(tmp_path, '[extract]\njobs = 4\nintegrity = "fingerprint"\n'
                             '[identify.extract]\nbatch_size = 5000\n')
    s = load_settings(path, env={"FAUL_EXTRACT_JOBS": "2", "FAUL_ACQUIRE_PACK": "no",
                                 "PATH": "/usr/bin"})
    assert s.extract.jobs == 2                       # env beats file
    assert s.extract.integrity == "fingerprint"      # file beats default
    assert s.extract.batch_size == ExtractOptions().batch_size
    assert s.acquire.pack is False
    assert s.identify.extract.batch_size == 5000     # nested section


def test_optional_numbers_accept_none_from_the_environment(tmp_path):
    s = load_settings(tmp_path / "absent.toml", env={"FAUL_ACQUIRE_SIZE_LIMIT": "none"})
    assert s.acquire.size_limit is None


@pytest.mark.parametrize("text, words", [
    ("[extract]\njbos = 8\n", "did you mean 'extract.jobs'"),
    ("[extract]\noverwrite = true\n", "unknown setting 'extract.overwrite'"),
    ("[extract]\njobs = \"many\"\n", "expected a whole number"),
    ("[extract]\nfts = 1\n", "expected true or false"),
    ("[extract]\nintegrity = \"most\"\n", "expected one of full, fingerprint, off"),
    ("[extract]\nbatch_size = 0\n", "at least 1"),
    ("[extract\n", "faul.toml"),
])
def test_bad_file_entries_are_refused(tmp_path, text, words):
    with pytest.raises(SettingsError) as caught:
        load_settings(_config(tmp_path, text), env={})
    assert words in str(caught.value)


def test_unknown_faul_variable_is_refused_with_a_hint(tmp_path):
    with pytest.raises(SettingsError, match="did you mean FAUL_EXTRACT_JOBS"):
        load_settings(tmp_path / "absent.toml", env={"FAUL_EXTRACT_JOB": "4"})


def test_every_problem_is_reported_at_once(tmp_path):
    path = _config(tmp_path, "[extract]\njobs = -1\nbatch_size = 0\n")
    with pytest.raises(SettingsError) as caught:
        load_settings(path, env={"FAUL_IDENTIFY_STILL_SECONDS": "soon"})
    assert len(caught.value.problems) == 3


def test_per_run_choices_cannot_be_settings():
    for key in ("extract.overwrite", "extract.audit_log", "extract.work_dir", "acquire.udid"):
        assert key not in SETTABLE_KEYS
