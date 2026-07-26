"""Unit tests for the file-level acquisition check — forensic_aul/testing/archive_compare.py.

Builds two tiny synthetic logarchives exercising every verdict (identical, append,
diverged, only-a, only-b) plus a differing wrapper file that must be ignored, and
asserts the classification + pass/fail.
"""

from __future__ import annotations

from pathlib import Path

from forensic_aul.testing.archive_compare import (
    APPEND,
    DIVERGED,
    IDENTICAL,
    ONLY_A,
    ONLY_B,
    compare_archives,
)


def _write(root: Path, rel: str, data: bytes) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


def _build_pair(tmp_path: Path) -> tuple[Path, Path]:
    a, b = tmp_path / "a.logarchive", tmp_path / "b.logarchive"
    # identical
    _write(a, "Persist/0001.tracev3", b"same-bytes")
    _write(b, "Persist/0001.tracev3", b"same-bytes")
    _write(a, "timesync/0000.timesync", b"ts")
    _write(b, "timesync/0000.timesync", b"ts")
    # append: b = a + more (live tail grew)
    _write(a, "Persist/0002.tracev3", b"aaaa")
    _write(b, "Persist/0002.tracev3", b"aaaabbbb")
    # diverged: same length, different content (a rewrite)
    _write(a, "Persist/0003.tracev3", b"xxxx")
    _write(b, "Persist/0003.tracev3", b"yyyy")
    # only in a (vanished) / only in b (new rotated current)
    _write(a, "Persist/0004.tracev3", b"only-a")
    _write(b, "Persist/0005.tracev3", b"only-b")
    # wrapper metadata that differs — must be ignored (not log-data)
    _write(a, "Info.plist", b"meta-a")
    _write(b, "Info.plist", b"meta-b-different-length")
    return a, b


def test_verdicts_and_fail_on_divergence(tmp_path):
    a, b = _build_pair(tmp_path)
    cmp = compare_archives(a, b, label_a="pmd3", label_b="collect")

    by_rel = {v.rel_path: v.status for v in cmp.verdicts}
    assert by_rel["Persist/0001.tracev3"] == IDENTICAL
    assert by_rel["timesync/0000.timesync"] == IDENTICAL
    assert by_rel["Persist/0002.tracev3"] == APPEND
    assert by_rel["Persist/0003.tracev3"] == DIVERGED
    assert by_rel["Persist/0004.tracev3"] == ONLY_A
    assert by_rel["Persist/0005.tracev3"] == ONLY_B
    # Info.plist is wrapper metadata → not a verdict, counted separately.
    assert "Info.plist" not in by_rel
    assert cmp.meta_files_a == 1 and cmp.meta_files_b == 1

    assert cmp.identical == 2 and cmp.append == 1
    assert len(cmp.diverged) == 1 and len(cmp.only_a) == 1 and len(cmp.only_b) == 1
    assert cmp.passed is False  # the diverged file fails it


def test_pass_when_only_identical_and_append(tmp_path):
    a, b = tmp_path / "a.logarchive", tmp_path / "b.logarchive"
    _write(a, "Persist/0001.tracev3", b"sealed")
    _write(b, "Persist/0001.tracev3", b"sealed")
    _write(a, "Persist/live.tracev3", b"head")
    _write(b, "Persist/live.tracev3", b"head-plus-appended-tail")
    _write(b, "Persist/new.tracev3", b"rotated-in")  # only_b — expected
    cmp = compare_archives(a, b)
    assert cmp.passed is True
    assert cmp.identical == 1 and cmp.append == 1 and len(cmp.only_b) == 1
