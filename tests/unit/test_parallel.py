"""Unit tests for forensic_aul/engine/utils/parallel.py and the parallel pass 1.

Covers : parallel_map returns results in input order whatever order the workers
         finish in, passes each worker a cancel token, and stops on cancellation;
         collect_oversize merges per-file results in file order (a later file
         wins), the same rule serial and parallel.
Uses    : module-level worker functions (they must pickle under spawn).
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from forensic_aul.engine.utils.cancellation import CancelToken
from forensic_aul.engine.utils.parallel import parallel_map
from forensic_aul.errors import OperationCancelled
from forensic_aul.ops.extraction import oversize_pass


def _slow_echo(item: str, cancel: CancelToken) -> str:
    # Earlier items sleep longer, so they finish LAST.
    time.sleep(0.05 * (3 - int(item)))
    cancel.check()
    return item * 2


def test_results_keep_input_order():
    assert parallel_map(_slow_echo, ["0", "1", "2"], 3) == ["00", "11", "22"]


def test_a_cancelled_map_raises():
    token = CancelToken()
    token.cancel()
    with pytest.raises(OperationCancelled):
        parallel_map(_slow_echo, ["0", "1"], 2, cancel=token)


def test_oversize_results_merge_in_file_order(monkeypatch):
    found = {"a": {("k",): "from a"}, "b": {("k",): "from b"}}
    monkeypatch.setattr(oversize_pass, "scan_oversize", lambda path, cancel: found[path.name])
    cache = oversize_pass.collect_oversize([Path("a"), Path("b")], jobs=1)
    assert cache == {("k",): "from b"}, "a later file wins, as in a single sequential scan"
