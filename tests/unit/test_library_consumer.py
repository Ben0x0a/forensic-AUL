"""Library-consumer test — use the built wheel exactly as a third-party tool would.

Covers : packaging (pyproject.toml → wheel contents) and the public API of the
         installed package (forensic_aul.__all__, run_extract, query_logs, errors),
         run from the WHEEL, not from the repository.
Uses    : ``uv build`` (skipped when uv is absent), a copy of the sources in
          tmp_path (the repository is never written to), a ``python -I`` child
          process, and tests/synthetic.py for the input archive.

WHY: the library's audience is other tools. A gap that only shows once the
package is installed (a module left out of the wheel, an import-time side
effect, a frontend dependency leaking in) is invisible to the in-repo tests.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from tests.synthetic import synthetic_sysdiagnose

_ROOT = Path(__file__).resolve().parents[2]
_BUILD_INPUTS = ("forensic_aul", "pyproject.toml", "LICENSE")

# Child-process script: imports the wheel (first on sys.path), exercises the
# public API and prints one JSON report. Kept as text so the child never sees
# the repository on its path.
_CONSUMER = r'''
import json, logging, sys
site, archive, out = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, site)
handlers_before = list(logging.getLogger().handlers)
import forensic_aul as fa
report = {
    "module_file": fa.__file__,
    "frontends_loaded": sorted(m for m in ("PySide6", "pymobiledevice3", "app", "launcher", "gui") if m in sys.modules),
    "root_handlers_changed": logging.getLogger().handlers != handlers_before,
    "missing_public_names": [n for n in fa.__all__ if not hasattr(fa, n)],
}
result = fa.run_extract(archive, f"{out}/case.db",
                        fa.CaseInfo(case_number="C1", imei="350000000000000"),
                        fa.ExtractOptions(integrity="off"))
report["entry_count"] = result.entry_count
report["db_exists"] = result.db_path.is_file()
report["query_rows"] = len(list(fa.query_logs(result.db_path)))
# The shipped knowledge base loads from the wheel with no argument.
kb = fa.load_kb()
report["kb_signatures"] = len(kb.signatures)
report["kb_root_in_site"] = kb.root.startswith(site)
# Plain-string paths, as most calling tools pass them.
report["export_rows"] = fa.run_export(str(result.db_path), f"{out}/all.csv").rows
try:
    fa.run_extract(f"{out}/absent.logarchive", f"{out}/x.db")
    report["missing_source_error"] = None
except Exception as exc:
    report["missing_source_error"] = [type(exc).__name__, isinstance(exc, fa.ForensicAULError)]
print(json.dumps(report))
'''


@pytest.fixture(scope="module")
def wheel(tmp_path_factory) -> Path:
    """Build the wheel once from a copy of the sources; return its path."""
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is not installed")
    work = tmp_path_factory.mktemp("wheel")
    src = work / "src"
    src.mkdir()
    for name in _BUILD_INPUTS:
        origin = _ROOT / name
        if origin.is_dir():
            shutil.copytree(origin, src / name, ignore=shutil.ignore_patterns("__pycache__"))
        else:
            shutil.copy2(origin, src / name)
    subprocess.run(
        [uv, "build", "--wheel", "--out-dir", str(work / "dist"), str(src)],
        check=True, capture_output=True, timeout=300,
    )
    (built,) = (work / "dist").glob("*.whl")
    return built


def test_wheel_ships_the_library_only(wheel):
    names = zipfile.ZipFile(wheel).namelist()
    assert "forensic_aul/py.typed" in names, "PEP 561 marker must ship"
    assert "forensic_aul/engine/parser/decoder_tables.py" in names
    assert "forensic_aul/knowledge_base/VERSION" in names, "the shipped KB must be package data"
    assert any(n.startswith("forensic_aul/knowledge_base/signatures/") for n in names)
    leaked = sorted({n.split("/")[0] for n in names} & {"app", "launcher", "gui", "tests", "scripts"})
    assert leaked == [], f"clone-and-run layers must not ship in the wheel: {leaked}"


def test_public_api_works_from_the_installed_wheel(wheel, tmp_path):
    site = tmp_path / "site"
    zipfile.ZipFile(wheel).extractall(site)
    archive = synthetic_sysdiagnose(tmp_path)
    script = tmp_path / "consumer.py"
    script.write_text(_CONSUMER, encoding="utf-8")

    completed = subprocess.run(
        [sys.executable, "-I", str(script), str(site), str(archive), str(tmp_path)],
        capture_output=True, text=True, timeout=300, cwd=tmp_path,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    report = json.loads(completed.stdout.strip().splitlines()[-1])

    assert Path(report["module_file"]).is_relative_to(site), "must test the wheel, not the repo"
    assert report["frontends_loaded"] == [], "importing the library must not pull a frontend"
    assert report["root_handlers_changed"] is False, "a library must not configure logging on import"
    assert report["missing_public_names"] == []
    assert (report["db_exists"], report["entry_count"], report["query_rows"]) == (True, 0, 0)
    assert report["export_rows"] == 0
    assert report["kb_signatures"] > 0 and report["kb_root_in_site"] is True
    assert report["missing_source_error"] == ["SourceError", True]
