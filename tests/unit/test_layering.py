"""Layer contract — the import rules between the project's bricks, as a test.

Covers : every first-party module under forensic_aul/, app/, launcher/, gui/.
Uses    : the standard library only (ast over the source files); nothing is imported.

Rules (see tasks/review_2026-11.md, Phase 0 / S2–S5, S10):
  1. The library (forensic_aul) never imports a frontend (app, launcher, gui).
  2. forensic_aul.engine depends only on itself, forensic_aul.config and
     forensic_aul.errors.
  3. Frontends import only the public API: forensic_aul (its __all__),
     forensic_aul.reports and, for validate-tool, forensic_aul.validation.
  4. No import cycles between bricks.
  5. An ops brick (forensic_aul.ops.<brick>) imports another brick only for its
     data (``models`` / ``options`` modules); chaining bricks is the job of
     forensic_aul.ops.workflows (S4).
  6. A GUI view or widget takes only data types and pure helpers from the library;
     every operation goes through the screen's controller (S6, G6).

WHY a ratchet: today's known violations are listed explicitly. A NEW violation
fails the test; so does a FIXED one still listed — remove it from the list in
the commit that fixes it, so the list can only shrink. Lazy (function-level)
imports count: they are still a structural dependency.
"""

from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_PACKAGES = ("forensic_aul", "app", "launcher", "gui")
_FRONTENDS = ("app", "launcher", "gui")
_ENGINE_MAY_IMPORT = ("forensic_aul.engine", "forensic_aul.config", "forensic_aul.errors", "forensic_aul._version")


# ── Known violations (the ratchet) ─────────────────────────────────────────────
# Rule 3 — frontend → engine edges, as (importing file, imported module).
# Rule 3 — what a frontend may import from the library: the public API and the
# renderers; the QA tool only for the validate-tool command. No exception.
_FRONTEND_MAY_IMPORT = ("forensic_aul.reports", "forensic_aul.validation")
# Rule 4 — cycles between bricks, each as the set of bricks in one cycle.
_KNOWN_CYCLES: set[frozenset[str]] = set()  # none left — keep it that way

# Rule 5 — (importing module, imported module).
_KNOWN_BRICK_TO_BRICK: set[tuple[str, str]] = set()  # none left — keep it that way
_DATA_MODULES = ("models", "options")


# ── Import graph ───────────────────────────────────────────────────────────────

def _module_name(path: Path) -> str:
    parts = list(path.relative_to(_ROOT).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _source_files() -> list[Path]:
    return [
        path
        for pkg in _PACKAGES
        for path in sorted((_ROOT / pkg).rglob("*.py"))
        if "__pycache__" not in path.parts
    ]


def _imports(path: Path, modules: set[str]) -> set[str]:
    """Every first-party *module* *path* imports, at any nesting level.

    ``from pkg import x`` imports the module ``pkg.x`` when that module exists,
    otherwise the name ``x`` from ``pkg`` (so the dependency is on ``pkg``).
    """
    found: set[str] = set()
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            for alias in node.names:
                sub = f"{node.module}.{alias.name}"
                found.add(sub if sub in modules else node.module)
    return {name for name in found if name in modules}


def _graph() -> dict[str, set[str]]:
    """file (repo-relative, posix) → first-party modules it imports."""
    files = _source_files()
    modules = {_module_name(path) for path in files}
    return {path.relative_to(_ROOT).as_posix(): _imports(path, modules) for path in files}


def _brick(module: str) -> str:
    """The brick a module belongs to: forensic_aul.<layer>[.<sub>], app.<mod>, gui.<pkg>, launcher."""
    parts = module.split(".")
    if parts[0] == "forensic_aul":
        if len(parts) == 1:
            return "forensic_aul"
        if parts[1] in ("ops", "engine") and len(parts) > 2:
            return ".".join(parts[:3]) if parts[1] == "ops" else "forensic_aul.engine"
        return ".".join(parts[:2])
    if parts[0] == "launcher":
        return "launcher"
    return ".".join(parts[:2])


def _cycles(graph: dict[str, set[str]]) -> set[frozenset[str]]:
    """Strongly connected components (size > 1) of the brick-level graph."""
    edges: dict[str, set[str]] = defaultdict(set)
    for file, targets in graph.items():
        src = _brick(_module_name(_ROOT / file))
        for target in targets:
            dst = _brick(target)
            if dst != src:
                edges[src].add(dst)
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    result: set[frozenset[str]] = set()

    def visit(v: str) -> None:
        index[v] = low[v] = len(index)
        stack.append(v)
        on_stack.add(v)
        for w in edges.get(v, ()):
            if w not in index:
                visit(w)
                low[v] = min(low[v], low[w])
            elif w in on_stack:
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            component = set()
            while True:
                w = stack.pop()
                on_stack.discard(w)
                component.add(w)
                if w == v:
                    break
            if len(component) > 1:
                result.add(frozenset(component))

    for v in list(edges):
        if v not in index:
            visit(v)
    return result


# ── Rules ──────────────────────────────────────────────────────────────────────

def test_library_never_imports_a_frontend():
    bad = sorted(
        (file, target)
        for file, targets in _graph().items() if file.startswith("forensic_aul/")
        for target in targets if target.split(".")[0] in _FRONTENDS
    )
    assert bad == [], f"the library must not depend on a frontend: {bad}"


def test_engine_depends_only_on_engine_config_errors():
    bad = sorted(
        (file, target)
        for file, targets in _graph().items() if file.startswith("forensic_aul/engine/")
        for target in targets
        if target.startswith("forensic_aul") and not target.startswith(_ENGINE_MAY_IMPORT)
    )
    assert bad == [], f"engine must stay a leaf layer: {bad}"


def test_frontends_use_only_the_public_api():
    """S5: a frontend imports ``forensic_aul`` itself (plus the renderers and the
    QA tool), never an internal module — so moving one never breaks the CLI or the
    GUI, and what a frontend may rely on is exactly ``forensic_aul.__all__``."""
    deep = sorted(
        (file, target)
        for file, targets in _graph().items() if file.split("/")[0] in _FRONTENDS
        for target in targets
        if target.startswith("forensic_aul.") and not target.startswith(_FRONTEND_MAY_IMPORT)
    )
    assert not deep, f"frontend imports an internal module (use forensic_aul's public API): {deep}"


def test_no_new_import_cycles():
    actual = _cycles(_graph())
    new = [sorted(c) for c in actual - _KNOWN_CYCLES]
    fixed = [sorted(c) for c in _KNOWN_CYCLES - actual]
    assert not new, f"new import cycle between bricks: {new}"
    assert not fixed, f"cycle changed or fixed — update _KNOWN_CYCLES: {fixed}"


def _ops_brick(module: str) -> str | None:
    parts = module.split(".")
    if parts[:2] == ["forensic_aul", "ops"] and len(parts) > 2:
        return parts[2]
    return None


def test_ops_bricks_do_not_chain_each_other():
    graph = _graph()
    actual = set()
    for path, deps in graph.items():
        mod = path.removesuffix(".py").replace("/", ".")
        src = _ops_brick(mod)
        if src is None or src == "workflows":
            continue
        for dep in deps:
            dst = _ops_brick(dep)
            if dst is None or dst == src or dep.rsplit(".", 1)[-1] in _DATA_MODULES:
                continue
            actual.add((mod, dep))
    new = sorted(actual - _KNOWN_BRICK_TO_BRICK)
    fixed = sorted(_KNOWN_BRICK_TO_BRICK - actual)
    assert not new, f"a brick chains another brick — move it to ops/workflows: {new}"
    assert not fixed, f"fixed — remove from _KNOWN_BRICK_TO_BRICK: {fixed}"


# Rule 6 — what a GUI view or widget may take from the library: data types and
# pure helpers. Operations (open, extract, annotate, export, write…) belong to the
# screen's controller in gui/controllers (S6, G6).
_VIEW_MAY_IMPORT = frozenset({
    "LogFilter", "Match", "SignatureDraft",            # data the forms build
    "__version__", "default_kb_dir", "physical_cpu_count",  # pure helpers
    "AUTO_LOCK_ADVICE",                                 # shared operator text
})


def test_gui_views_call_no_library_operation():
    offending = []
    for path in sorted((_ROOT / "gui").rglob("*.py")):
        rel = path.relative_to(_ROOT).as_posix()
        if not rel.startswith(("gui/views/", "gui/widgets/")):
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and node.module == "forensic_aul":
                offending += [(rel, a.name) for a in node.names if a.name not in _VIEW_MAY_IMPORT]
    assert not offending, f"a view calls the library — move it to its controller: {offending}"
