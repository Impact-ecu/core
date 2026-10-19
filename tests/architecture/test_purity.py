"""Static checks on src/core (SPEC-001 R7-R9, R70, R71; SPEC-000 §Four layers, layer 4).

import-linter forbids the obvious I/O modules; this test is stricter: an allowlist of standard-library
modules, no floating point, no native byte order, no dynamic code, and the public kernel surface.
"""

import ast
from pathlib import Path

import pytest

import core.kernel

SRC = Path(__file__).resolve().parents[2] / "src" / "core"
FILES = sorted(SRC.rglob("*.py"))

# ast: the SPEC-002 R100 scan of plugin source text (parsing only, never compiling or running it).
# fractions, math and unicodedata: exact rationals, gcd and NFC for SPEC-003 R3, R4, R99; xml: the
# expat reader of SPEC-003 R80, with every DTD hook turned into a rejection.
ALLOWED_STDLIB = {
    "ast",
    "bisect",
    "collections",
    "dataclasses",
    "fractions",
    "hashlib",
    "heapq",
    "math",
    "re",
    "typing",
    "unicodedata",
    "xml",
}
FORBIDDEN_CALLS = {"open", "eval", "exec", "compile", "__import__", "input", "print", "float", "globals", "vars"}


def tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_sources_found() -> None:
    assert len(FILES) >= 10


# SPEC-001 R71: only allowlisted standard-library modules, and nothing from outside `core`.
@pytest.mark.parametrize("path", FILES, ids=lambda p: str(p.relative_to(SRC)))
def test_imports_are_allowlisted(path: Path) -> None:
    for node in ast.walk(tree(path)):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "relative imports hide the layer being imported"
            names = [node.module or ""]
        else:
            continue
        for name in names:
            top = name.split(".")[0]
            assert top == "core" or top in ALLOWED_STDLIB, f"{path}: import {name}"


# SPEC-001 R70: no floating point and no native byte order; R71: no dynamic code or I/O builtins.
@pytest.mark.parametrize("path", FILES, ids=lambda p: str(p.relative_to(SRC)))
def test_no_float_no_native_order_no_dynamic_code(path: Path) -> None:
    for node in ast.walk(tree(path)):
        assert not (isinstance(node, ast.Constant) and isinstance(node.value, float | complex)), f"{path}: float"
        assert not (isinstance(node, ast.BinOp | ast.AugAssign) and isinstance(node.op, ast.Div)), (
            f"{path}: true division"
        )
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in FORBIDDEN_CALLS, f"{path}: {node.func.id}()"
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value[:1] in {"@", "="}:
            pytest.fail(f"{path}: string starting with a native struct byte-order marker: {node.value!r}")


# SPEC-001 R8, R9: the public kernel API exposes no byte view and no way to build a ReleasedImage.
def test_public_kernel_surface() -> None:
    exported = set(core.kernel.__all__)
    assert "view" not in exported
    assert not any("Released" in name for name in exported)
    assert all(hasattr(core.kernel, name) for name in exported)
