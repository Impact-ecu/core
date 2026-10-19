"""R100 import and call scan of a plugin's source text (SPEC-002 R47, R100, R124). Pure: text in, findings out."""

import ast

STDLIB_ALLOWED = frozenset(
    {
        "__future__",
        "abc",
        "binascii",
        "bisect",
        "collections",
        "collections.abc",
        "dataclasses",
        "enum",
        "functools",
        "hashlib",
        "heapq",
        "itertools",
        "operator",
        "re",
        "struct",
        "typing",
        "zlib",
    }
)
FORBIDDEN_CALLS = frozenset({"open", "exec", "eval", "compile", "__import__"})
INTERPRETER = "core.plugins.descriptor"


def _core_public(module: str) -> bool:
    # The public API of `core`: no private component, no `_internal` (SPEC-001 R8), no interpreter (R47).
    parts = module.split(".")
    private = any(part.startswith("_") for part in parts)
    return not private and module != INTERPRETER and not module.startswith(INTERPRETER + ".")


def import_allowed(module: str, package: str) -> bool:
    """R100: `core`'s public API, the plugin's own package, or an allowlisted standard-library module."""
    if module == "core" or module.startswith("core."):
        return _core_public(module)
    if module == package or module.startswith(package + "."):
        return True
    return module in STDLIB_ALLOWED


def scan_source(source: str, package: str) -> tuple[str, ...]:
    """Every R100 violation in one module of `package`, as `line: what`. A syntax error is a finding."""
    try:
        tree = ast.parse(source)
    except SyntaxError as error:
        return (f"{error.lineno}: syntax error",)
    findings: list[tuple[int, str]] = []
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.asname or alias.name.split(".")[0])
                if not import_allowed(alias.name, package):
                    findings.append((node.lineno, f"import {alias.name}"))
        elif isinstance(node, ast.ImportFrom):
            # A relative import stays inside the plugin package.
            module = node.module or ""
            if node.level == 0:
                names = [module, *(f"{module}.{alias.name}" for alias in node.names)]
                if not import_allowed(module, package) or INTERPRETER in names:
                    findings.append((node.lineno, f"from {module} import"))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            findings.extend(_call(node, node.func.id, modules))
    return tuple(f"{line}: {what}" for line, what in sorted(set(findings)))


def _call(node: ast.Call, name: str, modules: set[str]) -> list[tuple[int, str]]:
    if name in FORBIDDEN_CALLS:
        return [(node.lineno, f"{name}()")]
    target = node.args[0] if node.args else None
    if name == "getattr" and isinstance(target, ast.Name) and target.id in modules:
        return [(node.lineno, f"getattr on module {target.id}")]
    return []
