"""Static checks on src/core/provenance (SPEC-005 R53, R55, R90, R91).

import-linter enforces the layers; this adds what it cannot express: no cryptographic library, no private key
in the public API, the kernel reached only through its public surface, and stable error reasons.
"""

import ast
import inspect
from pathlib import Path

import core.provenance
from core.provenance import ProvenanceError

PACKAGE = Path(core.provenance.__file__).resolve().parent
FILES = sorted(PACKAGE.glob("*.py"))
CRYPTO = {"cryptography", "nacl", "ed25519", "Crypto", "hmac", "secrets"}


def imported_modules(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add(node.module or "")
    return names


# SPEC-005 R55, R90: no Ed25519 or other cryptographic code; only `core.kernel`'s public API and never `core.gate`.
def test_provenance_imports() -> None:
    assert len(FILES) == 11
    for path in FILES:
        for name in imported_modules(path):
            assert name.split(".")[0] not in CRYPTO, f"{path.name}: {name}"
            if name.startswith("core."):
                assert name == "core.kernel" or name.startswith("core.provenance."), f"{path.name}: {name}"


# SPEC-005 R53: the private key never enters `core`; signing goes through an injected `Signer`.
def test_no_private_key_in_the_public_api() -> None:
    forbidden = ("private", "secret", "seed")
    for name in core.provenance.__all__:
        member = getattr(core.provenance, name)
        if callable(member) and not isinstance(member, type):
            for parameter in inspect.signature(member).parameters:
                assert not any(word in parameter for word in forbidden), f"{name}({parameter})"
    assert set(core.provenance.Signer.__dict__) >= {"key_id", "sign"}
    assert "verify" in core.provenance.Verifier.__dict__


# SPEC-005 R91: every rejection is a `ProvenanceError` subclass carrying a stable `reason`.
def test_errors_carry_a_reason() -> None:
    errors = [getattr(core.provenance, name) for name in core.provenance.__all__ if name.endswith("Error")]
    assert len(errors) == 6
    for error in errors:
        assert issubclass(error, ProvenanceError)
    assert ProvenanceError("bad_shape", "detail").reason == "bad_shape"
    assert str(ProvenanceError("bad_shape")) == "bad_shape"
