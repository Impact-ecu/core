"""Static checks on src/core/evidence (SPEC-006 R4, R5, R46, R49, R80, R111).

import-linter enforces the layers; this adds what it cannot express: no cryptographic or HMAC code (the commitment
secret and the attester keys never enter `core`), no personal-data field, and a test for every error reason.
"""

import ast
import inspect
from pathlib import Path

import core.evidence
from core.evidence import EvidenceError, parse_attestation
from tests.unit.evidence_support import TEMPLATE

PACKAGE = Path(core.evidence.__file__).resolve().parent
FILES = sorted(PACKAGE.glob("*.py"))
TESTS = Path(__file__).resolve().parents[1]
CRYPTO = {"cryptography", "nacl", "ed25519", "Crypto", "hmac", "secrets"}
STDLIB = {"collections", "dataclasses", "hashlib", "itertools", "re", "types", "typing"}
R80_REASONS = (
    "bad_shape",
    "bad_dtc",
    "bad_unit_id",
    "unpublished_dtc_set",
    "unpublished_head_policy",
    "registry_broken",
    "impact_oracle",
    "duplicate_record",
)


def imported_modules(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add(node.module or "")
    return names


# SPEC-006 R4, R46, R49: only the public APIs of core.kernel and core.provenance, the stdlib modules above, and no
# HMAC or signing code: `core` never holds the commitment secret nor computes a lookup key or a commitment.
def test_evidence_imports() -> None:
    assert len(FILES) == 9
    for path in FILES:
        for name in imported_modules(path):
            root = name.split(".")[0]
            assert root not in CRYPTO, f"{path.name}: {name}"
            if root == "core":
                assert name in {"core.kernel", "core.provenance"} or name.startswith("core.evidence."), name
            else:
                assert root in STDLIB, f"{path.name}: {name}"


# SPEC-006 R46, R49, SPEC-005 R53: no secret, private key or seed in the public API.
def test_no_secret_in_the_public_api() -> None:
    for name in core.evidence.__all__:
        member = getattr(core.evidence, name)
        if callable(member) and not isinstance(member, type):
            for parameter in inspect.signature(member).parameters:
                assert not any(word in parameter for word in ("private", "secret", "seed", "serial")), name


# SPEC-006 R5, R45, R102: the only per-unit value is the pseudonymous commitment; no VIN, serial, person or file.
def test_no_personal_data_fields() -> None:
    def keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return set(value) | {key for item in value.values() for key in keys(item)}
        return set()

    found = keys(parse_attestation(TEMPLATE).to_json())
    for word in ("vin", "serial", "email", "file", "owner", "customer", "person"):
        assert not any(word in key for key in found), word
    assert "ecu_commitment" in found


# SPEC-006 R80, R111: every reason is tested, and EvidenceError is the only error of the package.
def test_every_reason_has_a_test() -> None:
    sources = "".join(path.read_text(encoding="utf-8") for path in TESTS.rglob("test_evidence*.py"))
    sources += (TESTS / "vectors" / "test_spec_006_evidence.py").read_text(encoding="utf-8")
    for reason in R80_REASONS:
        assert f'"{reason}"' in sources, reason
    errors = [name for name in core.evidence.__all__ if name.endswith("Error")]
    assert errors == ["EvidenceError"]
    assert issubclass(EvidenceError, Exception)
