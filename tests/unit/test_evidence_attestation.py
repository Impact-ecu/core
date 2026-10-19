"""SPEC-006 §4: canonicalizers, the `FieldAttestation` shape and `verify_attestation` beyond the vectors."""

import copy
from collections.abc import Callable
from typing import Any, cast

import pytest
import rfc8785

from core.evidence import (
    EvidenceError,
    FieldAttestation,
    attestation_hash,
    canonical_dtcs,
    canonical_unit_id,
    parse_attestation,
    verify_attestation,
)
from core.evidence._errors import ensure
from core.evidence._json import encode as jcs
from core.evidence._json import try_jcs
from core.kernel import KernelError, KernelInvariantError
from core.provenance import ProvenanceError
from tests.unit.evidence_support import POOL, POST, PRE, TEMPLATE, A, R, attestation, sha, signed
from tests.unit.provenance_support import VERIFIER

NOT_A_STRING: Any = 7


def reason_of(call: Callable[[], object]) -> str:
    with pytest.raises(EvidenceError) as caught:
        call()
    return caught.value.reason


# SPEC-006 R43: ASCII whitespace and ASCII letters only; a non-string is not a DTC.
def test_canonical_dtcs_is_ascii_only() -> None:
    assert canonical_dtcs(["\tp062f\n", "P062F", "\x0bb3fff\x0c", "p0601-0a "]) == ["B3FFF", "P0601-0A", "P062F"]
    assert reason_of(lambda: canonical_dtcs(["\u00a0P0601"])) == "bad_dtc"
    assert reason_of(lambda: canonical_dtcs(["P0601\n-00"])) == "bad_dtc"
    assert reason_of(lambda: canonical_dtcs(["p0601-0\u0430"])) == "bad_dtc"
    assert reason_of(lambda: canonical_dtcs([NOT_A_STRING])) == "bad_dtc"


# SPEC-006 R45: separators removed, ASCII letters uppercased, 4 to 40 characters.
def test_canonical_unit_id_bounds() -> None:
    assert canonical_unit_id("ab-1.2") == "AB12"
    assert canonical_unit_id("a" * 40) == "A" * 40
    assert reason_of(lambda: canonical_unit_id("a" * 41)) == "bad_unit_id"
    assert reason_of(lambda: canonical_unit_id("-._/: ")) == "bad_unit_id"
    assert reason_of(lambda: canonical_unit_id("SNé0001")) == "bad_unit_id"
    assert reason_of(lambda: canonical_unit_id("SN0001\n")) == "bad_unit_id"
    assert reason_of(lambda: canonical_unit_id(NOT_A_STRING)) == "bad_unit_id"


def _with(path: tuple[str, ...], value: object) -> dict[str, Any]:
    changed = copy.deepcopy(TEMPLATE)
    target = changed
    for key in path[:-1]:
        target = target[key]
    if value is KeyError:
        del target[path[-1]]
    else:
        target[path[-1]] = value
    return changed


BAD_SHAPES = [
    (("schema",), "impact.field-attestation.v2"),
    (("schema",), KeyError),
    (("extra",), None),
    (("subject_image_hash",), "AA" * 32),
    (("identification", "family"), "Synthetic"),
    (("identification", "checksum_variant_id"), None),
    (("identification", "hw_id"), 1),
    (("identification", "sw_id"), "\ud800"),
    (("identification", "vin"), "WVW"),
    (("write_tool", "name"), " Flasher"),
    (("write_tool", "name"), "Flasher\n"),
    (("write_tool", "version"), ""),
    (("write_tool", "version"), "v" * 65),
    (("write_tool", "version"), 1),
    (("write_tool", "serial"), "1"),
    (("readback_image_hash",), "zz"),
    (("communicates",), 1),
    (("communicates",), None),
    (("dtcs_after_clear_and_reread",), ["P0602", "P0601"]),
    (("dtcs_after_clear_and_reread",), ["P0601", "P0601"]),
    (("dtcs_after_clear_and_reread",), ["p0601"]),
    (("dtcs_after_clear_and_reread",), "P0601"),
    (("tool_checksum_status",), "passed"),
    (("tool_checksum_status",), ["ok"]),
    (("ecu_commitment",), None),
    (("ecu_commitment_epoch",), None),
    (("ecu_commitment",), "SN0001X"),
    (("attester_key_id",), None),
    (("created_at",), "2026-10-18T14:00:00Z\n"),
    (("created_at",), "2026-10-18 14:00:00"),
]


# SPEC-006 R2, R3, R40, R43, R47: exactly the stated shape, else `bad_shape`; R5: no key for a VIN or serial.
@pytest.mark.parametrize(("path", "value"), BAD_SHAPES, ids=str)
def test_bad_shape(path: tuple[str, ...], value: object) -> None:
    changed = _with(path, value)
    assert reason_of(lambda: parse_attestation(changed)) == "bad_shape"
    assert reason_of(lambda: attestation_hash(changed)) == "bad_shape"
    wrapped: dict[str, Any] = {"attestation": changed, "attestation_hash": "00" * 32, "signature": "00" * 64}
    assert verify_attestation(wrapped, PRE, VERIFIER) == ["bad_shape"]


# SPEC-006 R40, R41, R44, R52: the forms that are valid at their limits; `communicates` is a JSON boolean.
def test_valid_limits() -> None:
    for path, value in [
        (("write_tool", "version"), "v" * 64),
        (("readback_image_hash",), None),
        (("identification", "hw_id"), None),
        (("identification", "sw_id"), ""),
        (("dtcs_after_clear_and_reread",), ["B3FFF", "P0601-00", "U0100"]),
        (("tool_checksum_status",), "not_reported"),
    ]:
        assert isinstance(parse_attestation(_with(path, value)), FieldAttestation)
    unit_less = attestation(A, None)
    parsed = parse_attestation(unit_less)
    assert (parsed.ecu_commitment, parsed.ecu_commitment_epoch) == (None, None)
    assert verify_attestation(signed(unit_less), PRE, VERIFIER) == []


# SPEC-006 R48: the hash is SHA-256 of the JCS (third-party rfc8785 here), and `to_json` is the input.
def test_hash_and_round_trip() -> None:
    parsed = parse_attestation(TEMPLATE)
    assert parsed.attestation_hash == attestation_hash(TEMPLATE) == sha(TEMPLATE) == POOL["AX"]["attestation_hash"]
    assert sha(parsed.to_json()) == sha(TEMPLATE)


# SPEC-006 R50: a signed attestation of any other shape is `bad_shape`, checked before anything else.
def test_signed_shape() -> None:
    good = POOL["AX"]
    variants: list[Any] = [
        None,
        [good],
        {**good, "extra": 1},
        {key: value for key, value in good.items() if key != "signature"},
        {**good, "attestation_hash": good["attestation_hash"].upper()},
        {**good, "signature": good["signature"][:-2]},
        {**good, "attestation": {**good["attestation"], "communicates": "true"}},
    ]
    for variant in variants:
        assert verify_attestation(variant, PRE, VERIFIER) == ["bad_shape"]


# SPEC-006 R50: `bad_signature` through the injected verifier; only a literal True is acceptance (SPEC-005 R55).
def test_verifier_must_return_true() -> None:
    class Truthy:
        def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
            return cast(bool, len(public_key) and len(message) and len(signature))

    assert verify_attestation(POOL["AX"], PRE, Truthy()) == ["bad_signature"]


# SPEC-006 R51: `created_at` is never compared; two attestations that differ only there both qualify.
def test_created_at_is_informational() -> None:
    early = signed(attestation(A, "X", created_at="1970-01-01T00:00:00Z"))
    late = signed(attestation(A, "X", created_at="2099-12-31T23:59:59Z"))
    assert verify_attestation(early, PRE, VERIFIER) == verify_attestation(late, PRE, VERIFIER) == []


# SPEC-006 R77: a retired key's attestation survives only through its own inclusion before the revocation.
def test_retired_key_needs_its_own_inclusion() -> None:
    ry = POOL["RY"]
    assert verify_attestation(ry, POST, VERIFIER) == []
    included = POST.inclusion(ry["attestation_hash"])
    assert included is not None
    assert included.attester_key_id == R.key_id
    unincluded = signed(attestation(R, "Y", created_at="2026-10-18T15:00:00Z"))
    assert verify_attestation(unincluded, POST, VERIFIER) == ["revoked_attester"]
    assert verify_attestation(unincluded, PRE, VERIFIER) == []


# SPEC-006 R111, R112: errors are not kernel or provenance errors; a failed assertion is a KernelInvariantError.
def test_errors_and_assertions() -> None:
    assert not issubclass(EvidenceError, KernelError | ProvenanceError)
    error = EvidenceError("bad_shape")
    assert (error.reason, error.detail, str(error)) == ("bad_shape", "", "bad_shape")
    assert str(EvidenceError("bad_dtc", "x")) == "bad_dtc: x"
    ensure(True, "SPEC-006 R50")
    with pytest.raises(KernelInvariantError) as caught:
        ensure(False, "SPEC-006 R50")
    assert caught.value.rule == "SPEC-006 R50"


# SPEC-006 R1: RFC 8785 with booleans (third-party rfc8785 as the reference); floats and unsafe integers never occur.
def test_canonical_json() -> None:
    value: dict[str, Any] = {
        "b": [True, False, None],
        "a": {"\u00e9": 1, "z": "\u20ac\n"},
        "\U0001f600": 0,
        "\ufb01": 2,
    }
    assert jcs(value) == rfc8785.dumps(value)
    with pytest.raises(TypeError):
        jcs({"x": 1.5})
    with pytest.raises(ValueError, match="exact JSON range"):
        jcs([2**53])
    assert try_jcs({"x": 0.5}) is None
    assert try_jcs(["\ud800"]) is None
