"""Differential test: the one RFC 8785 encoder of the core against `rfc8785` and the encoders it replaced.

SPEC-001 R60, R65; SPEC-002 R9; SPEC-005 R1; SPEC-006 R1. The oracle for the bytes is the third-party
`rfc8785` package; `tests.differential.legacy_jcs` holds the four encoders as they were before unification, so
each caller's bytes and failure modes are shown unchanged on that caller's domain.
"""

from collections.abc import Callable, Mapping, Sequence
from typing import cast

import pytest
import rfc8785
from hypothesis import given
from hypothesis import strategies as st

from core.importers._json import freeze_json
from core.kernel import canonical_json, jcs
from core.provenance import Raw
from tests.differential import legacy_jcs

SAFE = 2**53 - 1

type Value = bool | int | str | Sequence[Value] | Mapping[str, Value] | None

# Keys and strings reach the astral planes so the UTF-16 key order of RFC 8785 §3.2.3 differs from code-point order.
_text = st.text(st.characters(codec="utf-8"), max_size=8)


def _values(scalars: st.SearchStrategy[Value], keys: st.SearchStrategy[str]) -> st.SearchStrategy[Value]:
    return st.recursive(
        scalars,
        lambda children: (
            st.lists(children, max_size=4)
            | st.lists(children, max_size=4).map(tuple)
            | st.dictionaries(keys, children, max_size=4)
        ),
        max_leaves=16,
    )


values = _values(st.none() | st.booleans() | st.integers(-SAFE, SAFE) | _text, _text)
kernel_values = _values(st.none() | st.integers(-SAFE, SAFE) | _text, _text)
# SPEC-006 R1, R2: what `freeze_json` admits, the only domain the importers encoder was defined on.
_ascii = st.text(st.characters(max_codepoint=127))
importer_values = _values(st.none() | st.booleans() | st.integers(0, SAFE) | _text, _ascii)


def _contains_bool(value: Value) -> bool:
    if isinstance(value, bool):
        return True
    if isinstance(value, Mapping):
        return any(_contains_bool(item) for item in value.values())
    if isinstance(value, Sequence) and not isinstance(value, str):
        return any(_contains_bool(item) for item in value)
    return False


# SPEC-001 R60; SPEC-006 R1: the unified encoder is RFC 8785 over null, booleans, safe integers, strings,
# arrays and objects.
@given(values)
def test_jcs_matches_rfc8785(value: Value) -> None:
    assert jcs(value) == rfc8785.dumps(value)


# SPEC-002 R9: byte-identical to the contract encoder it replaced.
@given(values)
def test_jcs_matches_legacy_contract_encoder(value: Value) -> None:
    assert jcs(value) == legacy_jcs.contract(value)


# SPEC-006 R1: byte-identical to the evidence encoder it replaced.
@given(values)
def test_jcs_matches_legacy_evidence_encoder(value: Value) -> None:
    assert jcs(value) == legacy_jcs.evidence(cast("Raw", value))


# SPEC-006 R1, R2: byte-identical to the importers encoder it replaced, on frozen values.
@given(importer_values)
def test_jcs_matches_legacy_importers_encoder(value: Value) -> None:
    frozen = freeze_json(value)
    assert jcs(frozen) == legacy_jcs.importers(frozen) == rfc8785.dumps(value)


# SPEC-001 R60, R65: kernel hash inputs keep the strict encoder, byte-identical to the old one and to `jcs`.
@given(kernel_values)
def test_canonical_json_matches_legacy_kernel_encoder(value: Value) -> None:
    assert canonical_json(value) == legacy_jcs.kernel(value) == jcs(value) == rfc8785.dumps(value)


# SPEC-001 R60: a boolean anywhere in a kernel hash input is rejected, as before.
@given(values.filter(_contains_bool))
def test_canonical_json_rejects_booleans(value: Value) -> None:
    with pytest.raises(TypeError):
        legacy_jcs.kernel(value)
    with pytest.raises(TypeError):
        canonical_json(value)


_REJECTED: list[tuple[object, type[Exception]]] = [
    (1.5, TypeError),
    (0.0, TypeError),
    ({"x": [1, 2.5]}, TypeError),
    (SAFE + 1, ValueError),
    (-SAFE - 1, ValueError),
    ([2**64], ValueError),
    (object(), TypeError),
    ("\ud800", UnicodeEncodeError),
    ({"\udfff": 1}, UnicodeEncodeError),
]


def _raises(encode: Callable[[object], bytes], value: object) -> type[Exception] | None:
    try:
        encode(value)
    except (TypeError, ValueError) as exc:
        return type(exc)
    return None


# SPEC-001 R60, SPEC-005 R1, SPEC-006 R1: values outside JCS fail with the same exception type as before;
# floats are never accepted.
@pytest.mark.parametrize(("value", "error"), _REJECTED)
def test_rejections_match_legacy_encoders(value: object, error: type[Exception]) -> None:
    unified = _raises(cast("Callable[[object], bytes]", jcs), value)
    strict = _raises(cast("Callable[[object], bytes]", canonical_json), value)
    assert unified is strict is error
    assert _raises(cast("Callable[[object], bytes]", legacy_jcs.contract), value) is error
    assert _raises(cast("Callable[[object], bytes]", legacy_jcs.evidence), value) is error
    assert _raises(cast("Callable[[object], bytes]", legacy_jcs.kernel), value) is error


# SPEC-001 R60: byte strings are hex-encoded before hashing. The kernel and contract encoders rejected them; the
# evidence encoder, whose `Raw` domain has no bytes, framed them as integer arrays. The unified encoder rejects them.
@pytest.mark.parametrize("value", [b"x", bytearray(b"x"), memoryview(b"x")])
def test_byte_strings_are_rejected(value: object) -> None:
    for encode in (jcs, canonical_json, legacy_jcs.kernel, legacy_jcs.contract):
        assert _raises(cast("Callable[[object], bytes]", encode), value) is TypeError
    assert legacy_jcs.evidence(cast("Raw", value)) == b"[120]"
