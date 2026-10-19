"""JCS edge cases (SPEC-001 R60, R65), error shape (R72) and the runtime invariant check (R73)."""

from typing import cast

import pytest
import rfc8785

from core.kernel import KernelError, KernelInvariantError, PreconditionConflict, ShapeError, canonical_json
from core.kernel._canonical import Json
from core.kernel._errors import ensure


# SPEC-001 R60: RFC 8785 §3.2.3 sorts keys by UTF-16 code units (the emoji sorts before U+FB33).
def test_key_order_is_utf16() -> None:
    value = {"€": 1, "\r": 2, "דּ": 3, "1": 4, "\U0001f600": 5, "\u0080": 6, "ö": 7}
    expected = rfc8785.dumps(value)
    assert canonical_json(value) == expected
    order = ["\r", "1", "\u0080", "ö", "€", "\U0001f600", "דּ"]
    assert expected == ("{" + ",".join(f'"{k}":{value[k]}' for k in order) + "}").replace("\r", "\\r").encode()


# SPEC-001 R60: control characters, quotes and backslashes are escaped as in JCS.
def test_string_escapes() -> None:
    text = 'a"b\\c\b\f\n\r\t\x00\x1f\x7f\u2028'
    assert canonical_json(text) == rfc8785.dumps(text)
    assert canonical_json(text) == b'"a\\"b\\\\c\\b\\f\\n\\r\\t\\u0000\\u001f\x7f\xe2\x80\xa8"'


# SPEC-001 R60: no booleans, floats, byte strings or integers beyond 2**53 - 1 in a hashed object.
@pytest.mark.parametrize(
    ("value", "error"),
    [
        (True, TypeError),
        (1.5, TypeError),
        (b"\x00", TypeError),
        (bytearray(b"\x00"), TypeError),
        (2**53, ValueError),
        (-(2**53), ValueError),
        ({1, 2}, TypeError),
    ],
)
def test_values_outside_the_domain_are_rejected(value: object, error: type[Exception]) -> None:
    with pytest.raises(error):
        canonical_json(cast(Json, value))


def test_nested_values() -> None:
    value: Json = {"b": [1, None, "x", ()], "a": {}}
    assert canonical_json(value) == b'{"a":{},"b":[1,null,"x",[]]}'


# SPEC-001 R72: every rejection is a KernelError with a stable machine reason.
def test_error_shape() -> None:
    error = ShapeError("bad_length", "detail")
    assert isinstance(error, KernelError)
    assert (error.reason, error.detail, str(error)) == ("bad_length", "detail", "bad_length: detail")
    assert str(ShapeError("empty_dump")) == "empty_dump"
    conflict = PreconditionConflict(3, "ab" * 32)
    assert (conflict.reason, conflict.index, conflict.patch_hash) == ("before_mismatch", 3, "ab" * 32)


# SPEC-001 R73: a failed runtime assertion raises, and stays active under `python -O`.
def test_ensure() -> None:
    ensure(holds=True, rule="SPEC-001 R24")
    with pytest.raises(KernelInvariantError) as caught:
        ensure(holds=False, rule="SPEC-001 R24")
    assert caught.value.rule == "SPEC-001 R24"
    assert str(caught.value) == "invariant_violation: SPEC-001 R24"
    assert not isinstance(caught.value, KernelError)
