"""SPEC-003 R7, R12-R15 as properties. Oracles: `int.from_bytes`, `struct` with explicit byte order and
`fractions.Fraction` of the exact binary64 that holds each binary32; never the core's own decoder."""

import math
import struct
from fractions import Fraction
from typing import Literal

from hypothesis import assume, given
from hypothesis import strategies as st

from core.definitions import DefinitionError, Dtype, Scaling, decode_cell, encode_cell
from core.definitions._cells import decode_raw
from tests.properties.definition_strategies import INTEGER_DTYPES, Cells, cell_runs, rationals, scalings

F32 = {"be": Dtype("float", 32, "be"), "le": Dtype("float", 32, "le")}
IDENTITY = Scaling(Fraction(1), Fraction(0))


def binary32(pattern: int) -> Fraction | None:
    """Independent decoder: struct (explicit big-endian) to a binary64 float, exact as a Fraction."""
    value = struct.unpack(">f", pattern.to_bytes(4, "big"))[0]
    if math.isnan(value) or math.isinf(value):
        return None
    return Fraction(value)


def raw_range(dtype: Dtype) -> tuple[int, int]:
    if dtype.kind == "int":
        return -(1 << (dtype.bits - 1)), (1 << (dtype.bits - 1)) - 1
    return 0, (1 << dtype.bits) - 1


def order(dtype: Dtype) -> Literal["little", "big"]:
    return "little" if dtype.byte_order == "le" else "big"


# SPEC-003 R7, R12: integer cells decode by explicit byte order and two's complement.
@given(st.sampled_from(INTEGER_DTYPES), st.data(), scalings)
def test_integer_decode_matches_int_from_bytes(dtype: Dtype, data: st.DataObject, scaling: Scaling) -> None:
    raw_bytes = data.draw(st.binary(min_size=dtype.size, max_size=dtype.size))
    raw = int.from_bytes(raw_bytes, "little" if dtype.byte_order == "le" else "big", signed=dtype.kind == "int")
    assert decode_raw(dtype, raw_bytes) == raw
    assert decode_cell(dtype, scaling, raw_bytes) == scaling.factor * raw + scaling.addend


# SPEC-003 R14: raw -> physical -> raw is the identity for every raw value of an integer dtype.
@given(st.sampled_from(INTEGER_DTYPES), st.data(), scalings)
def test_integer_round_trip_is_exact(dtype: Dtype, data: st.DataObject, scaling: Scaling) -> None:
    low, high = raw_range(dtype)
    raw = data.draw(st.integers(low, high))
    expected = raw.to_bytes(dtype.size, "little" if dtype.byte_order == "le" else "big", signed=dtype.kind == "int")
    assert encode_cell(dtype, scaling, scaling.factor * raw + scaling.addend, None) == expected


# SPEC-003 R13, R14: half-even rounding to the nearest raw value, never clamped.
@given(st.sampled_from(INTEGER_DTYPES), scalings, rationals(10**12, 10**4))
def test_integer_encoding_is_nearest_half_even(dtype: Dtype, scaling: Scaling, target: Fraction) -> None:
    q = (target - scaling.addend) / scaling.factor
    floor = q.numerator // q.denominator
    below, above = q - floor, floor + 1 - q
    nearest = floor if below < above or (below == above and floor % 2 == 0) else floor + 1
    low, high = raw_range(dtype)
    try:
        encoded = encode_cell(dtype, scaling, target, None)
    except DefinitionError as error:
        reason: str | None = error.reason
    else:
        reason = None
    if reason is not None:
        assert reason == "out_of_range"
        assert not low <= nearest <= high
        return
    raw = int.from_bytes(encoded, "little" if dtype.byte_order == "le" else "big", signed=dtype.kind == "int")
    assert raw == nearest
    assert 2 * abs(scaling.factor * raw + scaling.addend - target) <= abs(scaling.factor)


finite_patterns = st.integers(0, 2**32 - 1).filter(lambda p: (p >> 23) & 0xFF != 0xFF)


# SPEC-003 R7: binary32 decodes to its exact value (subnormals included, -0 as 0); inf and NaN are non_finite.
@given(st.integers(0, 2**32 - 1), st.sampled_from(["be", "le"]))
def test_float_decode_is_exact(pattern: int, byte_order: str) -> None:
    dtype = F32[byte_order]
    assert decode_raw(dtype, pattern.to_bytes(4, order(dtype))) == binary32(pattern)


# SPEC-003 R13, R14: every finite binary32 (but -0) encodes back to its own pattern.
@given(finite_patterns.filter(lambda p: p != 0x80000000), st.sampled_from(["be", "le"]))
def test_float_patterns_round_trip(pattern: int, byte_order: str) -> None:
    dtype = F32[byte_order]
    value = binary32(pattern)
    assert value is not None
    assert encode_cell(dtype, IDENTITY, value, None) == pattern.to_bytes(4, order(dtype))


def _neighbours(pattern: int) -> list[int]:
    magnitude, sign = pattern & 0x7FFFFFFF, pattern & 0x80000000
    out = [sign | (magnitude + 1)] if magnitude < 0x7F7FFFFF else []
    return out + ([sign | (magnitude - 1)] if magnitude else [pattern ^ 0x80000000])


# SPEC-003 R13: the result is the nearest binary32, ties to an even fraction field; zero as +0.
@given(
    st.one_of(
        rationals(10**40, 10**40),
        st.builds(lambda m, e: Fraction(m) * Fraction(2) ** e, st.integers(-(2**26), 2**26), st.integers(-170, 110)),
    )
)
def test_float_encoding_is_nearest_even(target: Fraction) -> None:
    try:
        encoded = encode_cell(F32["be"], IDENTITY, target, None)
    except DefinitionError as error:
        reason: str | None = error.reason
    else:
        reason = None
    if reason is not None:
        assert reason == "out_of_range"
        assert abs(target) >= 2**128 - 2**103
        return
    pattern = int.from_bytes(encoded, "big")
    value = binary32(pattern)
    assert value is not None
    assert pattern != 0x80000000
    distance = abs(value - target)
    for other in _neighbours(pattern):
        other_value = binary32(other)
        assert other_value is not None
        assert distance <= abs(other_value - target)
        if distance == abs(other_value - target) and other_value != value:
            assert pattern % 2 == 0


# SPEC-003 R15: a cell whose bytes already decode to the target keeps its bytes (-0 and all).
@given(cell_runs(max_cells=1))
def test_unchanged_cells_keep_their_bytes(cells: Cells) -> None:
    value = decode_cell(cells.dtype, cells.scaling, cells.data)
    assume(not isinstance(value, str))
    assert not isinstance(value, str)
    assert encode_cell(cells.dtype, cells.scaling, value, cells.data) == cells.data
