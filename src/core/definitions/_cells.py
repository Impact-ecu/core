"""Cell decoding and encoding (SPEC-003 R7, R12-R15), with integer arithmetic only (R120)."""

from fractions import Fraction
from typing import Literal

from core.definitions._errors import DefinitionError, ensure
from core.definitions._model import Dtype, Scaling

type NonFinite = Literal["non_finite"]
type Value = Fraction | NonFinite
NON_FINITE: NonFinite = "non_finite"

_EXPONENT_MASK = 0xFF
_FRACTION_BITS = 23
_SIGN_BIT = 0x80000000
_INFINITY = 0x7F800000
# R13: the rounding boundary above the largest finite binary32 (2**128 - 2**104).
_FLOAT_LIMIT = Fraction(2**128 - 2**103)
_TWO = Fraction(2)


def _order(dtype: Dtype) -> Literal["little", "big"]:
    # Explicit byte order, never native (SPEC-001 R70). A single byte reads the same either way.
    return "little" if dtype.byte_order == "le" else "big"


def _binary32_value(pattern: int) -> Fraction | None:
    exponent = (pattern >> _FRACTION_BITS) & _EXPONENT_MASK
    fraction = pattern & ((1 << _FRACTION_BITS) - 1)
    sign = -1 if pattern & _SIGN_BIT else 1
    if exponent == _EXPONENT_MASK:
        return None
    if exponent == 0:
        return Fraction(sign * fraction, 1 << 149)
    return sign * ((1 << _FRACTION_BITS) | fraction) * _TWO ** (exponent - 150)


def decode_raw(dtype: Dtype, data: bytes) -> Fraction | None:
    """R7: the exact raw value of one cell, or None for a binary32 infinity or NaN."""
    ensure(len(data) == dtype.size, "SPEC-003 R7")
    if dtype.kind == "float":
        return _binary32_value(int.from_bytes(data, _order(dtype)))
    return Fraction(int.from_bytes(data, _order(dtype), signed=dtype.kind == "int"))


def raw_to_physical(scaling: Scaling, raw: Fraction) -> Fraction:
    """R12."""
    return scaling.factor * raw + scaling.addend


def decode_cell(dtype: Dtype, scaling: Scaling, data: bytes) -> Value:
    raw = decode_raw(dtype, data)
    return NON_FINITE if raw is None else raw_to_physical(scaling, raw)


def round_half_even(value: Fraction) -> int:
    floor = value.numerator // value.denominator
    twice_remainder = 2 * (value.numerator - floor * value.denominator)
    if twice_remainder > value.denominator or (twice_remainder == value.denominator and floor % 2):
        return floor + 1
    return floor


def _binary32_pattern(value: Fraction) -> int:
    """R13: the binary32 nearest to `value`, ties to an even fraction field, zero as +0."""
    magnitude = abs(value)
    if magnitude >= _FLOAT_LIMIT:
        raise DefinitionError("out_of_range", "beyond the largest finite binary32")
    if magnitude == 0:
        return 0
    numerator, denominator = magnitude.numerator, magnitude.denominator
    exponent = numerator.bit_length() - denominator.bit_length()
    at_least = numerator >= denominator << exponent if exponent >= 0 else numerator << -exponent >= denominator
    if not at_least:
        exponent -= 1
    # Below 2**-126 the quantum stays 2**-149: the subnormal range continues the normal formula.
    exponent = max(exponent, -126)
    quantum = exponent - _FRACTION_BITS
    mantissa = round_half_even(magnitude * _TWO**-quantum)
    pattern = ((exponent + 127) << _FRACTION_BITS) + mantissa - (1 << _FRACTION_BITS)
    ensure(0 <= pattern < _INFINITY, "SPEC-003 R13")
    if pattern and value < 0:
        pattern |= _SIGN_BIT
    return pattern


def physical_to_raw(dtype: Dtype, scaling: Scaling, target: Fraction) -> int:
    """R13 for integer kinds: `round_half_even((target - addend) / factor)`, never clamped."""
    raw = round_half_even(_quotient(scaling, target))
    if dtype.kind == "int":
        low, high = -(1 << (dtype.bits - 1)), (1 << (dtype.bits - 1)) - 1
    else:
        low, high = 0, (1 << dtype.bits) - 1
    if not low <= raw <= high:
        raise DefinitionError("out_of_range", f"{raw} does not fit {dtype.kind}{dtype.bits}")
    return raw


def _quotient(scaling: Scaling, target: Fraction) -> Fraction:
    inverse = Fraction(scaling.factor.denominator, scaling.factor.numerator)
    return (target - scaling.addend) * inverse


def encode_cell(dtype: Dtype, scaling: Scaling, target: Fraction, current: bytes | None) -> bytes:
    """R13-R15: the bytes of a cell holding `target`. Current bytes that already decode to `target`
    are kept as they are (R15), so `-0` and untouched cells stay byte-identical."""
    if current is not None:
        raw = decode_raw(dtype, current)
        if raw is not None and raw_to_physical(scaling, raw) == target:
            return current
    if dtype.kind == "float":
        pattern = _binary32_pattern(_quotient(scaling, target))
        encoded = pattern.to_bytes(4, _order(dtype))
        _check_accuracy_float(scaling, target, pattern)
        return encoded
    raw_int = physical_to_raw(dtype, scaling, target)
    # R14: the result is within half a step of the target.
    ensure(2 * abs(raw_to_physical(scaling, Fraction(raw_int)) - target) <= abs(scaling.factor), "SPEC-003 R14")
    return raw_int.to_bytes(dtype.size, _order(dtype), signed=dtype.kind == "int")


def _check_accuracy_float(scaling: Scaling, target: Fraction, pattern: int) -> None:
    # R14 for binary32: within half a unit in the last place of the result, times |factor|.
    exponent = max((pattern >> _FRACTION_BITS) & _EXPONENT_MASK, 1)
    ulp = _TWO ** (exponent - 150)
    value = _binary32_value(pattern)
    ensure(
        value is not None and 2 * abs(raw_to_physical(scaling, value) - target) <= ulp * abs(scaling.factor),
        "SPEC-003 R14",
    )
