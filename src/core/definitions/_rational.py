"""Exact rationals: canonical text (SPEC-003 R3), XDF decimals (R74, R77) and A2L numbers (R91).

No floating point anywhere (R120): every value is a `fractions.Fraction` built from integers.
"""

import re
from fractions import Fraction

from core.definitions._errors import DefinitionError

MAX_DIGITS = 40
# CPython refuses int() of more than 4300 decimal digits. A mantissa longer than this, or a decimal
# exponent beyond _MAX_SCALE, cannot fit the 40-digit bound of a stored rational (R3) even after an
# R17 unit factor of 1000, so it is rejected before any big-integer work: the parsers stay linear.
_MAX_MANTISSA = 4000
_MAX_SCALE = 40000
_STORED_LIMIT = 10**40
_TEN = Fraction(10)
ASCII_WHITESPACE = " \t\r\n"

_CANONICAL = re.compile(r"-?(?:0|[1-9][0-9]*)(?:/[1-9][0-9]*)?")
_XDF_DECIMAL = re.compile(r"-?[0-9]+(?:\.[0-9]+)?")
_A2L_NUMBER = re.compile(r"[+-]?[0-9]+(?:\.[0-9]*)?(?:[eE][+-]?[0-9]+)?")


def parse_rational(text: object) -> Fraction:
    """Canonical rational text of R3 (SPEC-004 R30), reduced, within the stored bound."""
    if not isinstance(text, str) or _CANONICAL.fullmatch(text) is None or text == "-0":
        raise DefinitionError("bad_rational", repr(text))
    numerator, _, denominator = text.lstrip("-").partition("/")
    if len(numerator) > MAX_DIGITS or len(denominator) > MAX_DIGITS:
        raise DefinitionError("rational_too_large", repr(text))
    sign = -1 if text.startswith("-") else 1
    if not denominator:
        return Fraction(sign * int(numerator))
    value = Fraction(sign * int(numerator), int(denominator))
    if value.denominator != int(denominator) or value.denominator < 2:
        raise DefinitionError("bad_rational", f"{text!r} is not reduced, or its denominator is 1")
    return value


def rational_text(value: Fraction) -> str:
    """The canonical text of R3: `n` or `n/d`, reduced, no `-0`."""
    if value.denominator == 1:
        return str(value.numerator)
    return f"{value.numerator}/{value.denominator}"


def check_stored(value: Fraction, what: str) -> None:
    """R3: numerator and denominator of a stored rational have at most 40 decimal digits."""
    if abs(value.numerator) >= _STORED_LIMIT or value.denominator >= _STORED_LIMIT:
        raise DefinitionError("rational_too_large", what)


def _decimal(negative: bool, integer: str, fraction: str, exponent: int) -> Fraction:
    mantissa = integer.lstrip("0") + fraction.rstrip("0")
    if not mantissa:
        return Fraction(0)
    scale = exponent - len(fraction.rstrip("0"))
    if len(mantissa) > _MAX_MANTISSA or abs(scale) > _MAX_SCALE:
        raise DefinitionError("rational_too_large", f"{len(mantissa)} digits, scale {scale}")
    numerator = -int(mantissa) if negative else int(mantissa)
    return numerator * _TEN**scale


def parse_xdf_decimal(text: str) -> Fraction:
    """`-?[0-9]+(\\.[0-9]+)?`, exact (R74). The caller removes R61 whitespace first."""
    if _XDF_DECIMAL.fullmatch(text) is None:
        raise DefinitionError("bad_number", repr(text))
    integer, _, fraction = text.lstrip("-").partition(".")
    return _decimal(text.startswith("-"), integer, fraction, 0)


def parse_a2l_number(text: str) -> Fraction:
    """R91: `[+-]?[0-9]+(\\.[0-9]*)?([eE][+-]?[0-9]+)?`, exact. The `.5` form is a P row and is refused."""
    if _A2L_NUMBER.fullmatch(text) is None:
        raise DefinitionError("bad_number", repr(text))
    mantissa, _, exponent_text = text.replace("E", "e").partition("e")
    integer, _, fraction = mantissa.lstrip("+-").partition(".")
    digits = exponent_text.lstrip("+-").lstrip("0")
    # More than 6 exponent digits is beyond _MAX_SCALE whatever the mantissa; saturate before int().
    exponent = int(digits or "0") if len(digits) <= 6 else _MAX_SCALE * 2
    return _decimal(
        mantissa.startswith("-"), integer, fraction, -exponent if exponent_text.startswith("-") else exponent
    )


def finite_decimal_text(value: Fraction) -> str | None:
    """R77 decimal text (exact, no exponent, no trailing fractional zeros, `0` before the point),
    or None when `value` is not a finite decimal."""
    rest, twos, fives = value.denominator, 0, 0
    while rest % 2 == 0:
        rest //= 2
        twos += 1
    while rest % 5 == 0:
        rest //= 5
        fives += 1
    if rest != 1:
        return None
    places = max(twos, fives)
    digits = str((abs(value) * _TEN**places).numerator).rjust(places + 1, "0")
    integer, fraction = digits[: len(digits) - places], digits[len(digits) - places :].rstrip("0")
    return ("-" if value < 0 else "") + integer + ("." + fraction if fraction else "")
