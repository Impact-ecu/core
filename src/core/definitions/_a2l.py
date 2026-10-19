"""A2L (ASAM MCD-2 MC): the conversion arithmetic of SPEC-003 R90 and R99 only.

The A2L converter itself is specified but not implemented (R99): the export template, the tokenizer
and most mapping rows wait for the ASAM standard text (§12, question 4). `import_a2l` and
`export_a2l` therefore refuse every call. What is implemented is the exact arithmetic between a
`COMPU_METHOD` and a `Scaling`, whose rows are confirmed (**C**) and which vectors A1 and A2 check.
"""

import math
from collections.abc import Sequence
from fractions import Fraction
from typing import NoReturn

from core.definitions._errors import DefinitionError
from core.definitions._model import Scaling
from core.definitions._rational import parse_a2l_number


def compu_method_scaling(conversion_type: str, coeffs: Sequence[str]) -> Scaling:
    """R90: `IDENTICAL`, `LINEAR` (`physical = a·raw + b`) and the affine case of `RAT_FUNC`, whose
    `COEFFS` map physical to internal: with `a = d = e = 0`, `physical = (f·raw - c) / b`."""
    values = [parse_a2l_number(text) for text in coeffs]
    if conversion_type == "IDENTICAL" and not values:
        return Scaling(Fraction(1), Fraction(0))
    if conversion_type == "LINEAR" and len(values) == 2:
        if values[0] == 0:
            raise DefinitionError("zero_factor", "LINEAR with a = 0")
        return Scaling(values[0], values[1])
    if conversion_type == "RAT_FUNC" and len(values) == 6:
        a, b, c, d, e, f = values
        if a == 0 and d == 0 and e == 0 and b != 0 and f != 0:
            inverse_b = Fraction(b.denominator, b.numerator)
            return Scaling(f * inverse_b, -c * inverse_b)
    raise DefinitionError("unsupported_conversion", f"{conversion_type} {list(coeffs)}")


def rat_func_coeffs(scaling: Scaling) -> tuple[int, int, int, int, int, int]:
    """R99: `COEFFS 0 b c 0 0 f` for factor p/q and addend r/s: f = p·s, c = -r·q, b = q·s, over their gcd."""
    p, q = scaling.factor.numerator, scaling.factor.denominator
    r, s = scaling.addend.numerator, scaling.addend.denominator
    f, c, b = p * s, -r * q, q * s
    divisor = math.gcd(b, c, f)
    return 0, b // divisor, c // divisor, 0, 0, f // divisor


def import_a2l(*_args: object) -> NoReturn:
    """Not implemented (R99, §12 question 4): refuses every input instead of guessing a mapping."""
    raise NotImplementedError("A2L import waits for the ASAM MCD-2 MC text (SPEC-003 R99, §12 question 4)")


def export_a2l(*_args: object) -> NoReturn:
    """Not implemented (R99, §12 question 4): the export template is not fixed yet."""
    raise NotImplementedError("A2L export waits for the ASAM MCD-2 MC text (SPEC-003 R99, §12 question 4)")
