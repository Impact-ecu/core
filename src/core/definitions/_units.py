"""Canonical units and source-text mapping (SPEC-003 R16, R17)."""

from collections.abc import Callable, Sequence
from fractions import Fraction
from typing import Literal

Unit = Literal[
    "deg_crank", "lambda", "kPa_abs", "kPa_rel", "mg_per_stroke", "percent", "rpm", "degC", "ms", "Nm", "one"
]

# R16 "Export text and identity alias".
EXPORT_TEXT: dict[Unit, str] = {
    "deg_crank": "deg_crank",
    "lambda": "lambda",
    "kPa_abs": "kPa_abs",
    "kPa_rel": "kPa_rel",
    "mg_per_stroke": "mg/stroke",
    "percent": "%",
    "rpm": "rpm",
    "degC": "degC",
    "ms": "ms",
    "Nm": "Nm",
    "one": "1",
}
UNITS: frozenset[str] = frozenset(EXPORT_TEXT)

# R16: export texts (factor 1) plus the "other exact aliases". Pressure has none on purpose.
ALIASES: dict[str, tuple[Unit, Fraction]] = {text: (unit, Fraction(1)) for unit, text in EXPORT_TEXT.items()}
ALIASES.update(
    {
        "λ": ("lambda", Fraction(1)),
        "1/min": ("rpm", Fraction(1)),
        "°C": ("degC", Fraction(1)),
        "s": ("ms", Fraction(1000)),
        "us": ("ms", Fraction(1, 1000)),
        "µs": ("ms", Fraction(1, 1000)),
    }
)

type Exportable = Callable[[Fraction, Fraction, Sequence[Fraction]], bool]


def resolve_unit(
    text: str, factor: Fraction, addend: Fraction, values: Sequence[Fraction], exportable: Exportable
) -> tuple[Unit | None, str | None, Fraction]:
    """R17: `(unit, unit_text, k)`. Exact, case-sensitive match; an alias with `k != 1` applies only
    when `exportable(factor·k, addend·k, values·k)` holds for the importing format."""
    match = ALIASES.get(text)
    if match is not None:
        unit, k = match
        if k == 1 or exportable(factor * k, addend * k, [value * k for value in values]):
            return unit, None, k
    return None, text, Fraction(1)
