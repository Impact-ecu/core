"""Hypothesis strategies for SPEC-003 objects. Every definition is synthetic (R47)."""

import unicodedata
from dataclasses import dataclass
from fractions import Fraction
from typing import cast

from hypothesis import strategies as st

from core.definitions import (
    AxisRef,
    Category,
    Definition,
    Dtype,
    FixedAxis,
    InlineAxis,
    License,
    MapDef,
    MapType,
    Origin,
    Scaling,
    SoftwareVersion,
    State,
    Unit,
)
from core.definitions._model import CATEGORIES, MAP_TYPES, STATES
from core.definitions._units import UNITS

DTYPES = (
    Dtype("uint", 8, "none"),
    Dtype("int", 8, "none"),
    Dtype("uint", 16, "le"),
    Dtype("uint", 16, "be"),
    Dtype("int", 16, "le"),
    Dtype("int", 16, "be"),
    Dtype("uint", 32, "le"),
    Dtype("uint", 32, "be"),
    Dtype("int", 32, "le"),
    Dtype("int", 32, "be"),
    Dtype("float", 32, "le"),
    Dtype("float", 32, "be"),
)
INTEGER_DTYPES = tuple(d for d in DTYPES if d.kind != "float")
UNIT_TEXTS = (
    "",
    "kPa",
    "°",
    "s",
    "us",
    "µs",
    "1/min",
    "°C",
    "λ",
    "%",
    "rpm",
    "RPM",
    "mg/stroke",
    'A&B<"x">',
    "Grad KW",
)

dtypes = st.sampled_from(DTYPES)


def rationals(numerator: int = 10**6, denominator: int = 10**3) -> st.SearchStrategy[Fraction]:
    return st.builds(Fraction, st.integers(-numerator, numerator), st.integers(1, denominator))


nonzero_rationals = rationals().filter(lambda q: q != 0)
decimals = st.builds(lambda n, places: Fraction(n, 10**places), st.integers(-(10**6), 10**6), st.integers(0, 4))
xdf_factors = st.one_of(decimals.filter(lambda q: q != 0), st.builds(Fraction, st.just(1), st.integers(1, 999)))
scalings = st.builds(Scaling, nonzero_rationals, rationals())
xdf_scalings = st.builds(Scaling, xdf_factors, decimals)


@st.composite
def units(draw: st.DrawFn) -> tuple[Unit | None, str | None]:
    if draw(st.booleans()):
        return cast(Unit, draw(st.sampled_from(sorted(UNITS)))), None
    return None, draw(st.sampled_from(UNIT_TEXTS))


def _nfc(text: str) -> bool:
    return unicodedata.normalize("NFC", text) == text


# R4 text that XML can carry: no C0/C1 controls, no surrogates, no U+FFFE/U+FFFF, NFC.
names = st.text(
    st.characters(blacklist_categories=("Cc", "Cs"), blacklist_characters="￾￿", max_codepoint=0x2FFFF),
    min_size=1,
    max_size=24,
).filter(_nfc)


@st.composite
def xdf_axes(draw: st.DrawFn, count: int, memory_size: int) -> AxisRef:
    unit, unit_text = draw(units())
    if draw(st.booleans()):
        values = tuple(draw(st.lists(decimals, min_size=count, max_size=count)))
        return FixedAxis(values, unit, unit_text)
    dtype = draw(dtypes)
    offset = draw(st.integers(0, memory_size - count * dtype.size))
    return InlineAxis("cal", offset, count, dtype, draw(xdf_scalings), unit, unit_text)


@st.composite
def xdf_mapdefs(draw: st.DrawFn, index: int, memory_size: int = 512) -> MapDef:
    """A map the XDF exporter accepts: memory `cal`, x_fastest, an axis on every dimension above 1."""
    rows, cols = draw(st.integers(1, 3)), draw(st.integers(1, 4))
    dtype = draw(dtypes)
    unit, unit_text = draw(units())
    x = draw(xdf_axes(cols, memory_size)) if cols > 1 or draw(st.booleans()) else None
    y = draw(xdf_axes(rows, memory_size)) if rows > 1 or draw(st.booleans()) else None
    return MapDef(
        map_id=f"syn.m{index}",
        name=draw(names),
        category=cast(Category | None, draw(st.sampled_from([None, *sorted(CATEGORIES)]))),
        map_type=cast(MapType | None, draw(st.sampled_from([None, *sorted(MAP_TYPES)]))),
        state=cast(State, draw(st.sampled_from(sorted(STATES)))),
        memory_id="cal",
        offset=draw(st.integers(0, memory_size - rows * cols * dtype.size)),
        rows=rows,
        cols=cols,
        cell_order="x_fastest",
        dtype=dtype,
        scaling=draw(xdf_scalings),
        unit=unit,
        unit_text=unit_text,
        x=x,
        y=y,
    )


@st.composite
def xdf_definitions(draw: st.DrawFn) -> Definition:
    count = draw(st.integers(0, 4))
    mapdefs: list[MapDef] = []
    places: set[tuple[str, int]] = set()
    for index in range(count):
        mapdef = draw(xdf_mapdefs(index))
        # R28: two maps with one name at one offset would re-import with one derived id.
        if (mapdef.name, mapdef.offset) not in places:
            places.add((mapdef.name, mapdef.offset))
            mapdefs.append(mapdef)
    return Definition(
        family_id="synthetic.platform",
        software_version=SoftwareVersion("prefix", ("SYN",)),
        axes=(),
        mapdefs=tuple(mapdefs),
        origin=Origin("platform", ()),
        license=License("platform_created", None),
        confidence_permille=draw(st.integers(0, 1000)),
    )


@dataclass(frozen=True)
class Cells:
    """A dtype, a scaling and the bytes of `count` cells."""

    dtype: Dtype
    scaling: Scaling
    data: bytes


@st.composite
def cell_runs(draw: st.DrawFn, max_cells: int = 12) -> Cells:
    dtype = draw(dtypes)
    count = draw(st.integers(1, max_cells))
    data = draw(st.binary(min_size=count * dtype.size, max_size=count * dtype.size))
    return Cells(dtype, draw(scalings), data)
