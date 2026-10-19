"""Synthetic SPEC-003 objects for unit tests. No name, address or factor comes from a real definition (R47)."""

from dataclasses import replace
from fractions import Fraction

from core.definitions import (
    AxisDef,
    Definition,
    Dtype,
    FixedAxis,
    InlineAxis,
    License,
    MapDef,
    Origin,
    PointerAxis,
    Scaling,
    SharedAxis,
    SoftwareVersion,
)
from core.kernel import Dump, Memory

U8 = Dtype("uint", 8, "none")
I8 = Dtype("int", 8, "none")
U16BE = Dtype("uint", 16, "be")
U16LE = Dtype("uint", 16, "le")
U32BE = Dtype("uint", 32, "be")
U32LE = Dtype("uint", 32, "le")
F32BE = Dtype("float", 32, "be")
IDENTITY = Scaling(Fraction(1), Fraction(0))
QUARTER = Scaling(Fraction(1, 4), Fraction(0))

INLINE = InlineAxis("cal", 32, 4, U8, Scaling(Fraction(25), Fraction(0)), "rpm", None)
FIXED3 = FixedAxis((Fraction(10), Fraction(20), Fraction(30)), None, "kPa")
POINTER = PointerAxis("pflash", 0, U32BE, "cal", 4, U8, IDENTITY, None, "")

SCALAR = MapDef(
    map_id="syn.scalar",
    name="SYN_SCALAR",
    category=None,
    map_type=None,
    state="proposed",
    memory_id="cal",
    offset=0,
    rows=1,
    cols=1,
    cell_order="x_fastest",
    dtype=U8,
    scaling=IDENTITY,
    unit="one",
    unit_text=None,
    x=None,
    y=None,
)
TABLE = replace(SCALAR, map_id="syn.table", name="SYN_TABLE", offset=8, rows=3, cols=4, x=INLINE, y=FIXED3)
SHARED_MAP = replace(SCALAR, map_id="syn.shared", name="SYN_SHARED", offset=40, cols=4, x=SharedAxis("syn.axis"))
AXIS_DEF = AxisDef("syn.axis", "SYN_AXIS", INLINE)

VERSION = SoftwareVersion("exact", ("SYN0001",))
PLATFORM = Origin("platform", ())
CREATED = License("platform_created", None)
UNVERIFIED = License("unverified", None)


def definition(*mapdefs: MapDef, axes: tuple[AxisDef, ...] = ()) -> Definition:
    return Definition("synthetic.test", VERSION, axes, mapdefs, PLATFORM, CREATED, 500)


CAL = bytes(range(64))
PFLASH = bytes.fromhex("80001010") + bytes(12)
DUMP = Dump("virtual", (Memory("cal", 0x8000_1000, CAL), Memory("pflash", 0x8000_0000, PFLASH)))
