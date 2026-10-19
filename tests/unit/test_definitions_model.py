"""SPEC-003 §2-§4, §3.7, §3.8: construction rejections with their reasons, canonical JSON, labels, licensing."""

import hashlib
from collections.abc import Callable
from copy import deepcopy
from dataclasses import replace
from fractions import Fraction
from typing import Any, cast

import pytest
import rfc8785

from core.definitions import (
    AxisDef,
    Definition,
    DefinitionError,
    Distribution,
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
    State,
    axis_from_json,
    axis_json,
    axisdef_from_json,
    axisdef_json,
    definition_from_json,
    definition_hash,
    definition_json,
    derive_axis_id,
    derive_map_id,
    distribution,
    has_reviewed_category,
    mapdef_from_json,
    mapdef_json,
    revise,
    transition,
)
from core.definitions._model import CATEGORIES, MAP_TYPES, STATES, TRANSITIONS, resolve_axis
from core.definitions._units import UNITS
from tests.unit.definitions_fixtures import (
    AXIS_DEF,
    CREATED,
    FIXED3,
    IDENTITY,
    INLINE,
    PLATFORM,
    POINTER,
    SCALAR,
    SHARED_MAP,
    TABLE,
    U8,
    U32BE,
    UNVERIFIED,
    VERSION,
    definition,
)

F = Fraction
BIG = F(10**40)


BASE = Definition("synthetic.test", VERSION, (), (SCALAR,), PLATFORM, CREATED, 0)


def _definition(**changes: object) -> Definition:
    return replace(BASE, **cast("dict[str, Any]", changes))


def _mapdef(**changes: object) -> MapDef:
    return replace(SCALAR, **cast("dict[str, Any]", changes))


def _inline(**changes: object) -> InlineAxis:
    return replace(INLINE, **cast("dict[str, Any]", changes))


def _pointer(**changes: object) -> PointerAxis:
    return replace(POINTER, **cast("dict[str, Any]", changes))


CASES: list[tuple[str, str, Callable[[], object]]] = [
    # SPEC-003 R6
    ("unknown kind", "bad_dtype", lambda: Dtype(cast(Any, "bool"), 8, "none")),
    ("unknown byte order", "bad_dtype", lambda: Dtype("uint", 16, cast(Any, "native"))),
    ("64-bit cell", "bad_dtype", lambda: Dtype("uint", 64, "le")),
    ("boolean bits", "bad_dtype", lambda: Dtype("uint", cast(Any, True), "none")),
    ("byte order on 8 bits", "bad_dtype", lambda: Dtype("uint", 8, "le")),
    ("no byte order on 16 bits", "bad_dtype", lambda: Dtype("uint", 16, "none")),
    ("float16", "bad_dtype", lambda: Dtype("float", 16, "le")),
    # SPEC-003 R3, R10
    ("zero factor", "zero_factor", lambda: Scaling(F(0), F(0))),
    ("int factor", "bad_shape", lambda: Scaling(cast(Any, 1), F(0))),
    ("huge numerator", "rational_too_large", lambda: Scaling(BIG, F(0))),
    ("huge denominator", "rational_too_large", lambda: Scaling(F(1), 1 / BIG)),
    # SPEC-003 R2, R5, R17, R21 on axes
    ("memory id", "bad_identifier", lambda: _inline(memory_id="Cal")),
    ("negative offset", "bad_shape", lambda: _inline(offset=-1)),
    ("offset above 2**53 - 1", "bad_shape", lambda: _inline(offset=2**53)),
    ("boolean offset", "bad_shape", lambda: _inline(offset=True)),
    ("zero count", "bad_dims", lambda: _inline(count=0)),
    ("dtype not a Dtype", "bad_shape", lambda: _inline(dtype="u8")),
    ("scaling not a Scaling", "bad_shape", lambda: _inline(scaling=None)),
    ("unit and unit_text", "non_canonical", lambda: _inline(unit_text="rpm")),
    ("neither unit nor text", "non_canonical", lambda: _inline(unit=None)),
    ("unknown unit", "bad_shape", lambda: _inline(unit="furlong")),
    ("unit text too long", "bad_text", lambda: _inline(unit=None, unit_text="u" * 65)),
    ("unit text not a string", "bad_shape", lambda: _inline(unit=None, unit_text=5)),
    ("signed pointer", "bad_dtype", lambda: _pointer(pointer_dtype=Dtype("int", 32, "be"))),
    ("8-bit pointer", "bad_dtype", lambda: _pointer(pointer_dtype=U8)),
    ("pointer dtype not a Dtype", "bad_shape", lambda: _pointer(pointer_dtype=None)),
    ("target memory id", "bad_identifier", lambda: _pointer(target_memory_id="9")),
    ("pointer offset", "bad_shape", lambda: _pointer(pointer_offset=-4)),
    ("pointer count", "bad_dims", lambda: _pointer(count=0)),
    ("shared axis id", "bad_identifier", lambda: SharedAxis("Axis")),
    ("shared axis id too long", "bad_identifier", lambda: SharedAxis("a" * 65)),
    ("fixed values as a list", "bad_shape", lambda: FixedAxis(cast(Any, [F(1)]), "one", None)),
    ("fixed values as ints", "bad_shape", lambda: FixedAxis(cast(Any, (1,)), "one", None)),
    ("no fixed value", "bad_dims", lambda: FixedAxis((), "one", None)),
    ("huge fixed value", "rational_too_large", lambda: FixedAxis((BIG,), "one", None)),
    # SPEC-003 R4, R23 on axis definitions
    ("shared AxisDef", "bad_shape", lambda: AxisDef("syn.a", "A", cast(Any, SharedAxis("syn.b")))),
    ("empty name", "bad_text", lambda: AxisDef("syn.a", "", INLINE)),
    ("name not NFC", "bad_text", lambda: AxisDef("syn.a", "é", INLINE)),
    ("name with NUL", "bad_text", lambda: AxisDef("syn.a", "a\x00", INLINE)),
    ("name with DEL", "bad_text", lambda: AxisDef("syn.a", "a\x7f", INLINE)),
    ("name with C1 control", "bad_text", lambda: AxisDef("syn.a", "a\x85", INLINE)),
    ("name with lone surrogate", "bad_text", lambda: AxisDef("syn.a", "a\ud800", INLINE)),
    ("name too long", "bad_text", lambda: AxisDef("syn.a", "n" * 257, INLINE)),
    ("name not a string", "bad_shape", lambda: AxisDef("syn.a", cast(Any, 7), INLINE)),
    # SPEC-003 R5, R8, R18, R21, R26 on maps
    ("map id", "bad_identifier", lambda: _mapdef(map_id="M")),
    ("map id with space", "bad_identifier", lambda: _mapdef(map_id="a b")),
    ("unknown category", "bad_shape", lambda: _mapdef(category="fuel")),
    ("unknown map type", "bad_shape", lambda: _mapdef(map_type="table")),
    ("unknown state", "bad_shape", lambda: _mapdef(state="draft")),
    ("zero rows", "bad_dims", lambda: _mapdef(rows=0)),
    ("too many cols", "bad_dims", lambda: _mapdef(cols=65536)),
    ("rows as text", "bad_shape", lambda: _mapdef(rows="1")),
    ("unknown cell order", "bad_shape", lambda: _mapdef(cell_order="z_fastest")),
    ("y_fastest single row", "non_canonical", lambda: _mapdef(cols=2, cell_order="y_fastest")),
    ("y_fastest single col", "non_canonical", lambda: _mapdef(rows=2, cell_order="y_fastest")),
    ("x axis count", "dims_mismatch", lambda: _mapdef(cols=3, x=INLINE)),
    ("y axis count", "dims_mismatch", lambda: _mapdef(rows=2, y=FIXED3)),
    ("axis not an axis", "bad_shape", lambda: _mapdef(x="rpm")),
    ("map dtype", "bad_shape", lambda: _mapdef(dtype=None)),
    ("map scaling", "bad_shape", lambda: _mapdef(scaling=IDENTITY.factor)),
    ("map unit", "non_canonical", lambda: _mapdef(unit=None, unit_text=None)),
    # SPEC-003 R34
    ("unknown match", "bad_shape", lambda: SoftwareVersion(cast(Any, "regex"), ("A",))),
    ("versions as a list", "bad_shape", lambda: SoftwareVersion("exact", cast(Any, ["A"]))),
    ("no version", "bad_shape", lambda: SoftwareVersion("exact", ())),
    ("non-ASCII version", "bad_text", lambda: SoftwareVersion("exact", ("é",))),
    ("empty version", "bad_text", lambda: SoftwareVersion("exact", ("",))),
    ("version too long", "bad_text", lambda: SoftwareVersion("exact", ("v" * 65,))),
    ("unsorted versions", "non_canonical", lambda: SoftwareVersion("exact", ("B", "A"))),
    ("duplicate versions", "non_canonical", lambda: SoftwareVersion("prefix", ("A", "A"))),
    # SPEC-003 R37, R44
    ("unknown origin", "bad_shape", lambda: Origin(cast(Any, "scraped"), ())),
    ("derived_from not a hash", "bad_shape", lambda: Origin("platform", ("ABC",))),
    ("derived_from unsorted", "non_canonical", lambda: Origin("platform", ("b" * 64, "a" * 64))),
    ("unknown license", "bad_shape", lambda: License(cast(Any, "gpl"), None)),
    ("claimed license without reference", "bad_shape", lambda: License("verifiable_license", None)),
    ("empty reference", "bad_text", lambda: License("verifiable_license", "")),
    # SPEC-003 R5, R23, R28, R35, R36
    ("family id", "bad_identifier", lambda: _definition(family_id="Bosch.med17")),
    ("family id without dot", "bad_identifier", lambda: _definition(family_id="bosch")),
    ("software version type", "bad_shape", lambda: _definition(software_version="SYN0001")),
    ("axes as a list", "bad_shape", lambda: _definition(axes=[])),
    ("mapdef not a MapDef", "bad_shape", lambda: _definition(mapdefs=(mapdef_json(SCALAR),))),
    ("origin type", "bad_shape", lambda: _definition(origin="platform")),
    ("license type", "bad_shape", lambda: _definition(license=None)),
    ("confidence above 1000", "bad_shape", lambda: _definition(confidence_permille=1001)),
    ("negative confidence", "bad_shape", lambda: _definition(confidence_permille=-1)),
    ("duplicate axis id", "duplicate_axis_id", lambda: definition(SHARED_MAP, axes=(AXIS_DEF, AXIS_DEF))),
    ("duplicate map id", "duplicate_map_id", lambda: definition(SCALAR, replace(SCALAR, offset=1))),
    ("unknown shared axis", "unknown_axis", lambda: definition(SHARED_MAP)),
    ("shared axis count", "dims_mismatch", lambda: definition(replace(SHARED_MAP, cols=2), axes=(AXIS_DEF,))),
    ("orphan axis", "orphan_axis", lambda: definition(SCALAR, axes=(AXIS_DEF,))),
]


@pytest.mark.parametrize(("label", "reason", "build"), CASES, ids=[case[0] for case in CASES])
def test_invalid_shapes_are_rejected(label: str, reason: str, build: Callable[[], object]) -> None:
    with pytest.raises(DefinitionError) as caught:
        build()
    assert caught.value.reason == reason, label


# SPEC-003 R121: errors carry a stable reason and an optional detail and field.
def test_error_shape() -> None:
    assert str(DefinitionError("bad_shape")) == "bad_shape"
    error = DefinitionError("unrepresentable", "why", field="axes.x")
    assert (str(error), error.reason, error.detail, error.field) == (
        "unrepresentable: why",
        "unrepresentable",
        "why",
        "axes.x",
    )


# SPEC-003 R16, R18: the runtime sets are exactly the spec's lists.
def test_vocabularies_match_the_spec() -> None:
    assert {
        "deg_crank",
        "lambda",
        "kPa_abs",
        "kPa_rel",
        "mg_per_stroke",
        "percent",
        "rpm",
        "degC",
        "ms",
        "Nm",
        "one",
    } == UNITS
    assert len(CATEGORIES) == 14
    assert {"ignition", "lambda", "boost", "vvt", "fuel_trim_limit"} <= CATEGORIES
    assert {"base", "correction", "limit", "flag"} == MAP_TYPES
    assert {"potential", "imported", "proposed", "reviewed", "golden"} == STATES


# SPEC-003 R4: text is rejected, never normalized; the boundary lengths are accepted.
def test_text_boundaries() -> None:
    assert AxisDef("syn.a", "n" * 256, INLINE).name == "n" * 256
    assert AxisDef("syn.a", "Zündwinkel", INLINE).name == "Zündwinkel"
    assert _inline(unit=None, unit_text="").unit_text == ""
    assert _inline(unit=None, unit_text="u" * 64).unit_text == "u" * 64
    assert License("verifiable_license", "SPDX-License-Identifier: CC0-1.0").reference is not None


# SPEC-003 R34: matching is equality or prefix, never a regular expression.
def test_software_version_matching() -> None:
    exact = SoftwareVersion("exact", ("SYN.1", "SYN0002"))
    prefix = SoftwareVersion("prefix", ("SYN",))
    assert exact.matches("SYN.1")
    assert not exact.matches("SYNX1")
    assert not exact.matches("SYN0002A")
    assert prefix.matches("SYN0002A")
    assert not prefix.matches("SY")


# SPEC-003 R1, R50: every shape round-trips through its canonical JSON form.
@pytest.mark.parametrize("axis", [INLINE, POINTER, FIXED3, SharedAxis("syn.axis")], ids=lambda a: type(a).__name__)
def test_axis_json_round_trip(axis: InlineAxis | PointerAxis | FixedAxis | SharedAxis) -> None:
    assert axis_from_json(axis_json(axis)) == axis


def test_definition_json_round_trip() -> None:
    value = definition(TABLE, SHARED_MAP, axes=(AXIS_DEF,))
    assert definition_from_json(definition_json(value)) == value
    assert axisdef_from_json(axisdef_json(AXIS_DEF)) == AXIS_DEF
    assert mapdef_from_json(mapdef_json(TABLE)) == TABLE


GOOD = definition_json(definition(TABLE))
GOOD_MAP = mapdef_json(TABLE)


def _with(base: dict[str, Any], path: tuple[str | int, ...], value: object) -> dict[str, Any]:
    copy: Any = deepcopy(base)
    target = copy
    for key in path[:-1]:
        target = target[key]
    if value is _DELETE:
        del target[path[-1]]
    else:
        target[path[-1]] = value
    return cast(dict[str, Any], copy)


_DELETE = object()

JSON_CASES: list[tuple[str, str, Callable[[], object]]] = [
    ("not an object", "bad_shape", lambda: definition_from_json([])),
    ("unknown key", "bad_shape", lambda: definition_from_json(_with(GOOD, ("extra",), 1))),
    ("missing key", "bad_shape", lambda: definition_from_json(_with(GOOD, ("license",), _DELETE))),
    ("other spec", "bad_shape", lambda: definition_from_json(_with(GOOD, ("spec",), "SPEC-003/2"))),
    ("axes not an array", "bad_shape", lambda: definition_from_json(_with(GOOD, ("axes",), {}))),
    ("family id not a string", "bad_shape", lambda: definition_from_json(_with(GOOD, ("family_id",), 1))),
    ("confidence as text", "bad_shape", lambda: definition_from_json(_with(GOOD, ("confidence_permille",), "1"))),
    ("confidence as boolean", "bad_shape", lambda: definition_from_json(_with(GOOD, ("confidence_permille",), True))),
    ("reference not a string", "bad_shape", lambda: definition_from_json(_with(GOOD, ("license", "reference"), 1))),
    (
        "version not a string",
        "bad_shape",
        lambda: definition_from_json(_with(GOOD, ("software_version", "values", 0), 1)),
    ),
    ("dims key", "bad_shape", lambda: mapdef_from_json(_with(GOOD_MAP, ("dims", "depth"), 1))),
    ("axes key", "bad_shape", lambda: mapdef_from_json(_with(GOOD_MAP, ("axes", "z"), None))),
    ("decimal factor", "bad_rational", lambda: mapdef_from_json(_with(GOOD_MAP, ("scaling", "factor"), "0.5"))),
    ("numeric factor", "bad_rational", lambda: mapdef_from_json(_with(GOOD_MAP, ("scaling", "factor"), 1))),
    (
        "41-digit addend",
        "rational_too_large",
        lambda: mapdef_from_json(_with(GOOD_MAP, ("scaling", "addend"), "1" * 41)),
    ),
    ("bits as text", "bad_shape", lambda: mapdef_from_json(_with(GOOD_MAP, ("dtype", "bits"), "8"))),
    ("unit not a string", "bad_shape", lambda: mapdef_from_json(_with(GOOD_MAP, ("unit",), 1))),
    ("unit_text not a string", "bad_shape", lambda: mapdef_from_json(_with(GOOD_MAP, ("unit_text",), 1))),
    ("unknown axis source", "bad_shape", lambda: axis_from_json({"axis_source": "table"})),
    ("axis not an object", "bad_shape", lambda: axis_from_json("inline")),
    ("axis with extra key", "bad_shape", lambda: axis_from_json({"axis_source": "shared", "axis_id": "a", "x": 1})),
    (
        "fixed values not an array",
        "bad_shape",
        lambda: axis_from_json(_with(GOOD_MAP, ("axes", "y", "values"), "1")["axes"]["y"]),
    ),
    (
        "shared AxisDef",
        "bad_shape",
        lambda: axisdef_from_json({"axis_id": "a", "name": "A", "axis": {"axis_source": "shared", "axis_id": "b"}}),
    ),
]


@pytest.mark.parametrize(("label", "reason", "build"), JSON_CASES, ids=[case[0] for case in JSON_CASES])
def test_invalid_json_is_rejected(label: str, reason: str, build: Callable[[], object]) -> None:
    with pytest.raises(DefinitionError) as caught:
        build()
    assert caught.value.reason == reason, label


# SPEC-003 R28, R98: ids derived from sha256(JCS({memory_id, name, offset})), computed here with rfc8785.
def test_derived_ids() -> None:
    digest = hashlib.sha256(rfc8785.dumps({"memory_id": "cal", "name": "Zündwinkel", "offset": 7})).hexdigest()
    assert derive_map_id("cal", "Zündwinkel", 7) == "m_" + digest[:24]
    assert derive_axis_id("cal", "Zündwinkel", 7) == "a_" + digest[:24]


# SPEC-003 R52: the hash is over the canonical JSON, independent of the core's serializer.
def test_definition_hash_is_jcs_sha256() -> None:
    value = definition(TABLE, SHARED_MAP, axes=(AXIS_DEF,))
    assert definition_hash(value) == hashlib.sha256(rfc8785.dumps(definition_json(value))).hexdigest()


# SPEC-003 R23: a shared reference resolves to its AxisDef's axis; an unknown one is rejected.
def test_resolve_axis() -> None:
    value = definition(SHARED_MAP, axes=(AXIS_DEF,))
    assert resolve_axis(SharedAxis("syn.axis"), value) == INLINE
    assert resolve_axis(FIXED3, value) == FIXED3
    assert resolve_axis(None, value) is None
    with pytest.raises(DefinitionError) as caught:
        resolve_axis(SharedAxis("syn.other"), value)
    assert caught.value.reason == "unknown_axis"


PAIRS = [(a, b) for a in sorted(STATES) for b in sorted(STATES)]


# SPEC-003 R41: exactly the six transitions of the table are allowed.
@pytest.mark.parametrize(("current", "target"), PAIRS, ids=[f"{a}->{b}" for a, b in PAIRS])
def test_transitions(current: State, target: State) -> None:
    mapdef = replace(SCALAR, state=current)
    allowed = {
        ("potential", "proposed"),
        ("imported", "proposed"),
        ("proposed", "reviewed"),
        ("reviewed", "golden"),
        ("reviewed", "proposed"),
        ("golden", "proposed"),
    }
    assert allowed == TRANSITIONS
    if (current, target) in allowed:
        assert transition(mapdef, target) == replace(mapdef, state=target)
    else:
        with pytest.raises(DefinitionError) as caught:
            transition(mapdef, target)
        assert caught.value.reason == "bad_transition"


# SPEC-003 R29: any change other than state marks the map proposed; a state change alone is R41.
def test_revise() -> None:
    golden = replace(SCALAR, state="golden")
    assert revise(golden, golden) is golden
    assert revise(golden, replace(golden, offset=9)) == replace(golden, offset=9, state="proposed")
    assert revise(golden, replace(golden, offset=9, state="golden")).state == "proposed"
    assert revise(golden, replace(golden, state="proposed")) == replace(golden, state="proposed")
    with pytest.raises(DefinitionError) as caught:
        revise(golden, replace(golden, state="reviewed"))
    assert caught.value.reason == "bad_transition"


# SPEC-003 R42: reviewed or golden, with category, map type and unit; anything less is not.
def test_reviewed_category_contract() -> None:
    reviewed = replace(SCALAR, state="reviewed", category="ignition", map_type="base", unit="deg_crank")
    assert has_reviewed_category(reviewed)
    assert has_reviewed_category(replace(reviewed, state="golden"))
    assert not has_reviewed_category(replace(reviewed, state="proposed"))
    assert not has_reviewed_category(replace(reviewed, category=None))
    assert not has_reviewed_category(replace(reviewed, map_type=None))
    assert not has_reviewed_category(replace(reviewed, unit=None, unit_text="°"))


SOURCE_A, SOURCE_B = "a" * 64, "b" * 64


# SPEC-003 R45: shareable only with a claimed license and every source shareable; taint propagates.
@pytest.mark.parametrize(
    ("license_", "derived", "sources", "expected"),
    [
        (UNVERIFIED, (), {}, "local_only"),
        (CREATED, (), {}, "shareable"),
        (License("verifiable_license", "contract-7"), (SOURCE_A,), {SOURCE_A: "shareable"}, "shareable"),
        (CREATED, (SOURCE_A, SOURCE_B), {SOURCE_A: "shareable", SOURCE_B: "local_only"}, "local_only"),
        (CREATED, (SOURCE_A,), {}, "local_only"),
    ],
)
def test_distribution(
    license_: License, derived: tuple[str, ...], sources: dict[str, Distribution], expected: Distribution
) -> None:
    value = _definition(license=license_, origin=Origin("platform", derived))
    assert distribution(value, sources) == expected


# SPEC-003 R35: construction sorts axes and mapdefs; the order given never matters.
def test_definition_sorts_on_construction() -> None:
    a = definition(TABLE, SCALAR, SHARED_MAP, axes=(AXIS_DEF,))
    b = definition(SHARED_MAP, SCALAR, TABLE, axes=(AXIS_DEF,))
    assert a == b
    assert [m.map_id for m in a.mapdefs] == ["syn.scalar", "syn.shared", "syn.table"]
    assert definition_hash(a) == definition_hash(b)
    second = AxisDef("syn.axis2", "SYN_AXIS2", FIXED3)
    c = definition(SHARED_MAP, replace(TABLE, y=SharedAxis("syn.axis2")), axes=(second, AXIS_DEF))
    assert [x.axis_id for x in c.axes] == ["syn.axis", "syn.axis2"]
    assert U32BE.size == 4
