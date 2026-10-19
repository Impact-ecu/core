"""Data shapes of SPEC-003 §3, their canonical JSON (§4) and the label rules of §3.7 and §3.8.

Every shape validates on construction and never exists half-valid (R121). Rationals are
`fractions.Fraction` values; their JSON form is the canonical text of R3.
"""

import hashlib
import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from fractions import Fraction
from typing import Literal, TypeGuard, cast

from core.definitions._errors import DefinitionError, ensure
from core.definitions._rational import check_stored, parse_rational, rational_text
from core.definitions._units import UNITS, Unit
from core.kernel import canonical_json

type Json = int | str | Sequence[Json] | Mapping[str, Json] | None

Kind = Literal["uint", "int", "float"]
ByteOrder = Literal["le", "be", "none"]
CellOrder = Literal["x_fastest", "y_fastest"]
Category = Literal[
    "ignition",
    "lambda",
    "boost",
    "injection_quantity",
    "injector_duty",
    "injector_dead_time",
    "injector_flow",
    "rail_pressure",
    "torque_limit",
    "speed_limit",
    "egt_target",
    "vvt",
    "wastegate_duty",
    "fuel_trim_limit",
]
MapType = Literal["base", "correction", "limit", "flag"]
State = Literal["potential", "imported", "proposed", "reviewed", "golden"]
Match = Literal["exact", "prefix"]
OriginKind = Literal["platform", "xdf_import", "a2l_import", "damos_import", "heuristic", "sibling_realignment"]
LicenseKind = Literal["platform_created", "verifiable_license", "unverified"]
Distribution = Literal["shareable", "local_only"]

SPEC = "SPEC-003/1"
MAX_SAFE_INTEGER = 2**53 - 1
MAX_DIM = 65535

KINDS: frozenset[str] = frozenset({"uint", "int", "float"})
BYTE_ORDERS: frozenset[str] = frozenset({"le", "be", "none"})
CELL_ORDERS: frozenset[str] = frozenset({"x_fastest", "y_fastest"})
CATEGORIES: frozenset[str] = frozenset(
    {
        "ignition",
        "lambda",
        "boost",
        "injection_quantity",
        "injector_duty",
        "injector_dead_time",
        "injector_flow",
        "rail_pressure",
        "torque_limit",
        "speed_limit",
        "egt_target",
        "vvt",
        "wastegate_duty",
        "fuel_trim_limit",
    }
)
MAP_TYPES: frozenset[str] = frozenset({"base", "correction", "limit", "flag"})
STATES: frozenset[str] = frozenset({"potential", "imported", "proposed", "reviewed", "golden"})
MATCHES: frozenset[str] = frozenset({"exact", "prefix"})
ORIGIN_KINDS: frozenset[str] = frozenset(
    {"platform", "xdf_import", "a2l_import", "damos_import", "heuristic", "sibling_realignment"}
)
LICENSE_KINDS: frozenset[str] = frozenset({"platform_created", "verifiable_license", "unverified"})

# R41: allowed label transitions.
TRANSITIONS: frozenset[tuple[str, str]] = frozenset(
    {
        ("potential", "proposed"),
        ("imported", "proposed"),
        ("proposed", "reviewed"),
        ("reviewed", "golden"),
        ("reviewed", "proposed"),
        ("golden", "proposed"),
    }
)

_MEMORY_ID = re.compile(r"[a-z][a-z0-9_]{0,31}")  # SPEC-001 §2.1 MemoryId
_LOCAL_ID = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")  # R5 map_id, axis_id
_FAMILY_ID = re.compile(r"[a-z][a-z0-9]*(?:\.[a-z0-9][a-z0-9_]*)+")  # R5, SPEC-002 R2
_HASH = re.compile(r"[0-9a-f]{64}")
_PRINTABLE_ASCII = re.compile(r"[\x20-\x7e]{1,64}")


# Field checks.


def _check_int(value: int, what: str) -> None:
    # R2: non-negative and at most 2**53 - 1; never a bool.
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_SAFE_INTEGER:
        raise DefinitionError("bad_shape", f"{what} = {value!r}")


def _check_choice(value: object, allowed: frozenset[str], what: str, reason: str = "bad_shape") -> None:
    if not isinstance(value, str) or value not in allowed:
        raise DefinitionError(reason, f"{what} = {value!r}")


def _check_optional_choice(value: object, allowed: frozenset[str], what: str) -> None:
    if value is not None:
        _check_choice(value, allowed, what)


def _check_identifier(value: object, pattern: re.Pattern[str], what: str) -> None:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise DefinitionError("bad_identifier", f"{what} = {value!r}")


def check_memory_id(value: object, what: str = "memory_id") -> None:
    _check_identifier(value, _MEMORY_ID, what)


def check_text(value: object, low: int, high: int, what: str) -> None:
    """R4: NFC, no C0/C1 control code point, no lone surrogate, length in code points."""
    if not isinstance(value, str):
        raise DefinitionError("bad_shape", f"{what} must be a string")
    if not low <= len(value) <= high or unicodedata.normalize("NFC", value) != value:
        raise DefinitionError("bad_text", f"{what} = {value!r}")
    if any(c < "\x20" or "\x7f" <= c <= "\x9f" or "\ud800" <= c <= "\udfff" for c in value):
        raise DefinitionError("bad_text", f"{what} = {value!r}")


def _check_rational(value: object, what: str) -> None:
    if not isinstance(value, Fraction):
        raise DefinitionError("bad_shape", f"{what} must be a Fraction")
    check_stored(value, what)


def _check_instance(value: object, kind: type | tuple[type, ...], what: str) -> None:
    if not isinstance(value, kind):
        raise DefinitionError("bad_shape", f"{what} has the wrong type")


def _check_tuple(value: object, kind: type, what: str) -> None:
    # A list inside a frozen dataclass could still be mutated after its hash was taken.
    if not isinstance(value, tuple) or not all(isinstance(item, kind) for item in cast("tuple[object, ...]", value)):
        raise DefinitionError("bad_shape", f"{what} must be a tuple of {kind.__name__}")


def _check_unit(unit: object, unit_text: object, what: str) -> None:
    # R17: a unit has exactly one encoding.
    _check_optional_choice(unit, UNITS, f"{what}.unit")
    if unit is not None:
        if unit_text is not None:
            raise DefinitionError("non_canonical", f"{what}: unit_text must be null when unit is set")
        return
    if unit_text is None:
        raise DefinitionError("non_canonical", f"{what}: unit_text must be a string when unit is null")
    check_text(unit_text, 0, 64, f"{what}.unit_text")


def _check_count(count: int, what: str) -> None:
    _check_int(count, what)
    if count < 1:
        raise DefinitionError("bad_dims", f"{what} = {count}")


# Shapes - §3.


@dataclass(frozen=True, slots=True)
class Dtype:
    """R6. `byte_order` is "none" iff `bits == 8`; "float" is IEEE 754 binary32."""

    kind: Kind
    bits: int
    byte_order: ByteOrder

    def __post_init__(self) -> None:
        _check_choice(self.kind, KINDS, "kind", "bad_dtype")
        _check_choice(self.byte_order, BYTE_ORDERS, "byte_order", "bad_dtype")
        if isinstance(self.bits, bool) or self.bits not in (8, 16, 32):
            raise DefinitionError("bad_dtype", f"bits = {self.bits!r}")
        if (self.byte_order == "none") != (self.bits == 8) or (self.kind == "float" and self.bits != 32):
            raise DefinitionError("bad_dtype", f"{self.kind}{self.bits} {self.byte_order}")

    @property
    def size(self) -> int:
        return self.bits // 8


@dataclass(frozen=True, slots=True)
class Scaling:
    """R10, R12: `physical = factor · raw + addend`, exact."""

    factor: Fraction
    addend: Fraction

    def __post_init__(self) -> None:
        _check_rational(self.factor, "factor")
        _check_rational(self.addend, "addend")
        if self.factor == 0:
            raise DefinitionError("zero_factor")


@dataclass(frozen=True, slots=True)
class InlineAxis:
    """R20 `inline`: `count` contiguous breakpoint cells at `offset` of `memory_id`."""

    memory_id: str
    offset: int
    count: int
    dtype: Dtype
    scaling: Scaling
    unit: Unit | None
    unit_text: str | None

    def __post_init__(self) -> None:
        check_memory_id(self.memory_id)
        _check_int(self.offset, "offset")
        _check_count(self.count, "count")
        _check_instance(self.dtype, Dtype, "dtype")
        _check_instance(self.scaling, Scaling, "scaling")
        _check_unit(self.unit, self.unit_text, "axis")


@dataclass(frozen=True, slots=True)
class PointerAxis:
    """R20 `pointer`: an unsigned pointer at `pointer_offset` names the breakpoints in `target_memory_id`."""

    memory_id: str
    pointer_offset: int
    pointer_dtype: Dtype
    target_memory_id: str
    count: int
    dtype: Dtype
    scaling: Scaling
    unit: Unit | None
    unit_text: str | None

    def __post_init__(self) -> None:
        check_memory_id(self.memory_id)
        _check_int(self.pointer_offset, "pointer_offset")
        _check_instance(self.pointer_dtype, Dtype, "pointer_dtype")
        if self.pointer_dtype.kind != "uint" or self.pointer_dtype.bits not in (16, 32):
            raise DefinitionError("bad_dtype", "a pointer is uint16 or uint32")
        check_memory_id(self.target_memory_id, "target_memory_id")
        _check_count(self.count, "count")
        _check_instance(self.dtype, Dtype, "dtype")
        _check_instance(self.scaling, Scaling, "scaling")
        _check_unit(self.unit, self.unit_text, "axis")


@dataclass(frozen=True, slots=True)
class SharedAxis:
    """R20 `shared`: the `AxisDef` with `axis_id` in the same `Definition` (R23)."""

    axis_id: str

    def __post_init__(self) -> None:
        _check_identifier(self.axis_id, _LOCAL_ID, "axis_id")


@dataclass(frozen=True, slots=True)
class FixedAxis:
    """R20 `fixed`: physical breakpoints written in the definition, stored in no memory."""

    values: tuple[Fraction, ...]
    unit: Unit | None
    unit_text: str | None

    def __post_init__(self) -> None:
        _check_tuple(self.values, Fraction, "values")
        if not self.values:
            raise DefinitionError("bad_dims", "a fixed axis has at least one value")
        for value in self.values:
            check_stored(value, "values")
        _check_unit(self.unit, self.unit_text, "axis")


type StoredAxis = InlineAxis | PointerAxis | FixedAxis
type AxisRef = InlineAxis | PointerAxis | SharedAxis | FixedAxis
AXIS_TYPES = (InlineAxis, PointerAxis, SharedAxis, FixedAxis)


def axis_count(axis: StoredAxis) -> int:
    return len(axis.values) if isinstance(axis, FixedAxis) else axis.count


@dataclass(frozen=True, slots=True)
class AxisDef:
    """R23: a named axis that maps reference with `shared`. It is never itself `shared`."""

    axis_id: str
    name: str
    axis: StoredAxis

    def __post_init__(self) -> None:
        _check_identifier(self.axis_id, _LOCAL_ID, "axis_id")
        check_text(self.name, 1, 256, "name")
        # R23: an AxisDef is never itself shared, so there are no chains or cycles.
        _check_instance(self.axis, (InlineAxis, PointerAxis, FixedAxis), "axis")


@dataclass(frozen=True, slots=True)
class MapDef:
    """§3.5. `rows`, `cols` are `dims`; `x`, `y` are `axes` in the JSON form."""

    map_id: str
    name: str
    category: Category | None
    map_type: MapType | None
    state: State
    memory_id: str
    offset: int
    rows: int
    cols: int
    cell_order: CellOrder
    dtype: Dtype
    scaling: Scaling
    unit: Unit | None
    unit_text: str | None
    x: AxisRef | None
    y: AxisRef | None

    def __post_init__(self) -> None:
        _check_identifier(self.map_id, _LOCAL_ID, "map_id")
        check_text(self.name, 1, 256, "name")
        _check_optional_choice(self.category, CATEGORIES, "category")
        _check_optional_choice(self.map_type, MAP_TYPES, "map_type")
        _check_choice(self.state, STATES, "state")
        check_memory_id(self.memory_id)
        _check_int(self.offset, "offset")
        for what, dim in (("rows", self.rows), ("cols", self.cols)):
            _check_int(dim, what)
            if not 1 <= dim <= MAX_DIM:
                raise DefinitionError("bad_dims", f"{what} = {dim}")
        _check_choice(self.cell_order, CELL_ORDERS, "cell_order")
        if self.cell_order == "y_fastest" and (self.rows == 1 or self.cols == 1):
            raise DefinitionError("non_canonical", "a single row or column is x_fastest (R8)")
        _check_instance(self.dtype, Dtype, "dtype")
        _check_instance(self.scaling, Scaling, "scaling")
        _check_unit(self.unit, self.unit_text, "map")
        for key, axis, need in (("x", self.x, self.cols), ("y", self.y, self.rows)):
            if axis is None:
                continue
            _check_instance(axis, AXIS_TYPES, f"axes.{key}")
            if not isinstance(axis, SharedAxis) and axis_count(axis) != need:
                raise DefinitionError("dims_mismatch", f"axes.{key} has {axis_count(axis)} points, map has {need}")

    @property
    def cell_bytes(self) -> int:
        return self.rows * self.cols * self.dtype.size


@dataclass(frozen=True, slots=True)
class SoftwareVersion:
    """R34. Values are sorted by code point and unique; matching is equality or prefix, never a regex."""

    match: Match
    values: tuple[str, ...]

    def __post_init__(self) -> None:
        _check_choice(self.match, MATCHES, "match")
        _check_tuple(self.values, str, "values")
        if not self.values:
            raise DefinitionError("bad_shape", "software_version.values is empty")
        for value in self.values:
            if _PRINTABLE_ASCII.fullmatch(value) is None:
                raise DefinitionError("bad_text", f"software version {value!r}")
        if list(self.values) != sorted(set(self.values)):
            raise DefinitionError("non_canonical", "software_version.values must be sorted and unique")

    def matches(self, sw_id: str) -> bool:
        if self.match == "exact":
            return sw_id in self.values
        return any(sw_id.startswith(value) for value in self.values)


@dataclass(frozen=True, slots=True)
class Origin:
    """R37. `derived_from` lists definition hashes, sorted and unique."""

    kind: OriginKind
    derived_from: tuple[str, ...]

    def __post_init__(self) -> None:
        _check_choice(self.kind, ORIGIN_KINDS, "origin.kind")
        _check_tuple(self.derived_from, str, "derived_from")
        if not all(_HASH.fullmatch(value) for value in self.derived_from):
            raise DefinitionError("bad_shape", "derived_from holds lowercase hex SHA-256 hashes")
        if list(self.derived_from) != sorted(set(self.derived_from)):
            raise DefinitionError("non_canonical", "derived_from must be sorted and unique")


@dataclass(frozen=True, slots=True)
class License:
    """R44. `core` records who claimed a license; it cannot verify one."""

    kind: LicenseKind
    reference: str | None

    def __post_init__(self) -> None:
        _check_choice(self.kind, LICENSE_KINDS, "license.kind")
        if self.reference is not None:
            check_text(self.reference, 1, MAX_SAFE_INTEGER, "license.reference")
        elif self.kind == "verifiable_license":
            raise DefinitionError("bad_shape", "verifiable_license needs a non-empty reference")


def _first_repeat(ids: list[str]) -> str | None:
    seen: set[str] = set()
    for identifier in ids:
        if identifier in seen:
            return identifier
        seen.add(identifier)
    return None


def _axis_id(axis_def: AxisDef) -> str:
    return axis_def.axis_id


def _map_id(mapdef: MapDef) -> str:
    return mapdef.map_id


@dataclass(frozen=True, slots=True)
class Definition:
    """§3.6. Axes and mapdefs are sorted on construction (R35), so input order never changes the hash."""

    family_id: str
    software_version: SoftwareVersion
    axes: tuple[AxisDef, ...]
    mapdefs: tuple[MapDef, ...]
    origin: Origin
    license: License
    confidence_permille: int

    def __post_init__(self) -> None:
        _check_identifier(self.family_id, _FAMILY_ID, "family_id")
        _check_instance(self.software_version, SoftwareVersion, "software_version")
        _check_tuple(self.axes, AxisDef, "axes")
        _check_tuple(self.mapdefs, MapDef, "mapdefs")
        _check_instance(self.origin, Origin, "origin")
        _check_instance(self.license, License, "license")
        _check_int(self.confidence_permille, "confidence_permille")
        if self.confidence_permille > 1000:
            raise DefinitionError("bad_shape", f"confidence_permille = {self.confidence_permille}")
        axes = tuple(sorted(self.axes, key=_axis_id))
        mapdefs = tuple(sorted(self.mapdefs, key=_map_id))
        duplicate_axis = _first_repeat([axis_def.axis_id for axis_def in axes])
        if duplicate_axis is not None:
            raise DefinitionError("duplicate_axis_id", duplicate_axis)
        duplicate_map = _first_repeat([mapdef.map_id for mapdef in mapdefs])
        if duplicate_map is not None:
            raise DefinitionError("duplicate_map_id", duplicate_map)
        object.__setattr__(self, "axes", axes)
        object.__setattr__(self, "mapdefs", mapdefs)
        ensure(
            [a.axis_id for a in self.axes] == sorted({a.axis_id for a in self.axes})
            and [m.map_id for m in self.mapdefs] == sorted({m.map_id for m in self.mapdefs}),
            "SPEC-003 R35",
        )
        by_id = {axis_def.axis_id: axis_def for axis_def in axes}
        used: set[str] = set()
        for mapdef in mapdefs:
            for key, axis, need in (("x", mapdef.x, mapdef.cols), ("y", mapdef.y, mapdef.rows)):
                if not isinstance(axis, SharedAxis):
                    continue
                target = by_id.get(axis.axis_id)
                if target is None:
                    raise DefinitionError("unknown_axis", f"{mapdef.map_id} axes.{key} -> {axis.axis_id}")
                if axis_count(target.axis) != need:
                    raise DefinitionError("dims_mismatch", f"{mapdef.map_id} axes.{key} -> {axis.axis_id}")
                used.add(axis.axis_id)
        orphans = sorted(set(by_id) - used)
        if orphans:
            raise DefinitionError("orphan_axis", ",".join(orphans))

    def axis_def(self, axis_id: str) -> AxisDef:
        for axis_def in self.axes:
            if axis_def.axis_id == axis_id:
                return axis_def
        raise DefinitionError("unknown_axis", axis_id)


def resolve_axis(axis: AxisRef | None, definition: Definition) -> StoredAxis | None:
    """R23: a `shared` reference resolves to the axis of its `AxisDef`; there are no chains."""
    if isinstance(axis, SharedAxis):
        return definition.axis_def(axis.axis_id).axis
    return axis


# Canonical JSON - §4.


def _dtype_json(dtype: Dtype) -> dict[str, Json]:
    return {"kind": dtype.kind, "bits": dtype.bits, "byte_order": dtype.byte_order}


def _scaling_json(scaling: Scaling) -> dict[str, Json]:
    return {"factor": rational_text(scaling.factor), "addend": rational_text(scaling.addend)}


def axis_json(axis: AxisRef) -> dict[str, Json]:
    if isinstance(axis, SharedAxis):
        return {"axis_source": "shared", "axis_id": axis.axis_id}
    if isinstance(axis, FixedAxis):
        return {
            "axis_source": "fixed",
            "values": [rational_text(value) for value in axis.values],
            "unit": axis.unit,
            "unit_text": axis.unit_text,
        }
    tail: dict[str, Json] = {
        "count": axis.count,
        "dtype": _dtype_json(axis.dtype),
        "scaling": _scaling_json(axis.scaling),
        "unit": axis.unit,
        "unit_text": axis.unit_text,
    }
    if isinstance(axis, InlineAxis):
        return {"axis_source": "inline", "memory_id": axis.memory_id, "offset": axis.offset, **tail}
    return {
        "axis_source": "pointer",
        "memory_id": axis.memory_id,
        "pointer_offset": axis.pointer_offset,
        "pointer_dtype": _dtype_json(axis.pointer_dtype),
        "target_memory_id": axis.target_memory_id,
        **tail,
    }


def axisdef_json(axis_def: AxisDef) -> dict[str, Json]:
    return {"axis_id": axis_def.axis_id, "name": axis_def.name, "axis": axis_json(axis_def.axis)}


def mapdef_json(mapdef: MapDef) -> dict[str, Json]:
    return {
        "map_id": mapdef.map_id,
        "name": mapdef.name,
        "category": mapdef.category,
        "map_type": mapdef.map_type,
        "state": mapdef.state,
        "memory_id": mapdef.memory_id,
        "offset": mapdef.offset,
        "dims": {"rows": mapdef.rows, "cols": mapdef.cols},
        "cell_order": mapdef.cell_order,
        "dtype": _dtype_json(mapdef.dtype),
        "scaling": _scaling_json(mapdef.scaling),
        "unit": mapdef.unit,
        "unit_text": mapdef.unit_text,
        "axes": {
            "x": None if mapdef.x is None else axis_json(mapdef.x),
            "y": None if mapdef.y is None else axis_json(mapdef.y),
        },
    }


def definition_json(definition: Definition) -> dict[str, Json]:
    return {
        "spec": SPEC,
        "family_id": definition.family_id,
        "software_version": {
            "match": definition.software_version.match,
            "values": list(definition.software_version.values),
        },
        "axes": [axisdef_json(axis_def) for axis_def in definition.axes],
        "mapdefs": [mapdef_json(mapdef) for mapdef in definition.mapdefs],
        "origin": {"kind": definition.origin.kind, "derived_from": list(definition.origin.derived_from)},
        "license": {"kind": definition.license.kind, "reference": definition.license.reference},
        "confidence_permille": definition.confidence_permille,
    }


def _hash(value: Json) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def mapdef_hash(mapdef: MapDef) -> str:
    """R51."""
    return _hash(mapdef_json(mapdef))


def axisdef_hash(axis_def: AxisDef) -> str:
    """R51."""
    return _hash(axisdef_json(axis_def))


def definition_hash(definition: Definition) -> str:
    """R52: over the sorted form (R35), so input order never changes it."""
    return _hash(definition_json(definition))


def derive_map_id(memory_id: str, name: str, offset: int) -> str:
    """R28: the id converters give a map, stable across imports of the same map at the same place."""
    return "m_" + _hash({"memory_id": memory_id, "name": name, "offset": offset})[:24]


def derive_axis_id(memory_id: str, name: str, offset: int) -> str:
    """R98."""
    return "a_" + _hash({"memory_id": memory_id, "name": name, "offset": offset})[:24]


# Parsing canonical JSON - R1.


def _is_object(value: object) -> TypeGuard[dict[object, object]]:
    return isinstance(value, dict)


def _is_array(value: object) -> TypeGuard[list[object]]:
    return isinstance(value, list)


def _object(value: object, keys: frozenset[str], what: str) -> dict[object, object]:
    # R1: every listed key is present; nothing else is.
    if not _is_object(value) or set(value) != keys:
        raise DefinitionError("bad_shape", f"{what} must be an object with keys {sorted(keys)}")
    return value


def _array(value: object, what: str) -> list[object]:
    if not _is_array(value):
        raise DefinitionError("bad_shape", f"{what} must be an array")
    return value


def _string(value: object, what: str) -> str:
    if not isinstance(value, str):
        raise DefinitionError("bad_shape", f"{what} must be a string")
    return value


def _optional_string(value: object, what: str) -> str | None:
    return None if value is None else _string(value, what)


def _integer(value: object, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise DefinitionError("bad_shape", f"{what} must be an integer")
    return value


_DTYPE_KEYS = frozenset({"kind", "bits", "byte_order"})
_SCALING_KEYS = frozenset({"factor", "addend"})
_INLINE_KEYS = frozenset({"axis_source", "memory_id", "offset", "count", "dtype", "scaling", "unit", "unit_text"})
_POINTER_KEYS = frozenset(
    {
        "axis_source",
        "memory_id",
        "pointer_offset",
        "pointer_dtype",
        "target_memory_id",
        "count",
        "dtype",
        "scaling",
        "unit",
        "unit_text",
    }
)
_SHARED_KEYS = frozenset({"axis_source", "axis_id"})
_FIXED_KEYS = frozenset({"axis_source", "values", "unit", "unit_text"})
_AXISDEF_KEYS = frozenset({"axis_id", "name", "axis"})
_MAPDEF_KEYS = frozenset(
    {
        "map_id",
        "name",
        "category",
        "map_type",
        "state",
        "memory_id",
        "offset",
        "dims",
        "cell_order",
        "dtype",
        "scaling",
        "unit",
        "unit_text",
        "axes",
    }
)
_DEFINITION_KEYS = frozenset(
    {"spec", "family_id", "software_version", "axes", "mapdefs", "origin", "license", "confidence_permille"}
)


def _dtype_from(value: object) -> Dtype:
    obj = _object(value, _DTYPE_KEYS, "dtype")
    return Dtype(
        cast("Kind", _string(obj["kind"], "kind")),
        _integer(obj["bits"], "bits"),
        cast("ByteOrder", _string(obj["byte_order"], "byte_order")),
    )


def _scaling_from(value: object) -> Scaling:
    obj = _object(value, _SCALING_KEYS, "scaling")
    return Scaling(parse_rational(obj["factor"]), parse_rational(obj["addend"]))


def _unit_from(value: object) -> Unit | None:
    return cast("Unit | None", _optional_string(value, "unit"))


_AXIS_KEYS: dict[object, frozenset[str]] = {
    "inline": _INLINE_KEYS,
    "pointer": _POINTER_KEYS,
    "shared": _SHARED_KEYS,
    "fixed": _FIXED_KEYS,
}


def axis_from_json(value: object) -> AxisRef:
    source = value.get("axis_source") if _is_object(value) else None
    keys = _AXIS_KEYS.get(source)
    if keys is None:
        raise DefinitionError("bad_shape", f"axis_source = {source!r}")
    obj = _object(value, keys, f"{source} axis")
    if source == "shared":
        return SharedAxis(_string(obj["axis_id"], "axis_id"))
    unit = _unit_from(obj["unit"])
    unit_text = _optional_string(obj["unit_text"], "unit_text")
    if source == "fixed":
        values = tuple(parse_rational(item) for item in _array(obj["values"], "values"))
        return FixedAxis(values, unit, unit_text)
    count = _integer(obj["count"], "count")
    dtype = _dtype_from(obj["dtype"])
    scaling = _scaling_from(obj["scaling"])
    memory_id = _string(obj["memory_id"], "memory_id")
    if source == "inline":
        return InlineAxis(memory_id, _integer(obj["offset"], "offset"), count, dtype, scaling, unit, unit_text)
    return PointerAxis(
        memory_id,
        _integer(obj["pointer_offset"], "pointer_offset"),
        _dtype_from(obj["pointer_dtype"]),
        _string(obj["target_memory_id"], "target_memory_id"),
        count,
        dtype,
        scaling,
        unit,
        unit_text,
    )


def _optional_axis(value: object) -> AxisRef | None:
    return None if value is None else axis_from_json(value)


def axisdef_from_json(value: object) -> AxisDef:
    obj = _object(value, _AXISDEF_KEYS, "axis definition")
    axis = axis_from_json(obj["axis"])
    if isinstance(axis, SharedAxis):
        raise DefinitionError("bad_shape", "an AxisDef is never shared (R23)")
    return AxisDef(_string(obj["axis_id"], "axis_id"), _string(obj["name"], "name"), axis)


def mapdef_from_json(value: object) -> MapDef:
    obj = _object(value, _MAPDEF_KEYS, "mapdef")
    dims = _object(obj["dims"], frozenset({"rows", "cols"}), "dims")
    axes = _object(obj["axes"], frozenset({"x", "y"}), "axes")
    return MapDef(
        map_id=_string(obj["map_id"], "map_id"),
        name=_string(obj["name"], "name"),
        category=cast("Category | None", _optional_string(obj["category"], "category")),
        map_type=cast("MapType | None", _optional_string(obj["map_type"], "map_type")),
        state=cast("State", _string(obj["state"], "state")),
        memory_id=_string(obj["memory_id"], "memory_id"),
        offset=_integer(obj["offset"], "offset"),
        rows=_integer(dims["rows"], "rows"),
        cols=_integer(dims["cols"], "cols"),
        cell_order=cast("CellOrder", _string(obj["cell_order"], "cell_order")),
        dtype=_dtype_from(obj["dtype"]),
        scaling=_scaling_from(obj["scaling"]),
        unit=_unit_from(obj["unit"]),
        unit_text=_optional_string(obj["unit_text"], "unit_text"),
        x=_optional_axis(axes["x"]),
        y=_optional_axis(axes["y"]),
    )


def definition_from_json(value: object) -> Definition:
    obj = _object(value, _DEFINITION_KEYS, "definition")
    if obj["spec"] != SPEC:
        raise DefinitionError("bad_shape", f"spec = {obj['spec']!r}")
    version = _object(obj["software_version"], frozenset({"match", "values"}), "software_version")
    origin = _object(obj["origin"], frozenset({"kind", "derived_from"}), "origin")
    license_ = _object(obj["license"], frozenset({"kind", "reference"}), "license")
    return Definition(
        family_id=_string(obj["family_id"], "family_id"),
        software_version=SoftwareVersion(
            cast("Match", _string(version["match"], "match")),
            tuple(_string(item, "software version") for item in _array(version["values"], "values")),
        ),
        axes=tuple(axisdef_from_json(item) for item in _array(obj["axes"], "axes")),
        mapdefs=tuple(mapdef_from_json(item) for item in _array(obj["mapdefs"], "mapdefs")),
        origin=Origin(
            cast("OriginKind", _string(origin["kind"], "origin.kind")),
            tuple(_string(item, "derived_from") for item in _array(origin["derived_from"], "derived_from")),
        ),
        license=License(
            cast("LicenseKind", _string(license_["kind"], "license.kind")),
            _optional_string(license_["reference"], "license.reference"),
        ),
        confidence_permille=_integer(obj["confidence_permille"], "confidence_permille"),
    )


# Labels and licensing - §3.7, §3.8.


def transition(mapdef: MapDef, state: State) -> MapDef:
    """R41: the only way to change a label state."""
    if (mapdef.state, state) not in TRANSITIONS:
        raise DefinitionError("bad_transition", f"{mapdef.state} -> {state}")
    return _replace_state(mapdef, state)


def _replace_state(mapdef: MapDef, state: State) -> MapDef:
    return replace(mapdef, state=state)


def revise(current: MapDef, revised: MapDef) -> MapDef:
    """R29: a change to any field other than `state` yields `state: proposed`; a change of `state`
    alone is a transition (R41)."""
    if _replace_state(revised, current.state) == current:
        return current if revised.state == current.state else transition(current, revised.state)
    return _replace_state(revised, "proposed")


def has_reviewed_category(mapdef: MapDef) -> bool:
    """R42: the gate applies keyed physical ranges only to such a map (SPEC-004 R35)."""
    return (
        mapdef.state in ("reviewed", "golden")
        and mapdef.category is not None
        and mapdef.map_type is not None
        and mapdef.unit is not None
    )


def distribution(definition: Definition, sources: Mapping[str, Distribution]) -> Distribution:
    """R45: `shareable` only with a claimed license and every source shareable. `sources` maps the
    `definition_hash` of each `derived_from` entry, resolved by the caller; a missing one is `local_only`."""
    if definition.license.kind == "unverified":
        return "local_only"
    if all(sources.get(source) == "shareable" for source in definition.origin.derived_from):
        return "shareable"
    return "local_only"
