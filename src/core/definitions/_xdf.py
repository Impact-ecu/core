"""XDF (TunerPro) import and export: the subset of SPEC-003 §7 and the common rules of §6.

Rows marked **P** in §7.1 rest on one community source. They are implemented so that vectors and
tests run (R66), but a `core` release whose XDF importer accepts input depending on them MUST NOT be
published until a SPEC-003 revision confirms them (§12, question 1). They are: `mmedtypeflags`
(bits 0x01, 0x02, 0x10000 and its absence), strides of 0, `units`, and a zero `BASEOFFSET`.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass, replace
from fractions import Fraction

from core.definitions._errors import DefinitionError, ensure
from core.definitions._model import (
    MAX_DIM,
    MAX_SAFE_INTEGER,
    AxisRef,
    Definition,
    Dtype,
    FixedAxis,
    InlineAxis,
    License,
    MapDef,
    Origin,
    Scaling,
    SoftwareVersion,
    check_memory_id,
    check_text,
    derive_map_id,
)
from core.definitions._rational import ASCII_WHITESPACE, finite_decimal_text, parse_xdf_decimal
from core.definitions._units import EXPORT_TEXT, Unit, resolve_unit
from core.definitions._xml import Node, parse_xml


@dataclass(frozen=True, slots=True)
class XdfParams:
    """Import parameters (R60, R64, R79). `memory_id` names the memory the XDF file describes."""

    family_id: str
    software_version: SoftwareVersion
    memory_id: str
    license: License
    confidence_permille: int

    def __post_init__(self) -> None:
        check_memory_id(self.memory_id)
        if not isinstance(self.license, License) or self.license.kind == "platform_created":
            # R44: a converter records `unverified`, or a `verifiable_license` the caller claims.
            raise DefinitionError("bad_shape", "an import license is unverified or verifiable_license")


@dataclass(frozen=True, slots=True)
class Rejection:
    """R61: a source element that was not imported, with the reason."""

    path: str
    reason: str


@dataclass(frozen=True, slots=True)
class ImportResult:
    """R61: every source element is mapped, ignored (presentation only) or rejected."""

    definition: Definition
    rejected: tuple[Rejection, ...]
    ignored: tuple[str, ...]


IGNORED_MAP_CHILDREN = frozenset(
    {"description", "CATEGORYMEM", "DALINK", "datatype", "unittype", "outputtype", "decimalpl", "min", "max"}
)
IGNORED_HEADER_CHILDREN = frozenset({"deftitle", "description", "author", "fileversion", "CATEGORY", "REGION"})
IGNORED_DEFAULTS = frozenset({"datasizeinbits", "sigdigits", "outputtype"})
UNVERIFIED_DEFAULTS = frozenset({"signed", "lsbfirst", "float"})
UNSUPPORTED_TOP = frozenset({"XDFFLAG", "XDFPATCH", "XDFCHECKSUM"})

_SIGNED = 0x01
_LSB_FIRST = 0x02
_FLOAT = 0x10000

_HEX = re.compile(r"0x[0-9A-Fa-f]+")
_DECIMAL = re.compile(r"[0-9]+")
_D = r"[0-9]+(?:\.[0-9]+)?"
_TAIL = rf"(?:[+-]{_D})?"
# R74 forms. The constant term `A` and the divisor `N` are unsigned; the factor `F` may carry a minus.
_X_TAIL = re.compile(rf"X{_TAIL}")
_X_TIMES_F = re.compile(rf"X\*-?{_D}{_TAIL}")
_F_TIMES_X = re.compile(rf"-?{_D}\*X{_TAIL}")
_X_OVER_N = re.compile(rf"X/[0-9]+{_TAIL}")
_A_PLUS_X_TIMES_F = re.compile(rf"{_D}[+-]X\*-?{_D}")
_A_PLUS_X_OVER_N = re.compile(rf"{_D}\+X/[0-9]+")


# Numbers and equations.


def _strip(text: str) -> str:
    # R61: only these four characters are whitespace; U+00A0 and the like make the value malformed.
    return text.strip(ASCII_WHITESPACE)


def parse_integer(text: str) -> int:
    """R61, §7.1: a decimal or `0x` hexadecimal integer within R2's bound."""
    value = _strip(text)
    if _HEX.fullmatch(value) is not None:
        digits, base = value[2:], 16
    elif _DECIMAL.fullmatch(value) is not None:
        digits, base = value, 10
    else:
        raise DefinitionError("bad_number", repr(text))
    digits = digits.lstrip("0") or "0"
    # 2**53 - 1 has 16 decimal digits; a longer run is out of range before any big-integer work.
    if len(digits) > 16 or int(digits, base) > MAX_SAFE_INTEGER:
        raise DefinitionError("bad_number", f"{text!r} exceeds 2**53 - 1")
    return int(digits, base)


def _divisor(text: str) -> Fraction:
    divisor = parse_xdf_decimal(text)
    if divisor == 0:
        raise DefinitionError("zero_factor", "X/0")
    return Fraction(divisor.denominator, divisor.numerator)


def _tail(text: str) -> Fraction:
    """`+A`, `-A` or nothing, after the leading term."""
    if not text:
        return Fraction(0)
    value = parse_xdf_decimal(text[1:])
    return -value if text[0] == "-" else value


def parse_equation(equation: str) -> tuple[Fraction, Fraction]:
    """R74: `(factor, addend)` of the accepted equation forms, exact."""
    text = _strip(equation).replace(" ", "")
    if _X_TAIL.fullmatch(text):
        return Fraction(1), _tail(text[1:])
    if _X_TIMES_F.fullmatch(text) or _X_OVER_N.fullmatch(text):
        term, tail = _split_tail(text[2:])
        factor = parse_xdf_decimal(term) if text[1] == "*" else _divisor(term)
        return factor, _tail(tail)
    if _F_TIMES_X.fullmatch(text):
        term, _, rest = text.partition("*X")
        return parse_xdf_decimal(term), _tail(rest)
    if _A_PLUS_X_TIMES_F.fullmatch(text):
        head = text.index("X") - 1
        factor = parse_xdf_decimal(text[head + 3 :])
        return (factor if text[head] == "+" else -factor), parse_xdf_decimal(text[:head])
    if _A_PLUS_X_OVER_N.fullmatch(text):
        addend, _, divisor = text.partition("+X/")
        return _divisor(divisor), parse_xdf_decimal(addend)
    raise DefinitionError("unsupported_equation", repr(equation))


def _split_tail(text: str) -> tuple[str, str]:
    """Split `T[+-]A` after the first character, so a leading minus of `T` stays with it."""
    for position in range(1, len(text)):
        if text[position] in "+-":
            return text[:position], text[position:]
    return text, ""


# R17 for XDF.


def exportable(factor: Fraction, addend: Fraction, values: Sequence[Fraction]) -> bool:
    """R76: a factor that is a finite decimal or 1/N, a finite-decimal addend and labels."""
    if finite_decimal_text(factor) is None and factor.numerator != 1:
        return False
    return all(finite_decimal_text(value) is not None for value in (addend, *values))


def _scaled_unit(text: str, factor: Fraction, addend: Fraction) -> tuple[Unit | None, str | None, Scaling]:
    unit, unit_text, k = resolve_unit(text, factor, addend, (), exportable)
    return unit, unit_text, Scaling(factor * k, addend * k)


def _fixed_axis(text: str, values: Sequence[Fraction]) -> FixedAxis:
    unit, unit_text, k = resolve_unit(text, Fraction(1), Fraction(0), values, exportable)
    return FixedAxis(tuple(value * k for value in values), unit, unit_text)


# Importer.


class _MapReader:
    """Reads one XDFCONSTANT or XDFTABLE. Any DefinitionError rejects that map (R61)."""

    def __init__(self, memory_id: str) -> None:
        self.memory_id = memory_id
        self.ignored: list[str] = []

    def attributes(self, node: Node, allowed: frozenset[str]) -> None:
        for name in node.attrs:
            if name == "uniqueid":
                self.ignored.append(node.attribute_path(name))
            elif name not in allowed:
                raise DefinitionError("unknown_attribute", node.attribute_path(name))

    def children(self, node: Node, allowed: frozenset[str]) -> dict[str, list[Node]]:
        found: dict[str, list[Node]] = {}
        for child in node.children:
            if child.name in IGNORED_MAP_CHILDREN:
                self.ignored.append(child.path)
            elif child.name in allowed:
                found.setdefault(child.name, []).append(child)
            elif child.name == "embedinfo":
                raise DefinitionError("unsupported_linked_axis", child.path)
            else:
                raise DefinitionError("unknown_element", child.path)
        return found

    def embedded(self, node: Node, *, z: bool) -> tuple[int, Dtype]:
        allowed = {"mmedaddress", "mmedelementsizebits", "mmedtypeflags", "mmedmajorstridebits", "mmedminorstridebits"}
        if z:
            allowed |= {"mmedrowcount", "mmedcolcount"}
        _leaf(node, frozenset(allowed))
        for required in ("mmedaddress", "mmedelementsizebits"):
            if required not in node.attrs:
                raise DefinitionError("missing_element", node.attribute_path(required))
        for stride in ("mmedmajorstridebits", "mmedminorstridebits"):
            if stride in node.attrs and parse_integer(node.attrs[stride]) != 0:
                raise DefinitionError("unsupported_stride", node.attribute_path(stride))
        bits = parse_integer(node.attrs["mmedelementsizebits"])
        if bits not in (8, 16, 32):
            raise DefinitionError("bad_dtype", f"{bits} bits")
        flags = parse_integer(node.attrs.get("mmedtypeflags", "0"))
        is_float = bool(flags & _FLOAT)
        if flags & ~(_SIGNED | _LSB_FIRST | _FLOAT) or (is_float and (bits != 32 or flags & _SIGNED)):
            raise DefinitionError("unsupported_typeflags", f"{flags:#x}")
        dtype = Dtype(
            "float" if is_float else "int" if flags & _SIGNED else "uint",
            bits,
            "none" if bits == 8 else "le" if flags & _LSB_FIRST else "be",
        )
        return parse_integer(node.attrs["mmedaddress"]), dtype

    def unit_text(self, kids: dict[str, list[Node]]) -> str:
        node = _one(kids, "units")
        text = "" if node is None else _leaf(node).text
        check_text(text, 0, 64, "units")
        return text

    def axis(self, node: Node, need: int) -> AxisRef:
        kids = self.children(node, frozenset({"EMBEDDEDDATA", "indexcount", "units", "LABEL", "MATH"}))
        count = parse_integer(_leaf(_required(kids, "indexcount")).text)
        if count != need:
            raise DefinitionError("dims_mismatch", f"{node.path}: indexcount {count}, dimension {need}")
        data = _one(kids, "EMBEDDEDDATA")
        labels = kids.get("LABEL", [])
        text = self.unit_text(kids)
        if data is not None and "mmedaddress" in data.attrs:
            if labels:
                raise DefinitionError("bad_labels", f"{node.path}: labels on a stored axis")
            offset, dtype = self.embedded(data, z=False)
            factor, addend = _math(_required(kids, "MATH"))
            unit, unit_text, scaling = _scaled_unit(text, factor, addend)
            return InlineAxis(self.memory_id, offset, count, dtype, scaling, unit, unit_text)
        if data is not None:
            # R71: on a label axis the remaining EMBEDDEDDATA attributes are presentation only.
            _leaf(data, frozenset(data.attrs))
            self.ignored.extend(data.attribute_path(name) for name in data.attrs)
        math = _one(kids, "MATH")
        if math is not None:
            _math(math)
            if _strip(math.attrs["equation"]).replace(" ", "") != "X":
                raise DefinitionError("ambiguous_label_scaling", math.path)
        return _fixed_axis(text, _labels(labels, count))

    def mapdef(
        self,
        title: Node,
        place: tuple[int, int, int, Dtype],
        scale: tuple[Node, str],
        axes: tuple[AxisRef | None, AxisRef | None],
    ) -> MapDef:
        name = _leaf(title).text
        check_text(name, 1, 256, "title")
        offset, rows, cols, dtype = place
        math, text = scale
        factor, addend = _math(math)
        unit, unit_text, scaling = _scaled_unit(text, factor, addend)
        return MapDef(
            map_id=derive_map_id(self.memory_id, name, offset),
            name=name,
            category=None,
            map_type=None,
            state="imported",
            memory_id=self.memory_id,
            offset=offset,
            rows=rows,
            cols=cols,
            cell_order="x_fastest",
            dtype=dtype,
            scaling=scaling,
            unit=unit,
            unit_text=unit_text,
            x=axes[0],
            y=axes[1],
        )

    def constant(self, node: Node) -> MapDef:
        self.attributes(node, frozenset())
        kids = self.children(node, frozenset({"title", "EMBEDDEDDATA", "units", "MATH"}))
        title = _required(kids, "title")
        offset, dtype = self.embedded(_required(kids, "EMBEDDEDDATA"), z=False)
        return self.mapdef(title, (offset, 1, 1, dtype), (_required(kids, "MATH"), self.unit_text(kids)), (None, None))

    def table(self, node: Node) -> MapDef:
        self.attributes(node, frozenset({"flags"}))
        if "flags" in node.attrs and parse_integer(node.attrs["flags"]) != 0:
            raise DefinitionError("unsupported_flags", node.attribute_path("flags"))
        kids = self.children(node, frozenset({"title", "XDFAXIS"}))
        title = _required(kids, "title")
        axes: dict[str, Node] = {}
        for axis in kids.get("XDFAXIS", []):
            self.attributes(axis, frozenset({"id"}))
            axis_id = axis.attrs.get("id")
            if axis_id is None:
                raise DefinitionError("missing_element", axis.attribute_path("id"))
            if axis_id not in ("x", "y", "z") or axis_id in axes:
                raise DefinitionError("bad_shape", f"{axis.path}: id {axis_id!r}")
            axes[axis_id] = axis
        z = axes.get("z")
        if z is None:
            raise DefinitionError("missing_element", f"{node.path}/XDFAXIS[z]")
        z_kids = self.children(z, frozenset({"EMBEDDEDDATA", "units", "MATH"}))
        data = _required(z_kids, "EMBEDDEDDATA")
        offset, dtype = self.embedded(data, z=True)
        rows = parse_integer(data.attrs.get("mmedrowcount", "1"))
        cols = parse_integer(data.attrs.get("mmedcolcount", "1"))
        if not (1 <= rows <= MAX_DIM and 1 <= cols <= MAX_DIM):
            raise DefinitionError("bad_dims", f"{rows} x {cols}")
        math = _required(z_kids, "MATH")
        found: list[AxisRef | None] = []
        for key, need in (("x", cols), ("y", rows)):
            axis_node = axes.get(key)
            if axis_node is None and need > 1:
                raise DefinitionError("dims_mismatch", f"{node.path}: no {key} axis for {need} cells")
            found.append(None if axis_node is None else self.axis(axis_node, need))
        return self.mapdef(title, (offset, rows, cols, dtype), (math, self.unit_text(z_kids)), (found[0], found[1]))


def _one(kids: dict[str, list[Node]], name: str) -> Node | None:
    nodes = kids.get(name, [])
    if len(nodes) > 1:
        raise DefinitionError("bad_shape", f"{nodes[1].path}: {name} occurs more than once")
    return nodes[0] if nodes else None


def _required(kids: dict[str, list[Node]], name: str) -> Node:
    node = _one(kids, name)
    if node is None:
        raise DefinitionError("missing_element", name)
    return node


def _leaf(node: Node, allowed: frozenset[str] = frozenset()) -> Node:
    """An element read for its text or attributes: no child element, no attribute outside `allowed`."""
    if node.children:
        raise DefinitionError("unknown_element", node.children[0].path)
    for name in node.attrs:
        if name not in allowed:
            raise DefinitionError("unknown_attribute", node.attribute_path(name))
    return node


def _math(node: Node) -> tuple[Fraction, Fraction]:
    """R74: `MATH@equation` with exactly one `VAR id="X"`."""
    for name in node.attrs:
        if name != "equation":
            raise DefinitionError("unknown_attribute", node.attribute_path(name))
    if "equation" not in node.attrs:
        raise DefinitionError("missing_element", node.attribute_path("equation"))
    variables = node.children
    if len(variables) != 1 or variables[0].name != "VAR" or variables[0].attrs != {"id": "X"}:
        raise DefinitionError("unsupported_equation", f"{node.path}: variables other than one X")
    _leaf(variables[0], frozenset({"id"}))
    return parse_equation(node.attrs["equation"])


def _labels(labels: list[Node], count: int) -> list[Fraction]:
    """R73: indices 0 … count - 1, each once; values `-?D` after whitespace removal."""
    values: dict[int, Fraction] = {}
    for label in labels:
        _leaf(label, frozenset({"index", "value"}))
        for required in ("index", "value"):
            if required not in label.attrs:
                raise DefinitionError("missing_element", label.attribute_path(required))
        index = parse_integer(label.attrs["index"])
        if index in values:
            raise DefinitionError("bad_labels", f"{label.path}: index {index} repeated")
        try:
            values[index] = parse_xdf_decimal(_strip(label.attrs["value"]))
        except DefinitionError as error:
            if error.reason != "bad_number":
                raise
            raise DefinitionError("non_numeric_label", label.attribute_path("value")) from None
    if sorted(values) != list(range(count)):
        raise DefinitionError("bad_labels", f"indices {sorted(values)} for {count} points")
    return [values[i] for i in range(count)]


def _defaults(node: Node, ignored: list[str]) -> None:
    """R70, R71, §12 question 3: data-layout defaults are accepted only when zero."""
    _leaf(node, UNVERIFIED_DEFAULTS | IGNORED_DEFAULTS)
    for name, value in node.attrs.items():
        if name in IGNORED_DEFAULTS:
            ignored.append(node.attribute_path(name))
        elif parse_integer(value) != 0:
            raise DefinitionError("unverified_defaults", node.attribute_path(name))


def _header(node: Node, ignored: list[str]) -> None:
    """File-level settings (R70, R71): any violation rejects the whole file."""
    if node.attrs:
        raise DefinitionError("unknown_attribute", node.attribute_path(next(iter(node.attrs))))
    for child in node.children:
        if child.name in IGNORED_HEADER_CHILDREN:
            ignored.append(child.path)
        elif child.name == "BASEOFFSET":
            _leaf(child, frozenset({"offset", "subtract"}))
            if parse_integer(child.attrs.get("offset", "0")) != 0:
                raise DefinitionError("unsupported_baseoffset", child.path)
        elif child.name == "baseoffset":
            if parse_integer(_leaf(child).text) != 0:
                raise DefinitionError("unsupported_baseoffset", child.path)
        elif child.name == "DEFAULTS":
            _defaults(child, ignored)
        elif child.name == "flags":
            if parse_integer(_leaf(child).text) != 0:
                raise DefinitionError("unsupported_flags", child.path)
        else:
            raise DefinitionError("unknown_element", child.path)


def import_xdf(data: bytes, params: XdfParams) -> ImportResult:
    """R60-R64, R70-R75, R79, R80. Element-level rejections are listed; file-level ones raise."""
    if not isinstance(params, XdfParams):
        raise DefinitionError("bad_shape", "params must be XdfParams")
    root = parse_xml(data)
    if root.name != "XDFFORMAT":
        raise DefinitionError("unknown_element", root.path)
    ignored: list[str] = []
    for name in root.attrs:
        if name != "version":
            raise DefinitionError("unknown_attribute", root.attribute_path(name))
        ignored.append(root.attribute_path(name))
    for child in root.children:
        if child.name == "XDFHEADER":
            _header(child, ignored)
        elif child.name not in UNSUPPORTED_TOP | {"XDFCONSTANT", "XDFTABLE"}:
            raise DefinitionError("unknown_element", child.path)
    rejected: list[Rejection] = []
    mapdefs: list[MapDef] = []
    for child in root.children:
        if child.name in UNSUPPORTED_TOP:
            rejected.append(Rejection(child.path, "unsupported_element"))
        elif child.name != "XDFHEADER":
            reader = _MapReader(params.memory_id)
            try:
                mapdefs.append(reader.constant(child) if child.name == "XDFCONSTANT" else reader.table(child))
            except DefinitionError as error:
                rejected.append(Rejection(child.path, error.reason))
                continue
            ignored.extend(reader.ignored)
    definition = Definition(
        family_id=params.family_id,
        software_version=params.software_version,
        axes=(),
        mapdefs=tuple(mapdefs),
        origin=Origin("xdf_import", ()),
        license=params.license,
        confidence_permille=params.confidence_permille,
    )
    return ImportResult(definition, tuple(sorted(rejected, key=_rejection_path)), tuple(sorted(ignored)))


def _rejection_path(rejection: Rejection) -> str:
    return rejection.path


# R64 normal form.


def _normal_unit(unit: Unit | None, unit_text: str | None) -> str:
    return EXPORT_TEXT[unit] if unit is not None else unit_text or ""


def _normal_axis(axis: AxisRef | None) -> AxisRef | None:
    if isinstance(axis, InlineAxis):
        unit, unit_text, scaling = _scaled_unit(
            _normal_unit(axis.unit, axis.unit_text), axis.scaling.factor, axis.scaling.addend
        )
        return replace(axis, scaling=scaling, unit=unit, unit_text=unit_text)
    if isinstance(axis, FixedAxis):
        return _fixed_axis(_normal_unit(axis.unit, axis.unit_text), axis.values)
    return axis


def normalize_xdf(definition: Definition, params: XdfParams) -> Definition:
    """R64 `normalize(e, P)`: what importing the XDF export of `definition` with `params` yields."""
    mapdefs: list[MapDef] = []
    for mapdef in definition.mapdefs:
        unit, unit_text, scaling = _scaled_unit(
            _normal_unit(mapdef.unit, mapdef.unit_text), mapdef.scaling.factor, mapdef.scaling.addend
        )
        mapdefs.append(
            replace(
                mapdef,
                map_id=derive_map_id(params.memory_id, mapdef.name, mapdef.offset),
                category=None,
                map_type=None,
                state="imported",
                scaling=scaling,
                unit=unit,
                unit_text=unit_text,
                x=_normal_axis(mapdef.x),
                y=_normal_axis(mapdef.y),
            )
        )
    return Definition(
        family_id=params.family_id,
        software_version=params.software_version,
        axes=(),
        mapdefs=tuple(mapdefs),
        origin=Origin("xdf_import", ()),
        license=params.license,
        confidence_permille=params.confidence_permille,
    )


# Exporter - R76, R77.


def _unrepresentable(field: str, detail: str) -> DefinitionError:
    return DefinitionError("unrepresentable", detail, field=field)


def _xml_text(text: str, field: str) -> str:
    """R77 escaping. U+FFFE and U+FFFF pass R4 but are not XML characters, so they cannot round-trip."""
    if "￾" in text or "￿" in text:
        raise _unrepresentable(field, "U+FFFE and U+FFFF are not XML characters")
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _decimal(value: Fraction, field: str) -> str:
    text = finite_decimal_text(value)
    if text is None:
        raise _unrepresentable(field, f"{value} is not a finite decimal")
    return text


def _equation(scaling: Scaling, prefix: str) -> str:
    """R77 `EQ`: `X`, `X*F` or `X/N`, then `+A` or `-A` when the addend is non-zero."""
    factor, addend = scaling.factor, scaling.addend
    decimal = finite_decimal_text(factor)
    if factor == 1:
        equation = "X"
    elif decimal is not None:
        equation = "X*" + decimal
    elif factor.numerator == 1:
        equation = f"X/{factor.denominator}"
    else:
        raise _unrepresentable(prefix + "scaling.factor", f"{factor} is neither a finite decimal nor 1/N")
    if addend != 0:
        text = _decimal(addend, prefix + "scaling.addend")
        equation += text if text.startswith("-") else "+" + text
    return equation


def _flags(dtype: Dtype) -> str:
    value = (_SIGNED if dtype.kind == "int" else 0) | (_LSB_FIRST if dtype.byte_order == "le" else 0)
    value |= _FLOAT if dtype.kind == "float" else 0
    return f"0x{value:02X}"


def _units(indent: str, unit: Unit | None, unit_text: str | None, field: str) -> list[str]:
    text = _normal_unit(unit, unit_text)
    return [f"{indent}<units>{_xml_text(text, field)}</units>"] if text else []


def _math_lines(indent: str, scaling: Scaling, prefix: str) -> list[str]:
    return [f'{indent}<MATH equation="{_equation(scaling, prefix)}">', f'{indent}  <VAR id="X" />', f"{indent}</MATH>"]


def _embedded(dtype: Dtype, offset: int) -> str:
    return f'mmedtypeflags="{_flags(dtype)}" mmedaddress="0x{offset:X}" mmedelementsizebits="{dtype.bits}"'


def _axis_lines(key: str, axis: AxisRef, memory_id: str) -> list[str]:
    prefix = f"axes.{key}."
    lines = [f'    <XDFAXIS id="{key}">']
    if isinstance(axis, InlineAxis):
        if axis.memory_id != memory_id:
            raise _unrepresentable(prefix + "memory_id", f"{axis.memory_id} is not {memory_id}")
        math = _math_lines("      ", axis.scaling, prefix)
        lines.append(f"      <EMBEDDEDDATA {_embedded(axis.dtype, axis.offset)} />")
        lines.append(f"      <indexcount>{axis.count}</indexcount>")
        lines.extend(_units("      ", axis.unit, axis.unit_text, prefix + "unit_text"))
        lines.extend(math)
    elif isinstance(axis, FixedAxis):
        values = [_decimal(value, prefix + "values") for value in axis.values]
        lines.append(f"      <indexcount>{len(values)}</indexcount>")
        lines.extend(_units("      ", axis.unit, axis.unit_text, prefix + "unit_text"))
        lines.extend(f'      <LABEL index="{i}" value="{value}" />' for i, value in enumerate(values))
    else:
        # Shared axes exist only in definitions XDF never produces; pointers need an address translation.
        raise _unrepresentable(prefix + "axis_source", f"{type(axis).__name__} has no XDF form")
    lines.append("    </XDFAXIS>")
    return lines


def _map_lines(mapdef: MapDef, memory_id: str) -> list[str]:
    if mapdef.memory_id != memory_id:
        raise _unrepresentable("memory_id", f"{mapdef.map_id}: {mapdef.memory_id} is not {memory_id}")
    title = f"    <title>{_xml_text(mapdef.name, 'name')}</title>"
    if mapdef.rows == 1 and mapdef.cols == 1 and mapdef.x is None and mapdef.y is None:
        math = _math_lines("    ", mapdef.scaling, "")
        units = _units("    ", mapdef.unit, mapdef.unit_text, "unit_text")
        embedded = f"    <EMBEDDEDDATA {_embedded(mapdef.dtype, mapdef.offset)} />"
        return ["  <XDFCONSTANT>", title, embedded, *units, *math, "  </XDFCONSTANT>"]
    if mapdef.cell_order != "x_fastest":
        raise _unrepresentable("cell_order", f"{mapdef.map_id} is y_fastest")
    for key, axis, need in (("x", mapdef.x, mapdef.cols), ("y", mapdef.y, mapdef.rows)):
        if axis is None and need > 1:
            raise _unrepresentable(f"axes.{key}", f"{mapdef.map_id} has {need} cells along {key} and no axis")
    lines = ["  <XDFTABLE>", title]
    for key, axis in (("x", mapdef.x), ("y", mapdef.y)):
        if axis is not None:
            lines.extend(_axis_lines(key, axis, memory_id))
    math = _math_lines("      ", mapdef.scaling, "")
    dims = f'mmedrowcount="{mapdef.rows}" mmedcolcount="{mapdef.cols}"'
    lines.append('    <XDFAXIS id="z">')
    lines.append(f"      <EMBEDDEDDATA {_embedded(mapdef.dtype, mapdef.offset)} {dims} />")
    lines.extend(_units("      ", mapdef.unit, mapdef.unit_text, "unit_text"))
    lines.extend(math)
    lines.extend(["    </XDFAXIS>", "  </XDFTABLE>"])
    return lines


def export_xdf(definition: Definition, memory_id: str) -> bytes:
    """R76, R77: every map in `map_id` order, or `unrepresentable` at the first violation (with its field)."""
    check_memory_id(memory_id)
    lines = ['<?xml version="1.0" encoding="UTF-8"?>', "<XDFFORMAT>"]
    for mapdef in definition.mapdefs:
        lines.extend(_map_lines(mapdef, memory_id))
    lines.append("</XDFFORMAT>")
    exported = ("\n".join(lines) + "\n").encode("utf-8")
    params = XdfParams(definition.family_id, definition.software_version, memory_id, License("unverified", None), 0)
    try:
        expected = normalize_xdf(definition, params)
    except DefinitionError as error:
        # Two maps with one name at one offset re-import with one derived map_id (R28); a unit alias can
        # push a 40-digit scaling or label past the stored bound (R3, R17). Either import would fail.
        raise _unrepresentable("map_id" if error.reason == "duplicate_map_id" else "unit", str(error)) from None
    reimported = import_xdf(exported, params)
    # R64 (R122): the export re-imports to the normal form, with nothing rejected or ignored.
    ensure(reimported == ImportResult(expected, (), ()), "SPEC-003 R64")
    return exported
