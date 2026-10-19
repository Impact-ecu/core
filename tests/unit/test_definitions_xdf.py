"""SPEC-003 §6, §7: XDF rejections with their reasons, equation forms, unit mapping and export fields.

Every document here is synthetic and written for Impact (R47).
"""

from dataclasses import replace
from fractions import Fraction
from typing import Any, cast

import pytest

from core.definitions import (
    DefinitionError,
    FixedAxis,
    InlineAxis,
    License,
    MapDef,
    Scaling,
    SoftwareVersion,
    XdfParams,
    compu_method_scaling,
    export_a2l,
    export_xdf,
    import_a2l,
    import_xdf,
)
from core.definitions._xdf import parse_equation, parse_integer
from tests.unit.definitions_fixtures import F32BE, FIXED3, IDENTITY, INLINE, SCALAR, TABLE, U16LE, definition

F = Fraction
PARAMS = XdfParams("synthetic.test", SoftwareVersion("exact", ("SYN0001",)), "cal", License("unverified", None), 0)
EMBED = 'mmedaddress="0x10" mmedelementsizebits="8"'
MATH = '<MATH equation="X"><VAR id="X" /></MATH>'
LABELS2 = '<indexcount>2</indexcount><LABEL index="0" value="1" /><LABEL index="1" value="2" />'


def document(body: str, header: str = "") -> bytes:
    return f'<?xml version="1.0" encoding="UTF-8"?>\n<XDFFORMAT>{header}{body}</XDFFORMAT>'.encode()


def constant(inner: str | None = None, attrs: str = "") -> str:
    inner = f"<title>C</title><EMBEDDEDDATA {EMBED} />{MATH}" if inner is None else inner
    return f"<XDFCONSTANT{attrs}>{inner}</XDFCONSTANT>"


def table(x: str = LABELS2, z: str | None = None, attrs: str = "", extra: str = "") -> str:
    z = f'<EMBEDDEDDATA {EMBED} mmedcolcount="2" />{MATH}' if z is None else z
    x_axis = "" if x is None else f'<XDFAXIS id="x">{x}</XDFAXIS>'
    return f'<XDFTABLE{attrs}><title>T</title>{x_axis}{extra}<XDFAXIS id="z">{z}</XDFAXIS></XDFTABLE>'


def reasons(source: bytes) -> list[str]:
    return [r.reason for r in import_xdf(source, PARAMS).rejected]


MAP_CASES: list[tuple[str, str, str]] = [
    # SPEC-003 R61: unknown, missing and repeated items reject the map.
    ("constant attribute", constant(attrs=' foo="1"'), "unknown_attribute"),
    ("unknown child", constant(f"<title>C</title><bogus /><EMBEDDEDDATA {EMBED} />{MATH}"), "unknown_element"),
    (
        "linked axis",
        constant(f"<title>C</title><embedinfo /><EMBEDDEDDATA {EMBED} />{MATH}"),
        "unsupported_linked_axis",
    ),
    ("no title", constant(f"<EMBEDDEDDATA {EMBED} />{MATH}"), "missing_element"),
    ("two titles", constant(f"<title>C</title><title>D</title><EMBEDDEDDATA {EMBED} />{MATH}"), "bad_shape"),
    ("title with child", constant(f"<title>C<b /></title><EMBEDDEDDATA {EMBED} />{MATH}"), "unknown_element"),
    ("title attribute", constant(f'<title lang="de">C</title><EMBEDDEDDATA {EMBED} />{MATH}'), "unknown_attribute"),
    ("no embedded data", constant(f"<title>C</title>{MATH}"), "missing_element"),
    ("no address", constant(f'<title>C</title><EMBEDDEDDATA mmedelementsizebits="8" />{MATH}'), "missing_element"),
    ("no size", constant(f'<title>C</title><EMBEDDEDDATA mmedaddress="0" />{MATH}'), "missing_element"),
    (
        "rows on a constant",
        constant(f'<title>C</title><EMBEDDEDDATA {EMBED} mmedrowcount="1" />{MATH}'),
        "unknown_attribute",
    ),
    (
        "embedded child",
        constant(f"<title>C</title><EMBEDDEDDATA {EMBED}><x /></EMBEDDEDDATA>{MATH}"),
        "unknown_element",
    ),
    ("no MATH", constant(f"<title>C</title><EMBEDDEDDATA {EMBED} />"), "missing_element"),
    # SPEC-003 R4, R75
    ("empty title", constant(f"<title></title><EMBEDDEDDATA {EMBED} />{MATH}"), "bad_text"),
    ("C1 control in title", constant(f"<title>C\u0085</title><EMBEDDEDDATA {EMBED} />{MATH}"), "bad_text"),
    (
        "units too long",
        constant(f"<title>C</title><EMBEDDEDDATA {EMBED} /><units>{'u' * 65}</units>{MATH}"),
        "bad_text",
    ),
    (
        "units attribute",
        constant(f'<title>C</title><EMBEDDEDDATA {EMBED} /><units a="1">u</units>{MATH}'),
        "unknown_attribute",
    ),
    # SPEC-003 §7.1, R70: data types, strides and type flags.
    (
        "12-bit cells",
        constant(f'<title>C</title><EMBEDDEDDATA mmedaddress="0" mmedelementsizebits="12" />{MATH}'),
        "bad_dtype",
    ),
    (
        "float16",
        constant(f'<title>C</title><EMBEDDEDDATA {EMBED} mmedtypeflags="0x10000" />{MATH}'.replace('"8"', '"16"')),
        "unsupported_typeflags",
    ),
    (
        "signed float",
        constant(f'<title>C</title><EMBEDDEDDATA {EMBED} mmedtypeflags="0x10001" />{MATH}'.replace('"8"', '"32"')),
        "unsupported_typeflags",
    ),
    (
        "minor stride",
        constant(f'<title>C</title><EMBEDDEDDATA {EMBED} mmedminorstridebits="8" />{MATH}'),
        "unsupported_stride",
    ),
    # SPEC-003 R61: numbers.
    (
        "address not a number",
        constant(f'<title>C</title><EMBEDDEDDATA mmedaddress="zz" mmedelementsizebits="8" />{MATH}'),
        "bad_number",
    ),
    (
        "address above 2**53 - 1",
        constant(f'<title>C</title><EMBEDDEDDATA mmedaddress="0x20000000000000" mmedelementsizebits="8" />{MATH}'),
        "bad_number",
    ),
    (
        "address of 30 digits",
        constant(f'<title>C</title><EMBEDDEDDATA mmedaddress="{"9" * 30}" mmedelementsizebits="8" />{MATH}'),
        "bad_number",
    ),
    # SPEC-003 R74: MATH and equations.
    (
        "MATH attribute",
        constant(f'<title>C</title><EMBEDDEDDATA {EMBED} /><MATH equation="X" x="1"><VAR id="X" /></MATH>'),
        "unknown_attribute",
    ),
    ("no VAR", constant(f'<title>C</title><EMBEDDEDDATA {EMBED} /><MATH equation="X" />'), "unsupported_equation"),
    (
        "two VARs",
        constant(f'<title>C</title><EMBEDDEDDATA {EMBED} /><MATH equation="X"><VAR id="X" /><VAR id="Y" /></MATH>'),
        "unsupported_equation",
    ),
    (
        "VAR Y",
        constant(f'<title>C</title><EMBEDDEDDATA {EMBED} /><MATH equation="X"><VAR id="Y" /></MATH>'),
        "unsupported_equation",
    ),
    (
        "VAR child",
        constant(f'<title>C</title><EMBEDDEDDATA {EMBED} /><MATH equation="X"><VAR id="X"><a /></VAR></MATH>'),
        "unknown_element",
    ),
    (
        "divide by zero",
        constant(f'<title>C</title><EMBEDDEDDATA {EMBED} /><MATH equation="X/0"><VAR id="X" /></MATH>'),
        "zero_factor",
    ),
    (
        "times zero",
        constant(f'<title>C</title><EMBEDDEDDATA {EMBED} /><MATH equation="X*0"><VAR id="X" /></MATH>'),
        "zero_factor",
    ),
    # SPEC-003 R70, R72: tables.
    ("table flags", table(attrs=' flags="0x1"'), "unsupported_flags"),
    ("axis without id", table(extra="<XDFAXIS />"), "missing_element"),
    ("axis id w", table(extra='<XDFAXIS id="w" />'), "bad_shape"),
    ("two x axes", table(extra=f'<XDFAXIS id="x">{LABELS2}</XDFAXIS>'), "bad_shape"),
    ("axis attribute", table(extra='<XDFAXIS id="y" size="1" />'), "unknown_attribute"),
    ("no z", "<XDFTABLE><title>T</title></XDFTABLE>", "missing_element"),
    (
        "labels on z",
        table(z=f'<EMBEDDEDDATA {EMBED} mmedcolcount="2" /><LABEL index="0" value="1" />{MATH}'),
        "unknown_element",
    ),
    ("zero rows", table(z=f'<EMBEDDEDDATA {EMBED} mmedrowcount="0" mmedcolcount="2" />{MATH}'), "bad_dims"),
    ("too many cols", table(z=f'<EMBEDDEDDATA {EMBED} mmedcolcount="65536" />{MATH}'), "bad_dims"),
    (
        "no y axis for 2 rows",
        table(z=f'<EMBEDDEDDATA {EMBED} mmedrowcount="2" mmedcolcount="2" />{MATH}'),
        "dims_mismatch",
    ),
    ("z without MATH", table(z=f'<EMBEDDEDDATA {EMBED} mmedcolcount="2" />'), "missing_element"),
    # SPEC-003 R73: stored and label axes.
    ("labels on a stored axis", table(x=f"<EMBEDDEDDATA {EMBED} />{LABELS2}{MATH}"), "bad_labels"),
    ("stored axis without MATH", table(x=f"<EMBEDDEDDATA {EMBED} /><indexcount>2</indexcount>"), "missing_element"),
    (
        "stored axis with rows",
        table(x=f'<EMBEDDEDDATA {EMBED} mmedrowcount="1" /><indexcount>2</indexcount>{MATH}'),
        "unknown_attribute",
    ),
    (
        "label axis embedded child",
        table(x=f'<EMBEDDEDDATA mmedelementsizebits="8"><a /></EMBEDDEDDATA>{LABELS2}'),
        "unknown_element",
    ),
    (
        "repeated label",
        table(x='<indexcount>2</indexcount><LABEL index="0" value="1" /><LABEL index="0" value="2" />'),
        "bad_labels",
    ),
    (
        "label gap",
        table(x='<indexcount>2</indexcount><LABEL index="0" value="1" /><LABEL index="2" value="2" />'),
        "bad_labels",
    ),
    (
        "label without index",
        table(x='<indexcount>2</indexcount><LABEL value="1" /><LABEL index="1" value="2" />'),
        "missing_element",
    ),
    (
        "label attribute",
        table(x='<indexcount>2</indexcount><LABEL index="0" value="1" n="a" /><LABEL index="1" value="2" />'),
        "unknown_attribute",
    ),
    (
        "free-text label",
        table(x='<indexcount>2</indexcount><LABEL index="0" value="low" /><LABEL index="1" value="2" />'),
        "non_numeric_label",
    ),
    (
        "label of 5000 digits",
        table(x=f'<indexcount>2</indexcount><LABEL index="0" value="{"7" * 5000}" /><LABEL index="1" value="2" />'),
        "rational_too_large",
    ),
    (
        "label index not a number",
        table(x='<indexcount>2</indexcount><LABEL index="a" value="1" /><LABEL index="1" value="2" />'),
        "bad_number",
    ),
    ("label MATH without equation", table(x=f'{LABELS2}<MATH><VAR id="X" /></MATH>'), "missing_element"),
]


@pytest.mark.parametrize(("label", "body", "reason"), MAP_CASES, ids=[case[0] for case in MAP_CASES])
def test_map_rejections(label: str, body: str, reason: str) -> None:
    result = import_xdf(document(body), PARAMS)
    assert [r.reason for r in result.rejected] == [reason], label
    assert result.definition.mapdefs == ()
    assert result.ignored == ()


FILE_CASES: list[tuple[str, bytes, str]] = [
    # SPEC-003 R80
    ("declared Latin-1", b'<?xml version="1.0" encoding="ISO-8859-1"?><XDFFORMAT />', "unsupported_encoding"),
    ("not UTF-8", b"<XDFFORMAT>\xff</XDFFORMAT>", "unsupported_encoding"),
    ("UTF-16 with BOM", "<XDFFORMAT />".encode("utf-16"), "unsupported_encoding"),
    ("doctype", b"<!DOCTYPE XDFFORMAT><XDFFORMAT />", "xml_forbidden"),
    ("external entity", b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>', "xml_forbidden"),
    ("billion laughs", b'<!DOCTYPE x [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;">]><x>&b;</x>', "xml_forbidden"),
    ("undefined entity", b"<XDFFORMAT>&nope;</XDFFORMAT>", "bad_xml"),
    ("unclosed", b"<XDFFORMAT>", "bad_xml"),
    ("empty", b"", "bad_xml"),
    # SPEC-003 R61: file level.
    ("other root", b"<XDF />", "unknown_element"),
    ("root attribute", b'<XDFFORMAT lang="de" />', "unknown_attribute"),
    ("unknown top element", document("<XDFNOTE />"), "unknown_element"),
    ("header attribute", document("", '<XDFHEADER a="1" />'), "unknown_attribute"),
    ("unknown header child", document("", "<XDFHEADER><bogus /></XDFHEADER>"), "unknown_element"),
    # SPEC-003 R70
    (
        "BASEOFFSET attribute",
        document("", '<XDFHEADER><BASEOFFSET offset="0" scale="1" /></XDFHEADER>'),
        "unknown_attribute",
    ),
    ("text baseoffset", document("", "<XDFHEADER><baseoffset>16</baseoffset></XDFHEADER>"), "unsupported_baseoffset"),
    ("DEFAULTS attribute", document("", '<XDFHEADER><DEFAULTS endian="1" /></XDFHEADER>'), "unknown_attribute"),
    ("DEFAULTS float", document("", '<XDFHEADER><DEFAULTS float="1" /></XDFHEADER>'), "unverified_defaults"),
    ("DEFAULTS not a number", document("", '<XDFHEADER><DEFAULTS signed="no" /></XDFHEADER>'), "bad_number"),
    ("header flags", document("", "<XDFHEADER><flags>0x1</flags></XDFHEADER>"), "unsupported_flags"),
    # SPEC-003 R28, R35: two maps with one name at one address get one derived id.
    ("same map twice", document(constant() + constant()), "duplicate_map_id"),
]


@pytest.mark.parametrize(("label", "source", "reason"), FILE_CASES, ids=[case[0] for case in FILE_CASES])
def test_file_rejections(label: str, source: bytes, reason: str) -> None:
    with pytest.raises(DefinitionError) as caught:
        import_xdf(source, PARAMS)
    assert caught.value.reason == reason, label


# SPEC-003 R70, R71: accepted zero settings and ignored items at file level and in maps.
def test_accepted_and_ignored() -> None:
    header = (
        '<XDFHEADER><baseoffset> 0 </baseoffset><flags>0</flags><BASEOFFSET subtract="1" /><author>me</author>'
        '<DEFAULTS signed="0x0" /></XDFHEADER>'
    )
    body = (
        constant(f'<title>C</title><description>d</description><EMBEDDEDDATA {EMBED} mmedmajorstridebits="0" />{MATH}')
        + table(attrs=' flags="0" uniqueid="0x9"', z=f'<EMBEDDEDDATA {EMBED} mmedcolcount="2" /><min>0</min>{MATH}')
        + "<XDFPATCH /><XDFFLAG />"
    )
    result = import_xdf(document(body, header), PARAMS)
    assert [(r.path, r.reason) for r in result.rejected] == [
        ("XDFFORMAT[0]/XDFFLAG[0]", "unsupported_element"),
        ("XDFFORMAT[0]/XDFPATCH[0]", "unsupported_element"),
    ]
    assert result.ignored == (
        "XDFFORMAT[0]/XDFCONSTANT[0]/description[0]",
        "XDFFORMAT[0]/XDFHEADER[0]/author[0]",
        "XDFFORMAT[0]/XDFTABLE[0]/@uniqueid",
        "XDFFORMAT[0]/XDFTABLE[0]/XDFAXIS[1]/min[0]",
    )
    assert len(result.definition.mapdefs) == 2


# SPEC-003 R71 (literal reading): `uniqueid` on an axis is ignored, the z axis included.
def test_uniqueid_on_z_is_ignored() -> None:
    body = table().replace('<XDFAXIS id="z">', '<XDFAXIS id="z" uniqueid="0x1">')
    assert import_xdf(document(body), PARAMS).ignored == ("XDFFORMAT[0]/XDFTABLE[0]/XDFAXIS[1]/@uniqueid",)


# SPEC-003 R72: an axis on a dimension of size 1 is kept, so the file round-trips.
def test_axis_on_dimension_one_is_kept() -> None:
    body = table(extra='<XDFAXIS id="y"><indexcount>1</indexcount><LABEL index="0" value="5" /></XDFAXIS>')
    (mapdef,) = import_xdf(document(body), PARAMS).definition.mapdefs
    assert mapdef.y == FixedAxis((F(5),), None, "")
    assert import_xdf(export_xdf(definition(mapdef), "cal"), PARAMS).definition.mapdefs == (mapdef,)


# SPEC-003 §7.1 (P rows): type flags give signedness, byte order and binary32.
@pytest.mark.parametrize(
    ("flags", "bits", "dtype"),
    [
        ("0x00", "16", ("uint", 16, "be")),
        ("0x01", "16", ("int", 16, "be")),
        ("0x02", "32", ("uint", 32, "le")),
        ("0x03", "8", ("int", 8, "none")),
        ("0x10000", "32", ("float", 32, "be")),
        ("0x10002", "32", ("float", 32, "le")),
    ],
)
def test_type_flags(flags: str, bits: str, dtype: tuple[str, int, str]) -> None:
    body = constant(
        f'<title>C</title><EMBEDDEDDATA mmedaddress="16" mmedelementsizebits="{bits}" mmedtypeflags="{flags}" />{MATH}'
    )
    (mapdef,) = import_xdf(document(body), PARAMS).definition.mapdefs
    assert (mapdef.dtype.kind, mapdef.dtype.bits, mapdef.dtype.byte_order) == dtype


EQUATIONS = [
    ("X", F(1), F(0)),
    ("X+5", F(1), F(5)),
    ("X-0.5", F(1), F(-1, 2)),
    ("X*2", F(2), F(0)),
    ("X*-2+1", F(-2), F(1)),
    ("X*0.25-1.5", F(1, 4), F(-3, 2)),
    ("-2*X", F(-2), F(0)),
    ("2.5*X-1", F(5, 2), F(-1)),
    ("X/4", F(1, 4), F(0)),
    ("X/3+1", F(1, 3), F(1)),
    ("X/3-1", F(1, 3), F(-1)),
    ("1+X*2", F(2), F(1)),
    ("1-X*2", F(-2), F(1)),
    ("1-X*-2", F(2), F(1)),
    ("1.5+X/8", F(1, 8), F(3, 2)),
    (" X * 2 ", F(2), F(0)),
    ("\tX + 1\n", F(1), F(1)),
]


# SPEC-003 R74: every accepted form, exact.
@pytest.mark.parametrize(("text", "factor", "addend"), EQUATIONS, ids=[e[0].strip() for e in EQUATIONS])
def test_equation_forms(text: str, factor: Fraction, addend: Fraction) -> None:
    assert parse_equation(text) == (factor, addend)


# SPEC-003 R74: anything else is unsupported; X/0 has no factor.
@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("X*X", "unsupported_equation"),
        ("X/3.5", "unsupported_equation"),
        ("(X)", "unsupported_equation"),
        ("X^2", "unsupported_equation"),
        ("1-X/4", "unsupported_equation"),
        ("Y", "unsupported_equation"),
        ("X+-1", "unsupported_equation"),
        ("+1+X*2", "unsupported_equation"),
        ("X*1e3", "unsupported_equation"),
        ("X\u00a0", "unsupported_equation"),
        ("X/0", "zero_factor"),
        ("1+X/00", "zero_factor"),
    ],
)
def test_equation_rejections(text: str, reason: str) -> None:
    with pytest.raises(DefinitionError) as caught:
        parse_equation(text)
    assert caught.value.reason == reason


# SPEC-003 §7.1, R61: decimal or 0x hexadecimal, ASCII whitespace only, within 2**53 - 1.
def test_parse_integer() -> None:
    assert parse_integer("0x1F") == 31
    assert parse_integer("0xff") == 255
    assert parse_integer(" \t12\r\n") == 12
    assert parse_integer("0x" + "0" * 100 + "1") == 1
    assert parse_integer(str(2**53 - 1)) == 2**53 - 1
    for text in ("0X1F", "+1", "1_0", "0x", "", "1.0", "\u00a012", str(2**53)):
        with pytest.raises(DefinitionError) as caught:
            parse_integer(text)
        assert caught.value.reason == "bad_number", text


# SPEC-003 R17: exact aliases; a k != 1 alias applies only when the result stays XDF-exportable.
def test_unit_mapping_on_import() -> None:
    body = (
        constant(f"<title>A</title><EMBEDDEDDATA {EMBED} /><units>°C</units>{MATH}")
        + constant(
            f'<title>B</title><EMBEDDEDDATA {EMBED} /><units>s</units><MATH equation="X/3"><VAR id="X" /></MATH>'
        )
        + table(
            x='<indexcount>2</indexcount><units>s</units><LABEL index="0" value="0.5" /><LABEL index="1" value="2" />'
        )
    )
    a, b, t = sorted(import_xdf(document(body), PARAMS).definition.mapdefs, key=lambda m: m.name)
    assert (a.unit, a.unit_text) == ("degC", None)
    assert (b.unit, b.unit_text, b.scaling) == (None, "s", Scaling(F(1, 3), F(0)))
    assert t.x == FixedAxis((F(500), F(2000)), "ms", None)


# SPEC-003 R44: converters take an unverified or a claimed license, never platform_created.
def test_params() -> None:
    claimed = License("verifiable_license", "contract-7")
    assert replace(PARAMS, license=claimed).license == claimed
    with pytest.raises(DefinitionError) as caught:
        replace(PARAMS, license=License("platform_created", None))
    assert caught.value.reason == "bad_shape"
    with pytest.raises(DefinitionError) as caught:
        replace(PARAMS, license=cast(Any, "unverified"))
    assert caught.value.reason == "bad_shape"
    with pytest.raises(DefinitionError) as caught:
        replace(PARAMS, memory_id="Cal")
    assert caught.value.reason == "bad_identifier"
    with pytest.raises(DefinitionError) as caught:
        import_xdf(document(""), cast(Any, {"memory_id": "cal"}))
    assert caught.value.reason == "bad_shape"


def _export_error(*mapdefs: MapDef) -> str | None:
    with pytest.raises(DefinitionError) as caught:
        export_xdf(definition(*mapdefs), "cal")
    assert caught.value.reason == "unrepresentable"
    return caught.value.field


TWO_BY_TWO = replace(
    SCALAR, map_id="syn.grid", rows=2, cols=2, x=replace(INLINE, count=2), y=replace(FIXED3, values=(F(1), F(2)))
)


# SPEC-003 R64, R76: the field of the first violation.
def test_export_fields() -> None:
    assert _export_error(replace(TWO_BY_TWO, cell_order="y_fastest")) == "cell_order"
    assert _export_error(replace(TWO_BY_TWO, x=replace(INLINE, count=2, memory_id="pflash"))) == "axes.x.memory_id"
    third = Scaling(F(2, 3), F(0))
    assert _export_error(replace(TWO_BY_TWO, x=replace(INLINE, count=2, scaling=third))) == "axes.x.scaling.factor"
    assert (
        _export_error(replace(TWO_BY_TWO, x=replace(INLINE, count=2, scaling=Scaling(F(1), F(1, 3)))))
        == "axes.x.scaling.addend"
    )
    assert _export_error(replace(TWO_BY_TWO, y=replace(FIXED3, values=(F(1), F(1, 3))))) == "axes.y.values"
    assert _export_error(replace(TWO_BY_TWO, scaling=third)) == "scaling.factor"
    assert _export_error(replace(SCALAR, name="A￾")) == "name"
    assert _export_error(replace(SCALAR, unit=None, unit_text="￿")) == "unit_text"
    assert (
        _export_error(replace(TWO_BY_TWO, x=replace(INLINE, count=2, unit=None, unit_text="￿"))) == "axes.x.unit_text"
    )
    assert (
        _export_error(replace(TWO_BY_TWO, y=replace(FIXED3, values=(F(1), F(2)), unit_text="￾"))) == "axes.y.unit_text"
    )
    assert _export_error(SCALAR, replace(SCALAR, map_id="syn.copy")) == "map_id"
    assert _export_error(replace(SCALAR, unit=None, unit_text="s", scaling=Scaling(F(10**39), F(0)))) == "unit"
    with pytest.raises(DefinitionError) as caught:
        export_xdf(definition(SCALAR), "Cal")
    assert caught.value.reason == "bad_identifier"


# SPEC-003 R77: escaping, negative factors, 1/N factors, flags; R64: each re-imports to its normal form.
def test_export_round_trips() -> None:
    maps = (
        replace(SCALAR, map_id="syn.a", name='A&B <"x">', unit=None, unit_text="a<b"),
        replace(SCALAR, map_id="syn.b", name="B", offset=4, dtype=F32BE, scaling=Scaling(F(-1, 2), F(-40))),
        replace(SCALAR, map_id="syn.c", name="C", offset=8, dtype=U16LE, scaling=Scaling(F(1, 3), F(7, 4))),
        replace(TABLE, x=replace(INLINE, dtype=U16LE, scaling=Scaling(F(1, 7), F(0)))),
    )
    exported = export_xdf(definition(*maps), "cal")
    assert b"<title>A&amp;B &lt;&quot;x&quot;&gt;</title>" in exported
    assert b'equation="X*-0.5-40"' in exported
    assert b'equation="X/3+1.75"' in exported
    assert b'mmedtypeflags="0x10000"' in exported
    assert b'mmedtypeflags="0x02"' in exported
    names = sorted(m.name for m in import_xdf(exported, PARAMS).definition.mapdefs)
    assert names == ['A&B <"x">', "B", "C", "SYN_TABLE"]
    assert IDENTITY.factor == 1


# SPEC-003 R99, §12 question 4: the A2L converter is specified but not implemented; it refuses.
def test_a2l_converter_refuses() -> None:
    with pytest.raises(NotImplementedError):
        import_a2l(b"/begin PROJECT p /end PROJECT")
    with pytest.raises(NotImplementedError):
        export_a2l(definition(SCALAR), ())


# SPEC-003 R90: wrong arity and unknown types are unsupported conversions.
@pytest.mark.parametrize(
    ("kind", "coeffs"),
    [
        ("IDENTICAL", ["1"]),
        ("LINEAR", ["1"]),
        ("RAT_FUNC", ["0", "0", "0", "0", "0", "1"]),
        ("RAT_FUNC", ["1"]),
        ("TAB_INTP", []),
    ],
)
def test_compu_method_rejections(kind: str, coeffs: list[str]) -> None:
    with pytest.raises(DefinitionError) as caught:
        compu_method_scaling(kind, coeffs)
    assert caught.value.reason == "unsupported_conversion"


def test_inline_axis_import_keeps_its_dtype() -> None:
    embedded = '<EMBEDDEDDATA mmedaddress="0x20" mmedelementsizebits="16" mmedtypeflags="0x02" />'
    body = table(x=f"{embedded}<indexcount>2</indexcount>{MATH}")
    (mapdef,) = import_xdf(document(body), PARAMS).definition.mapdefs
    assert mapdef.x == InlineAxis("cal", 32, 2, U16LE, IDENTITY, None, "")
