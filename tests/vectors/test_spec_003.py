"""SPEC-003 §10: every vector in specs/vectors/spec-003/vectors.json, against the core.

Expected values come from generate.py (hand-written JSON literals, `fractions`, `struct`, third-party
rfc8785) and are cross-checked by crosscheck.py; nothing here is computed by the core and then
compared with itself.
"""

import json
from collections.abc import Callable
from fractions import Fraction
from pathlib import Path
from typing import Any

import pytest

from core.definitions import (
    Definition,
    DefinitionError,
    Dtype,
    License,
    Scaling,
    SoftwareVersion,
    XdfParams,
    axisdef_hash,
    compu_method_scaling,
    decode_cell,
    definition_from_json,
    definition_hash,
    definition_json,
    derive_map_id,
    encode_cell,
    export_xdf,
    import_xdf,
    mapdef_from_json,
    mapdef_hash,
    mapdef_json,
    normalize_xdf,
    parse_a2l_number,
    parse_rational,
    parse_xdf_decimal,
    rat_func_coeffs,
    rational_text,
    span,
)
from core.definitions._cells import decode_raw, physical_to_raw, raw_to_physical
from core.definitions._xdf import _scaled_unit
from core.kernel import Dump, Memory

VECTORS_PATH = Path(__file__).resolve().parents[2] / "specs" / "vectors" / "spec-003" / "vectors.json"
VECTORS: dict[str, Any] = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))

GRAMMARS: dict[str, Callable[[str], Fraction]] = {
    "xdf_decimal": parse_xdf_decimal,
    "a2l_number": parse_a2l_number,
    "rational_text": parse_rational,
}


def dtype_of(value: dict[str, Any]) -> Dtype:
    return Dtype(value["kind"], value["bits"], value["byte_order"])


def scaling_of(value: dict[str, Any]) -> Scaling:
    return Scaling(parse_rational(value["factor"]), parse_rational(value["addend"]))


def params_of(value: dict[str, Any]) -> XdfParams:
    version = value["software_version"]
    return XdfParams(
        value["family_id"],
        SoftwareVersion(version["match"], tuple(version["values"])),
        value["memory_id"],
        License(value["license"]["kind"], value["license"]["reference"]),
        value["confidence_permille"],
    )


def dump_of(value: dict[str, Any]) -> Dump:
    data = {m["memory_id"]: bytearray(m["size"]) for m in value["memories"]}
    for chunk in value["bytes"]:
        raw = bytes.fromhex(chunk["hex"])
        data[chunk["memory_id"]][chunk["offset"] : chunk["offset"] + len(raw)] = raw
    memories = tuple(Memory(m["memory_id"], m["base_address"], bytes(data[m["memory_id"]])) for m in value["memories"])
    return Dump("virtual", memories)


def by_id(section: str) -> list[Any]:
    return [pytest.param(v, id=v["id"]) for v in VECTORS[section]]


def by_key(section: str) -> list[Any]:
    return [pytest.param(k, v, id=k) for k, v in VECTORS[section].items()]


# SPEC-003 R3, R74, R91 (vectors Q1-Q16)
@pytest.mark.parametrize("vector", by_id("rationals"))
def test_rationals(vector: dict[str, Any]) -> None:
    parse = GRAMMARS[vector["grammar"]]
    if "error" in vector["expect"]:
        with pytest.raises(DefinitionError) as caught:
            parse(vector["text"])
        assert caught.value.reason == vector["expect"]["error"]
    else:
        assert rational_text(parse(vector["text"])) == vector["expect"]["value"]


# SPEC-003 R6, R7, R12 (vectors C1-C16)
@pytest.mark.parametrize("vector", by_id("decode"))
def test_decode(vector: dict[str, Any]) -> None:
    dtype, scaling = dtype_of(vector["dtype"]), scaling_of(vector["scaling"])
    data = bytes.fromhex(vector["bytes_hex"])
    raw = decode_raw(dtype, data)
    physical = decode_cell(dtype, scaling, data)
    assert ("non_finite" if raw is None else rational_text(raw)) == vector["expect"]["raw"]
    assert (physical if isinstance(physical, str) else rational_text(physical)) == vector["expect"]["physical"]


# SPEC-003 R13, R14, R15 (vectors E1-E19)
@pytest.mark.parametrize("vector", by_id("encode"))
def test_encode(vector: dict[str, Any]) -> None:
    dtype, scaling = dtype_of(vector["dtype"]), scaling_of(vector["scaling"])
    # Targets are conversion values, unbounded by R3, so they are parsed by the standard library.
    target = Fraction(vector["target"])
    current = None if vector["current_hex"] is None else bytes.fromhex(vector["current_hex"])
    if "error" in vector["expect"]:
        with pytest.raises(DefinitionError) as caught:
            encode_cell(dtype, scaling, target, current)
        assert caught.value.reason == vector["expect"]["error"]
        return
    encoded = encode_cell(dtype, scaling, target, current)
    assert encoded.hex() == vector["expect"]["bytes_hex"]
    raw = decode_raw(dtype, encoded)
    assert raw is not None
    if dtype.kind != "float":
        # R14: raw -> physical -> raw is the identity on the integer result.
        assert physical_to_raw(dtype, scaling, raw_to_physical(scaling, raw)) == raw


# SPEC-003 R16, R17 (vectors U1-U7)
@pytest.mark.parametrize("vector", by_id("units"))
def test_units(vector: dict[str, Any]) -> None:
    scaling = scaling_of(vector["scaling"])
    unit, unit_text, mapped = _scaled_unit(vector["unit_text"], scaling.factor, scaling.addend)
    assert unit == vector["expect"]["unit"]
    assert unit_text == vector["expect"]["unit_text"]
    assert mapped == scaling_of(vector["expect"]["scaling"])


# SPEC-003 R90 (vectors A1a-A1j)
@pytest.mark.parametrize("vector", by_id("a2l_compu"))
def test_a2l_compu_method(vector: dict[str, Any]) -> None:
    if "error" in vector["expect"]:
        with pytest.raises(DefinitionError) as caught:
            compu_method_scaling(vector["conversion_type"], vector["coeffs"])
        assert caught.value.reason == vector["expect"]["error"]
    else:
        scaling = compu_method_scaling(vector["conversion_type"], vector["coeffs"])
        assert scaling == scaling_of(vector["expect"]["scaling"])


# SPEC-003 R99 (vectors A2a-A2d): export coefficients and their re-import through R90.
@pytest.mark.parametrize("vector", by_id("a2l_export"))
def test_a2l_export_coefficients(vector: dict[str, Any]) -> None:
    scaling = scaling_of(vector["scaling"])
    coeffs = rat_func_coeffs(scaling)
    assert list(coeffs) == vector["expect"]["coeffs"]
    assert compu_method_scaling("RAT_FUNC", [str(c) for c in coeffs]) == scaling


# SPEC-003 R26, R28, R51 (vectors M1, M2)
@pytest.mark.parametrize(("key", "vector"), by_key("mapdefs"))
def test_mapdefs(key: str, vector: dict[str, Any]) -> None:
    mapdef = mapdef_from_json(vector["value"])
    assert mapdef_json(mapdef) == vector["value"]
    assert mapdef_hash(mapdef) == vector["mapdef_hash"], key
    if "derive" in vector:
        derive = vector["derive"]
        assert derive_map_id(derive["memory_id"], derive["name"], derive["offset"]) == mapdef.map_id


def definition_vector(key: str) -> Definition:
    vector = VECTORS["definitions"][key]
    return definition_from_json(vector.get("value", vector.get("input")))


# SPEC-003 R20, R21, R23, R34-R38, R51, R52 (vectors D1-D3)
@pytest.mark.parametrize(("key", "vector"), by_key("definitions"))
def test_definitions(key: str, vector: dict[str, Any]) -> None:
    definition = definition_vector(key)
    assert definition_hash(definition) == vector["definition_hash"]
    if "value" in vector:
        assert definition_json(definition) == vector["value"]
    for axis_id, expected in vector.get("axisdef_hashes", {}).items():
        assert axisdef_hash(definition.axes[[a.axis_id for a in definition.axes].index(axis_id)]) == expected
    if "expect_same_as" in vector:
        # R35: input order never changes the definition or its hash.
        assert definition == definition_vector(vector["expect_same_as"])
        assert definition_json(definition) == VECTORS["definitions"][vector["expect_same_as"]]["value"]
    if "differs_from" in vector:
        assert definition_hash(definition) != definition_hash(definition_vector(vector["differs_from"]))


# SPEC-003 R22, R30, R55 (vectors S1, S2)
@pytest.mark.parametrize(("key", "vector"), by_key("spans"))
def test_spans(key: str, vector: dict[str, Any]) -> None:
    source = vector["definition"]
    definition = definition_vector(source) if isinstance(source, str) else definition_from_json(source)
    dump = dump_of(vector["dump"])
    assert {m.map_id for m in definition.mapdefs} == set(vector["expect"]), key
    for mapdef in definition.mapdefs:
        expected = vector["expect"][mapdef.map_id]
        if isinstance(expected, dict):
            with pytest.raises(DefinitionError) as caught:
                span(mapdef, definition, dump)
            assert caught.value.reason == expected["error"]
        else:
            got = [{"memory_id": r.memory_id, "start": r.start, "end": r.end} for r in span(mapdef, definition, dump)]
            assert got == expected


# SPEC-003 R61-R64, R70-R77, R79 (vector X1)
def test_xdf_import_export_reimport() -> None:
    vector = VECTORS["xdf"]["X1"]
    params = params_of(vector["params"])
    result = import_xdf(vector["source"].encode("utf-8"), params)
    assert definition_json(result.definition) == vector["expect"]["definition"]
    assert definition_hash(result.definition) == vector["expect"]["definition_hash"]
    assert [{"path": r.path, "reason": r.reason} for r in result.rejected] == vector["expect"]["rejected"]
    assert list(result.ignored) == vector["expect"]["ignored"]
    exported = export_xdf(result.definition, params.memory_id)
    assert exported == vector["export"].encode("utf-8")
    again = import_xdf(exported, params)
    assert definition_hash(again.definition) == vector["reimport"]["definition_hash"]
    assert [r.path for r in again.rejected] == vector["reimport"]["rejected"]
    assert list(again.ignored) == vector["reimport"]["ignored"]


# SPEC-003 R64, R76, R77 (vector XE1): a definition already in import-normal form.
def test_xdf_export_of_import_normal_form() -> None:
    vector = VECTORS["xdf"]["XE1"]
    definition = definition_from_json(vector["definition"])
    assert definition_hash(definition) == vector["definition_hash"]
    exported = export_xdf(definition, "cal")
    assert exported == vector["export"].encode("utf-8")
    again = import_xdf(exported, params_of(vector["params"]))
    assert definition_hash(again.definition) == vector["reimport"]["definition_hash"]
    assert [r.path for r in again.rejected] == vector["reimport"]["rejected"]
    assert list(again.ignored) == vector["reimport"]["ignored"]


# SPEC-003 R64, R75-R77 (vector XN1): a platform-form definition re-imports as normalize(e, P).
def test_xdf_export_of_platform_form() -> None:
    vector = VECTORS["xdf"]["XN1"]
    params = params_of(vector["params"])
    definition = definition_from_json(vector["definition"])
    exported = export_xdf(definition, params.memory_id)
    assert exported == vector["export"].encode("utf-8")
    again = import_xdf(exported, params)
    assert definition_json(again.definition) == vector["normalized"]
    assert definition_hash(again.definition) == vector["normalized_hash"]
    assert again.rejected == ()
    assert definition_json(normalize_xdf(definition, params)) == vector["normalized"]


# SPEC-003 R76 (vectors XU1-XU7)
@pytest.mark.parametrize("vector", [pytest.param(v, id=v["id"]) for v in VECTORS["xdf"]["export_rejects"]])
def test_xdf_export_rejects(vector: dict[str, Any]) -> None:
    definition = definition_from_json(vector["definition"])
    with pytest.raises(DefinitionError) as caught:
        export_xdf(definition, vector["memory_id"])
    assert caught.value.reason == vector["expect"]["error"]
    assert caught.value.field == vector["expect"]["field"]


X_PARAMS = XdfParams("synthetic.test", SoftwareVersion("exact", ("SYN0001",)), "cal", License("unverified", None), 0)


# SPEC-003 R61, R70, R72-R74, R80 (vectors X2-X15)
@pytest.mark.parametrize("vector", [pytest.param(v, id=v["id"]) for v in VECTORS["xdf"]["rejects"]])
def test_xdf_import_rejects(vector: dict[str, Any]) -> None:
    source = vector["source"].encode("utf-8")
    if "error" in vector["expect"]:
        with pytest.raises(DefinitionError) as caught:
            import_xdf(source, X_PARAMS)
        assert caught.value.reason == vector["expect"]["error"]
    else:
        result = import_xdf(source, X_PARAMS)
        assert [{"path": r.path, "reason": r.reason} for r in result.rejected] == vector["expect"]["rejected"]
        assert len(result.definition.mapdefs) == (0 if result.rejected else 1)


def test_every_vector_section_is_tested() -> None:
    tested = {"rationals", "decode", "encode", "units", "a2l_compu", "a2l_export", "mapdefs", "definitions", "spans"}
    assert set(VECTORS) - {"spec", "generator"} == {*tested, "xdf"}
    assert set(VECTORS["xdf"]) == {"X1", "XE1", "XN1", "export_rejects", "rejects"}
