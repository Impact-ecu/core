"""SPEC-002 §2, §4.1: contract shapes, descriptor schema, JSON forms and the contract JCS encoder."""

import copy
import hashlib
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import replace
from typing import Any, cast

import pytest
import rfc8785

import core.kernel
import core.plugins
from core.plugins import (
    Bypass,
    ChecksumDescriptor,
    ChecksumRegion,
    Compensate,
    ContractJson,
    Crc32,
    DescriptorError,
    Field,
    InterpreterDivergence,
    MapHint,
    MirrorBlock,
    MirrorDescriptor,
    PiiLocation,
    PluginContractError,
    PresentMemory,
    Range,
    Reference,
    RegionResult,
    Table,
    TableField,
    VerifyReport,
    WordAlgorithm,
    checksum_region_json,
    contract_hash,
    contract_json,
    descriptor_from_json,
    descriptor_hash,
    descriptor_json,
    identification_hash,
    identification_json,
    map_hint_json,
    output_fields,
    region_result_json,
    verify_report_json,
    width,
)
from tests.unit.plugin_fixtures import DESCRIPTORS, FIXTURE, IDENT, INTERPRETER, NONE, REGIONS, python_region


def contract_error(reason: str) -> AbstractContextManager[pytest.ExceptionInfo[PluginContractError]]:
    return pytest.raises(PluginContractError, match=rf"^{reason}\b")


def schema_error() -> AbstractContextManager[pytest.ExceptionInfo[DescriptorError]]:
    return pytest.raises(DescriptorError, match=r"^schema")


def fixture_json(name: str) -> dict[str, Any]:
    for entry in FIXTURE["descriptors"]:
        if entry["value"]["name"] == name:
            return copy.deepcopy(entry["value"])
    raise KeyError(name)


def force(obj: object, attribute: str, value: object) -> None:
    # Bypass __post_init__ to test that the core re-validates what it is handed (R11).
    object.__setattr__(obj, attribute, value)


# SPEC-002 R1: kernel types are the SPEC-001 ones, not redefined in core.plugins.
def test_kernel_types_are_reused() -> None:
    for name in ("Dump", "Memory", "MemoryLayout", "Patch", "Region"):
        assert not hasattr(core.plugins, name) or getattr(core.plugins, name) is getattr(core.kernel, name)
    assert all(hasattr(core.plugins, name) for name in core.plugins.__all__)


# SPEC-002 R9: errors carry a stable reason and none is a KernelError.
def test_errors() -> None:
    error = PluginContractError("r7", "detail")
    assert (error.reason, error.detail, str(error)) == ("r7", "detail", "r7: detail")
    assert str(DescriptorError("schema")) == "schema"
    divergence = InterpreterDivergence("x")
    assert divergence.reason == "engine_divergence"
    for kind in (PluginContractError, DescriptorError, InterpreterDivergence):
        assert not issubclass(kind, core.kernel.KernelError)


# SPEC-002 R9, R78, R106: contract JCS equals RFC 8785 (rfc8785 is the independent oracle).
@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        False,
        0,
        -5,
        2**53 - 1,
        'a"b\\c\b\f\n\r\t\x01é',
        [1, "x", [None, True]],
        {"b": 1, "a": {"\U0001f600": 1, "￿": 2, "z": False}},
    ],
)
def test_contract_json_is_rfc8785(value: ContractJson) -> None:
    assert contract_json(value) == rfc8785.dumps(value)
    assert contract_hash(value) == hashlib.sha256(rfc8785.dumps(value)).hexdigest()


# SPEC-002 R3, R9: no float, no bytes, only exact integers.
def test_contract_json_rejections() -> None:
    with pytest.raises(ValueError, match="exact JSON range"):
        contract_json(2**53)
    with pytest.raises(TypeError, match="hex-encoded"):
        contract_json(cast(Any, b"x"))
    with pytest.raises(TypeError, match="float"):
        contract_json(cast(Any, 1.5))
    with pytest.raises(TypeError, match="object"):
        contract_json(cast(Any, object()))


# SPEC-002 R2, R3, R4, R5, R6, R14: the Identification shape.
def test_identification_valid_and_json() -> None:
    ident = replace(
        IDENT,
        pii_locations=(PiiLocation("pflash", 480, 497, "vin"), PiiLocation("pflash", 10, 12, "serial")),
        protection_flags=("tprot",),
    )
    value = identification_json(ident)
    assert value["pii_locations"] == [
        {"memory_id": "pflash", "start": 480, "end": 497, "kind": "vin"},
        {"memory_id": "pflash", "start": 10, "end": 12, "kind": "serial"},
    ]
    assert value["protection_flags"] == ["tprot"]
    assert identification_hash(ident) == hashlib.sha256(rfc8785.dumps(value)).hexdigest()


# SPEC-002 R13: same sw_id, another checksum variant: different identifications and hashes.
def test_variant_discrimination_is_visible() -> None:
    other = replace(IDENT, checksum_variant_id="fixture-512-b")
    assert other.sw_id == IDENT.sw_id
    assert identification_hash(other) != identification_hash(IDENT)
    assert replace(IDENT, checksum_variant_id=None).checksum_variant_id is None


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"family": "Bosch"}, "r2"),
        ({"family": "bosch"}, "r2"),
        ({"checksum_variant_id": "Bad"}, "r2"),
        ({"checksum_variant_id": 3}, "r2"),
        ({"hw_id": 1}, "r2"),
        ({"sw_id": 1}, "r2"),
        ({"mcu": 1}, "r2"),
        ({"confidence": 1001}, "r3"),
        ({"confidence": True}, "r3"),
        ({"confidence": -1}, "r3"),
        ({"memories_present": []}, "r4"),
        ({"memories_present": ()}, "r4"),
        ({"memories_present": (PresentMemory("b", None, 1), PresentMemory("a", None, 1))}, "r4"),
        ({"memories_present": (PresentMemory("a", None, 1), PresentMemory("a", None, 1))}, "r4"),
        ({"memories_absent": ["x"]}, "r5"),
        ({"memories_absent": ("Bad",)}, "r5"),
        ({"memories_absent": ("z", "a")}, "r5"),
        ({"memories_absent": ("pflash",)}, "r5"),
        ({"pii_locations": [PiiLocation("pflash", 0, 1, "vin")]}, "r6"),
        ({"pii_locations": (PiiLocation("pflash", 5, 6, "vin"), PiiLocation("pflash", 0, 1, "vin"))}, "r6"),
        ({"protection_flags": ("tprot", "tprot")}, "r14"),
        ({"protection_flags": ("off",)}, "r14"),
        ({"protection_flags": ["tprot"]}, "r14"),
    ],
)
def test_identification_rejections(changes: dict[str, Any], reason: str) -> None:
    # SPEC-002 R2-R6, R14
    with contract_error(reason):
        replace(IDENT, **changes)


# SPEC-002 R14, R91: TPROT is only a detected flag; the vocabulary has no value that writes it.
def test_tprot_is_informational() -> None:
    assert frozenset({"tprot"}) == core.plugins._contract.PROTECTION_FLAGS
    assert replace(IDENT, protection_flags=("tprot",)).protection_flags == ("tprot",)


# SPEC-002 R4, R6: element shapes.
@pytest.mark.parametrize(
    "build",
    [
        lambda: PresentMemory("Bad", None, 1),
        lambda: PresentMemory("a", -1, 1),
        lambda: PresentMemory("a", None, 0),
        lambda: PresentMemory("a", None, cast(Any, True)),
    ],
)
def test_present_memory_rejections(build: Callable[[], object]) -> None:
    with contract_error("r4"):
        build()


@pytest.mark.parametrize(
    "build",
    [
        lambda: PiiLocation("Bad", 0, 1, "vin"),
        lambda: PiiLocation("a", 1, 1, "vin"),
        lambda: PiiLocation("a", -1, 1, "vin"),
        lambda: PiiLocation("a", 0, 1, cast(Any, "plate")),
    ],
)
def test_pii_location_rejections(build: Callable[[], object]) -> None:
    # SPEC-002 R6: locations only, never values.
    with contract_error("r6"):
        build()


# SPEC-002 R7, R33, R78: ChecksumRegion shape, references and the derived descriptor_hash.
def test_regions_valid() -> None:
    signed = ChecksumRegion("sig", "pflash", "signed", None, None, None, NONE)
    assert signed.descriptor_hash is None
    independent = python_region("py", (Range(32, 40),), (Range(256, 260),), Reference("independent", "ref-1", "x"))
    unreferenced = python_region("py", (Range(32, 40),), (Range(256, 260),), NONE)
    assert REGIONS[0].descriptor_hash == descriptor_hash(DESCRIPTORS[0])
    value = checksum_region_json(independent)
    assert value["covered"] == [{"start": 32, "end": 40}]
    assert value["reference"] == {"kind": "independent", "id": "ref-1", "source": "x"}
    assert checksum_region_json(REGIONS[0])["descriptor"] == descriptor_json(DESCRIPTORS[0])
    assert checksum_region_json(signed)["fields"] is None
    assert unreferenced.reference.kind == "none"


R7_CASES = [
    lambda: ChecksumRegion("Bad", "pflash", "signed", None, None, None, NONE),
    lambda: ChecksumRegion("sig", "Bad", "signed", None, None, None, NONE),
    lambda: ChecksumRegion("sig", "pflash", "signed", None, (Range(0, 1),), None, NONE),
    lambda: ChecksumRegion("sig", "pflash", "signed", DESCRIPTORS[0], None, None, NONE),
    lambda: ChecksumRegion("sig", "pflash", "signed", None, None, (Range(0, 1),), NONE),
    lambda: ChecksumRegion("x", "pflash", cast(Any, "other"), None, None, None, NONE),
    lambda: python_region("py", cast(Any, None), (Range(0, 1),), NONE),
    lambda: python_region("py", (Range(0, 1),), cast(Any, [Range(0, 1)]), NONE),
    lambda: python_region("py", (Range(1, 1),), (Range(0, 1),), NONE),
    lambda: python_region("py", (Range(-1, 1),), (Range(0, 1),), NONE),
    lambda: python_region("py", (Range(0, 1),), (cast(Any, (0, 1)),), NONE),
    lambda: ChecksumRegion("a_comp", "pflash", "recalculable", DESCRIPTORS[0], (Range(0, 1),), None, INTERPRETER),
    lambda: ChecksumRegion("a_comp", "pflash", "recalculable", DESCRIPTORS[0], None, (Range(0, 1),), INTERPRETER),
    lambda: ChecksumRegion("other", "pflash", "recalculable", DESCRIPTORS[0], None, None, INTERPRETER),
    lambda: ChecksumRegion("a_comp", "eeprom", "recalculable", DESCRIPTORS[0], None, None, INTERPRETER),
]


@pytest.mark.parametrize("build", R7_CASES)
def test_region_r7(build: Callable[[], object]) -> None:
    # SPEC-002 R7
    with contract_error("r7"):
        build()


BAD_REFERENCE_CASES = [
    lambda: ChecksumRegion("a_comp", "pflash", "recalculable", DESCRIPTORS[0], None, None, NONE),
    lambda: ChecksumRegion("a_comp", "pflash", "recalculable", DESCRIPTORS[0], None, None, cast(Any, "interpreter")),
    lambda: ChecksumRegion("sig", "pflash", "signed", None, None, None, INTERPRETER),
    lambda: python_region("py", (Range(0, 1),), (Range(0, 1),), INTERPRETER),
    lambda: python_region("py", (Range(0, 1),), (Range(0, 1),), Reference("independent", None, "src")),
    lambda: python_region("py", (Range(0, 1),), (Range(0, 1),), Reference("independent", "Bad id", "src")),
    lambda: python_region("py", (Range(0, 1),), (Range(0, 1),), Reference("independent", "ref", "")),
    lambda: python_region("py", (Range(0, 1),), (Range(0, 1),), Reference("independent", "ref", None)),
    lambda: python_region("py", (Range(0, 1),), (Range(0, 1),), Reference("none", "ref", None)),
]


@pytest.mark.parametrize("build", BAD_REFERENCE_CASES)
def test_region_bad_reference(build: Callable[[], object]) -> None:
    # SPEC-002 R33: no default reference; only the allowed pairings.
    with contract_error("bad_reference"):
        build()


def ok_result(**changes: object) -> RegionResult:
    base: dict[str, Any] = {
        "name": "a",
        "memory_id": "pflash",
        "kind": "recalculable",
        "status": "ok",
        "stored": "00ff",
        "computed": "00ff",
        "reason": None,
        "bypass": None,
    }
    return RegionResult(**(base | changes))


# SPEC-002 R8, R40, R44, R46, R66: RegionResult shape.
def test_region_result_valid_and_json() -> None:
    bypassed = ok_result(status="bypassed", bypass=Bypass("pflash", 300, 310))
    assert region_result_json(bypassed)["bypass"] == {"memory_id": "pflash", "start": 300, "end": 310}
    assert region_result_json(ok_result())["bypass"] is None
    failed = ok_result(status="fail", computed=None, reason="table_out_of_bounds")
    assert failed.reason == "table_out_of_bounds"
    signed = ok_result(kind="signed", status="signature_unverifiable", stored=None, computed=None)
    assert signed.kind == "signed"


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"name": 1}, "r40"),
        ({"memory_id": "Bad"}, "r40"),
        ({"kind": "other"}, "r40"),
        ({"status": "pass"}, "r40"),
        ({"stored": "00FF"}, "r40"),
        ({"computed": "0"}, "r40"),
        ({"stored": 5}, "r40"),
        ({"reason": 5}, "r40"),
        ({"reason": "x"}, "r40"),
        ({"reason": "x", "status": "fail"}, "r40"),
        ({"kind": "signed"}, "r46"),
        ({"kind": "signed", "status": "signature_unverifiable", "computed": None}, "r46"),
        ({"kind": "signed", "status": "signature_unverifiable", "stored": None}, "r46"),
        (
            {
                "kind": "signed",
                "status": "signature_unverifiable",
                "stored": None,
                "computed": None,
                "bypass": Bypass("pflash", 0, 1),
            },
            "r46",
        ),
        ({"status": "signature_unverifiable"}, "r46"),
        ({"status": "bypassed"}, "r44"),
        ({"status": "bypassed", "bypass": (0, 1)}, "r44"),
        ({"status": "bypassed", "bypass": Bypass("pflash", 5, 5)}, "r44"),
        ({"status": "bypassed", "bypass": Bypass("Bad", 0, 5)}, "r44"),
        ({"status": "bypassed", "bypass": Bypass("pflash", -1, 5)}, "r44"),
        ({"bypass": Bypass("pflash", 0, 5)}, "r44"),
    ],
)
def test_region_result_rejections(changes: dict[str, Any], reason: str) -> None:
    # SPEC-002 R40, R44, R46
    with contract_error(reason):
        ok_result(**changes)


# SPEC-002 R8, R40, R41, R42: VerifyReport shape.
def test_verify_report_valid_and_json() -> None:
    report = VerifyReport("ok", None, (ok_result(name="a"), ok_result(name="b")))
    assert [r.name for r in report.regions] == ["a", "b"]
    assert verify_report_json(report)["regions"] == [region_result_json(r) for r in report.regions]
    for reason in ("virtual_dump", "unknown_variant", "no_checksum_regions"):
        assert VerifyReport("not_applicable", reason, ()).regions == ()


@pytest.mark.parametrize(
    "build",
    [
        lambda: VerifyReport("ok", None, cast(Any, [ok_result()])),
        lambda: VerifyReport("ok", None, (cast(Any, "x"),)),
        lambda: VerifyReport("not_applicable", "virtual_dump", (ok_result(),)),
        lambda: VerifyReport("not_applicable", "other", ()),
        lambda: VerifyReport("not_applicable", None, ()),
        lambda: VerifyReport("ok", "virtual_dump", (ok_result(),)),
        lambda: VerifyReport(cast(Any, "pass"), None, (ok_result(),)),
        lambda: VerifyReport("ok", None, (ok_result(name="b"), ok_result(name="a"))),
        lambda: VerifyReport("ok", None, (ok_result(name="a"), ok_result(name="a"))),
    ],
)
def test_verify_report_rejections(build: Callable[[], object]) -> None:
    # SPEC-002 R8 via R40
    with contract_error("r40"):
        build()


# SPEC-002 R58, §2.4: MapHint shape and SPEC-003 categories.
def test_map_hint() -> None:
    hint = MapHint("pflash", 32, 40, "spark", "ignition")
    assert map_hint_json(hint) == {
        "memory_id": "pflash",
        "start": 32,
        "end": 40,
        "name": "spark",
        "category": "ignition",
    }
    assert MapHint("pflash", 32, 40, "x", None).category is None
    hint_builds: list[Callable[[], object]] = [
        lambda: MapHint("Bad", 0, 1, "x", None),
        lambda: MapHint("pflash", 0, 1, cast(Any, 1), None),
        lambda: MapHint("pflash", 1, 1, "x", None),
        lambda: MapHint("pflash", -1, 1, "x", None),
        lambda: MapHint("pflash", 0, 1, "x", cast(Any, "dpf_delete")),
    ]
    for build in hint_builds:
        with contract_error("r58"):
            build()


# SPEC-002 R10: the protocol is exactly §3; its methods are declarations only.
def test_protocol_shape() -> None:
    methods = {"identify", "layout", "checksums", "verify", "checksum_patches", "hints"}
    assert methods <= set(dir(core.plugins.EcuPlugin))
    assert "fix_checksums" not in dir(core.plugins.EcuPlugin)
    assert {"verify_region", "patches_region"} <= set(dir(core.plugins.RegionReference))


# Descriptor schema - SPEC-002 R60, R61 (width), R78.


# SPEC-002 R60, R78: every fixture descriptor round-trips through its JSON form.
@pytest.mark.parametrize("entry", FIXTURE["descriptors"], ids=lambda e: e["value"]["name"])
def test_descriptor_round_trip(entry: dict[str, Any]) -> None:
    assert descriptor_json(descriptor_from_json(entry["value"])) == entry["value"]
    assert descriptor_hash(descriptor_from_json(entry["value"])) == entry["descriptor_hash"]


# SPEC-002 R61: widths.
def test_width_and_output_fields() -> None:
    assert width(Crc32(0, 0, 0, False, False)) == 32
    assert width(WordAlgorithm("sum32", 2, "big", 0, 0)) == 32
    assert width(WordAlgorithm("sum16", 1, "big", 0, 0)) == 16
    assert width(WordAlgorithm("xor", 2, "big", 0, 0)) == 16
    by_name = {d.name: d for d in DESCRIPTORS}
    assert output_fields(by_name["d_mirror"]) == (Range(272, 288),)
    assert output_fields(by_name["e_crc"]) == (Range(256, 260),)
    assert output_fields(by_name["a_comp"]) == (Range(268, 272),)
    e_crc = cast(ChecksumDescriptor, by_name["e_crc"])
    assert output_fields(replace(e_crc, store=None)) == ()
    assert output_fields(replace(e_crc, strategy="compensate", compensate=Compensate(0))) == ()
    a_comp = cast(ChecksumDescriptor, by_name["a_comp"])
    assert output_fields(replace(a_comp, compensate=None)) == ()
    assert Field(4, 2, "big").span == Range(4, 6)
    assert Table(10, 2, 8, TableField(0, 4, "big"), TableField(4, 4, "big"), "exclusive", "offset").span == Range(
        10, 26
    )
    assert MirrorBlock(Range(0, 4), 10).dest == Range(10, 14)


def mutate(name: str, path: list[str | int], value: object) -> dict[str, Any]:
    obj = fixture_json(name)
    target: Any = obj
    for key in path[:-1]:
        target = target[key]
    if value is DELETE:
        del target[path[-1]]
    else:
        target[path[-1]] = value
    return obj


DELETE = object()

SCHEMA_CASES = [
    ("e_crc", ["note"], "x"),
    ("e_crc", ["descriptor_version"], 2),
    ("e_crc", ["descriptor_version"], True),
    ("e_crc", ["name"], "Bad"),
    ("e_crc", ["name"], 5),
    ("e_crc", ["memory_id"], "Bad"),
    ("e_crc", ["memory_id"], 5),
    ("e_crc", ["target"], DELETE),
    ("e_crc", ["algorithm", "poly"], 2**32),
    ("e_crc", ["algorithm", "poly"], "x"),
    ("e_crc", ["algorithm", "init"], -1),
    ("e_crc", ["algorithm", "xor_out"], True),
    ("e_crc", ["algorithm", "reflect_in"], 1),
    ("e_crc", ["algorithm", "reflect_out"], "yes"),
    ("e_crc", ["algorithm", "word_size"], 4),
    ("e_crc", ["algorithm"], "crc32"),
    ("e_crc", ["algorithm", "name"], "crc64"),
    ("c_sum16", ["algorithm", "name"], "sum8"),
    ("c_sum16", ["algorithm", "word_size"], 3),
    ("c_sum16", ["algorithm", "endianness"], "middle"),
    ("c_sum16", ["algorithm", "init"], 0x10000),
    ("c_sum16", ["algorithm", "xor_out"], 0x10000),
    ("b_chain", ["algorithm", "xor_out"], 0x10000),
    ("c_sum16", ["algorithm", "poly"], 1),
    ("e_crc", ["ranges"], {"start": 0}),
    ("e_crc", ["ranges", 0], [32, 256]),
    ("e_crc", ["ranges", 0, "start"], -1),
    ("e_crc", ["ranges", 0, "end"], 2**32),
    ("e_crc", ["ranges", 0, "end"], "x"),
    ("e_crc", ["ranges", 0, "extra"], 1),
    ("e_crc", ["store", "size"], 8),
    ("e_crc", ["store", "endianness"], "native"),
    ("e_crc", ["store", "offset"], -1),
    ("e_crc", ["store", "extra"], 1),
    ("e_crc", ["skip_self"], 0),
    ("e_crc", ["strategy"], "patch"),
    ("e_crc", ["target"], "x"),
    ("a_comp", ["target"], 2**32),
    ("a_comp", ["compensate", "offset"], -1),
    ("a_comp", ["compensate"], {"offset": 1, "x": 2}),
    ("b_chain", ["chain"], "e_crc"),
    ("b_chain", ["chain"], ["e_crc", 5]),
    ("b_chain", ["skip_self"], True),
    ("f_table", ["ranges_from_table", "count"], 2**32),
    ("f_table", ["ranges_from_table", "offset"], -1),
    ("f_table", ["ranges_from_table", "entry_size"], "8"),
    ("f_table", ["ranges_from_table", "end_is"], "open"),
    ("f_table", ["ranges_from_table", "addressing"], "relative"),
    ("f_table", ["ranges_from_table", "start", "size"], 3),
    ("f_table", ["ranges_from_table", "start", "at"], -1),
    ("f_table", ["ranges_from_table", "end", "endianness"], "x"),
    ("f_table", ["ranges_from_table", "end", "extra"], 1),
    ("f_table", ["ranges_from_table", "extra"], 1),
    ("d_mirror", ["extra"], 1),
    ("d_mirror", ["mirror_block", "extra"], 1),
    ("d_mirror", ["mirror_block", "source", "start"], -1),
    ("d_mirror", ["mirror_block", "dest_offset"], 2**32),
    ("d_mirror", ["descriptor_version"], 0),
]


@pytest.mark.parametrize(("name", "path", "value"), SCHEMA_CASES)
def test_descriptor_schema_rejections(name: str, path: list[str | int], value: object) -> None:
    # SPEC-002 R60: exact key sets at every level, no default, typed values, widths.
    with schema_error():
        descriptor_from_json(mutate(name, path, value))


def test_descriptor_from_json_rejects_non_objects() -> None:
    # SPEC-002 R60
    values: list[object] = [None, [], "x", 5]
    for value in values:
        with schema_error():
            descriptor_from_json(value)


def test_descriptor_constructor_rejections() -> None:
    # SPEC-002 R60: plugin code that builds descriptors directly gets the same schema checks.
    e_crc = cast(ChecksumDescriptor, DESCRIPTORS[4])
    d_mirror = cast(MirrorDescriptor, DESCRIPTORS[3])
    builds: list[Callable[[], object]] = [
        lambda: replace(e_crc, algorithm=cast(Any, "crc32")),
        lambda: replace(e_crc, ranges=cast(Any, [Range(32, 256)])),
        lambda: replace(e_crc, ranges=(cast(Any, (32, 256)),)),
        lambda: replace(e_crc, ranges_from_table=cast(Any, "table")),
        lambda: replace(e_crc, store=cast(Any, (256, 4))),
        lambda: replace(e_crc, compensate=cast(Any, 268)),
        lambda: replace(e_crc, chain=cast(Any, ["a"]), ranges=None),
        lambda: replace(d_mirror, mirror_block=cast(Any, "block")),
        lambda: MirrorBlock(cast(Any, (0, 4)), 10),
        lambda: Table(0, 1, 8, cast(Any, (0, 4)), TableField(4, 4, "big"), "exclusive", "offset"),
        lambda: Table(0, 1, 8, TableField(0, 4, "big"), TableField(4, 4, "big"), "exclusive", cast(Any, "x")),
    ]
    for build in builds:
        with schema_error():
            build()
