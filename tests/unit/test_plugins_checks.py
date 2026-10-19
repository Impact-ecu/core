"""SPEC-002 §3, §5, §6, §8: core-side checks of plugin outputs, admission and limits."""

from contextlib import AbstractContextManager
from dataclasses import replace
from typing import Any, cast

import pytest

from core.kernel import Dump, LayoutMemory, Memory, MemoryLayout, Patch, Region, RegionKind
from core.plugins import (
    TIME_BUDGET_MS,
    Admission,
    Bypass,
    CallOutcome,
    ChecksumRegion,
    MapHint,
    PiiLocation,
    PluginContractError,
    PresentMemory,
    Range,
    RegionResult,
    VerifyReport,
    admission,
    aggregate,
    check_checksum_patches,
    check_hints,
    check_identification,
    check_layout,
    check_plugin,
    check_regions,
    check_verify_report,
    contract_json,
    identification_json,
    not_applicable,
    recalculable_fields,
    report_hash,
    variant_admitted,
    within_limits,
)
from tests.unit.plugin_fixtures import (
    DUMP,
    FAMILY,
    IDENT,
    LAYOUT,
    NONE,
    ORIGINAL,
    REGIONS,
    VARIANT,
    FakePlugin,
    dump_of,
    edited,
    python_region,
    report_of,
)


def contract_error(reason: str) -> AbstractContextManager[pytest.ExceptionInfo[PluginContractError]]:
    return pytest.raises(PluginContractError, match=rf"^{reason}\b")


def force(obj: object, attribute: str, value: object) -> None:
    # Bypass __post_init__: the core re-validates what the plugin hands it (R11).
    object.__setattr__(obj, attribute, value)


def layout_with(regions: tuple[Region, ...], memory_id: str = "pflash") -> MemoryLayout:
    return MemoryLayout((LayoutMemory(memory_id, 0x8000_0000, 512, regions),))


# SPEC-002 R10, R135, R2: the plugin's declared attributes.
def test_check_plugin() -> None:
    check_plugin(FakePlugin())
    with contract_error("contract_version"):
        check_plugin(FakePlugin(contract_version=2))
    with contract_error("contract_version"):
        check_plugin(FakePlugin(contract_version=cast(Any, True)))
    with contract_error("r2"):
        check_plugin(FakePlugin(family="Bosch"))
    with contract_error("r10"):
        check_plugin(FakePlugin(version=cast(Any, 1)))
    with contract_error("r10"):
        check_plugin(FakePlugin(pii_in_flash=cast(Any, "yes")))


# SPEC-002 R11: a plugin missing a declared attribute raises; the host makes it unavailable.
def test_check_plugin_missing_attribute() -> None:
    class Bare:
        contract_version = 1

    with pytest.raises(AttributeError):
        check_plugin(cast(Any, Bare()))


# SPEC-002 R12, R13: identify returns None or an Identification.
def test_check_identification_none_and_type() -> None:
    plugin = FakePlugin()
    assert check_identification(None, DUMP, FAMILY) is None
    assert check_identification(plugin.identify(dump_of(ORIGINAL[:100])), DUMP, FAMILY) is None
    assert check_identification(plugin.identify(DUMP), DUMP, FAMILY) == IDENT
    with contract_error("r12"):
        check_identification({"family": FAMILY}, DUMP, FAMILY)


# SPEC-002 R2, R3, R4, R6, R11: identification against the dump and the plugin, re-validated.
def test_check_identification_rejections() -> None:
    with contract_error("r2"):
        check_identification(IDENT, DUMP, "other.family")
    forged = replace(IDENT)
    force(forged, "confidence", 5000)
    with contract_error("r3"):
        check_identification(forged, DUMP, FAMILY)
    two = Dump("bench_full", (*DUMP.memories, Memory("eeprom", 0, b"\x00")))
    with contract_error("r4"):
        check_identification(IDENT, two, FAMILY)
    with contract_error("r4"):
        check_identification(
            replace(IDENT, memories_present=(PresentMemory("pflash", 0x8000_0000, 511),)), DUMP, FAMILY
        )
    with contract_error("r4"):
        check_identification(replace(IDENT, memories_present=(PresentMemory("pflash", 0, 512),)), DUMP, FAMILY)
    with contract_error("r6"):
        check_identification(replace(IDENT, pii_locations=(PiiLocation("pflash", 500, 513, "vin"),)), DUMP, FAMILY)
    with contract_error("r6"):
        check_identification(replace(IDENT, pii_locations=(PiiLocation("eeprom", 0, 1, "serial"),)), DUMP, FAMILY)


# SPEC-002 R4: with an unknown dump base address, the plugin's address (or null) stands.
def test_check_identification_unknown_base() -> None:
    dump = Dump("bench_full", (Memory("pflash", None, ORIGINAL),))
    for base in (None, 0x1000):
        ident = replace(IDENT, memories_present=(PresentMemory("pflash", base, 512),))
        assert check_identification(ident, dump, FAMILY) == ident


# SPEC-002 R20, R23: the layout has exactly the present memories; also for virtual dumps.
def test_check_layout_bad_layout() -> None:
    assert check_layout(FakePlugin().layout(IDENT, "virtual"), IDENT) == LAYOUT
    with contract_error("bad_layout"):
        check_layout("layout", IDENT)
    with contract_error("bad_layout"):
        check_layout(layout_with((Region("protected", 0, 512, "x"),), "eeprom"), IDENT)
    other = MemoryLayout((LayoutMemory("pflash", 0, 512, (Region("protected", 0, 512, "x"),)),))
    with contract_error("bad_layout"):
        check_layout(other, IDENT)


# SPEC-002 R21: an unrecognized memory is one protected region named `unrecognized`.
def test_check_layout_unrecognized() -> None:
    assert check_layout(layout_with((Region("protected", 0, 512, "unrecognized"),)), IDENT)
    with contract_error("r21"):
        check_layout(layout_with((Region("calibration", 0, 512, "unrecognized"),)), IDENT)
    split = (Region("protected", 0, 10, "unrecognized"), Region("protected", 10, 512, "code"))
    with contract_error("r21"):
        check_layout(layout_with(split), IDENT)


# SPEC-002 R22, R90, R92, R94: VIN, immo, coding, counters and emissions regions are protected.
@pytest.mark.parametrize("name", ["vin", "immo_key", "coding", "counter_flash", "emissions_egr", "emissions_dpf"])
@pytest.mark.parametrize("kind", ["calibration", "checksum"])
def test_check_layout_protected_names(name: str, kind: RegionKind) -> None:
    regions = (Region("protected", 0, 32, "boot"), Region(kind, 32, 64, name), Region("protected", 64, 512, "code"))
    with contract_error("r22"):
        check_layout(layout_with(regions), IDENT)
    protected = (
        Region("protected", 0, 32, "boot"),
        Region("protected", 32, 64, name),
        Region("protected", 64, 512, "x"),
    )
    assert check_layout(layout_with(protected), IDENT)


# SPEC-002 R43: aggregation; R41, R42: reports the core makes itself.
def test_aggregate_and_not_applicable() -> None:
    assert aggregate([]) == ("not_applicable", "no_checksum_regions")
    assert aggregate(["ok", "signature_unverifiable", "bypassed"]) == ("bypassed", None)
    assert aggregate(["ok", "ok"]) == ("ok", None)
    assert not_applicable("virtual_dump") == VerifyReport("not_applicable", "virtual_dump", ())
    assert not_applicable("unknown_variant").regions == ()


def result(name: str, **changes: object) -> RegionResult:
    base: dict[str, Any] = {
        "name": name,
        "memory_id": "pflash",
        "kind": "recalculable",
        "status": "ok",
        "stored": "00",
        "computed": "00",
        "reason": None,
        "bypass": None,
    }
    return RegionResult(**(base | changes))


def fixture_report() -> VerifyReport:
    return FakePlugin().verify(DUMP, IDENT)


# SPEC-002 R8, R40: one result per checksum region, re-validated.
def test_check_verify_report_valid_and_shape() -> None:
    assert check_verify_report(fixture_report(), DUMP, REGIONS, LAYOUT) == fixture_report()
    with contract_error("r40"):
        check_verify_report({"status": "ok"}, DUMP, REGIONS, LAYOUT)
    forged = fixture_report()
    force(forged, "regions", list(forged.regions))
    with contract_error("r40"):
        check_verify_report(forged, DUMP, REGIONS, LAYOUT)
    forged_result = fixture_report()
    force(forged_result.regions[0], "status", "pass")
    with contract_error("r40"):
        check_verify_report(forged_result, DUMP, REGIONS, LAYOUT)
    with contract_error("r40"):
        check_verify_report(fixture_report(), DUMP, REGIONS[:5], LAYOUT)
    with contract_error("r40"):
        check_verify_report(not_applicable("no_checksum_regions"), DUMP, REGIONS, LAYOUT)


# SPEC-002 R41: virtual dumps are not_applicable, reason virtual_dump.
def test_check_verify_report_virtual() -> None:
    virtual = dump_of(ORIGINAL, "virtual")
    assert check_verify_report(FakePlugin().verify(virtual, IDENT), virtual, REGIONS, LAYOUT).reason == "virtual_dump"
    with contract_error("r41"):
        check_verify_report(fixture_report(), virtual, REGIONS, LAYOUT)
    with contract_error("r41"):
        check_verify_report(not_applicable("no_checksum_regions"), virtual, REGIONS, LAYOUT)


# SPEC-002 R43: a status different from the recomputed aggregation is `r43`.
def test_check_verify_report_r43() -> None:
    assert check_verify_report(not_applicable("no_checksum_regions"), DUMP, (), LAYOUT).status == "not_applicable"
    with contract_error("r43"):
        check_verify_report(not_applicable("unknown_variant"), DUMP, (), LAYOUT)
    wrong = VerifyReport("fail", None, fixture_report().regions)
    with contract_error("r43"):
        check_verify_report(wrong, DUMP, REGIONS, LAYOUT)


# SPEC-002 R44, R93: bypass locations lie inside one protected region; bypassed dominates ok.
def test_check_verify_report_bypass() -> None:
    def with_bypass(bypass: Bypass) -> VerifyReport:
        results = list(fixture_report().regions)
        results[0] = replace(results[0], status="bypassed", bypass=bypass)
        return VerifyReport("bypassed", None, tuple(results))

    assert check_verify_report(with_bypass(Bypass("pflash", 300, 310)), DUMP, REGIONS, LAYOUT).status == "bypassed"
    for bypass in (Bypass("pflash", 40, 50), Bypass("pflash", 280, 300), Bypass("eeprom", 0, 4)):
        with contract_error("r44"):
            check_verify_report(with_bypass(bypass), DUMP, REGIONS, LAYOUT)


# SPEC-002 R46: a signed region is signature_unverifiable and lies in no checksum region.
def test_check_verify_report_signed() -> None:
    signed = ChecksumRegion("sig", "pflash", "signed", None, None, None, NONE)
    results = {r.name: r for r in fixture_report().regions}
    results["sig"] = result("sig", kind="signed", status="signature_unverifiable", stored=None, computed=None)
    report = report_of(results)
    assert check_verify_report(report, DUMP, (*REGIONS, signed), LAYOUT).status == "signature_unverifiable"
    forged = report_of(results)
    force(next(r for r in forged.regions if r.name == "sig"), "status", "ok")
    with contract_error("r46"):
        check_verify_report(forged, DUMP, (*REGIONS, signed), LAYOUT)
    assert recalculable_fields([signed]) == {}


def fixture_patches() -> list[Patch]:
    return FakePlugin().checksum_patches(dump_of(edited(ORIGINAL, 140, b"\x00\x11\x22\x33")), IDENT)


# SPEC-002 R50, R51, R52: the plugin's patches, against the dump and the layout.
def test_check_checksum_patches_valid() -> None:
    dump = dump_of(edited(ORIGINAL, 140, b"\x00\x11\x22\x33"))
    patches = fixture_patches()
    assert len(patches) == 4
    assert check_checksum_patches(patches, dump, LAYOUT, REGIONS) == tuple(patches)
    assert check_checksum_patches((), DUMP, LAYOUT, REGIONS) == ()
    assert check_checksum_patches([], dump_of(ORIGINAL, "virtual"), LAYOUT, REGIONS) == ()


def test_check_checksum_patches_r50() -> None:
    # SPEC-002 R50
    dump = dump_of(edited(ORIGINAL, 140, b"\x00\x11\x22\x33"))
    patches = fixture_patches()
    for bad in ("patches", [b"x"], {1: patches[0]}):
        with contract_error("r50"):
            check_checksum_patches(bad, dump, LAYOUT, REGIONS)
    with contract_error("r50"):
        check_checksum_patches(patches, dump_of(dump.memories[0].data, "virtual"), LAYOUT, REGIONS)
    with contract_error("r50"):
        check_checksum_patches(list(reversed(patches)), dump, LAYOUT, REGIONS)


def test_check_checksum_patches_r51_r52() -> None:
    # SPEC-002 R51, R52
    dump = dump_of(edited(ORIGINAL, 140, b"\x00\x11\x22\x33"))
    patches = fixture_patches()
    half = Patch("pflash", 256, 2, ORIGINAL[256:258], b"\x00\x00")
    with contract_error("r51"):
        check_checksum_patches([half], dump, LAYOUT, REGIONS)
    calibration_field = python_region("py", (Range(32, 40),), (Range(40, 44),), NONE)
    in_maps = Patch("pflash", 40, 4, ORIGINAL[40:44], b"\x00\x00\x00\x00")
    with contract_error("r51"):
        check_checksum_patches([in_maps], DUMP, LAYOUT, (calibration_field,))
    with contract_error("r51"):
        check_checksum_patches([patches[0], patches[0]], dump, LAYOUT, REGIONS)
    stale = Patch("pflash", 256, 4, b"\x01\x02\x03\x04", b"\x00\x00\x00\x00")
    with contract_error("r52"):
        check_checksum_patches([stale], dump, LAYOUT, REGIONS)
    eeprom = python_region("py", (Range(32, 40),), (Range(0, 2),), NONE)
    other_memory = Patch("eeprom", 0, 2, b"\x00\x00", b"\x01\x01")
    force(eeprom, "memory_id", "eeprom")
    eeprom_layout = MemoryLayout((*LAYOUT.memories, LayoutMemory("eeprom", 0, 2, (Region("checksum", 0, 2, ""),))))
    with contract_error("r52"):
        check_checksum_patches([other_memory], DUMP, eeprom_layout, (eeprom,))


# SPEC-002 R58, R59: hints lie inside one calibration region; one bad hint rejects them all.
def test_check_hints() -> None:
    plugin = FakePlugin()
    assert check_hints(plugin.hints(IDENT), LAYOUT) == tuple(plugin.hints(IDENT))
    assert check_hints([], LAYOUT) == ()
    good = MapHint("pflash", 32, 64, "spark", "ignition")
    for bad in (
        MapHint("pflash", 0, 8, "boot", None),
        MapHint("pflash", 256, 260, "crc", None),
        MapHint("pflash", 416, 420, "egr", None),
        MapHint("pflash", 250, 260, "straddle", None),
        MapHint("eeprom", 0, 1, "other", None),
    ):
        with contract_error("r58"):
            check_hints([good, bad], LAYOUT)
    for not_hints in ("hints", [("pflash", 32, 64)]):
        with contract_error("r58"):
            check_hints(not_hints, LAYOUT)
    forged = MapHint("pflash", 32, 64, "spark", None)
    force(forged, "end", 10)
    with contract_error("r58"):
        check_hints([forged], LAYOUT)


# SPEC-002 R30: checksums returns a list of valid ChecksumRegion, re-validated.
def test_check_regions() -> None:
    assert check_regions(list(REGIONS)) == REGIONS
    for bad in ("regions", [1]):
        with contract_error("r30"):
            check_regions(bad)
    forged = replace(REGIONS[0])
    force(forged, "name", "Bad")
    with contract_error("r7"):
        check_regions([forged])


# SPEC-002 R127, R132; SPEC-004 R15: admission from the published conformance report.
def test_admission() -> None:
    plugin = FakePlugin()
    report: dict[str, Any] = {
        "plugin": {"family": FAMILY, "version": "1.0.0"},
        "verdict": "conformant",
        "variants": [
            {"checksum_variant_id": VARIANT, "admitted": True},
            {"checksum_variant_id": "other", "admitted": False},
        ],
    }
    result_ = admission(report, plugin)
    assert result_ == Admission(report_hash(report), frozenset({VARIANT}))
    assert variant_admitted(IDENT, result_)
    assert not variant_admitted(replace(IDENT, checksum_variant_id="other"), result_)
    assert not variant_admitted(replace(IDENT, checksum_variant_id=None), result_)
    assert not variant_admitted(IDENT, None)
    broken_reports: list[Any] = [
        report | {"plugin": {"family": "other.family", "version": "1.0.0"}},
        report | {"plugin": {"family": FAMILY, "version": "2.0.0"}},
        report | {"plugin": "x"},
        report | {"verdict": "nonconformant"},
        report | {"variants": "x"},
        report | {"variants": [{"checksum_variant_id": 1, "admitted": True}]},
        report | {"variants": [{"checksum_variant_id": VARIANT, "admitted": "yes"}]},
        report | {"variants": ["x"]},
        [],
        None,
    ]
    for broken in broken_reports:
        assert admission(broken, plugin) is None


# SPEC-002 R103, R104, R105: budgets and the recorded outcome of a call.
def test_limits() -> None:
    assert TIME_BUDGET_MS == {
        "identify": 1000,
        "layout": 1000,
        "checksums": 1000,
        "hints": 1000,
        "verify": 2000,
        "checksum_patches": 2000,
    }
    assert within_limits(CallOutcome("verify", "result", 2000, None))
    assert not within_limits(CallOutcome("verify", "result", 2001, 10))
    assert not within_limits(CallOutcome("identify", "timeout", 5, None))
    assert not within_limits(CallOutcome("identify", "exception", 5, None))


# SPEC-002 R9, R101, R106: contract objects are JCS-serializable (the sandbox framing exchanges JCS) and
# repeated calls of a pure plugin give identical bytes.
def test_contract_objects_serialize_deterministically() -> None:
    plugin = FakePlugin()
    first = contract_json(identification_json(plugin.identify(DUMP) or IDENT))
    second = contract_json(identification_json(plugin.identify(DUMP) or IDENT))
    assert first == second


# SPEC-002 R100, R102: the plugin package of the fixture only goes through the public contract; patches are
# kernel `Patch`es with explicit bytes.
def test_patches_are_kernel_patches() -> None:
    assert all(isinstance(p, Patch) for p in fixture_patches())
