"""SPEC-002 §7, §8: the core side of the conformance suite (checks, mutations, scan, report, release).

Cases are built from the synthetic 512-byte vector fixture and a fake plugin that answers through the
interpreter; tests corrupt its outputs to reach each failure reason. No byte comes from a real ECU.
"""

import hashlib
from dataclasses import replace
from typing import Any, cast

import pytest
import rfc8785

from core.conformance import (
    MIN_CONFIDENCE,
    MIN_FUZZ_INPUTS,
    Check,
    DeterminismCase,
    DualCase,
    Failure,
    Fuzz,
    GoldenCase,
    Header,
    HintsCase,
    IdentifyCase,
    Identity,
    InsideCase,
    LayoutCase,
    LayoutReview,
    Limit,
    Mutation,
    MutationInput,
    OutsideCase,
    Piece,
    RegistryHead,
    RunResult,
    Stream,
    Variant,
    VerifyCase,
    admitted,
    build_report,
    bump_satisfied,
    catalog_ready,
    check_checksum_off,
    check_descriptors_and_references,
    check_fuzz,
    check_golden,
    check_hints_cases,
    check_identify_discrimination,
    check_identify_negative,
    check_identify_positive,
    check_inside,
    check_layouts,
    check_limits,
    check_originals,
    check_outside,
    check_purity,
    check_virtual,
    checksum_region_set,
    conformance_report_hash,
    golden_levels,
    import_allowed,
    inside_mutations,
    limits_summary,
    mutation_summary,
    outside_mutations,
    parse_semver,
    publishable,
    required_bump,
    review_fields,
    rule,
    scan_source,
)
from core.kernel import Dump, LayoutMemory, Memory, MemoryLayout, Patch, Region, image_hash, layout_hash
from core.plugins import (
    Bypass,
    CallOutcome,
    ChecksumRegion,
    ContractJson,
    MapHint,
    Range,
    Reference,
    RegionResult,
    VerifyReport,
    descriptor_from_json,
)
from core.plugins.descriptor import _engines
from tests.unit.plugin_fixtures import (
    DUMP,
    FAMILY,
    IDENT,
    LAYOUT,
    NONE,
    ORIGINAL,
    REGIONS,
    VARIANT,
    VECTORS,
    FakePlugin,
    dump_of,
    edited,
    python_region,
    region_of,
    report_of,
)

PLUGIN = FakePlugin()
EXPECTED = Identity(FAMILY, "hw-1", "sw-1", VARIANT)
H = image_hash(DUMP)
BROKEN = edited(ORIGINAL, 40, b"\xde\xad")


def reasons(check: Check) -> list[str]:
    return [failure.reason for failure in check.failures]


def report(dump: Dump) -> VerifyReport:
    return PLUGIN.verify(dump, IDENT)


def test_rule_names() -> None:
    assert rule(117) == "SPEC-002 R117"
    assert Check("x", 0, ()).passed
    assert not Check("x", 1, (Failure("x", "", "r"),)).passed


# SPEC-002 R111: the corpus identity and confidence >= 500.
def test_identify_positive() -> None:
    good = IdentifyCase(DUMP, PLUGIN.identify(DUMP), EXPECTED)
    assert check_identify_positive([good], FAMILY).passed
    cases = [
        IdentifyCase(DUMP, PLUGIN.identify(DUMP), replace(EXPECTED, hw_id="other")),
        IdentifyCase(DUMP, None, EXPECTED),
        IdentifyCase(DUMP, replace(IDENT, confidence=MIN_CONFIDENCE - 1), EXPECTED),
        IdentifyCase(DUMP, "not an identification", EXPECTED),
    ]
    check = check_identify_positive(cases, FAMILY)
    assert (check.rule, check.cases) == ("SPEC-002 R111", 4)
    assert reasons(check) == ["identity_mismatch", "identity_mismatch", "low_confidence", "r12"]
    assert all(failure.image_hash == H for failure in check.failures)
    assert check_identify_positive(
        [IdentifyCase(DUMP, replace(IDENT, confidence=MIN_CONFIDENCE), EXPECTED)], FAMILY
    ).passed


# SPEC-002 R112, R13: same sw_id with different variants must get different checksum_variant_ids.
def test_identify_discrimination() -> None:
    other = dump_of(BROKEN)
    a = IdentifyCase(DUMP, IDENT, EXPECTED)
    b_same = IdentifyCase(other, IDENT, replace(EXPECTED, checksum_variant_id="other-variant"))
    b_diff = IdentifyCase(other, replace(IDENT, checksum_variant_id="other-variant"), b_same.expected)
    unrelated = IdentifyCase(other, IDENT, replace(EXPECTED, sw_id="sw-2", checksum_variant_id="v3"))
    no_sw = IdentifyCase(other, IDENT, replace(EXPECTED, sw_id=None, checksum_variant_id="v4"))
    same_variant = IdentifyCase(other, IDENT, EXPECTED)
    passing = check_identify_discrimination([a, b_diff, unrelated, same_variant])
    assert (passing.passed, passing.cases) == (True, 2)
    failing = check_identify_discrimination([a, b_same])
    assert reasons(failing) == ["not_discriminated", "not_discriminated"]
    assert [f.image_hash for f in failing.failures] == [H, image_hash(other)]
    unknown = check_identify_discrimination([replace(a, result=None), b_diff])
    assert reasons(unknown) == ["not_discriminated"] * 2
    assert check_identify_discrimination([replace(a, expected=no_sw.expected), no_sw]).cases == 0


# SPEC-002 R113: other families and random dumps give None or confidence < 500.
def test_identify_negative() -> None:
    low = replace(IDENT, confidence=MIN_CONFIDENCE - 1)
    check = check_identify_negative([("a", None), ("b", low), ("c", IDENT), ("d", "junk")])
    assert check.cases == 4
    assert [(f.image_hash, f.reason) for f in check.failures] == [
        ("c", "identified_foreign_dump"),
        ("d", "identified_foreign_dump"),
    ]


# SPEC-002 R114: >= 100,000 fuzz inputs, no exception, no timeout.
def test_fuzz() -> None:
    assert check_fuzz(Fuzz(MIN_FUZZ_INPUTS, 0, 0)).passed
    check = check_fuzz(Fuzz(MIN_FUZZ_INPUTS - 1, 1, 2))
    assert reasons(check) == ["below_minimum_inputs", "exceptions", "timeouts"]
    assert check.cases == MIN_FUZZ_INPUTS - 1
    assert all(f.image_hash == "" for f in check.failures)


# SPEC-002 R115, R20-R22: reviewed layout hash and reviewed checksum region set.
def test_layouts() -> None:
    region_set = checksum_region_set(LAYOUT)
    expected = hashlib.sha256(
        rfc8785.dumps([{"memory_id": "pflash", "start": 256, "end": 288, "name": "checksums"}])
    ).hexdigest()
    assert region_set == expected
    reviewed = frozenset({region_set})
    good = LayoutCase(H, IDENT, LAYOUT, layout_hash(LAYOUT), reviewed)
    assert check_layouts([good, replace(good, reference_layout_hash=None)]).passed
    check = check_layouts(
        [
            replace(good, reference_layout_hash="0" * 64),
            replace(good, reviewed_region_sets=frozenset()),
            replace(good, layout="not a layout"),
        ]
    )
    assert reasons(check) == ["layout_hash_mismatch", "checksum_region_set_not_reviewed", "bad_layout"]


def bypassed(result: RegionResult, start: int = 300, end: int = 310) -> RegionResult:
    return replace(result, status="bypassed", bypass=Bypass("pflash", start, end))


# SPEC-002 R116: unmodified originals are ok; a malformed report is its contract reason.
def test_originals() -> None:
    broken = dump_of(BROKEN)
    assert check_originals([VerifyCase(DUMP, REGIONS, LAYOUT, report(DUMP))]).passed
    check = check_originals(
        [VerifyCase(broken, REGIONS, LAYOUT, report(broken)), VerifyCase(DUMP, REGIONS, LAYOUT, "junk")]
    )
    assert reasons(check) == ["original_not_ok", "r40"]
    assert check.failures[0].image_hash == image_hash(broken)


def off_report() -> VerifyReport:
    results = {r.name: r for r in report(DUMP).regions}
    results["e_crc"] = bypassed(results["e_crc"])
    return report_of(results)


# SPEC-002 R119, R44: "checksum off" verifies bypassed at an R44 location, never fail.
def test_checksum_off() -> None:
    assert off_report().status == "bypassed"
    assert check_checksum_off([VerifyCase(DUMP, REGIONS, LAYOUT, off_report())]).passed
    check = check_checksum_off(
        [VerifyCase(DUMP, REGIONS, LAYOUT, report(DUMP)), VerifyCase(DUMP, REGIONS, LAYOUT, "junk")]
    )
    assert reasons(check) == ["status_ok", "r40"]


# SPEC-002 R120, R41: virtual dumps verify not_applicable.
def test_virtual() -> None:
    virtual = dump_of(ORIGINAL, "virtual")
    na = VerifyReport("not_applicable", "virtual_dump", ())
    assert check_virtual([VerifyCase(virtual, REGIONS, LAYOUT, na)]).passed
    check = check_virtual(
        [VerifyCase(DUMP, REGIONS, LAYOUT, report(DUMP)), VerifyCase(virtual, REGIONS, LAYOUT, report(DUMP))]
    )
    assert reasons(check) == ["not_virtual", "r41"]


# SPEC-002 R117: every inside mutation turns the region to fail.
def test_inside() -> None:
    cases = [
        InsideCase(H, VARIANT, "e_crc", "sample", "fail"),
        InsideCase(H, VARIANT, "e_crc", "sample", "ok"),
    ]
    check = check_inside(cases)
    assert (check.cases, reasons(check)) == (2, ["undetected_e_crc"])


def outside(after: VerifyReport) -> OutsideCase:
    return OutsideCase(H, VARIANT, "sample", report(DUMP), after, LAYOUT)


def with_region(base: VerifyReport, name: str, new: RegionResult | None) -> VerifyReport:
    results = {r.name: r for r in base.regions}
    if new is None:
        del results[name]
    else:
        results[name] = new
    ordered = tuple(sorted(results.values(), key=lambda r: (r.memory_id, r.name)))
    return VerifyReport(base.status, None, ordered)


# SPEC-002 R118, R44: outside mutations change nothing, except a bypassed status at a protected location.
def test_outside() -> None:
    base = report(DUMP)
    e_crc = next(r for r in base.regions if r.name == "e_crc")
    accepted = [base, with_region(base, "e_crc", bypassed(e_crc))]
    assert check_outside([outside(after) for after in accepted]).passed
    rejected = [
        with_region(base, "e_crc", bypassed(e_crc, 32, 40)),  # calibration, not protected
        with_region(base, "e_crc", replace(bypassed(e_crc), bypass=Bypass("dflash", 0, 4))),
        with_region(base, "e_crc", None),
        with_region(base, "e_crc", replace(e_crc, stored="00000000", status="fail")),
    ]
    check = check_outside([outside(after) for after in rejected])
    assert (check.cases, reasons(check)) == (4, ["changed_e_crc"] * 4)


# SPEC-002 R126 `mutation`: counts per (variant, region, mode), sorted.
def test_mutation_summary() -> None:
    base = report(DUMP)
    e_crc = next(r for r in base.regions if r.name == "e_crc")
    inside = [
        InsideCase(H, VARIANT, "e_crc", "sample", "fail"),
        InsideCase(H, VARIANT, "e_crc", "sample", "ok"),
        InsideCase(H, VARIANT, "a_comp", "full", "fail"),
    ]
    rows = mutation_summary(inside, [outside(base), outside(with_region(base, "e_crc", None))])
    by_key = {(m.region, m.mode): m for m in rows}
    assert by_key[("e_crc", "sample")] == Mutation(VARIANT, "e_crc", "sample", 2, 1, 2, 1)
    assert by_key[("a_comp", "full")] == Mutation(VARIANT, "a_comp", "full", 1, 1, 0, 0)
    assert by_key[("a_comp", "sample")] == Mutation(VARIANT, "a_comp", "sample", 0, 0, 2, 2)
    assert [(m.checksum_variant_id, m.region, m.mode) for m in rows] == sorted(
        (m.checksum_variant_id, m.region, m.mode) for m in rows
    )
    assert e_crc.status == "ok"


def write(data: bytes, patches: list[Patch]) -> bytes:
    out = bytearray(data)
    for patch in patches:
        out[patch.offset : patch.end] = patch.after
    return bytes(out)


def golden_case(vector: dict[str, Any]) -> GoldenCase:
    # Synthetic test data from the vector cases, not a golden file (SPEC-002 §10).
    unverified = dump_of(bytes.fromhex(vector["unverified"]["bytes_hex"]))
    q = PLUGIN.checksum_patches(unverified, IDENT)
    released = dump_of(write(unverified.memories[0].data, q))
    return GoldenCase(
        expected_image_hash=vector["released"]["image_hash"],
        unverified=unverified,
        layout=LAYOUT,
        regions=REGIONS,
        patches=q,
        independent={},
        after=report(released),
        fixed_point=PLUGIN.checksum_patches(released, IDENT),
    )


# SPEC-002 R121, R51-R55: released image_hash equals the golden hash; recalculation and fixed point hold.
def test_golden() -> None:
    cases = [golden_case(vector) for vector in VECTORS["cases"]]
    assert check_golden(cases).passed
    case = cases[0]
    released = dump_of(write(case.unverified.memories[0].data, cast("list[Patch]", case.patches)))
    data = released.memories[0].data
    stray = Patch("pflash", 256, 4, data[256:260], bytes(b ^ 0xFF for b in data[256:260]))
    no_base = Dump("bench_full", (Memory("pflash", None, ORIGINAL),))
    flat = MemoryLayout((LayoutMemory("pflash", None, 512, (Region("protected", 0, 512, "all"),)),))
    failing = [
        replace(case, expected_image_hash="0" * 64),
        replace(case, after=report(case.unverified)),
        replace(case, fixed_point=[stray]),
        replace(case, patches=cast("list[Patch]", case.patches)[1:]),
        replace(case, patches="junk"),
        GoldenCase("0" * 64, no_base, flat, (), [], {}, None, []),
    ]
    check = check_golden(failing)
    assert reasons(check) == ["image_hash_mismatch", "r53", "r54", "plugin_disagreement", "r50", "unknown_base_address"]
    assert check.failures[0].image_hash == image_hash(case.unverified)


# SPEC-002 R122, R131: fail-closed seam until SPEC-006 evaluate_golden exists.
def test_golden_levels_seam() -> None:
    assert golden_levels([{"schema": "impact.golden-record.v1"}]) == (0, 0)
    assert golden_levels([]) == (0, 0)


# SPEC-002 R123, R58, R59: every hint inside one calibration region.
def test_hints() -> None:
    good = HintsCase(H, PLUGIN.hints(IDENT), LAYOUT)
    assert check_hints_cases([good]).passed
    bad = HintsCase(H, [MapHint("pflash", 0, 8, "boot", None)], LAYOUT)
    assert reasons(check_hints_cases([good, bad])) == ["r58"]


# SPEC-002 R124, R100, R101: the source scan and JCS-identical repeated outputs.
def test_purity() -> None:
    sources = {"plug.b": "import os\n", "plug.a": "import hashlib\nfrom plug.b import x\n"}
    same = DeterminismCase("layout", H, {"a": [1, True]}, {"a": [1, True]})
    other = DeterminismCase("verify", H, {"a": 1}, {"a": 2})
    check = check_purity(sources, "plug", [same, other])
    assert check.cases == 4
    assert [(f.image_hash, f.reason) for f in check.failures] == [
        ("", "plug.b 1: import os"),
        (H, "nondeterministic_verify"),
    ]
    assert check_purity({"plug.a": "import zlib\n"}, "plug", [same]).passed


# SPEC-002 R103-R105: a timeout, an exception or a result over budget fails the suite.
def test_limits() -> None:
    outcomes = [
        CallOutcome("verify", "result", 10, None),
        CallOutcome("verify", "result", 20, 5),
        CallOutcome("identify", "timeout", 1000, 7),
        CallOutcome("layout", "exception", 1, None),
        CallOutcome("hints", "result", 1001, None),
    ]
    check = check_limits(outcomes)
    assert check.rule == "SPEC-002 R105"
    assert reasons(check) == ["identify_timeout_1000ms", "layout_exception_1ms", "hints_result_1001ms"]
    assert check_limits(outcomes[:2]).passed
    assert limits_summary(outcomes) == (
        Limit("hints", 1000, 1001, 0),
        Limit("identify", 1000, 1000, 7),
        Limit("layout", 1000, 1, 0),
        Limit("verify", 2000, 20, 5),
    )


def dual(dump: Dump) -> DualCase:
    return DualCase(dump, IDENT, LAYOUT, list(REGIONS), report(dump), PLUGIN.checksum_patches(dump, IDENT), {}, {})


# SPEC-002 R125, R33, R45, R55, R79, R81: static validation and agreement on every case.
def test_descriptors_and_references(monkeypatch: pytest.MonkeyPatch) -> None:
    unverified = dump_of(bytes.fromhex(VECTORS["cases"][0]["unverified"]["bytes_hex"]))
    good = [dual(DUMP), dual(unverified)]
    assert check_descriptors_and_references(good).passed
    resolution = dump_of(bytes.fromhex(VECTORS["resolution_failures"][0]["bytes_hex"]))
    failing = [
        replace(good[1], patches=cast("list[Patch]", good[1].patches)[1:]),
        replace(good[0], regions="junk"),
        DualCase(resolution, IDENT, LAYOUT, list(REGIONS), report(resolution), [], {}, {}),
    ]
    check = check_descriptors_and_references(failing)
    assert reasons(check) == ["plugin_disagreement", "r30", "table_out_of_bounds"]
    case = dual(DUMP)

    def wrong_crc(message: bytes, algorithm: object) -> int:
        del message, algorithm
        return 0

    monkeypatch.setattr(_engines, "crc32_b", wrong_crc)
    assert reasons(check_descriptors_and_references([case])) == ["engine_divergence"]


# SPEC-002 R117: seeded inside positions, edges, fields, full mode and non-zero XOR.
def test_inside_mutations() -> None:
    covered = [Piece("m", 0, 3000), Piece("m", 4000, 6000)]
    fields = [Piece("m", 7000, 7004)]
    first = inside_mutations(7, "e_crc", covered, fields, "sample")
    assert first == inside_mutations(7, "e_crc", covered, fields, "sample")
    assert first != inside_mutations(8, "e_crc", covered, fields, "sample")
    offsets = {m.offset for m in first}
    edges = {*range(64), *range(2936, 3000), *range(4000, 4064), *range(5936, 6000)}
    assert edges | {7000, 7001, 7002, 7003} <= offsets
    assert len(offsets) == len(first)
    assert len(first) <= 1000 + len(edges) + 4
    assert any(3000 > o >= 64 or 4064 <= o < 5936 for o in offsets)
    assert all(1 <= m.xor <= 255 and m.memory_id == "m" for m in first)
    assert all(any(p.start <= m.offset < p.end for p in (*covered, *fields)) for m in first)
    full = inside_mutations(7, "e_crc", [Piece("m", 10, 20), Piece("n", 0, 5)], [], "full")
    assert [(m.memory_id, m.offset) for m in full] == [("m", o) for o in range(10, 20)] + [("n", o) for o in range(5)]
    assert inside_mutations(7, "x", [], [], "sample") == ()
    assert inside_mutations(7, "x", [], [], "full") == ()
    assert inside_mutations(7, "x", [], [Piece("m", 0, 2)], "sample") == (
        MutationInput("m", 0, first_xor(7, "x")),
        MutationInput("m", 1, second_xor(7, "x")),
    )


def first_xor(seed: int, label: str) -> int:
    return Stream(seed, label).nonzero_byte()


def second_xor(seed: int, label: str) -> int:
    stream = Stream(seed, label)
    stream.nonzero_byte()
    return stream.nonzero_byte()


# SPEC-002 R118: outside positions avoid every coverage, field and table.
def test_outside_mutations() -> None:
    sizes = {"a": 100, "b": 50}
    excluded = [Piece("a", 10, 20), Piece("a", 15, 30), Piece("a", 0, 5), Piece("b", 40, 50)]
    mutations = outside_mutations(3, "v", sizes, excluded)
    assert mutations == outside_mutations(3, "v", sizes, excluded)
    assert mutations
    for m in mutations:
        assert 0 <= m.offset < sizes[m.memory_id]
        assert not any(p.memory_id == m.memory_id and p.start <= m.offset < p.end for p in excluded)
        assert 1 <= m.xor <= 255
    assert {m.memory_id for m in mutations} == {"a", "b"}
    assert outside_mutations(3, "v", {"a": 10}, [Piece("a", 0, 10)]) == ()


# SPEC-002 R127: draws are uniform by rejection; a draw above the last full multiple is rejected.
def test_stream_rejection(monkeypatch: pytest.MonkeyPatch) -> None:
    stream = Stream(1, "y")
    assert all(0 <= stream.below(10) < 10 for _ in range(10))
    assert len(stream._bytes(100)) == 100
    draws = iter([b"\xff" * 8, (5).to_bytes(8, "big")])

    def scripted(self: Stream, count: int) -> bytes:
        del self, count
        return next(draws)

    monkeypatch.setattr(Stream, "_bytes", scripted)
    assert Stream(0, "x").below(3) == 2


# SPEC-002 R100, R47, R124: the import and call scan.
@pytest.mark.parametrize(
    ("source", "findings"),
    [
        ("import core\nimport core.kernel\nimport hashlib\nimport collections.abc\nimport plug\nimport plug.x\n", ()),
        ("from core.plugins import Patch\nfrom . import y\nfrom .z import w\nfrom plug.sub import q\n", ()),
        ("import os\n", ("1: import os",)),
        ("import core.kernel._internal\n", ("1: import core.kernel._internal",)),
        ("import core.plugins.descriptor\n", ("1: import core.plugins.descriptor",)),
        ("from core.plugins import descriptor\n", ("1: from core.plugins import",)),
        ("from core.plugins.descriptor import interpret_verify\n", ("1: from core.plugins.descriptor import",)),
        ("from core.kernel._model import Dump\n", ("1: from core.kernel._model import",)),
        ("from os import path\n", ("1: from os import",)),
        (
            "open('f')\nexec('1')\neval('1')\ncompile('1', 'f', 'exec')\n__import__('os')\n",
            (
                "1: open()",
                "2: exec()",
                "3: eval()",
                "4: compile()",
                "5: __import__()",
            ),
        ),
        (
            "import hashlib as h\ngetattr(h, 'sha256')\ngetattr(object(), 'x')\ngetattr()\nlen([])\nh.sha256()\n",
            ("2: getattr on module h",),
        ),
        ("def (\n", ("1: syntax error",)),
    ],
)
def test_scan_source(source: str, findings: tuple[str, ...]) -> None:
    assert scan_source(source, "plug") == findings


def test_import_allowed() -> None:
    assert import_allowed("core", "plug")
    assert import_allowed("core.plugins", "plug")
    assert not import_allowed("core.plugins.descriptor._engines", "plug")
    assert not import_allowed("plugx", "plug")
    assert import_allowed("plug", "plug")
    assert not import_allowed("struct.x", "plug")


SIGNED = ChecksumRegion("sig", "pflash", "signed", None, None, None, NONE)
PYTHON = python_region("py", (Range(0, 4),), (Range(4, 8),), Reference("independent", "ref-1", "someone/repo@abc"))
UNSUPPORTED = descriptor_from_json(
    next(
        d
        for v in VECTORS["invalid_descriptor_sets"]
        if v["id"] == "compensate_not_supported"
        for d in v["descriptors"]
        if d["name"] == "a_comp"
    )
)
VARIANT_REGIONS = (*REGIONS, SIGNED, PYTHON)
HEADER = Header("0.1.0", "a" * 40, FAMILY, "1.0.0", 1, "b" * 64, "rev-1", 12, "release", 7)
REVIEW = LayoutReview("tuner", "2026-10-19")
REGISTRY = RegistryHead("c" * 64, 3, "d" * 64, "e" * 64)


def variant(variant_id: str = VARIANT) -> Variant:
    return Variant(variant_id, 5, 1, 1, ({"schema": "x"},), VARIANT_REGIONS, frozenset({"s"}), frozenset({"s", "t"}))


def run() -> RunResult:
    return RunResult(
        HEADER,
        (variant("zz-variant"), variant()),
        (Check(rule(120), 1, ()), Check(rule(111), 2, ())),
        (Mutation(VARIANT, "e_crc", "sample", 1, 1, 1, 1), Mutation(VARIANT, "a_comp", "sample", 1, 1, 1, 1)),
        Fuzz(MIN_FUZZ_INPUTS, 0, 0),
        (Limit("verify", 2000, 5, 0), Limit("identify", 1000, 1, 0)),
        REVIEW,
        REGISTRY,
    )


# SPEC-002 R126, R127, R110, R135: the report shape, order, hash and fail-closed admission.
def test_build_report() -> None:
    report_json = build_report(run())
    assert set(report_json) == {
        "report_version",
        "core",
        "plugin",
        "corpus",
        "run",
        "variants",
        "checks",
        "mutation",
        "fuzz",
        "limits",
        "layout_review",
        "attester_registry",
        "failures",
        "verdict",
    }
    assert report_json["report_version"] == 1
    assert report_json["core"] == {"version": "0.1.0", "git_sha": "a" * 40}
    assert report_json["plugin"] == {
        "family": FAMILY,
        "version": "1.0.0",
        "contract_version": 1,
        "wheel_sha256": "b" * 64,
    }
    assert report_json["corpus"] == {"revision": "rev-1", "dumps": 12}
    assert report_json["run"] == {"kind": "release", "seed": 7}
    assert report_json["verdict"] == "conformant"
    assert report_json["failures"] == []
    assert report_json["layout_review"] == {"reviewer": "tuner", "date": "2026-10-19"}
    assert report_json["attester_registry"] == {
        "genesis_hash": "c" * 64,
        "seq": 3,
        "head_hash": "d" * 64,
        "registry_hash": "e" * 64,
    }
    variants = cast("list[dict[str, Any]]", report_json["variants"])
    assert [v["checksum_variant_id"] for v in variants] == [VARIANT, "zz-variant"]
    entry = variants[0]
    assert (entry["originals"], entry["checksum_off"], entry["virtual"]) == (5, 1, 1)
    assert (entry["golden_field"], entry["golden_concordant"], entry["admitted"]) == (0, 0, False)
    assert entry["descriptor_hashes"] == sorted(h for h in (r.descriptor_hash for r in REGIONS) if h is not None)
    assert entry["signed_regions"] == ["sig"]
    assert [r["region"] for r in entry["references"]] == sorted(r.name for r in VARIANT_REGIONS)
    assert {"region": "py", "kind": "independent", "id": "ref-1", "source": "someone/repo@abc"} in entry["references"]
    assert entry["checksum_region_sets"] == ["s"]
    assert entry["review_fields"] == [
        {"region": "a_comp", "kind": "compensation", "memory_id": "pflash", "start": 268, "end": 272},
        {"region": "d_mirror", "kind": "mirror_destination", "memory_id": "pflash", "start": 272, "end": 288},
    ]
    assert [c["rule"] for c in cast("list[dict[str, Any]]", report_json["checks"])] == [rule(111), rule(120)]
    assert [m["region"] for m in cast("list[dict[str, Any]]", report_json["mutation"])] == ["a_comp", "e_crc"]
    assert [x["method"] for x in cast("list[dict[str, Any]]", report_json["limits"])] == ["identify", "verify"]
    assert conformance_report_hash(report_json) == hashlib.sha256(rfc8785.dumps(report_json)).hexdigest()


def test_report_failures_and_nulls() -> None:
    failure = Failure(rule(117), H, "undetected_e_crc")
    checks = (Check(rule(117), 2, (failure, failure, Failure(rule(117), "", "a"))), Check(rule(111), 1, ()))
    report_json = build_report(replace(run(), checks=checks, layout_review=None, registry=None))
    assert report_json["verdict"] == "nonconformant"
    assert report_json["failures"] == [
        {"rule": rule(117), "image_hash": "", "reason": "a"},
        {"rule": rule(117), "image_hash": H, "reason": "undetected_e_crc"},
    ]
    assert cast("list[dict[str, Any]]", report_json["checks"])[1] == {
        "rule": rule(117),
        "passed": False,
        "cases": 2,
        "failures": 3,
    }
    assert report_json["layout_review"] is None
    assert report_json["attester_registry"] is None


@pytest.mark.parametrize(
    "changes",
    [
        {"variants": (variant(), variant())},
        {"checks": (Check(rule(111), 1, ()), Check(rule(111), 1, ()))},
        {"mutation": (Mutation(VARIANT, "e", "full", 0, 0, 0, 0),) * 2},
        {"limits": (Limit("verify", 1, 1, 1),) * 2},
        {"variants": (variant("Bad_Id"),)},
        {"header": replace(HEADER, core_git_sha="main")},  # SPEC-002 R110: pinned by a 40-hex SHA.
        {"header": replace(HEADER, family="NoFamily")},
        {"header": replace(HEADER, wheel_sha256="x")},
        {"header": replace(HEADER, seed=-1)},
        {"header": replace(HEADER, seed=2**53)},
    ],
)
def test_build_report_rejects_bad_runner_input(changes: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="R"):
        build_report(replace(run(), **changes))


def test_review_fields_skips_other_regions() -> None:
    regions = (region_of(UNSUPPORTED), SIGNED, PYTHON, *REGIONS)
    assert [f["region"] for f in review_fields(regions)] == ["a_comp", "d_mirror"]
    assert review_fields((region_of(UNSUPPORTED),)) == []


# SPEC-002 R131, R132, R33: admission needs every condition at once.
def test_admitted() -> None:
    good = variant()
    assert admitted(good, 1, True, REVIEW)
    assert admitted(replace(good, regions=(SIGNED,)), 1, True, REVIEW)
    assert not admitted(replace(good, originals=4), 1, True, REVIEW)
    assert not admitted(good, 0, True, REVIEW)
    assert not admitted(good, 1, False, REVIEW)
    none_ref = python_region("pn", (Range(0, 4),), (Range(4, 8),), NONE)
    assert not admitted(replace(good, regions=(*REGIONS, none_ref)), 1, True, REVIEW)
    assert not admitted(replace(good, checksum_region_sets=frozenset()), 1, True, REVIEW)
    assert not admitted(replace(good, checksum_region_sets=frozenset({"u"})), 1, True, REVIEW)
    assert not admitted(good, 1, True, None)


def released_report() -> ContractJson:
    return build_report(run())


# SPEC-002 R130: published only from a conformant release run for this exact wheel, nightly green.
def test_publishable() -> None:
    report_json = released_report()
    assert publishable(report_json, "b" * 64, True)
    assert not publishable(report_json, "c" * 64, True)
    assert not publishable(report_json, "b" * 64, False)
    assert not publishable(build_report(replace(run(), header=replace(HEADER, run_kind="pr"))), "b" * 64, True)
    failed = (Check(rule(111), 1, (Failure(rule(111), H, "x"),)),)
    assert not publishable(build_report(replace(run(), checks=failed)), "b" * 64, True)
    assert not publishable(None, "b" * 64, True)
    assert not publishable([1, 2], "b" * 64, True)


# SPEC-002 R133: catalog entry.
def test_catalog_ready() -> None:
    offered = frozenset({"v1"})
    assert catalog_ready(20, offered, frozenset({"v1", "v2"}), True)
    assert not catalog_ready(19, offered, offered, True)
    assert not catalog_ready(20, frozenset(), offered, True)
    assert not catalog_ready(20, frozenset({"v1", "v3"}), offered, True)
    assert not catalog_ready(20, offered, offered, False)


# SPEC-002 R134, R135: the automated semver rule.
def test_required_bump() -> None:
    old = {("verify", H): "1", ("identify", H): "2", ("layout", H): "3"}
    assert required_bump(old, dict(old)) == "none"
    assert required_bump(old, old | {("verify", H): "x"}) == "major"
    assert required_bump(old, old | {("identify", H): "x"}) == "minor"
    assert required_bump(old, old | {("hints", H): "x"}) == "minor"
    assert required_bump(old, {k: v for k, v in old.items() if k[0] != "layout"}) == "major"
    assert required_bump(old, old | {("other", H): "x"}) == "none"


def test_semver() -> None:
    assert parse_semver("10.2.0") == (10, 2, 0)
    for bad in ("1.0", "01.0.0", "1.0.0-rc1", "v1.0.0"):
        with pytest.raises(ValueError, match="semver"):
            parse_semver(bad)
    assert bump_satisfied("1.0.0", "2.0.0", "major")
    assert not bump_satisfied("1.0.0", "1.1.0", "major")
    assert bump_satisfied("1.0.0", "1.1.0", "minor")
    assert bump_satisfied("1.0.0", "2.0.0", "minor")
    assert not bump_satisfied("1.0.0", "1.0.1", "minor")
    assert not bump_satisfied("1.2.0", "0.3.0", "minor")
    assert bump_satisfied("1.0.0", "1.0.1", "none")
    assert not bump_satisfied("1.0.0", "1.0.0", "none")
