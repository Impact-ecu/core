"""SPEC-004 §4-§8 on a real (synthetic) plugin: `release`, every step of R20, `ReleasedImage` and `to_dump`."""

import copy
import pickle
from collections.abc import Callable, Mapping
from dataclasses import replace
from fractions import Fraction
from typing import Any, cast

import pytest

import core.gate._release
from core.definitions import AxisDef, Definition, Dtype, FixedAxis, InlineAxis, Scaling, SharedAxis
from core.gate import ExportRefused, GateBlocked, GateError, InputResult, ReleasedImage, alert_warnings, release
from core.gate._model import json_hash
from core.gate._output import KernelOutcome
from core.gate._report import GateReport
from core.kernel import (
    Dump,
    LayoutMemory,
    MemoryLayout,
    Patch,
    Region,
    UnverifiedImage,
    Version,
    canonical_json,
    image_hash,
    layout_hash,
)
from core.kernel._internal import view
from core.plugins import (
    Bypass,
    ChecksumRegion,
    Identification,
    InterpreterDivergence,
    Reference,
    RegionResult,
    VerifyReport,
)
from core.provenance import DISCLAIMER, Event
from tests.unit.gate_support import (
    CONFORMANCE,
    GOOD_EDITS,
    MAP,
    PROJECT,
    PYTHON_REGION,
    SHA_ORIGINAL,
    TABLE,
    U8,
    Overridden,
    PythonPlugin,
    Scenario,
    ShaReference,
    SignedPlugin,
    admit_all,
    check,
    definition,
    doc,
    event,
    export_basis,
    raises,
    ran_of,
    rule_ids,
    sha,
    skipped_of,
    write,
)
from tests.unit.plugin_fixtures import IDENT, LAYOUT, ORIGINAL, VECTORS, FakePlugin, dump_of

INTEGRITY = ["binding", "checksum_step", "dual_checksum", "input_state", "kernel_invariants", "verify"]
AFTER_AVAILABILITY = [*INTEGRITY[:5], "map_rules", "verify"]


def integrity_ran(report: Mapping[str, Any]) -> list[str]:
    return [kind for kind, map_id, _ in ran_of(report) if map_id is None]


def skipped_kinds(report: Mapping[str, Any], reason: str) -> list[str]:
    return [kind for kind, _, _, why in skipped_of(report) if why == reason]


def alert_ack(released: ReleasedImage, **override: object) -> Event:
    warns = [f for f in doc(released.report)["findings"] if f["severity"] == "warn"]
    payload = {
        "image_hash_release": released.image_hash,
        "gate_report_hash": released.report_hash,
        "warnings": [{"finding_id": json_hash(f), "rule_id": f["rule_id"], "text": f["text"]} for f in warns],
        "presented_ms": 1000,
        "confirmed_ms": 7000,
    }
    project_id = str(override.pop("project_id", PROJECT))
    return event("alert_ack", {**payload, **override}, project_id=project_id)


# SPEC-004 R20, R29, R51, SPEC-001 R9, R42: a clean release yields the release candidate, `no findings`.
def test_release_no_findings() -> None:
    s = Scenario()
    released = s.release()
    report = doc(released.report)
    assert released.verdict == "no findings"
    assert report["verdict"] == "no findings"
    assert integrity_ran(report) == INTEGRITY
    subject = report["subject"]
    assert subject["release_candidate_hash"] == released.image_hash
    assert subject["input_verify"] == "ok"
    assert subject["layout_hash"] == layout_hash(LAYOUT)
    assert subject["original_image_hash"] == image_hash(s.original)
    assert subject["unverified_image_hash"] == s.unverified().image_hash
    assert subject["engine"] == {"combustion": "SI", "fuel": "gasoline"}
    assert canonical_json(report).startswith(b'{"disclaimer":')
    assert report["disclaimer"] == DISCLAIMER
    dump = released.to_dump(None)
    data = dump.memories[0].data
    assert data[64:68] == bytes([10, 20, 25, 30])
    assert image_hash(dump) == released.image_hash
    assert FakePlugin().verify(dump, IDENT).status == "ok"
    assert released.dump_kind == "bench_full"
    assert [m.size for m in released.memories] == [512]
    assert released.report_hash == json_hash(report)
    with pytest.raises(ExportRefused) as refused:
        released.to_dump(alert_ack(released))
    assert refused.value.reason == "unexpected_ack"
    # R53: an event of another project is ignored, so nothing unexpected is acknowledged.
    assert released.to_dump(alert_ack(released, project_id="proj-2")) == dump


WARN_EDITS = {**GOOD_EDITS, 64: bytes([10, 20, 25, 40])}


# SPEC-004 R6, R50-R52: a `warn` export needs the `alert_ack` of exactly this release.
def test_release_warn_and_ack() -> None:
    released = Scenario(edits=WARN_EDITS).release()
    assert released.verdict == "warn"
    assert rule_ids(released.report) == ["ign.si.gasoline.base.boost_cap"]
    assert doc(released.report)["findings"][0]["cells"] == ((1, 1),)
    with pytest.raises(ExportRefused) as refused:
        released.to_dump(None)
    assert refused.value.reason == "ack_required"
    assert image_hash(released.to_dump(alert_ack(released))) == released.image_hash
    for ack, reason in (
        (event("rule_silence", {"rule_id": "x", "justification_commitment": None}), "bad_payload"),
        (alert_ack(released, gate_report_hash="0" * 64), "report_mismatch"),
        (alert_ack(released, image_hash_release="0" * 64), "image_mismatch"),
        (alert_ack(released, warnings=[]), "findings_mismatch"),
    ):
        with pytest.raises(ExportRefused) as refused:
            released.to_dump(ack)
        assert refused.value.reason == reason


CAP = "ign.si.gasoline.base.boost_cap"


def silence(rule_id: str, commitment: str | None, *, event_id: str = "0" * 32, project_id: str = PROJECT) -> Event:
    payload = {"rule_id": rule_id, "justification_commitment": commitment}
    return event("rule_silence", payload, event_id=event_id, project_id=project_id)


# SPEC-004 R60, R61: a justified silence moves a table warn to `silenced`; built-ins and blocks never move.
def test_silences() -> None:
    commitment = "c" * 64
    silences = (
        silence(CAP, commitment, event_id="b" * 32),
        silence(CAP, commitment, event_id="a" * 32),
        silence(CAP, None, event_id="0" * 32),
        silence("G-UNMAPPED", commitment),
        silence("ign.si.gasoline.base.range", commitment, project_id="proj-2"),
    )
    released = Scenario(edits={**WARN_EDITS, 200: b"\x01"}).release(silences=silences)
    assert released.verdict == "warn"
    assert rule_ids(released.report) == ["G-UNMAPPED"]
    assert rule_ids(released.report, "silenced") == ["ign.si.gasoline.base.boost_cap"]
    assert doc(released.report)["silenced"][0]["silence_event_id"] == "a" * 32
    quiet = Scenario(edits=WARN_EDITS).release(silences=silences[:1])
    assert quiet.verdict == "no findings"
    assert quiet.to_dump(None).memories[0].data[64:68] == bytes([10, 20, 25, 40])


# SPEC-004 R16: the public `release` runs the fail-closed evidence seam, so no variant is admitted and it blocks.
def test_public_release_without_evidence_blocks() -> None:
    s = Scenario()
    with pytest.raises(GateBlocked) as blocked:
        release(s.unverified(), **s.args())
    report = doc(blocked.value.report)
    assert blocked.value.reason == "block"
    assert blocked.value.report_hash == json_hash(report)
    assert "checksum verify returned not_applicable after the checksum step" in [f["text"] for f in report["findings"]]
    assert ("checksum_step", None, None, "unknown_variant") in skipped_of(report)
    assert ("dual_checksum", None, None, "unknown_variant") in skipped_of(report)
    assert report["subject"]["release_candidate_hash"] is None


# SPEC-004 R21, R45: unavailable rule table, plugin or dual reference stop the run before binding.
@pytest.mark.parametrize(
    ("overrides", "expected", "plugin_recorded"),
    [
        ({"rule_table": None}, ["G-UNAVAILABLE-RULES"], True),
        ({"rule_table": {**TABLE, "version": "1"}}, ["G-UNAVAILABLE-RULES"], True),
        ({"plugin": None}, ["G-UNAVAILABLE-PLUGIN"], False),
        ({"plugin": FakePlugin(contract_version=3)}, ["G-UNAVAILABLE-PLUGIN"], False),
        ({"conformance_report": None}, ["G-UNAVAILABLE-PLUGIN"], True),
        ({"conformance_report": {**CONFORMANCE, "verdict": "x"}}, ["G-UNAVAILABLE-PLUGIN"], True),
        ({"plugin": Overridden(replaced={"identify": raises})}, ["G-UNAVAILABLE-PLUGIN"], True),
        ({"plugin": None, "rule_table": None}, ["G-UNAVAILABLE-PLUGIN", "G-UNAVAILABLE-RULES"], False),
        ({"plugin": Overridden(replaced={"identify": lambda _d: 7})}, ["G-PLUGIN-ERROR"], True),
        ({"plugin": Overridden(replaced={"checksums": raises})}, ["G-PLUGIN-ERROR"], True),
        ({"plugin": Overridden(replaced={"checksums": lambda _i: "regions"})}, ["G-PLUGIN-ERROR"], True),
    ],
)
def test_unavailable(overrides: dict[str, Any], expected: list[str], plugin_recorded: bool) -> None:
    report = Scenario().blocked(**overrides)
    assert rule_ids(report) == expected
    assert ran_of(report) == []
    assert skipped_kinds(report, "gate_unavailable") == AFTER_AVAILABILITY
    subject = report["subject"]
    assert subject["layout_hash"] is None
    assert subject["input_verify"] is None
    assert subject["release_candidate_hash"] is None
    assert (subject["plugin"] is not None) is plugin_recorded
    if "G-UNAVAILABLE-PLUGIN" in expected:
        assert subject["conformance_report_hash"] is None
        assert subject["checksum_variant_id"] is None


def python_scenario(**overrides: object) -> Scenario:
    return Scenario(original=dump_of(SHA_ORIGINAL), plugin=PythonPlugin(), overrides=overrides)


# SPEC-004 R21: an independent region needs a usable reference; a recalculable region with reference `none` too.
@pytest.mark.parametrize(
    "references",
    [
        {},
        {"ref-sha": ShaReference(id="other")},
        {"ref-sha": ShaReference(version=cast("str", 1))},
        {"ref-sha": object()},
    ],
)
def test_dual_unavailable(references: dict[str, Any]) -> None:
    report = python_scenario().blocked(references=references)
    assert rule_ids(report) == ["G-UNAVAILABLE-DUAL"]
    assert skipped_kinds(report, "gate_unavailable") == AFTER_AVAILABILITY


def test_reference_none_is_unavailable() -> None:
    region = replace(PYTHON_REGION, reference=Reference("none", None, None))
    s = Scenario(original=dump_of(SHA_ORIGINAL), plugin=PythonPlugin(regions=(region,)))
    assert rule_ids(s.blocked()) == ["G-UNAVAILABLE-DUAL"]


# SPEC-004 R25, R27, §6: the independent reference is used and recorded with its version.
def test_independent_reference() -> None:
    released = python_scenario(references={"ref-sha": ShaReference()}).release()
    assert released.verdict == "no findings"
    assert doc(released.report)["subject"]["references"] == ({"id": "ref-sha", "version": "1.0.0"},)
    data = released.to_dump(None).memories[0].data
    assert data[256:288] == bytes.fromhex(sha(data[32:256]))


@pytest.mark.parametrize(
    ("replaced", "where"),
    [
        ({"patches_region": raises}, "checksum_step"),
        ({"patches_region": lambda _d: "patches"}, "checksum_step"),
        ({"verify_region": raises}, "dual_checksum"),
        ({"verify_region": lambda _d: RegionResult("p_sha", "pflash", "recalculable", "ok", *[None] * 4)}, None),
        (
            {
                "verify_region": lambda _d: RegionResult(
                    "p_sha", "pflash", "recalculable", "bypassed", None, None, None, Bypass("pflash", 0, 4)
                )
            },
            "dual_checksum",
        ),
    ],
)
def test_reference_failures(replaced: dict[str, Any], where: str | None) -> None:
    report = python_scenario(references={"ref-sha": ShaReference(replaced=replaced)}).blocked()
    if where is None:
        assert rule_ids(report) == ["G-DUAL-DIVERGENCE"]
        return
    assert rule_ids(report) == ["G-UNAVAILABLE-DUAL"]
    assert where in integrity_ran(report)
    assert report["subject"]["references"] == ({"id": "ref-sha", "version": "1.0.0"},)


# SPEC-004 R20, R23, R45: a binding mismatch stops the run; the layout computed before it is recorded.
def test_binding_mismatches() -> None:
    s = Scenario()
    other = Scenario(edits={64: bytes([1, 2, 3, 4])})
    cases = {
        "unverified image of another version": s.blocked(u=other.unverified()),
        "input of another original": s.blocked(input=check(dump_of(write(ORIGINAL, 300, b"\x00")))),
        "input of another plugin version": s.blocked(input=check(s.original, plugin=FakePlugin(version="1.0.1"))),
        "version on another base": s.blocked(
            version=Version("0" * 64, layout_hash(LAYOUT), s.version.patches), u=s.unverified()
        ),
        "version on another layout": s.blocked(
            version=Version(image_hash(s.original), "0" * 64, s.version.patches), u=s.unverified()
        ),
    }
    for what, report in cases.items():
        assert rule_ids(report) == ["G-BINDING"], what
        assert integrity_ran(report) == ["binding"], what
        assert skipped_kinds(report, "earlier_block") == AFTER_AVAILABILITY[1:], what
        assert report["subject"]["layout_hash"] == layout_hash(LAYOUT), what
        assert report["subject"]["input_verify"] is None, what


def test_binding_without_identification() -> None:
    s = Scenario(plugin=Overridden(replaced={"identify": lambda _d: None}))
    report = s.blocked(input=check(s.original))
    assert rule_ids(report) == ["G-BINDING"]
    assert report["subject"]["checksum_variant_id"] is None
    assert report["subject"]["layout_hash"] is None


def test_binding_unordered_overlaps() -> None:
    s = Scenario()
    first = Patch("pflash", 64, 2, ORIGINAL[64:66], b"\x01\x02")
    second = Patch("pflash", 65, 2, ORIGINAL[65:67], b"\x03\x04")
    version = Version(image_hash(s.original), layout_hash(LAYOUT), (first, second))
    report = s.blocked(version=version, u=s.unverified())
    assert rule_ids(report) == ["G-BINDING"]
    assert report["subject"]["version_hash"] is None


# SPEC-004 R23: layout and static descriptor validation failures are plugin errors at binding.
def test_binding_plugin_errors() -> None:
    report = Scenario(plugin=Overridden(replaced={"layout": raises})).blocked(input=check(Scenario().original))
    assert rule_ids(report) == ["G-PLUGIN-ERROR"]
    assert report["subject"]["layout_hash"] is None
    unsorted = Overridden(replaced={"checksums": lambda i: list(reversed(FakePlugin().checksums(i)))})
    report = Scenario(plugin=unsorted).blocked(input=check(Scenario().original))
    assert rule_ids(report) == ["G-PLUGIN-ERROR"]
    assert report["subject"]["layout_hash"] == layout_hash(LAYOUT)


# SPEC-000 emissions boundary, SPEC-004 R23, R24: a patch in a protected region (here `emissions_egr`) blocks.
def test_patch_in_protected_region() -> None:
    s = Scenario()
    data = s.original.memories[0].data
    egr = Patch("pflash", 420, 4, data[420:424], b"\x00\x00\x00\x00")
    version = Version(image_hash(s.original), layout_hash(LAYOUT), (*s.version.patches, egr))
    forged = UnverifiedImage(dump_of(write(view(s.unverified()).memories[0].data, 420, b"\x00\x00\x00\x00")))
    report = s.blocked(version=version, u=forged)
    assert rule_ids(report) == ["G-PROTECTED"]
    assert report["findings"][0]["runs"] == ({"memory_id": "pflash", "offset": 420, "length": 4},)
    assert report["findings"][0]["incident"] is None
    assert skipped_kinds(report, "earlier_block") == AFTER_AVAILABILITY[1:]


def suspect_ack(result: InputResult, original: Dump, **override: object) -> Event:
    subject = doc(result.report)["subject"]
    payload = {
        "artifact_sha256": subject["received_sha256"],
        "image_hash": image_hash(original),
        "input_report_hash": result.report_hash,
        "verify_status": subject["verify_status"],
    }
    project_id = str(override.pop("project_id", PROJECT))
    return event("suspect_ack", {**payload, **override}, project_id=project_id)


# SPEC-004 R14, R22: a suspect input blocks unless every block is G-INPUT-VERIFY and it was acknowledged.
def test_suspect_input() -> None:
    s = Scenario(original=dump_of(write(ORIGINAL, 200, b"\x00")))
    result = s.input()
    assert result.artifact_state == "suspect"
    report = s.blocked(input=result)
    assert rule_ids(report) == ["G-INPUT-SUSPECT"]
    assert integrity_ran(report) == INTEGRITY
    assert report["subject"]["input_verify"] == "ok"
    for ack in (
        suspect_ack(result, s.original, project_id="proj-2"),
        suspect_ack(result, s.original, verify_status="ok"),
        suspect_ack(result, s.original, input_report_hash="0" * 64),
    ):
        assert rule_ids(s.blocked(input=result, suspect_ack=ack)) == ["G-INPUT-SUSPECT"]
    released = s.release(input=result, suspect_ack=suspect_ack(result, s.original))
    assert doc(released.report)["subject"]["input_verify"] == "failed_acknowledged"
    hashed = check(s.original, declared_sha256="0" * 64)
    report = s.blocked(input=hashed, suspect_ack=suspect_ack(hashed, s.original))
    assert "G-INPUT-SUSPECT" in rule_ids(report)


# SPEC-004 R20, R25: a resolution failure of the core derivation blocks without S1 and stops the run.
def test_checksum_resolution() -> None:
    s = Scenario(original=dump_of(bytes.fromhex(VECTORS["resolution_failures"][0]["bytes_hex"])))
    result = s.input()
    report = s.blocked(input=result, suspect_ack=suspect_ack(result, s.original))
    assert rule_ids(report) == ["G-CHECKSUM-RESOLUTION"]
    assert report["findings"][0]["incident"] is None
    assert integrity_ran(report) == ["binding", "checksum_step", "input_state", "kernel_invariants"]
    assert skipped_kinds(report, "earlier_block") == ["dual_checksum", "map_rules", "verify"]
    assert report["subject"]["release_candidate_hash"] is None


def with_extra(patch: Patch) -> Callable[..., object]:
    return lambda d, i: [*FakePlugin().checksum_patches(d, i), patch]


def unverified_data() -> bytes:
    return view(Scenario().unverified()).memories[0].data


STRAY = Patch("pflash", 200, 1, ORIGINAL[200:201], b"\xee")


# SPEC-004 R25: every plugin fault of the checksum step, and the divergence with the core derivation.
@pytest.mark.parametrize(
    ("checksum_patches", "expected"),
    [
        (raises, "G-PLUGIN-ERROR"),
        (lambda _d, _i: "patches", "G-PLUGIN-ERROR"),
        (lambda _d, _i: [], "G-DUAL-DIVERGENCE"),
        (with_extra(STRAY), "G-CHECKSUM-CONTAINMENT"),
        (lambda d, i: [*FakePlugin().checksum_patches(d, i)] * 2, "G-PLUGIN-ERROR"),
        (lambda d, i: list(reversed(FakePlugin().checksum_patches(d, i))), "G-PLUGIN-ERROR"),
    ],
)
def test_checksum_step_faults(checksum_patches: Callable[..., object], expected: str) -> None:
    s = Scenario(plugin=Overridden(replaced={"checksum_patches": checksum_patches}))
    report = s.blocked(input=check(s.original))
    assert rule_ids(report) == [expected]
    assert skipped_kinds(report, "earlier_block") == ["dual_checksum", "map_rules", "verify"]
    incident = "S1" if expected == "G-DUAL-DIVERGENCE" else None
    assert report["findings"][0]["incident"] == incident


def test_checksum_patch_with_wrong_before() -> None:
    # A field patch with a wrong `before` is not byte-identical to the core derivation (SPEC-002 R55).
    patches = FakePlugin().checksum_patches(view(Scenario().unverified()), IDENT)
    first = patches[0]
    wrong = Patch(first.memory_id, first.offset, first.length, first.after, first.before)
    s = Scenario(plugin=Overridden(replaced={"checksum_patches": lambda _d, _i: [wrong, *patches[1:]]}))
    assert rule_ids(s.blocked(input=check(s.original))) == ["G-DUAL-DIVERGENCE"]


def test_interpreter_divergence(monkeypatch: pytest.MonkeyPatch) -> None:
    def diverge(*_args: object) -> object:
        raise InterpreterDivergence("engines")

    monkeypatch.setattr(core.gate._release, "interpret_patches", diverge)
    report = Scenario().blocked()
    assert rule_ids(report) == ["G-DUAL-DIVERGENCE"]
    assert report["findings"][0]["incident"] == "S1"


def test_compare_verify_divergence(monkeypatch: pytest.MonkeyPatch) -> None:
    def diverge(*_args: object) -> object:
        raise InterpreterDivergence("engines")

    monkeypatch.setattr(core.gate._release, "compare_verify", diverge)
    assert rule_ids(Scenario().blocked()) == ["G-DUAL-DIVERGENCE"]


# SPEC-004 R25, SPEC-001 R41: the gate re-asserts that the checksum step changed only checksum regions.
def test_checksum_step_r41_reassertion(monkeypatch: pytest.MonkeyPatch) -> None:
    def tampered(u: UnverifiedImage, q: object, layout: object) -> UnverifiedImage:
        del q, layout
        return UnverifiedImage(dump_of(write(view(u).memories[0].data, 150, b"\x99")))

    monkeypatch.setattr(core.gate._release, "apply_checksum_patches", tampered)
    report = Scenario().blocked()
    assert rule_ids(report) == ["G-INVARIANT"]
    assert report["findings"][0]["incident"] == "S1"


def disagreeing_verify(dump: Dump, ident: Identification) -> VerifyReport:
    report = FakePlugin().verify(dump, ident)
    first = report.regions[0]
    return VerifyReport(report.status, None, (replace(first, stored="00", computed="00"), *report.regions[1:]))


def failing_verify(dump: Dump, ident: Identification) -> VerifyReport:
    report = FakePlugin().verify(dump, ident)
    first = report.regions[0]
    return VerifyReport("fail", None, (replace(first, status="fail"), *report.regions[1:]))


# SPEC-004 R26, R27: verify maps only the status; the comparison with the reference happens once, in dual.
def test_verify_and_dual() -> None:
    def blocked(verify: Callable[..., object]) -> Mapping[str, Any]:
        s = Scenario(plugin=Overridden(replaced={"verify": verify}))
        return s.blocked(input=check(s.original))

    report = blocked(raises)
    assert rule_ids(report) == ["G-PLUGIN-ERROR"]
    assert ("dual_checksum", None, None, "earlier_block") in skipped_of(report)
    assert ("map_rules" in [k for k, _, _ in ran_of(report)]) is False
    assert rule_ids(blocked(lambda d, i: VerifyReport("bypassed", None, FakePlugin().verify(d, i).regions))) == [
        "G-PLUGIN-ERROR"
    ]
    report = blocked(disagreeing_verify)
    assert rule_ids(report) == ["G-DUAL-DIVERGENCE"]
    assert report["findings"][0]["incident"] == "S1"
    report = blocked(failing_verify)
    assert rule_ids(report) == ["G-DUAL-DIVERGENCE", "G-VERIFY"]
    assert "checksum verify returned fail after the checksum step" in [f["text"] for f in report["findings"]]


# SPEC-004 R6, R26: a signed region warns at both stages and is recorded; a signed-only variant skips dual.
def test_signed_regions() -> None:
    s = Scenario(plugin=SignedPlugin())
    released = s.release(input=check(s.original, plugin=SignedPlugin()))
    assert released.verdict == "warn"
    assert rule_ids(released.report) == ["G-VERIFY-SIGNED"]
    assert doc(released.report)["subject"]["signed_regions"] == ({"memory_id": "pflash", "name": "z_sig"},)
    assert image_hash(released.to_dump(alert_ack(released))) == released.image_hash


def test_signed_only_variant() -> None:
    region = ChecksumRegion("z_sig", "pflash", "signed", None, None, None, Reference("none", None, None))

    class SignedOnly(FakePlugin):
        def verify(self, dump: Dump, ident: Identification) -> VerifyReport:
            del dump, ident
            result = RegionResult("z_sig", "pflash", "signed", "signature_unverifiable", None, None, None, None)
            return VerifyReport("signature_unverifiable", None, (result,))

    layout = _layout_without_checksum()
    plugin = SignedOnly(regions=(region,), layout_value=layout)
    s = Scenario(plugin=plugin, layout=layout)
    released = s.release(input=check(s.original, plugin=plugin))
    assert ("dual_checksum", None, None, "signed_only") in skipped_of(released.report)
    assert released.verdict == "warn"


def _layout_without_checksum() -> MemoryLayout:
    memory = LAYOUT.memories[0]
    regions = tuple(Region("protected", r.start, r.end, r.name) if r.kind == "checksum" else r for r in memory.regions)
    return MemoryLayout((LayoutMemory(memory.memory_id, memory.base_address, memory.size, regions),))


F32 = Dtype("float", 32, "be")


# SPEC-004 R28, R30, R31, R35, R39: map rules on maps decoded from the release candidate.
def test_maps() -> None:
    nan = b"\x7f\xc0\x00\x00"
    float_map = replace(MAP, map_id="syn.f", offset=120, rows=1, cols=1, dtype=F32, x=None, y=None)
    duty = replace(
        MAP,
        map_id="syn.duty",
        offset=130,
        rows=1,
        cols=2,
        category="injector_duty",
        unit="percent",
        x=InlineAxis("pflash", 140, 2, U8, Scaling(Fraction(1), Fraction(0)), "rpm", None),
        y=None,
    )
    flat = FixedAxis((Fraction(1), Fraction(1)), "rpm", None)
    flat_axis = replace(MAP, map_id="syn.flat", offset=150, rows=1, cols=2, x=flat, y=None)
    proposed = replace(MAP, map_id="syn.proposed", offset=160, rows=1, cols=1, state="proposed", x=None, y=None)
    stale = replace(MAP, map_id="syn.stale", offset=600, rows=1, cols=1, x=None, y=None)
    untouched = replace(MAP, map_id="syn.untouched", offset=170, rows=1, cols=1, x=None, y=None)
    edits = {
        **GOOD_EDITS,
        120: nan,
        130: bytes([100, 101]),
        140: bytes([1, 2]),
        150: bytes([5, 5]),
        160: b"\x09",
        210: b"\x01",
    }
    defn = definition(MAP, float_map, duty, flat_axis, proposed, stale, untouched)
    report = Scenario(edits=edits).blocked(definition=defn)
    found = [(f["rule_id"], f["map_id"]) for f in report["findings"]]
    assert found == [
        ("G-AXIS-MONOTONIC", "syn.flat"),
        ("G-DEFINITION", "syn.stale"),
        ("G-INJECTOR-DUTY", "syn.duty"),
        ("G-NONFINITE", "syn.f"),
        ("G-UNMAPPED", None),
        ("G-UNREVIEWED", "syn.proposed"),
    ]
    unmapped = report["findings"][4]
    assert unmapped["runs"] == ({"memory_id": "pflash", "offset": 210, "length": 1},)
    assert ("map_rules", "syn.untouched", None, "not_edited") in skipped_of(report)
    assert ("map_rules", "syn.stale", None, "definition_bind") in skipped_of(report)
    assert report["findings"][1]["incident"] is None


# SPEC-004 R31: a map is edited when a patch reaches any byte of its span, axes included; shared axes resolve.
def test_shared_axis_and_axis_edit() -> None:
    inline = InlineAxis("pflash", 96, 2, U8, Scaling(Fraction(1), Fraction(0)), "kPa_rel", None)
    axis = AxisDef("syn.axis", "SYN_AXIS", inline)
    shared = replace(MAP, x=None, y=SharedAxis("syn.axis"), rows=2, cols=2)
    base = definition()
    defn = Definition(base.family_id, base.software_version, (axis,), (shared,), base.origin, base.license, 500)
    released = Scenario(edits={96: bytes([10, 60])}).release(definition=defn)
    assert ("axis_monotonic", "syn.ign", "G-AXIS-MONOTONIC") in ran_of(released.report)
    # The shared axis resolves to its `kPa_rel` unit, so the boost cap runs instead of `axis_unit_absent`.
    assert ("physical_range", "syn.ign", "ign.si.gasoline.base.boost_cap") in ran_of(released.report)


# SPEC-004 R28: an error a step cannot attribute is `G-INVARIANT`, S1, and stops the run there.
@pytest.mark.parametrize(
    ("target", "kind"),
    [
        ("parse_rule_table", None),
        ("layout_hash", "binding"),
        ("kernel_check", "kernel_invariants"),
        ("interpret_patches", "checksum_step"),
        ("check_verify_report", "verify"),
        ("compare_verify", "dual_checksum"),
        ("decode", "map_rules"),
    ],
)
def test_faults(monkeypatch: pytest.MonkeyPatch, target: str, kind: str | None) -> None:
    s = Scenario()
    args = s.args()
    u = s.unverified()
    monkeypatch.setattr(core.gate._release, target, raises)
    with pytest.raises(GateBlocked) as blocked:
        core.gate._release.run_release(u, args, admit_all, "0")
    report = doc(blocked.value.report)
    assert "G-INVARIANT" in rule_ids(report)
    if kind is not None:
        assert (kind, None, None) in ran_of(report)


def test_input_state_fault(monkeypatch: pytest.MonkeyPatch) -> None:
    s = Scenario(original=dump_of(write(ORIGINAL, 200, b"\x00")))
    args = s.args()
    monkeypatch.setattr(core.gate._release, "acknowledgement", raises)
    with pytest.raises(GateBlocked) as blocked:
        core.gate._release.run_release(s.unverified(), args, admit_all, "0")
    report = doc(blocked.value.report)
    assert rule_ids(report) == ["G-INVARIANT"]
    assert ("input_state", None, None) in ran_of(report)
    expected = ["checksum_step", "dual_checksum", "kernel_invariants", "map_rules", "verify"]
    assert skipped_kinds(report, "earlier_block") == expected


# SPEC-004 R24: the kernel invariant step blocks with S1 and stops the run.
def test_kernel_invariant_stops(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(core.gate._release, "kernel_check", lambda *_a: KernelOutcome((), invariant=True))
    report = Scenario().blocked()
    assert rule_ids(report) == ["G-INVARIANT"]
    assert skipped_kinds(report, "earlier_block") == ["checksum_step", "dual_checksum", "map_rules", "verify"]


# SPEC-004 R82: wrong argument types are a `GateError` with a stable reason.
@pytest.mark.parametrize("field", ["original", "version", "definition", "engine", "input", "project_id"])
def test_bad_types(field: str) -> None:
    with pytest.raises(GateError) as error:
        Scenario().release(None, admit_all, **{field: None})
    assert error.value.reason == "bad_type"
    with pytest.raises(GateError):
        Scenario().release(u=cast("UnverifiedImage", object()))


# SPEC-004 R29, SPEC-001 R9: sealed, immutable, never serialized; only `release` builds one.
def test_released_image_is_sealed() -> None:
    released = Scenario().release()
    report = GateReport(released.report, released.report_hash, "no findings")
    with pytest.raises(GateError) as error:
        ReleasedImage(object(), Scenario().unverified(), report, PROJECT, export_basis(Scenario()))
    assert error.value.reason == "sealed"
    name = "_report"
    with pytest.raises(AttributeError):
        setattr(released, name, None)
    for clone in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError):
            clone(released)
    assert "no findings" in repr(released)
    assert not any(isinstance(getattr(released, a), bytes | bytearray) for a in dir(released) if not a.startswith("_"))


class _Spoof:
    """Claims a sealed class through `__class__`, which `isinstance` honours and `type` does not."""

    def __init__(self, sealed: type) -> None:
        self.sealed = sealed

    def __getattribute__(self, name: str) -> object:
        if name == "__class__":
            return object.__getattribute__(self, "sealed")
        return object.__getattribute__(self, name)


# SPEC-004 R9, R29 (revision 5): a sealed result cannot be subclassed, and the gate takes only exact instances,
# so neither a subclass nor an object claiming the class through `__class__` reaches what the gate reads.
def test_sealed_results_are_exact_types() -> None:
    for sealed in (ReleasedImage, InputResult):
        with pytest.raises(TypeError, match="sealed"):
            type("Subclass", (sealed,), {})
    spoofed_image: object = _Spoof(ReleasedImage)
    spoofed_input: object = _Spoof(InputResult)
    assert isinstance(spoofed_image, ReleasedImage)
    assert isinstance(spoofed_input, InputResult)
    for call in (
        lambda: alert_warnings(spoofed_image),
        lambda: Scenario().release(None, admit_all, input=spoofed_input),
    ):
        with pytest.raises(GateError) as error:
            call()
        assert error.value.reason == "bad_type"
