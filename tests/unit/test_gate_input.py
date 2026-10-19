"""SPEC-004 §3: the input gate on a real (synthetic) plugin, and the sealed `InputResult` (R9)."""

import copy
import pickle
from dataclasses import replace
from typing import Any, cast

import pytest

import core.gate._check
from core.gate import GateError, InputResult, check_input
from core.gate._report import GateReport
from core.kernel import Dump, Memory, image_hash
from core.plugins import Identification, RegionResult, VerifyReport, identification_hash
from core.provenance import Event
from tests.unit.gate_support import (
    CONFORMANCE,
    TABLE,
    Overridden,
    SignedPlugin,
    admit_all,
    check,
    doc,
    event,
    input_args,
    raises,
    ran_of,
    rule_ids,
    sha,
    skipped_of,
    write,
)
from tests.unit.plugin_fixtures import DUMP, IDENT, ORIGINAL, FakePlugin, dump_of

ALL_TESTED = [("identify", None, None), ("input_hash", None, None), ("input_verify", None, None)]


def confirmation(**override: object) -> Event:
    payload = {
        "artifact_sha256": sha(ORIGINAL),
        "image_hash": image_hash(DUMP),
        "family": IDENT.family,
        "plugin_version": "1.0.0",
        "hw_id": IDENT.hw_id,
        "sw_id": IDENT.sw_id,
        "checksum_variant_id": IDENT.checksum_variant_id,
    }
    project_id = str(override.pop("project_id", "proj-1"))
    return event("identification_confirmed", {**payload, **override}, event_id="a" * 32, project_id=project_id)


# SPEC-004 R10-R15: an intact, identified, admitted original is accepted; the identification is the gate's own.
def test_accepted() -> None:
    result = check(DUMP)
    report = doc(result.report)
    assert result.artifact_state == "accepted"
    assert report["verdict"] == "no findings"
    assert report["stage"] == "input"
    assert ran_of(report) == ALL_TESTED
    assert skipped_of(report) == []
    assert result.identification is not None
    subject = report["subject"]
    assert subject["identification_hash"] == identification_hash(result.identification)
    assert subject["confidence"] == 900
    assert subject["verify_status"] == "ok"
    assert subject["plugin"] == {"family": "synthetic.fixture", "version": "1.0.0"}
    assert subject["image_hash"] == image_hash(DUMP)
    assert report["gate"]["core_version"] == "9.9.9"


# SPEC-004 R11: lowercase-hex comparison; any difference blocks; hashes that are not hex never match.
@pytest.mark.parametrize(
    ("declared", "blocked"),
    [(sha(ORIGINAL).upper(), False), (sha(b"other"), True), ("not hex", True)],
)
def test_input_hash(declared: str, blocked: bool) -> None:
    report = doc(check(DUMP, declared_sha256=declared).report)
    assert ("G-INPUT-HASH" in rule_ids(report)) is blocked
    assert report["subject"]["declared_sha256"] == declared


# SPEC-004 R12: confidence must exceed the threshold, or a matching confirmation must confirm it.
def test_identify_threshold_and_confirmation() -> None:
    strict = {**TABLE, "identify_min_confidence": 900}
    report = doc(check(DUMP, rule_table=strict).report)
    assert rule_ids(report) == ["G-INPUT-IDENTIFY"]
    assert skipped_of(report) == [("input_verify", None, None, "identify_failed")]
    assert report["subject"]["verify_status"] is None
    confirmed = doc(check(DUMP, rule_table=strict, confirmation=confirmation()).report)
    assert confirmed["verdict"] == "no findings"
    assert confirmed["subject"]["identify_confirmation_event_id"] == "a" * 32
    for ignored in (
        confirmation(sw_id="other"),
        confirmation(project_id="proj-2"),
        confirmation(plugin_version="2.0.0"),
        event(
            "suspect_ack",
            {
                "artifact_sha256": sha(ORIGINAL),
                "image_hash": "0" * 64,
                "input_report_hash": "0" * 64,
                "verify_status": "ok",
            },
        ),
    ):
        assert rule_ids(check(DUMP, rule_table=strict, confirmation=ignored).report) == ["G-INPUT-IDENTIFY"]
    # Above the threshold the confirmation is not used, so it is not recorded.
    assert doc(check(DUMP, confirmation=confirmation()).report)["subject"]["identify_confirmation_event_id"] is None


# SPEC-004 R12: `identify` returning None is an identification failure.
def test_not_this_family() -> None:
    small = Dump("bench_full", (Memory("pflash", 0x8000_0000, ORIGINAL[:256]),))
    report = doc(check(small).report)
    assert rule_ids(report) == ["G-INPUT-IDENTIFY"]
    assert report["subject"]["identification_hash"] is None
    assert report["subject"]["confidence"] is None


# SPEC-004 R13, R14: a failing input verify blocks and marks the artifact suspect.
def test_input_verify_fail() -> None:
    result = check(dump_of(write(ORIGINAL, 80, b"\x00")))
    assert result.artifact_state == "suspect"
    assert [f["text"] for f in doc(result.report)["findings"]] == ["input verify returned fail"]
    assert doc(result.report)["subject"]["verify_status"] == "fail"


# SPEC-004 R6, R13: a signed region warns and is recorded in `signed_regions`.
def test_signed_input_warns() -> None:
    result = check(DUMP, plugin=SignedPlugin())
    assert rule_ids(result.report) == ["G-INPUT-SIGNED"]
    assert result.artifact_state == "accepted"
    assert doc(result.report)["subject"]["signed_regions"] == ({"memory_id": "pflash", "name": "z_sig"},)


# SPEC-004 R15, R16: without field evidence (the default seam) or conformance admission the variant is unknown.
def test_variant_not_admitted() -> None:
    args = input_args(DUMP)
    public = check_input(DUMP, **args)
    assert [f["text"] for f in doc(public.report)["findings"]] == ["input verify returned not_applicable"]
    assert doc(public.report)["subject"]["verify_status"] == "not_applicable"
    unlisted = {**CONFORMANCE, "variants": [{"checksum_variant_id": "other", "admitted": True}]}
    assert rule_ids(check(DUMP, conformance_report=unlisted).report) == ["G-INPUT-VERIFY"]
    unknown = Overridden(replaced={"identify": lambda _d: replace(IDENT, checksum_variant_id=None)})
    report = doc(check(DUMP, plugin=unknown).report)
    assert report["subject"]["verify_status"] == "not_applicable"
    assert report["subject"]["checksum_variant_id"] is None


# SPEC-004 R10, R21: an unavailable rule table blocks; identify and verify are not tested.
@pytest.mark.parametrize("table", [None, {"rules": []}])
def test_rules_unavailable(table: object) -> None:
    report = doc(check(DUMP, rule_table=table).report)
    assert rule_ids(report) == ["G-UNAVAILABLE-RULES"]
    assert skipped_of(report) == [
        ("identify", None, None, "gate_unavailable"),
        ("input_verify", None, None, "gate_unavailable"),
    ]
    assert report["gate"]["rule_table"] is None
    assert report["subject"]["identification_hash"] is not None


BAD_CONFORMANCE = [
    None,
    {**CONFORMANCE, "verdict": "not_conformant"},
    {**CONFORMANCE, "plugin": {"family": "synthetic.fixture", "version": "2.0.0"}},
    {**CONFORMANCE, "variants": [{"checksum_variant_id": "fixture-512", "admitted": "yes"}]},
    {**CONFORMANCE, "extra": 0.5},
]


# SPEC-004 R10, R12, R15: no plugin, a broken plugin, no matching conformance report or a raising identify.
@pytest.mark.parametrize(
    ("overrides", "recorded"),
    [
        ({"plugin": None}, False),
        ({"plugin": FakePlugin(contract_version=2)}, False),
        ({"plugin": Overridden(replaced={"identify": raises})}, True),
        *(({"conformance_report": report}, True) for report in BAD_CONFORMANCE),
    ],
)
def test_plugin_unavailable(overrides: dict[str, Any], recorded: bool) -> None:
    report = doc(check(DUMP, **overrides).report)
    assert rule_ids(report) == ["G-UNAVAILABLE-PLUGIN"]
    assert report["subject"]["conformance_report_hash"] is None
    assert report["subject"]["identification_hash"] is None
    assert ("identify", None, None, "gate_unavailable") in skipped_of(report)
    assert (report["subject"]["plugin"] is not None) is recorded


def wrong_status(dump: Dump, ident: Identification) -> VerifyReport:
    report = FakePlugin().verify(dump, ident)
    return VerifyReport("bypassed", None, report.regions)


# SPEC-004 R12, R13: a plugin output that breaks SPEC-002 is `G-PLUGIN-ERROR`, block.
@pytest.mark.parametrize(
    "replaced",
    [
        {"layout": raises},
        {"checksums": raises},
        {"verify": raises},
        {"verify": lambda _d, _i: "ok"},
        {"verify": wrong_status},
    ],
)
def test_plugin_error_at_verify(replaced: dict[str, Any]) -> None:
    report = doc(check(DUMP, plugin=Overridden(replaced=replaced)).report)
    assert rule_ids(report) == ["G-PLUGIN-ERROR"]
    assert report["subject"]["verify_status"] is None
    assert ran_of(report) == ALL_TESTED


def test_plugin_error_at_identify() -> None:
    report = doc(check(DUMP, plugin=Overridden(replaced={"identify": lambda _d: "fixture"})).report)
    assert rule_ids(report) == ["G-PLUGIN-ERROR"]
    assert skipped_of(report) == [("input_verify", None, None, "identify_failed")]
    assert ("identify", None, None) in ran_of(report)


def disagreeing(dump: Dump, ident: Identification) -> VerifyReport:
    report = FakePlugin().verify(dump, ident)
    first = report.regions[0]
    wrong = RegionResult(first.name, first.memory_id, first.kind, "ok", "00", "00", None, None)
    return VerifyReport(report.status, None, (wrong, *report.regions[1:]))


# SPEC-004 R13: the plugin disagreeing with the core interpreter is `G-DUAL-DIVERGENCE`, S1.
def test_input_divergence() -> None:
    report = doc(check(DUMP, plugin=Overridden(replaced={"verify": disagreeing})).report)
    assert rule_ids(report) == ["G-DUAL-DIVERGENCE"]
    assert report["findings"][0]["incident"] == "S1"
    assert report["subject"]["verify_status"] == "ok"


# SPEC-004 R28 at the input stage: an error the gate cannot attribute is `G-INVARIANT`, S1.
def test_input_faults(monkeypatch: pytest.MonkeyPatch) -> None:
    with monkeypatch.context() as patch:
        patch.setattr(core.gate._check, "parse_rule_table", raises)
        report = doc(check(DUMP).report)
        assert rule_ids(report) == ["G-INVARIANT"]
        assert skipped_of(report) == [
            ("identify", None, None, "earlier_block"),
            ("input_verify", None, None, "earlier_block"),
        ]
    with monkeypatch.context() as patch:
        patch.setattr(core.gate._check, "compare_verify", raises)
        report = doc(check(DUMP).report)
        assert rule_ids(report) == ["G-INVARIANT"]
        assert report["findings"][0]["incident"] == "S1"


# SPEC-004 R82: wrong argument types are a `GateError` with a stable reason.
def test_bad_types() -> None:
    with pytest.raises(GateError) as error:
        core.gate._check.run_check_input(cast("Dump", ORIGINAL), input_args(DUMP), admit_all, "0")
    assert error.value.reason == "bad_type"
    with pytest.raises(GateError):
        check(DUMP, received_sha256=None)


# SPEC-004 R9: sealed, immutable, not copyable or serializable.
def test_input_result_is_sealed() -> None:
    result = check(DUMP)
    with pytest.raises(GateError) as error:
        InputResult(object(), GateReport({}, "0" * 64, "no findings"), "accepted", None)
    assert error.value.reason == "sealed"
    name = "_report"
    with pytest.raises(AttributeError):
        setattr(result, name, None)
    with pytest.raises(AttributeError):
        delattr(result, name)
    for clone in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError):
            clone(result)
    assert "accepted" in repr(result)
    with pytest.raises(TypeError):
        cast("dict[str, object]", result.report)["verdict"] = "no findings"
