"""SPEC-005 §8: the customer report (R60-R63), its signature (R51) and its binding (R61)."""

import dataclasses
import hashlib
import json
from typing import Any

import pytest
import rfc8785

from core.kernel import Version, image_hash
from core.provenance import (
    DISCLAIMER,
    Event,
    ExportInputs,
    Report,
    ReportBindingError,
    ReportContext,
    ShapeError,
    SignatureError,
    audit_record,
    audit_report,
    check_report_file,
    export_report,
    issue_report,
)
from tests.unit.fixtures import DUMP, patch
from tests.unit.provenance_scenario import LOCK_BUILD, VERSION, Scenario, gate_report, scenario, sha
from tests.unit.provenance_support import (
    CLI,
    OTHER,
    SERVER,
    VERIFIER,
    _plain,
    add,
    expect,
    import_payload,
    meta,
    raw,
    start,
)
from tests.unit.test_provenance_records import audit_inputs, export

CONTEXT = ReportContext("tenant-a", "aa" * 32, SERVER.public_key)
MAP_IDS: dict[str, str | None] = {VERSION.patches[0].patch_hash: "map.boost"}


def plain(value: object) -> dict[str, Any]:
    result: dict[str, Any] = json.loads(json.dumps(_plain(value)))
    return result


def build_export(s: Scenario, import_event: Event | None = None, inputs: ExportInputs | None = None) -> Report:
    record = export(s)
    event = import_event if import_event is not None else s.chain[1]
    return export_report(CONTEXT, inputs or s.inputs, record, map_ids=MAP_IDS, import_event=event)


# SPEC-005 R60, R62, R63: sections from the record, the version, the gate report and the import event only.
def test_export_report_sections() -> None:
    s = scenario()
    report = build_export(s)
    value = plain(report.value)
    assert value["schema"] == "impact.report.v1"
    assert value["kind"] == "export" == report.kind
    assert value["signer"] == {"key_id": SERVER.key_id, "public_key": SERVER.public_key}
    assert value["record_hash"] == export(s).provenance_hash
    # Canonical order: offset 10 before offset 16; `map_id` from the version metadata, `region_name` from the layout.
    assert value["sections"]["what_changed"] == {
        "patches": [
            {"memory_id": "pflash", "offset": 10, "length": 1, "region_name": "maps", "map_id": None},
            {"memory_id": "pflash", "offset": 16, "length": 2, "region_name": "maps", "map_id": "map.boost"},
        ],
        "foreign": [],
    }
    assert value["sections"]["integrity"] == {
        "input_verify": "fail",
        "input_result": "failed_acknowledged",
        "candidate_verify": None,
        "verdict": "warn",
        "reproducibility": "full",
        "checksum_patch_count": 2,
    }
    assert value["sections"]["not_verified"] == ["firmware_behavior", "map_interaction", "real_engine"]
    assert value["notices"] == ["emissions_and_regulation", "input_verify_failed_acknowledged"]
    assert value["disclaimer"] == DISCLAIMER
    assert DISCLAIMER == (
        "This gate verifies file integrity and cell-by-cell plausibility. It does not verify the combination "
        "between maps, firmware behavior, or the real engine."
    )
    assert report.report_hash == hashlib.sha256(rfc8785.dumps(value)).hexdigest()


# SPEC-005 R63: every conditional code, each from its own input.
def test_report_codes() -> None:
    unreviewed = {"rule_id": "G-UNREVIEWED", "severity": "warn", "text": "t"}
    gate = gate_report("no findings", signed_regions=[{"memory_id": "pflash", "name": "sig"}])
    gate = {**gate, "findings": [unreviewed], "verdict": "no findings"}
    s = scenario(warn=False, suspect=False, build=LOCK_BUILD)
    s.inputs = dataclasses.replace(s.inputs, gate_report=gate)
    chain = [start()]
    virtual = add(chain, "import", import_payload(image_hash(DUMP), origin="virtual_read"))
    s.chain = chain
    report = build_export(s, import_event=virtual)
    value = plain(report.value)
    assert value["sections"]["not_verified"] == [
        "best_effort_build",
        "firmware_behavior",
        "map_interaction",
        "physical_range_unreviewed",
        "real_engine",
        "signature_unverifiable",
    ]
    assert value["notices"] == ["emissions_and_regulation", "origin_not_evidence"]
    assert value["sections"]["integrity"]["input_result"] == "ok"
    assert value["sections"]["integrity"]["verdict"] == "no findings"


# SPEC-005 R62: the report is built from the record's own inputs or not at all.
def test_export_report_rejects_other_inputs() -> None:
    s = scenario()
    with expect("inconsistent_record"):
        build_export(
            s,
            inputs=dataclasses.replace(
                s.inputs, version=Version(VERSION.base_image_hash, VERSION.layout_hash, VERSION.patches[:1])
            ),
        )
    overlapping = Version(VERSION.base_image_hash, VERSION.layout_hash, (patch(10, b"\x01\x02"), patch(11, b"\x05")))
    with expect("inconsistent_record"):
        build_export(s, inputs=dataclasses.replace(s.inputs, version=overlapping))
    with expect("inconsistent_record"):
        build_export(s, inputs=dataclasses.replace(s.inputs, gate_report=gate_report("warn", layout_hash="00" * 32)))
    with expect("inconsistent_record"):
        build_export(s, import_event=s.chain[2])
    other = [start()]
    with expect("inconsistent_record"):
        build_export(s, import_event=add(other, "import", import_payload("cc" * 32)))
    with expect("bad_shape", ShapeError):
        export_report(
            dataclasses.replace(CONTEXT, signer_public_key="xy"),
            s.inputs,
            export(s),
            map_ids={},
            import_event=s.chain[1],
        )


# SPEC-005 R22, R62, R63 for an audit.
def test_audit_report() -> None:
    inputs = audit_inputs()
    record = audit_record(inputs)
    report = audit_report(CONTEXT, inputs, record, map_ids={})
    value = plain(report.value)
    assert report.kind == "audit"
    assert value["record_hash"] == record.audit_hash
    assert value["sections"]["what_changed"]["patches"] == [
        {"memory_id": "pflash", "offset": 12, "length": 1, "region_name": "maps", "map_id": None}
    ]
    assert value["sections"]["what_changed"]["foreign"] == plain(record.value)["foreign"]
    assert value["sections"]["integrity"] == {
        "input_verify": "ok",
        "input_result": "ok",
        "candidate_verify": "bypassed",
        "verdict": None,
        "reproducibility": "full",
        "checksum_patch_count": 0,
    }
    assert value["notices"] == ["emissions_and_regulation", "origin_not_evidence"]
    failing = dataclasses.replace(audit_inputs(), verify_original="fail", candidate_origin="bench_read")
    failing_value = plain(audit_report(CONTEXT, failing, audit_record(failing), map_ids={}).value)
    assert failing_value["sections"]["integrity"]["input_result"] == "failed_acknowledged"
    assert failing_value["notices"] == ["emissions_and_regulation"]


def test_audit_report_rejects_other_inputs() -> None:
    inputs = audit_inputs()
    record = audit_record(inputs)
    with expect("inconsistent_record"):
        audit_report(CONTEXT, dataclasses.replace(inputs, candidate=inputs.original), record, map_ids={})
    with expect("inconsistent_record"):
        audit_report(CONTEXT, dataclasses.replace(inputs, gate_report=gate_report("warn")), record, map_ids={})
    short = dataclasses.replace(
        inputs, candidate=dataclasses.replace(inputs.candidate, memories=inputs.candidate.memories[:1])
    )
    with expect("inconsistent_record"):
        audit_report(CONTEXT, short, record, map_ids={})


# SPEC-005 R3: a report has exactly its form; the record is checked as its kind.
@pytest.mark.parametrize(
    "change",
    [
        {"notices": ["origin_not_evidence", "emissions_and_regulation"]},
        {"notices": ["new_code"]},
        {"disclaimer": "This gate verifies everything."},
        {"kind": "audit"},
        {"record": {}},
        {"extra": 1},
    ],
)
def test_report_shape(change: dict[str, Any]) -> None:
    value = {**plain(build_export(scenario()).value), **change}
    with pytest.raises(ShapeError) as caught:
        Report(value)
    assert caught.value.reason == "bad_shape"


def issued(s: Scenario | None = None) -> tuple[Any, list[Event]]:
    s = s or scenario()
    report = build_export(s)
    report_file = issue_report(report, head=s.chain[-1], meta=meta(90), signer=SERVER)
    return plain(report_file.to_json()), [*s.chain, report_file.event]


# SPEC-005 R51, R60, R61: issue, then check with an independent recomputation of the signed message.
def test_issue_and_check_report_file() -> None:
    value, chain = issued()
    checked = check_report_file(value, VERIFIER)
    assert checked.report_hash == sha(value["report"])
    event = value["event"]
    assert event["type"] == "export"
    assert event["seq"] == chain[-2].seq + 1
    assert event["payload"]["provenance_hash"] == value["report"]["record_hash"]
    message = rfc8785.dumps({"domain": "impact.report-signature.v1", "hash": value["report_hash"]})
    assert VERIFIER.verify(bytes.fromhex(SERVER.public_key), message, bytes.fromhex(event["payload"]["signature"]))
    inputs = audit_inputs()
    audit = audit_report(CONTEXT, inputs, audit_record(inputs), map_ids={})
    audit_file = issue_report(audit, head=chain[-1], meta=meta(91), signer=SERVER)
    assert audit_file.event.type == "audit"
    assert check_report_file(plain(audit_file.to_json()), VERIFIER).report.kind == "audit"


def test_issue_report_rejections() -> None:
    s = scenario()
    report = build_export(s)
    with pytest.raises(ReportBindingError) as wrong_key:
        issue_report(report, head=s.chain[-1], meta=meta(90), signer=OTHER)
    assert wrong_key.value.reasons == ("key_id_mismatch",)
    with pytest.raises(ReportBindingError) as wrong_tenant:
        issue_report(report, head=start(tenant="tenant-b"), meta=meta(90), signer=SERVER)
    assert wrong_tenant.value.reason == "event_mismatch"

    class ShortSigner:
        key_id = SERVER.key_id

        def sign(self, message: bytes) -> bytes:
            return SERVER.sign(message)[:63]

    with pytest.raises(SignatureError) as short:
        issue_report(report, head=s.chain[-1], meta=meta(90), signer=ShortSigner())
    assert short.value.reason == "bad_signature"


def _rehash(event: dict[str, Any]) -> None:
    event["hash"] = hashlib.sha256(rfc8785.dumps({k: v for k, v in event.items() if k != "hash"})).hexdigest()


# SPEC-005 R61: every reason, each with its own defect.
def test_check_report_file_reasons() -> None:
    value, _ = issued()

    def reasons(mutated: dict[str, Any]) -> tuple[str, ...]:
        with pytest.raises(ReportBindingError) as caught:
            check_report_file(mutated, VERIFIER)
        return caught.value.reasons

    tampered = json.loads(json.dumps(value))
    tampered["report_hash"] = "00" * 32
    assert reasons(tampered) == ("bad_signature", "event_mismatch", "report_hash_mismatch")
    tampered = json.loads(json.dumps(value))
    tampered["report"]["record_hash"] = "00" * 32
    assert "record_hash_mismatch" in reasons(tampered)
    tampered = json.loads(json.dumps(value))
    tampered["report"]["signer"]["key_id"] = CLI.key_id
    assert "key_id_mismatch" in reasons(tampered)
    tampered = json.loads(json.dumps(value))
    tampered["event"]["tenant_id"] = "tenant-b"
    _rehash(tampered["event"])
    assert reasons(tampered) == ("event_mismatch",)
    tampered = json.loads(json.dumps(value))
    tampered["event"]["ts"] = "2027-01-01T00:00:00Z"
    assert reasons(tampered) == ("event_mismatch",)
    tampered = json.loads(json.dumps(value))
    signature = tampered["event"]["payload"]["signature"]
    tampered["event"]["payload"]["signature"] = ("1" if signature[0] == "0" else "0") + signature[1:]
    _rehash(tampered["event"])
    assert reasons(tampered) == ("bad_signature",)
    tampered = json.loads(json.dumps(value))
    tampered["event"]["type"] = "audit"
    tampered["event"]["payload"] = {
        "audit_hash": value["report"]["record_hash"],
        **{k: v for k, v in value["event"]["payload"].items() if k != "provenance_hash"},
    }
    _rehash(tampered["event"])
    assert reasons(tampered) == ("event_mismatch",)
    tampered = json.loads(json.dumps(value))
    tampered["event"] = raw([start()])[0]
    assert reasons(tampered) == ("bad_signature", "event_mismatch")


def test_check_report_file_shape() -> None:
    value, _ = issued()
    for broken in ({**value, "extra": 1}, {**value, "report": [1]}, "report", {**value, "report_hash": "x"}):
        with pytest.raises(ShapeError) as caught:
            check_report_file(broken, VERIFIER)
        assert caught.value.reason == "bad_shape"
    with pytest.raises(ShapeError):
        check_report_file({**value, "event": {**value["event"], "extra": 1}}, VERIFIER)
