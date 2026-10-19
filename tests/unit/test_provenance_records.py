"""SPEC-005 §3 `ExportProvenance` (R10-R19) and §4 `AuditRecord` (R20-R21)."""

import dataclasses
import inspect
import json
import platform
import sys
from typing import Any

import pytest

from core.kernel import Dump, Memory, Version, apply, canonical_order, image_hash, layout_hash, version_hash
from core.provenance import (
    AuditInputs,
    AuditRecord,
    ExportInputs,
    ExportProvenance,
    ShapeError,
    audit_record,
    check_alert_ack,
    check_export_record,
    check_suspect_ack,
    export_provenance,
)
from core.provenance._records import check_gate_subject, check_kernel_fields
from tests.unit.fixtures import DUMP, EEPROM, LAYOUT, PFLASH, patch
from tests.unit.provenance_scenario import (
    CHECKSUM,
    IMAGE_BUILD,
    LOCK_BUILD,
    RELEASE_HASH,
    VERSION,
    VERSIONS,
    WARN,
    Scenario,
    gate_report,
    scenario,
    sha,
)
from tests.unit.provenance_support import _plain, add, expect, import_payload, start

VERSIONS_JSON: dict[str, Any] = json.loads(json.dumps(VERSIONS.to_json()))


def plain(record: ExportProvenance | AuditRecord) -> dict[str, Any]:
    value: dict[str, Any] = json.loads(json.dumps(_plain(record.value)))
    return value


def export(s: Scenario) -> ExportProvenance:
    return export_provenance(s.inputs, alert_ack=s.alert_ack, suspect_ack=s.suspect_ack, chain=s.chain)


# SPEC-005 R10, R12, R15, R16, R17, R18: every hash computed by the core; the hash is an independent JCS's.
def test_export_provenance_warn_suspect() -> None:
    s = scenario()
    record = export(s)
    value = plain(record)
    applied = apply(DUMP, VERSION, LAYOUT)
    assert value["schema"] == "impact.export-provenance.v1"
    assert value["image_hash_original"] == image_hash(DUMP)
    assert value["image_hash_apply"] == applied.image_hash
    assert value["image_hash_release"] == RELEASE_HASH
    assert value["layout_hash"] == layout_hash(LAYOUT) == VERSION.layout_hash
    assert value["version_hash"] == version_hash(VERSION)
    assert value["patch_hashes"] == [p.patch_hash for p in canonical_order(VERSION)]
    assert value["patch_hashes"] == [VERSION.patches[1].patch_hash, VERSION.patches[0].patch_hash]
    # R12: sorted by (memory_id, offset), not in the order given.
    assert value["checksum_patch_hashes"] == [CHECKSUM[1].patch_hash, CHECKSUM[0].patch_hash]
    assert value["versions"]["plugins"][0]["family"] == "alpha.family"
    assert [r["id"] for r in value["versions"]["references"]] == ["ref.a", "ref.b"]
    assert value["gate_report_hash"] == sha(gate_report("warn"))
    assert value["verdict"] == "warn"
    assert s.alert_ack is not None
    assert s.suspect_ack is not None
    assert value["alert_ack"] == {"event_id": s.alert_ack.event_id, "seq": s.alert_ack.seq, "hash": s.alert_ack.hash}
    assert value["input_verify"]["result"] == "failed_acknowledged"
    assert value["input_verify"]["suspect_ack"]["seq"] == s.suspect_ack.seq
    # R15: read from the running interpreter.
    assert value["python"] == {"implementation": sys.implementation.name, "version": platform.python_version()}
    assert value["build"] == {
        "kind": "image",
        "value": "sha256:" + "33" * 32,
        "platform": "linux/amd64",
        "attestation_id": "build-1",
    }
    assert value["reproducibility"] == "full"
    assert record.provenance_hash == sha(value)


# SPEC-005 R17: a lockfile build is `best_effort`.
def test_export_provenance_lockfile_is_best_effort() -> None:
    value = plain(export(scenario(warn=False, suspect=False, build=LOCK_BUILD)))
    assert value["reproducibility"] == "best_effort"
    assert value["alert_ack"] is None
    assert value["input_verify"] == {"status": "ok", "result": "ok", "suspect_ack": None}


# SPEC-005 R19: no tenant, project, actor or time; a no findings export hashes the same for any chain.
def test_record_has_no_personal_or_binding_fields() -> None:
    first = export(scenario(warn=False, suspect=False))
    other_chain = [start(tenant="tenant-b")]
    add(other_chain, "import", import_payload(image_hash(DUMP)))
    s = scenario(warn=False, suspect=False)
    second = export_provenance(s.inputs, alert_ack=None, suspect_ack=None, chain=other_chain)
    assert first.provenance_hash == second.provenance_hash
    keys = json.dumps(plain(first))
    for forbidden in ("tenant", "project", "actor", '"ts"', "vin"):
        assert forbidden not in keys


# SPEC-005 R10: the only hash a caller supplies is `definition_hash`, which R11 binds to the gate report.
def test_no_hash_accepted_from_a_caller() -> None:
    fields = {f.name for f in dataclasses.fields(ExportInputs)}
    assert {name for name in fields if "hash" in name} == {"definition_hash"}
    assert set(inspect.signature(export_provenance).parameters) == {"inputs", "alert_ack", "suspect_ack", "chain"}
    s = scenario()
    lying = dataclasses.replace(s.inputs, definition_hash="99" * 32)
    with expect("inconsistent_record"):
        export_provenance(lying, alert_ack=s.alert_ack, suspect_ack=s.suspect_ack, chain=s.chain)


# SPEC-005 R11
def test_inconsistent_kernel_fields() -> None:
    s = scenario()
    record = export(s)
    other_base = Version("00" * 32, VERSION.layout_hash, VERSION.patches)
    with expect("inconsistent_record"):
        check_kernel_fields(record, other_base)
    reordered = {**plain(record), "patch_hashes": plain(record)["patch_hashes"][::-1]}
    with expect("inconsistent_record"):
        check_kernel_fields(ExportProvenance(reordered), VERSION)
    stray = {**plain(record), "overlaps": [["ee" * 32, "ff" * 32]]}
    with expect("inconsistent_record"):
        check_kernel_fields(ExportProvenance(stray), VERSION)
    overlapping = Version(VERSION.base_image_hash, VERSION.layout_hash, (patch(10, b"\x01\x02"), patch(11, b"\x05")))
    with expect("inconsistent_record"):
        check_kernel_fields(record, overlapping)
    check_export_record(
        record, version=VERSION, gate_report=s.inputs.gate_report, input_report=s.inputs.input_report, chain=s.chain
    )


# SPEC-005 R11: the gate report's output subject.
@pytest.mark.parametrize(
    "subject",
    [{"definition_hash": "98" * 32}, {"layout_hash": "97" * 32}, {"references": []}, {"references": [1.5]}],
)
def test_inconsistent_gate_subject(subject: dict[str, Any]) -> None:
    record = export(scenario())
    with expect("inconsistent_record"):
        check_gate_subject(record, gate_report("warn", **subject))
    with expect("inconsistent_record"):
        check_gate_subject(record, {**gate_report("warn"), "verdict": "no findings"})


# SPEC-005 R10, R11: kernel rejections surface as an inconsistent record.
def test_kernel_rejection_is_inconsistent_record() -> None:
    s = scenario()
    wrong_layout = dataclasses.replace(s.inputs, checksum_patches=(patch(10, b"\x00"),))
    with expect("inconsistent_record"):
        export_provenance(wrong_layout, alert_ack=s.alert_ack, suspect_ack=s.suspect_ack, chain=s.chain)
    with expect("bad_shape", ShapeError):
        export_provenance(dataclasses.replace(s.inputs, gate_report=[1]), alert_ack=None, suspect_ack=None, chain=[])
    with expect("bad_shape", ShapeError):
        export_provenance(
            dataclasses.replace(s.inputs, gate_report={"v": 1.5}), alert_ack=None, suspect_ack=None, chain=[]
        )
    blocked = dataclasses.replace(s.inputs, gate_report=gate_report("block"))
    with expect("bad_shape", ShapeError):
        export_provenance(blocked, alert_ack=None, suspect_ack=None, chain=s.chain)


# SPEC-005 R13, R92: asserted at runtime on every export
def test_alert_ack_rules() -> None:
    s = scenario()
    with expect("missing_alert_ack"):
        export_provenance(s.inputs, alert_ack=None, suspect_ack=s.suspect_ack, chain=s.chain)
    record = export(s)
    gate = gate_report("warn")
    with expect("alert_ack_mismatch"):
        check_alert_ack(record, gate, s.chain[:-1])
    other_warning = {**gate, "findings": [WARN, {**WARN, "text": "another"}]}
    with expect("alert_ack_mismatch"):
        check_alert_ack(record, other_warning, s.chain)
    tampered = dataclasses.replace(s.chain[-1], ts="2026-10-18T13:00:00Z")
    with expect("alert_ack_mismatch"):
        check_alert_ack(record, gate, [*s.chain[:-1], tampered])
    assert s.suspect_ack is not None
    wrong_type = {**plain(record), "alert_ack": {**plain(record)["alert_ack"], "seq": s.suspect_ack.seq}}
    with expect("alert_ack_mismatch"):
        check_alert_ack(ExportProvenance(wrong_type), gate, s.chain)
    clean = scenario(warn=False)
    with expect("alert_ack_mismatch"):
        export_provenance(clean.inputs, alert_ack=s.alert_ack, suspect_ack=clean.suspect_ack, chain=s.chain)


# SPEC-005 R14, R92
def test_suspect_ack_rules() -> None:
    s = scenario()
    with expect("missing_suspect_ack"):
        export_provenance(s.inputs, alert_ack=s.alert_ack, suspect_ack=None, chain=s.chain)
    record = export(s)
    with expect("missing_suspect_ack"):
        check_suspect_ack(record, input_verdict="block", input_verify_status="bypassed", chain=s.chain)
    with expect("missing_suspect_ack"):
        check_suspect_ack(record, input_verdict="warn", input_verify_status="fail", chain=s.chain)
    other_status = {**plain(record), "input_verify": {**plain(record)["input_verify"], "status": "bypassed"}}
    with expect("missing_suspect_ack"):
        check_suspect_ack(
            ExportProvenance(other_status), input_verdict="block", input_verify_status="bypassed", chain=s.chain
        )
    accepted = scenario(suspect=False)
    with expect("missing_suspect_ack"):
        export_provenance(
            accepted.inputs, alert_ack=accepted.alert_ack, suspect_ack=s.suspect_ack, chain=accepted.chain
        )
    # `signature_unverifiable` is a green verify: not suspect, result ok.
    unverifiable = dataclasses.replace(
        accepted.inputs, input_report={"verdict": "warn", "subject": {"verify_status": "signature_unverifiable"}}
    )
    value = plain(export_provenance(unverifiable, alert_ack=accepted.alert_ack, suspect_ack=None, chain=accepted.chain))
    assert value["input_verify"] == {"status": "signature_unverifiable", "result": "ok", "suspect_ack": None}


# SPEC-005 R16, R17
@pytest.mark.parametrize(
    "build",
    [
        {"kind": "lockfile", "value": "sha256:" + "44" * 32, "platform": "linux/arm64", "attestation_id": None},
        {"kind": "lockfile", "value": "sha256:" + "44" * 32, "platform": "linux/arm64", "attestation_id": "x"},
    ],
)
def test_reproducibility_follows_build(build: dict[str, Any]) -> None:
    value = plain(export(scenario()))
    with expect("inconsistent_record"):
        ExportProvenance(
            {**value, "build": build, "reproducibility": "full" if build["attestation_id"] is None else "best_effort"}
        )
    lock = plain(export(scenario(build=LOCK_BUILD)))
    with expect("inconsistent_record"):
        ExportProvenance({**lock, "reproducibility": "full"})


# SPEC-005 R3: exactly the listed keys, each of its type, one canonical form.
@pytest.mark.parametrize(
    "change",
    [
        {"extra": None},
        {"verdict": "block"},
        {"patch_hashes": ["AB" * 32]},
        {"overlaps": [["ff" * 32, "ee" * 32], ["aa" * 32, "bb" * 32]]},
        {"overlaps": [["ff" * 32]]},
        {"versions": {**VERSIONS_JSON, "plugins": VERSIONS_JSON["plugins"][::-1]}},
        {"build": {**IMAGE_BUILD.to_json(), "value": "md5:00"}},
        {"alert_ack": {"event_id": "x", "seq": 0, "hash": "00" * 32}},
        {"dump_kind": "flash"},
        {"versions": {**VERSIONS_JSON, "plugins": "alpha.family"}},
    ],
)
def test_record_shape(change: dict[str, Any]) -> None:
    value = {**plain(export(scenario())), **change}
    with expect("bad_shape", ShapeError):
        ExportProvenance(value)
    without = {k: v for k, v in plain(export(scenario())).items() if k != "python"}
    with expect("bad_shape", ShapeError):
        ExportProvenance(without)


def candidate(pflash: bytes = PFLASH, eeprom: bytes = EEPROM) -> Dump:
    return Dump("bench_full", (Memory("pflash", 0x8000_0000, pflash), Memory("eeprom", 0x0, eeprom)))


def audit_inputs() -> AuditInputs:
    edited = bytearray(PFLASH)
    edited[2] = 0xEE  # protected
    edited[12] = 0x44  # calibration
    edited[30] = 0x55  # checksum
    return AuditInputs(
        original=DUMP,
        candidate=candidate(bytes(edited)),
        candidate_origin="file_service",
        layout=LAYOUT,
        verify_original="ok",
        verify_candidate="bypassed",
        versions=VERSIONS,
        gate_report=gate_report("no findings"),
        build=IMAGE_BUILD,
    )


# SPEC-005 R20, R21: hashes and lists from `diff`; `audit_hash` is an independent JCS's.
def test_audit_record() -> None:
    inputs = audit_inputs()
    record = audit_record(inputs)
    value = plain(record)
    assert value["schema"] == "impact.audit-record.v1"
    assert value["image_hash_candidate"] == image_hash(inputs.candidate)
    assert len(value["diff_patch_hashes"]) == 1
    assert [(f["offset"], f["region_kind"], f["region_name"]) for f in value["foreign"]] == [
        (2, "protected", "boot"),
        (30, "checksum", "crc"),
    ]
    assert value["verify"] == {"original": "ok", "candidate": "bypassed"}
    assert value["versions"] == VERSIONS_JSON
    assert value["python"]["implementation"] == sys.implementation.name
    assert record.audit_hash == sha(value)


def test_audit_record_rejections() -> None:
    without_references = plain(audit_record(audit_inputs()))
    without_references["versions"] = {k: v for k, v in VERSIONS_JSON.items() if k != "references"}
    with expect("bad_shape", ShapeError):
        AuditRecord(without_references)
    short = Dump("bench_full", (Memory("pflash", 0x8000_0000, PFLASH),))
    with expect("inconsistent_record"):
        audit_record(dataclasses.replace(audit_inputs(), candidate=short))
    with expect("bad_shape", ShapeError):
        audit_record(dataclasses.replace(audit_inputs(), candidate_origin="partner"))
    with expect("bad_shape", ShapeError):
        AuditRecord({**plain(audit_record(audit_inputs())), "foreign": [{"memory_id": "pflash"}]})
