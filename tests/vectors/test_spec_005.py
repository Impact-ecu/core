"""SPEC-005 §12: every value in specs/vectors/spec-005/vectors.json, against `core.provenance`.

Expected values come from generate.py (third-party rfc8785 and cryptography, hand-written tamper findings) and are
cross-checked by crosscheck.py; nothing here is computed by the core and then compared with itself. Chain checks run
with `test_mode = True` except T10 (SPEC-005 R56).
"""

import copy
import hashlib
import importlib.metadata
import json
import re
from itertools import pairwise
from typing import Any

import pytest
import rfc8785

from core.kernel import (
    Dump,
    Memory,
    Version,
    apply,
    apply_checksum_patches,
    canonical_json,
    diff,
    image_hash,
    version_hash,
)
from core.provenance import (
    AuditRecord,
    Build,
    EventMeta,
    ExportInputs,
    ExportProvenance,
    ReportBindingError,
    ReportContext,
    check_alert_ack,
    check_report_file,
    check_suspect_ack,
    commitment,
    event_hash,
    export_report,
    issue_report,
    make_anchor,
    parse_anchor,
    parse_event,
    verify_chain,
)
from core.provenance import Versions as VersionsInfo
from core.provenance._json import signing_input, try_hash
from core.provenance._records import check_kernel_fields
from core.provenance._signing import ANCHOR_DOMAIN, REPORT_DOMAIN, TEST_KEY_IDS, key_id_of
from tests.unit.provenance_support import ROOT, SPEC005, SPEC006, TEST_SIGNER, VERIFIER, Ed25519Signer, _plain, raw
from tests.vectors.test_spec_001 import BASE, ORIGINAL, PATCHES
from tests.vectors.test_spec_001 import VECTORS as SPEC001

V = SPEC005
CHAIN_RAW: list[Any] = [entry["event"] for entry in V["chain"]["events"]]
CHAIN = [parse_event(event) for event in CHAIN_RAW]
ANCHOR = parse_anchor(V["anchor"]["value"])
V4 = Version(image_hash(ORIGINAL), V["spec001_inputs"]["layout_hash"], (PATCHES["P1"], PATCHES["P2"]))


def jcs(value: dict[str, Any]) -> str:
    return canonical_json(value).decode("utf-8")


# SPEC-005 §12 generator block: the SPEC-001 input file and the third-party versions it was made with.
def test_generator() -> None:
    generator = V["generator"]
    spec001_bytes = (ROOT / "specs" / "vectors" / "spec-001" / "vectors.json").read_bytes()
    assert generator["spec001_vectors_sha256"] == hashlib.sha256(spec001_bytes).hexdigest()
    assert generator["jcs"] == f"rfc8785 {importlib.metadata.version('rfc8785')}"
    assert generator["ed25519"] == f"cryptography {importlib.metadata.version('cryptography')}"
    assert generator["sha256"] == "python hashlib"
    assert re.fullmatch(r"3\.\d+\.\d+", generator["python"])


# SPEC-005 R1: SPEC-001 hashes are reused, never recomputed another way.
def test_spec001_inputs() -> None:
    inputs = V["spec001_inputs"]
    applied = apply(ORIGINAL, V4, BASE)
    assert inputs["image_hash_original"] == image_hash(ORIGINAL) == SPEC001["original"]["image_hash"]
    assert inputs["image_hash_apply"] == applied.image_hash
    assert inputs["image_hash_release"] == apply_checksum_patches(applied, [PATCHES["Q1"]], BASE).image_hash
    assert inputs["layout_hash"] == SPEC001["layouts"]["base"]["layout_hash"]
    assert inputs["version_hash"] == version_hash(V4)
    assert inputs["patch_hashes"] == {name: PATCHES[name].patch_hash for name in ("P1", "P2", "Q1")}
    assert inputs["from"] == [
        "original",
        "layouts.base",
        "patches",
        "V4-apply-disjoint",
        "V9-checksum-patch",
        "V8-diff-reports-foreign-changes",
    ]


# SPEC-005 R50, R56
def test_key() -> None:
    key = V["key"]
    assert key["rules"] == ["R50"]
    assert key["seed_hex"] == hashlib.sha256(key["seed_text"].encode()).hexdigest()
    assert TEST_SIGNER.public_key == key["public_key"]
    assert key_id_of(key["public_key"]) == key["key_id"] == hashlib.sha256(bytes.fromhex(key["public_key"])).hexdigest()
    second = Ed25519Signer(hashlib.sha256(key["second_seed_text"].encode()).digest())
    assert second.public_key == key["second_public_key"]
    assert key_id_of(key["second_public_key"]) == key["second_key_id"]
    # R56: the core's test-key set is exactly the SPEC-005 key and the SPEC-006 keys.
    assert {key["key_id"]} | {k["key_id"] for k in SPEC006["keys"]["keys"].values()} == TEST_KEY_IDS


# SPEC-005 R1 (gate report placeholders and SPEC-004 R43 finding ids)
def test_gate_report_placeholders() -> None:
    gate = V["gate_report"]
    assert try_hash(gate["value"]) == gate["gate_report_hash"]
    assert [try_hash(f) for f in gate["value"]["findings"]] == gate["finding_ids"]
    assert try_hash(V["gate_report_no_findings"]["value"]) == V["gate_report_no_findings"]["gate_report_hash"]
    assert try_hash(V["input_report"]["value"]) == V["input_report"]["input_report_hash"]


# SPEC-005 R2, R5, R30, R31, R32, R33, R35, R36
def test_chain_events() -> None:
    assert V["chain"]["rules"] == ["R2", "R5", "R30", "R31", "R32", "R33", "R35", "R36"]
    for entry, event in zip(V["chain"]["events"], CHAIN, strict=True):
        assert raw([event])[0] == entry["event"]
        body = {k: v for k, v in entry["event"].items() if k != "hash"}
        assert jcs(body) == entry["jcs_without_hash"]
        assert event_hash(event.to_json()) == entry["hash"] == event.hash
    assert [e.seq for e in CHAIN] == [0, 1, 2, 3, 4]
    assert all(b.prev_hash == a.hash for a, b in pairwise(CHAIN))


# SPEC-005 R40, R42: the vector chain verifies intact with its anchor.
def test_chain_verifies_with_anchor() -> None:
    assert V["chain"]["test_mode"] is True
    report = verify_chain(CHAIN_RAW, [ANCHOR], VERIFIER, test_mode=True)
    assert report.status == "intact"
    assert report.findings == ()
    assert report.genesis_hash == CHAIN[0].hash
    assert report.signer_key_id == V["key"]["key_id"]
    assert report.head is not None
    assert (report.head.seq, report.head.hash) == (4, CHAIN[4].hash)
    assert report.anchored_through == 4


def _record(name: str) -> ExportProvenance:
    vector = V[name]
    record = ExportProvenance(vector["value"])
    assert record.provenance_hash == vector["provenance_hash"]
    assert jcs(vector["value"]) == vector["jcs"]
    assert raw_value(record) == vector["value"]
    return record


def raw_value(record: ExportProvenance | AuditRecord) -> dict[str, Any]:
    value: dict[str, Any] = json.loads(json.dumps(_plain(record.value)))
    return value


# SPEC-005 R10, R11, R12, R13, R14, R16, R17, R18
def test_provenance_warn_suspect() -> None:
    record = _record("provenance")
    value = V["provenance"]["value"]
    assert V["provenance"]["rules"] == ["R10", "R11", "R12", "R13", "R14", "R16", "R17", "R18"]
    check_kernel_fields(record, V4)
    applied = apply(ORIGINAL, V4, BASE)
    assert value["image_hash_apply"] == applied.image_hash
    assert value["image_hash_release"] == apply_checksum_patches(applied, [PATCHES["Q1"]], BASE).image_hash
    assert value["checksum_patch_hashes"] == [PATCHES["Q1"].patch_hash]
    check_alert_ack(record, V["gate_report"]["value"], CHAIN)
    # The placeholder input report has no SPEC-004 subject; its only finding says the verify status.
    assert V["input_report"]["value"]["findings"][0]["text"] == "input verify returned fail"
    check_suspect_ack(record, input_verdict="block", input_verify_status="fail", chain=CHAIN)
    assert value["reproducibility"] == "full"
    assert value["build"]["kind"] == "image"


# SPEC-005 R11, R13, R14, R18
def test_provenance_no_findings() -> None:
    record = _record("provenance_no_findings")
    assert V["provenance_no_findings"]["rules"] == ["R11", "R13", "R14", "R18"]
    check_kernel_fields(record, V4)
    check_alert_ack(record, V["gate_report_no_findings"]["value"], CHAIN)
    check_suspect_ack(record, input_verdict="no findings", input_verify_status="ok", chain=CHAIN)
    assert record.value["alert_ack"] is None


# SPEC-005 R16, R17, R18
def test_provenance_lockfile() -> None:
    assert _record("provenance_lockfile").value["reproducibility"] == "best_effort"
    assert V["provenance_lockfile"]["rules"] == ["R16", "R17", "R18"]
    assert V["provenance_lockfile"]["value"]["reproducibility"] == "best_effort"
    assert V["provenance_lockfile"]["value"]["build"]["attestation_id"] is None


def _report_inputs() -> ExportInputs:
    return ExportInputs(
        original=ORIGINAL,
        version=V4,
        layout=BASE,
        checksum_patches=(PATCHES["Q1"],),
        definition_hash="00" * 32,
        versions=VersionsInfo("0.0.0-synthetic", (), "0.0.0-synthetic"),
        gate_report=V["gate_report"]["value"],
        input_report=V["input_report"]["value"],
        build=Build("image", "sha256:" + "00" * 32, "linux/amd64", None),
    )


# SPEC-005 R51, R60, R61, R62, R63
def test_report_file() -> None:
    vector = V["report_file"]
    assert vector["rules"] == ["R51", "R60", "R61", "R62", "R63"]
    checked = check_report_file(vector["value"], VERIFIER)
    report = vector["value"]["report"]
    assert jcs(report) == vector["report_jcs"]
    assert checked.report_hash == vector["value"]["report_hash"] == checked.report.report_hash
    assert signing_input(REPORT_DOMAIN, checked.report_hash).decode() == vector["signing_input"]
    assert vector["value"]["event"]["payload"]["signature"] == vector["signature"]
    assert vector["value"]["event"] == CHAIN_RAW[4]
    # R62, R63: rebuilding the report from its named inputs gives the same bytes.
    record = ExportProvenance(report["record"])
    context = ReportContext(report["tenant_id"], CHAIN[0].hash, TEST_SIGNER.public_key)
    map_ids = {PATCHES["P1"].patch_hash: "synthetic.map.a"}
    rebuilt = export_report(context, _report_inputs(), record, map_ids=map_ids, import_event=CHAIN[1])
    assert rebuilt.report_hash == vector["value"]["report_hash"]
    # R51, R60: issuing it after the alert_ack reproduces the vector's export event, signature included.
    e4 = CHAIN[4]
    issued = issue_report(
        rebuilt, head=CHAIN[3], meta=EventMeta(e4.event_id, e4.project_id, e4.actor, e4.ts), signer=TEST_SIGNER
    )
    assert issued.event == e4
    assert raw([issued.event])[0] == vector["value"]["event"]


# SPEC-005 R42, R51
def test_anchor() -> None:
    vector = V["anchor"]
    assert vector["rules"] == ["R42", "R51"]
    assert jcs(vector["value"]["statement"]) == vector["statement_jcs"]
    assert ANCHOR.statement.statement_hash == vector["value"]["statement_hash"]
    assert signing_input(ANCHOR_DOMAIN, ANCHOR.statement_hash).decode() == vector["signing_input"]
    made = make_anchor(
        tenant_id=CHAIN[0].tenant_id, genesis_hash=CHAIN[0].hash, head=CHAIN[4], day="2026-10-18", signer=TEST_SIGNER
    )
    assert made == ANCHOR
    assert dict(made.to_json()) | {"statement": dict(made.statement.to_json())} == vector["value"]


# SPEC-005 R20, R21
def test_audit() -> None:
    vector = V["audit"]
    assert vector["rules"] == ["R20", "R21"]
    value = vector["value"]
    candidate = Dump(
        "bench_full",
        tuple(
            Memory(m.memory_id, m.base_address, bytes.fromhex(vector["candidate"][f"{m.memory_id}_hex"]))
            for m in ORIGINAL.memories
        ),
    )
    v8 = next(c for c in SPEC001["cases"] if c["id"] == "V8-diff-reports-foreign-changes")
    assert vector["candidate"] == {"pflash_hex": v8["x_pflash_hex"], "dflash_hex": v8["x_dflash_hex"]}
    assert image_hash(candidate) == value["image_hash_candidate"]
    candidate_image = {
        "dump_kind": "bench_full",
        "memories": [
            {
                "memory_id": m.memory_id,
                "base_address": m.base_address,
                "size": len(m.data),
                "sha256": hashlib.sha256(m.data).hexdigest(),
            }
            for m in sorted(candidate.memories, key=lambda m: m.memory_id)
        ],
    }
    assert jcs(candidate_image) == vector["candidate_image_jcs"]
    result = diff(ORIGINAL, candidate, BASE)
    assert [p.patch_hash for p in result.patches] == value["diff_patch_hashes"]
    assert [
        {
            "memory_id": f.memory_id,
            "offset": f.offset,
            "length": f.length,
            "region_kind": f.region_kind,
            "region_name": f.region_name,
        }
        for f in result.foreign
    ] == value["foreign"]
    assert try_hash(value) == vector["audit_hash"]
    assert jcs(value) == vector["jcs"]
    record = AuditRecord(value)
    assert record.audit_hash == vector["audit_hash"]
    assert raw_value(record) == value
    assert set(value["versions"]) == {"core", "plugins", "gate_rules", "references"}


# SPEC-005 R82
def test_commitment() -> None:
    vector = V["commitment"]
    assert vector["rules"] == ["R82"]
    assert jcs(vector["value"]) == vector["jcs"]
    assert commitment(vector["value"]["nonce"], vector["value"]["content"]) == vector["commitment"]


def _rehash_from(events: list[dict[str, Any]], start: int) -> None:
    for i in range(start, len(events)):
        if i > 0:
            events[i]["prev_hash"] = events[i - 1]["hash"]
        events[i]["hash"] = hashlib.sha256(
            rfc8785.dumps({k: v for k, v in events[i].items() if k != "hash"})
        ).hexdigest()


def _mutate(mutation: dict[str, Any] | None) -> list[dict[str, Any]]:
    """The mutations of generate.py, applied with rfc8785 (never with the core) when they rehash."""
    events: list[dict[str, Any]] = copy.deepcopy(CHAIN_RAW)
    if mutation is None:
        return events
    index = next(i for i, e in enumerate(events) if e["seq"] == mutation["seq"])
    if mutation["op"] == "delete":
        del events[index]
    elif mutation["op"] == "set":
        target = events[index]
        for key in mutation["path"][:-1]:
            target = target[key]
        target[mutation["path"][-1]] = mutation["value"]
        if mutation["rehash"]:
            _rehash_from(events, index)
    else:
        assert mutation["op"] == "insert"
        new = {
            "schema": "impact.event.v1",
            "tenant_id": events[0]["tenant_id"],
            "seq": mutation["seq"],
            **mutation["event"],
        }
        events.insert(index, {**new, "prev_hash": "", "hash": ""})
        for later in events[index + 1 :]:
            later["seq"] += 1
        _rehash_from(events, index)
    return events


TAMPERS = {t["id"]: t for t in V["tampers"]}


# SPEC-005 R38, R40, R41, R45, R51, R52, R56, R57, R61
@pytest.mark.parametrize("tamper_id", sorted(TAMPERS))
def test_tamper(tamper_id: str) -> None:
    tamper = TAMPERS[tamper_id]
    if tamper["target"] == "report_file":
        report_file = copy.deepcopy(V["report_file"]["value"])
        target = report_file
        for key in tamper["mutation"]["path"][:-1]:
            target = target[key]
        target[tamper["mutation"]["path"][-1]] = tamper["mutation"]["value"]
        with pytest.raises(ReportBindingError) as caught:
            check_report_file(report_file, VERIFIER)
        assert [{"reason": r} for r in caught.value.reasons] == tamper["expect"]
        assert caught.value.reason == tamper["expect"][0]["reason"]
        return
    events = _mutate(tamper["mutation"])
    anchors = [ANCHOR] if tamper["use_anchor"] else []
    report = verify_chain(events, anchors, VERIFIER, test_mode=tamper["test_mode"])
    assert report.status == tamper["status"]
    assert [f.to_json() for f in report.findings] == tamper["expect"]


def test_every_tamper_is_run() -> None:
    assert len(TAMPERS) == 16
    assert {t["target"] for t in V["tampers"]} == {"chain", "report_file"}
