"""SPEC-005 properties: records (R1, R3, R10-R19), the chain (R31-R41, R52, R57), reports (R61) and commitments (R82).

Expected hashes come from the third-party `rfc8785` JCS and `hashlib`; signatures from the dev-only `cryptography`
Ed25519. Nothing the core computes is compared with itself.
"""

import copy
import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import replace
from itertools import pairwise
from random import Random
from typing import Any

import pytest
import rfc8785
from hypothesis import assume, given
from hypothesis import strategies as st

from core.kernel import Patch, apply, apply_checksum_patches, canonical_order, image_hash, layout_hash, version_hash
from core.provenance import (
    Build,
    Event,
    ExportInputs,
    ExportProvenance,
    ProvenanceError,
    ReportContext,
    check_report_file,
    commitment,
    export_provenance,
    export_report,
    issue_report,
    make_anchor,
    verify_chain,
)
from tests.properties.strategies import Scenario, calibration_slots, patch_in, scenarios
from tests.unit.provenance_scenario import VERSIONS
from tests.unit.provenance_support import (
    OTHER,
    SERVER,
    TENANT,
    VERIFIER,
    _plain,
    add,
    add_signed,
    import_payload,
    next_meta,
    raw,
    start,
)

type JsonValue = int | str | Sequence[JsonValue] | Mapping[str, JsonValue] | None
HEX = st.text("0123456789abcdef", min_size=64, max_size=64)
TEXT = st.text(st.characters(codec="utf-8"), min_size=1, max_size=12)


def sha(value: object) -> str:
    plain: Any = json.loads(json.dumps(_plain(value)))
    return hashlib.sha256(rfc8785.dumps(plain)).hexdigest()


def rehash_from(events: list[dict[str, Any]], index: int) -> None:
    for i in range(index, len(events)):
        if i > 0:
            events[i]["prev_hash"] = events[i - 1]["hash"]
        events[i]["hash"] = sha({k: v for k, v in events[i].items() if k != "hash"})


def found(events: list[Any], anchors: list[Any] | None = None) -> set[tuple[int, str]]:
    return {(f.seq, f.reason) for f in verify_chain(events, anchors or [], VERIFIER).findings}


@st.composite
def payloads(draw: st.DrawFn) -> tuple[str, dict[str, Any]]:
    kind = draw(st.sampled_from(["import", "rule_silence", "erasure", "alert_ack", "consent_revoked"]))
    if kind == "import":
        return kind, import_payload(draw(HEX), draw(st.sampled_from(["bench_read", "virtual_read", "file_service"])))
    if kind == "rule_silence":
        return kind, {"rule_id": draw(TEXT), "justification_commitment": draw(st.none() | HEX)}
    if kind == "erasure":
        return kind, {"subject": "artifact", "ref": draw(HEX), "reason": "data_subject_request"}
    if kind == "alert_ack":
        presented = draw(st.integers(0, 2**52 - 1))
        warnings = draw(
            st.lists(st.builds(lambda f, r, t: {"finding_id": f, "rule_id": r, "text": t}, HEX, TEXT, TEXT), max_size=3)
        )
        return kind, {
            "image_hash_release": draw(HEX),
            "gate_report_hash": draw(HEX),
            "warnings": warnings,
            "presented_ms": presented,
            "confirmed_ms": presented + draw(st.integers(0, 2**52 - 1)),
        }
    return kind, {"artifact_sha256": draw(HEX), "purpose": "corpus", "record_commitment": draw(HEX)}


@st.composite
def chains(draw: st.DrawFn, *, min_events: int = 1) -> list[Event]:
    """A server chain: genesis, then events of R36 types, some exports signed by the genesis key."""
    chain = [start()]
    for _ in range(draw(st.integers(min_events, 6))):
        if draw(st.booleans()):
            kind, payload = draw(payloads())
            add(chain, kind, payload)
        else:
            report_hash = draw(HEX)
            message = rfc8785.dumps({"domain": "impact.report-signature.v1", "hash": report_hash})
            signature = SERVER.sign(message).hex()
            payload = {"provenance_hash": draw(HEX), "report_hash": report_hash, "key_id": SERVER.key_id}
            add(chain, "export", {**payload, "signature": signature})
    return chain


# SPEC-005 R2, R30, R31, R33, R34, R40: a chain built by `append` verifies intact; every hash is an independent JCS's.
@given(chains())
def test_appended_chain_is_intact(chain: list[Event]) -> None:
    events = raw(chain)
    for index, event in enumerate(events):
        assert event["hash"] == sha({k: v for k, v in event.items() if k != "hash"})
        assert event["seq"] == index
        assert event["schema"] == "impact.event.v1"
        assert event["prev_hash"] == (events[index - 1]["hash"] if index else "0" * 64)
    report = verify_chain(events, [], VERIFIER)
    assert report.status == "intact"
    assert report.findings == ()
    assert report.head is not None
    assert report.head.hash == events[-1]["hash"]


# SPEC-005 R40: the verifier sorts; input order is not trusted.
@given(chains(), st.randoms(use_true_random=False))
def test_order_is_not_trusted(chain: list[Event], random: Random) -> None:
    events = raw(chain)
    shuffled = list(events)
    random.shuffle(shuffled)
    assert verify_chain(shuffled, [], VERIFIER) == verify_chain(events, [], VERIFIER)


# SPEC-005 R41: a removed middle event is detected without anchors; a removed tail only by an anchor.
@given(chains(min_events=2), st.data())
def test_removed_event_is_detected(chain: list[Event], data: st.DataObject) -> None:
    events = raw(chain)
    index = data.draw(st.integers(1, len(events) - 2))
    seq = events[index + 1]["seq"]
    assert {(seq, "seq_gap"), (seq, "prev_mismatch")} <= found(events[:index] + events[index + 1 :])
    anchor = make_anchor(tenant_id=TENANT, genesis_hash=chain[0].hash, head=chain[-1], day="2026-10-18", signer=SERVER)
    assert found(events[:-1]) == set()
    assert found(events[:-1], [anchor]) == {(chain[-1].seq, "truncated")}


# SPEC-005 R31, R40: any edit to a stored event without rehashing breaks the chain.
@given(chains(), st.data())
def test_edit_without_rehash_breaks(chain: list[Event], data: st.DataObject) -> None:
    events = raw(chain)
    index = data.draw(st.integers(0, len(events) - 1))
    field = data.draw(st.sampled_from(["event_id", "ts", "project_id", "payload", "actor", "tenant_id"]))
    edited = copy.deepcopy(events)
    replacement = {
        "event_id": "ff" * 16,
        "ts": "2026-10-18T23:59:59Z",
        "project_id": "project-z",
        "payload": {**events[index]["payload"], "extra": 1},
        "actor": {"kind": "user", "id": "someone-else"},
        "tenant_id": "tenant-z",
    }[field]
    assume(edited[index][field] != replacement)
    edited[index][field] = replacement
    assert verify_chain(edited, [], VERIFIER).status == "broken"


# SPEC-005 R41: a consistent rewrite is caught only by an anchor that covers it.
@given(chains(min_events=1), st.data())
def test_consistent_rewrite_needs_an_anchor(chain: list[Event], data: st.DataObject) -> None:
    events = raw(chain)
    index = data.draw(st.integers(1, len(events) - 1))
    rewritten = copy.deepcopy(events)
    rewritten[index]["ts"] = (
        "2026-10-18T12:00:00Z" if rewritten[index]["ts"] != "2026-10-18T12:00:00Z" else "2026-10-18T12:00:01Z"
    )
    rehash_from(rewritten, index)
    assert verify_chain(rewritten, [], VERIFIER).status == "intact"
    anchor = make_anchor(tenant_id=TENANT, genesis_hash=chain[0].hash, head=chain[-1], day="2026-10-18", signer=SERVER)
    assert (chain[-1].seq, "anchor_mismatch") in found(rewritten, [anchor])


# SPEC-005 R38: order is `seq`; a timestamp going backwards is informational only.
@given(chains(min_events=1), st.lists(st.integers(0, 86399), min_size=7, max_size=7))
def test_ts_regression_is_informational(chain: list[Event], seconds: list[int]) -> None:
    events = raw(chain)
    for event, second in zip(events, seconds, strict=False):
        event["ts"] = f"2026-10-18T{second // 3600:02d}:{second // 60 % 60:02d}:{second % 60:02d}Z"
    rehash_from(events, 0)
    report = verify_chain(events, [], VERIFIER)
    regressions = {e["seq"] for a, e in pairwise(events) if e["ts"] < a["ts"]}
    assert report.status == "intact"
    assert {(f.seq, f.reason) for f in report.findings} == {(seq, "ts_regression") for seq in regressions}
    assert all(f.informational for f in report.findings)


# SPEC-005 R52: a key signs only after its enrollment and before its revocation; earlier signatures stay valid.
@given(st.integers(1, 5), st.integers(0, 5))
def test_revocation_window(exports_before: int, exports_after: int) -> None:
    chain = [start()]
    add_signed(chain, "key_enrolled", {"key_id": OTHER.key_id, "public_key": OTHER.public_key}, SERVER)
    signed = [_export(chain).seq for _ in range(exports_before)]
    revoked_at = add_signed(chain, "key_revoked", {"key_id": OTHER.key_id, "reason": "retired"}, SERVER).seq
    late = [_export(chain).seq for _ in range(exports_after)]
    assert found(raw(chain)) == {(seq, "revoked_key") for seq in late}
    assert all(seq < revoked_at for seq in signed)


def _export(chain: list[Event]) -> Event:
    report_hash = hashlib.sha256(str(len(chain)).encode()).hexdigest()
    message = rfc8785.dumps({"domain": "impact.report-signature.v1", "hash": report_hash})
    payload = {"provenance_hash": report_hash, "report_hash": report_hash, "key_id": OTHER.key_id}
    return add(chain, "export", {**payload, "signature": OTHER.sign(message).hex()})


# SPEC-005 R57: a signed key event replayed at another seq or into another chain fails its signature.
@given(chains(), st.booleans())
def test_key_event_replay(chain: list[Event], into_other_chain: bool) -> None:
    source = [start()]
    enrolled = add_signed(source, "key_enrolled", {"key_id": OTHER.key_id, "public_key": OTHER.public_key}, SERVER)
    if not into_other_chain:
        chain = source[:1]
        add(chain, "import", import_payload())
    replayed = replace(
        enrolled, seq=chain[-1].seq + 1, prev_hash=chain[-1].hash, event_id=next_meta(0).event_id, ts=chain[-1].ts
    )
    events = raw([*chain, replayed])
    rehash_from(events, len(events) - 1)
    assert found(events) == {(replayed.seq, "bad_signature")}


@st.composite
def exports(draw: st.DrawFn) -> tuple[Scenario, tuple[Patch, ...], dict[str, Any], dict[str, Any], list[Event], bool]:
    s = draw(scenarios(min_patches=1))
    checksum_slots = calibration_slots(s.layout, "checksum")
    chosen = draw(st.lists(st.sampled_from(checksum_slots), unique=True, max_size=2)) if checksum_slots else []
    q = tuple(draw(patch_in(memory_id, region, s.expected[memory_id])) for memory_id, region in chosen)
    warn = draw(st.booleans())
    findings = draw(
        st.lists(
            st.builds(
                lambda r, sev, t: {"rule_id": r, "severity": sev, "text": t},
                TEXT,
                st.sampled_from(["warn", "info"]),
                TEXT,
            ),
            max_size=3,
        )
    )
    if warn:
        findings.append({"rule_id": "T-WARN", "severity": "warn", "text": "w"})
    else:
        findings = [f for f in findings if f["severity"] != "warn"]
    references = [{"id": "ref.a", "version": "2"}, {"id": "ref.b", "version": "1"}]
    subject = {"definition_hash": "de" * 32, "layout_hash": layout_hash(s.layout), "references": references}
    gate = {"verdict": "warn" if warn else "no findings", "findings": findings, "subject": subject}
    suspect = draw(st.booleans())
    input_report = {
        "verdict": "block" if suspect else "no findings",
        "subject": {"verify_status": "fail" if suspect else "ok"},
    }
    chain = [start()]
    add(chain, "import", import_payload(image_hash(s.dump)))
    if suspect:
        payload = {
            "artifact_sha256": "bb" * 32,
            "image_hash": image_hash(s.dump),
            "input_report_hash": sha(input_report),
        }
        add(chain, "suspect_ack", {**payload, "verify_status": "fail"})
    if warn:
        release = apply_checksum_patches(apply(s.dump, s.version, s.layout), q, s.layout).image_hash
        warnings = [
            {"finding_id": sha(f), "rule_id": f["rule_id"], "text": f["text"]}
            for f in findings
            if f["severity"] == "warn"
        ]
        ack = {"image_hash_release": release, "gate_report_hash": sha(gate), "warnings": warnings}
        add(chain, "alert_ack", {**ack, "presented_ms": 1, "confirmed_ms": 1})
    return s, q, gate, input_report, chain, draw(st.booleans())


def _inputs(
    s: Scenario, q: tuple[Patch, ...], gate: dict[str, Any], input_report: dict[str, Any], lockfile: bool
) -> ExportInputs:
    build = (
        Build("lockfile", "sha256:" + "44" * 32, "linux/arm64", None)
        if lockfile
        else Build("image", "sha256:" + "33" * 32, "linux/amd64", None)
    )
    return ExportInputs(s.dump, s.version, s.layout, q, "de" * 32, VERSIONS, gate, input_report, build)


def _acks(chain: list[Event]) -> tuple[Event | None, Event | None]:
    alert = next((e for e in chain if e.type == "alert_ack"), None)
    suspect = next((e for e in chain if e.type == "suspect_ack"), None)
    return alert, suspect


# SPEC-005 R1, R10, R11, R12, R13, R14, R17, R18: every field computed by the core; the hash is an independent JCS's.
@given(exports())
def test_export_provenance(
    case: tuple[Scenario, tuple[Patch, ...], dict[str, Any], dict[str, Any], list[Event], bool],
) -> None:
    s, q, gate, input_report, chain, lockfile = case
    alert, suspect = _acks(chain)
    record = export_provenance(
        _inputs(s, q, gate, input_report, lockfile), alert_ack=alert, suspect_ack=suspect, chain=chain
    )
    value: dict[str, Any] = json.loads(json.dumps(_plain(record.value)))
    assert record.provenance_hash == sha(value)
    assert value["image_hash_original"] == image_hash(s.dump)
    assert value["image_hash_apply"] == apply(s.dump, s.version, s.layout).image_hash
    assert value["version_hash"] == version_hash(s.version)
    assert value["patch_hashes"] == [p.patch_hash for p in canonical_order(s.version)]
    assert value["checksum_patch_hashes"] == [p.patch_hash for p in sorted(q, key=lambda p: (p.memory_id, p.offset))]
    assert value["gate_report_hash"] == sha(gate)
    assert value["reproducibility"] == ("best_effort" if lockfile else "full")
    assert (value["alert_ack"] is None) == (alert is None)
    assert (value["input_verify"]["suspect_ack"] is None) == (suspect is None)
    # R3: one extra key or one missing key is never a valid record.
    key = sorted(value)[len(chain) % len(value)]
    for broken in ({**value, "unexpected": None}, {k: v for k, v in value.items() if k != key}):
        with pytest.raises(ProvenanceError) as caught:
            ExportProvenance(broken)
        assert caught.value.reason == "bad_shape"


# SPEC-005 R19: a no findings export has the same provenance_hash whatever chain, tenant or time it is recorded in.
@given(exports(), st.sampled_from(["tenant-a", "tenant-b", "t9"]))
def test_no_findings_hash_is_chain_independent(
    case: tuple[Scenario, tuple[Patch, ...], dict[str, Any], dict[str, Any], list[Event], bool], tenant: str
) -> None:
    s, q, gate, input_report, chain, lockfile = case
    assume(gate["verdict"] == "no findings" and input_report["verdict"] != "block")
    inputs = _inputs(s, q, gate, input_report, lockfile)
    first = export_provenance(inputs, alert_ack=None, suspect_ack=None, chain=chain)
    second = export_provenance(inputs, alert_ack=None, suspect_ack=None, chain=[start(tenant=tenant)])
    assert first.provenance_hash == second.provenance_hash


# SPEC-005 R51, R60, R61: any single-character change to a signed report file is rejected.
@given(exports(), st.data())
def test_report_file_tamper(
    case: tuple[Scenario, tuple[Patch, ...], dict[str, Any], dict[str, Any], list[Event], bool], data: st.DataObject
) -> None:
    s, q, gate, input_report, chain, lockfile = case
    alert, suspect = _acks(chain)
    inputs = _inputs(s, q, gate, input_report, lockfile)
    record = export_provenance(inputs, alert_ack=alert, suspect_ack=suspect, chain=chain)
    context = ReportContext(TENANT, chain[0].hash, SERVER.public_key)
    report = export_report(context, inputs, record, map_ids={}, import_event=chain[1])
    report_file = issue_report(report, head=chain[-1], meta=next_meta(chain[-1].seq + 1), signer=SERVER)
    value: dict[str, Any] = json.loads(json.dumps(_plain(report_file.to_json())))
    assert check_report_file(value, VERIFIER).report_hash == sha(value["report"])
    path = data.draw(
        st.sampled_from(
            [
                ("report_hash",),
                ("report", "record_hash"),
                ("report", "record", "image_hash_release"),
                ("report", "record", "gate_report_hash"),
                ("report", "genesis_hash"),
                ("event", "payload", "signature"),
                ("event", "payload", "report_hash"),
            ]
        )
    )
    target = value
    for key in path[:-1]:
        target = target[key]
    original = target[path[-1]]
    position = data.draw(st.integers(0, len(original) - 1))
    target[path[-1]] = original[:position] + ("0" if original[position] != "0" else "1") + original[position + 1 :]
    with pytest.raises(ProvenanceError):
        check_report_file(value, VERIFIER)


# SPEC-005 R82: the commitment is an independent JCS's hash.
JSON_VALUES: st.SearchStrategy[JsonValue] = st.recursive(
    st.none() | st.integers(0, 2**53 - 1) | TEXT,
    lambda inner: st.lists(inner, max_size=3) | st.dictionaries(st.text("abcdef", max_size=4), inner, max_size=3),
    max_leaves=8,
)


@given(HEX, JSON_VALUES)
def test_commitment(nonce: str, content: JsonValue) -> None:
    want = {"schema": "impact.commitment.v1", "nonce": nonce, "content": content}
    assert commitment(nonce, content) == hashlib.sha256(rfc8785.dumps(want)).hexdigest()
