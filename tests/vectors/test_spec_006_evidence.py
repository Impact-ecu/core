"""SPEC-006 §12: every evidence value in specs/vectors/spec-006/vectors.json, against `core.evidence`.

Expected values are written by hand in generate.py (hashes and signatures by third-party rfc8785 and cryptography)
and cross-checked by crosscheck.py; nothing here is computed by the core and then compared with itself. The
`raw_import` cases belong to `core.importers` and are tested there. Vector chains run with `test_mode = True`
except G27 (SPEC-006 R66).
"""

import copy
import hashlib
import json
from typing import Any

import pytest

from core.evidence import (
    DTC_SET_V1,
    HEAD_POLICY_V1,
    PUBLISHED_DTC_SETS,
    PUBLISHED_HEAD_POLICIES,
    AttesterRegistry,
    EvidenceError,
    FieldEvidence,
    attestation_hash,
    attester_registry,
    canonical_dtcs,
    canonical_unit_id,
    evaluate_golden,
    evidence_admission,
    parse_attestation,
    verify_attestation,
)
from core.evidence._json import jcs, signing_input
from core.provenance import TEST_KEY_IDS, Raw, event_hash, parse_event, verify_chain
from tests.unit.evidence_support import CHAIN, EPOCH, KEYS, POOL, POST, PRE, REVIEWED, V
from tests.unit.provenance_support import ROOT, VERIFIER
from tests.unit.provenance_support import _plain as plain

REGISTRIES = {"pre": PRE, "post": POST, "reviewed": REVIEWED}


def as_json(value: Raw) -> object:
    parsed: object = json.loads(jcs(value))
    return parsed


# SPEC-006 §12: inputs read from SPEC-001, never recomputed.
def test_generator_and_spec001_inputs() -> None:
    spec001_bytes = (ROOT / "specs" / "vectors" / "spec-001" / "vectors.json").read_bytes()
    assert V["generator"]["spec001_vectors_sha256"] == hashlib.sha256(spec001_bytes).hexdigest()
    spec001 = json.loads(spec001_bytes)
    cases = {case["id"]: case for case in spec001["cases"]}
    inputs = V["spec001_inputs"]
    assert inputs["base_image_hash"] == spec001["original"]["image_hash"]
    assert inputs["version_hash"] == cases["V4-apply-disjoint"]["expect"]["version_hash"]
    assert inputs["golden_image_hash"] == cases["V9-checksum-patch"]["expect"]["image_hash"]
    assert inputs["other_image_hash"] == cases["V4-apply-disjoint"]["expect"]["image_hash"]


# SPEC-006 R49, R66: the synthetic keys and their key_ids are exactly the SPEC-005 R56 test keys of this spec.
def test_keys() -> None:
    for name, entry in V["keys"]["keys"].items():
        assert entry["seed_text"] == f"impact spec-006 synthetic {name} key; never use outside test vectors"
        assert KEYS[name].public_key == entry["public_key"]
        assert KEYS[name].key_id == entry["key_id"] == hashlib.sha256(bytes.fromhex(entry["public_key"])).hexdigest()
    assert {entry["key_id"] for entry in V["keys"]["keys"].values()} <= TEST_KEY_IDS


# SPEC-006 R43
@pytest.mark.parametrize("case", V["dtcs"]["canonical"])
def test_canonical_dtcs(case: dict[str, Any]) -> None:
    assert canonical_dtcs(case["raw"]) == case["expect"]


# SPEC-006 R43, R80: `bad_dtc`.
@pytest.mark.parametrize("case", V["dtcs"]["invalid"])
def test_invalid_dtcs(case: dict[str, Any]) -> None:
    with pytest.raises(EvidenceError) as caught:
        canonical_dtcs(case["raw"])
    assert caught.value.reason == case["reason"] == "bad_dtc"


# SPEC-006 R45
@pytest.mark.parametrize("case", V["unit_ids"]["canonical"])
def test_canonical_unit_ids(case: dict[str, Any]) -> None:
    assert canonical_unit_id(case["raw"]) == case["expect"]


# SPEC-006 R45, R80: `bad_unit_id`.
@pytest.mark.parametrize("case", V["unit_ids"]["invalid"])
def test_invalid_unit_ids(case: dict[str, Any]) -> None:
    with pytest.raises(EvidenceError) as caught:
        canonical_unit_id(case["raw"])
    assert caught.value.reason == case["reason"] == "bad_unit_id"


# SPEC-006 R46, R47: `core` only checks commitment shapes. Every commitment the service issued, in both epochs,
# is a valid `ecu_commitment`; the lookup keys and the secret never reach `core`.
def test_commitment_shapes() -> None:
    service = V["commitment_service"]
    second = service["second_epoch"]
    issued = [(unit["ecu_commitment"], service["epoch"]) for unit in service["units"]]
    issued += [(unit["ecu_commitment"], second["epoch"]) for unit in second["units"]]
    for commitment, epoch in issued:
        value = copy.deepcopy(POOL["AX"]["attestation"])
        value.update(ecu_commitment=commitment, ecu_commitment_epoch=epoch)
        assert parse_attestation(value).ecu_commitment == commitment
    assert len({commitment for commitment, _ in issued}) == len(issued)
    for label, entry in POOL.items():
        attestation = entry["attestation"]
        assert (attestation["ecu_commitment"] is None) == (attestation["ecu_commitment_epoch"] is None), label


# SPEC-006 R55, R56, R57: version 1, its JCS and hash, and the only published set.
def test_dtc_set() -> None:
    vector = V["dtc_set"]
    assert as_json(DTC_SET_V1) == vector["value"]
    assert jcs(DTC_SET_V1).decode("utf-8") == vector["jcs"]
    assert hashlib.sha256(jcs(vector["value"])).hexdigest() == vector["dtc_set_hash"]
    assert vector["dtc_set_hash"] in PUBLISHED_DTC_SETS


# SPEC-006 R82
def test_head_policy() -> None:
    vector = V["head_policy"]
    assert as_json(HEAD_POLICY_V1) == vector["value"]
    assert hashlib.sha256(jcs(HEAD_POLICY_V1)).hexdigest() == vector["head_policy_hash"]
    assert vector["head_policy_hash"] in PUBLISHED_HEAD_POLICIES


# SPEC-006 R60-R62: the registry chain is an intact SPEC-005 server chain whose genesis enrolls no attester.
def test_registry_chain() -> None:
    assert V["registry_chain"]["test_mode"] is True
    for entry in V["registry_chain"]["events"]:
        assert event_hash(parse_event(entry["event"]).to_json()) == entry["hash"]
    report = verify_chain(CHAIN, [], VERIFIER, test_mode=True)
    assert report.status == "intact"
    assert report.findings == ()
    assert CHAIN[0]["payload"]["role"] == "server"


# SPEC-006 R61-R65, R67, R68: the registry before the revocations, after them, and after a record review.
@pytest.mark.parametrize("name", ["pre", "post", "reviewed"])
def test_registries(name: str) -> None:
    built = REGISTRIES[name]
    assert as_json(built.to_json()) == V["registries"][name]["value"]
    assert built.registry_hash == V["registries"][name]["registry_hash"]


# SPEC-006 R48: every attestation of the pool hashes to its stored hash, except the one edited without rehash.
@pytest.mark.parametrize("label", sorted(POOL))
def test_attestation_hashes(label: str) -> None:
    entry = POOL[label]
    matches = attestation_hash(entry["attestation"]) == entry["attestation_hash"]
    assert matches == (label != "BY_EDITED_NOREHASH")


# SPEC-006 R48, R49: JCS, hash and signing input of the example, and its signature verifies by the registry key.
def test_attestation_example() -> None:
    example = V["attestation_verify"]["example"]
    attestation = POOL[example["label"]]["attestation"]
    assert jcs(attestation).decode("utf-8") == example["attestation_jcs"]
    assert attestation_hash(attestation) == example["attestation_hash"]
    message = signing_input("impact.field-attestation-signature.v1", example["attestation_hash"])
    assert message.decode("utf-8") == example["signing_input"]
    assert POOL[example["label"]]["signature"] == example["signature"]
    entry = PRE.attester(attestation["attester_key_id"])
    assert entry is not None
    assert VERIFIER.verify(bytes.fromhex(entry.public_key), message, bytes.fromhex(example["signature"]))


# SPEC-006 R50, R77
@pytest.mark.parametrize("case", V["attestation_verify"]["cases"], ids=lambda c: f"{c['label']}-{c['registry']}")
def test_attestation_verify(case: dict[str, Any]) -> None:
    assert verify_attestation(POOL[case["label"]], REGISTRIES[case["registry"]], VERIFIER) == case["expect"]


def _evaluate(case: dict[str, Any], supplied: list[Any]) -> dict[str, Any]:
    registry: AttesterRegistry
    try:
        if case["test_mode"]:
            registry = REGISTRIES[case["registry"]]
        else:
            registry = attester_registry(CHAIN[:10], [], VERIFIER, test_mode=False)
        evaluation = evaluate_golden(case["record"], supplied, registry, V["dtc_set"]["value"], EPOCH, VERIFIER)
    except EvidenceError as error:
        return {"error": error.reason}
    return {"evaluation": as_json(evaluation.to_json()), "evaluation_hash": evaluation.evaluation_hash}


# SPEC-006 R42, R44, R47, R50-R52, R55, R56, R62, R64-R66, R70-R80: the matrix G01-G33, in both input orders.
@pytest.mark.parametrize("case", V["evaluations"], ids=lambda c: c["id"])
def test_evaluations(case: dict[str, Any]) -> None:
    supplied = [POOL[label] for label in case["supplied"]]
    assert hashlib.sha256(jcs(case["record"])).hexdigest() == case["golden_record_hash"]
    assert _evaluate(case, supplied) == case["expect"]
    assert _evaluate(case, list(reversed(supplied))) == case["expect"]


# SPEC-006 R60, R81: the trust anchor is the registry chain's signing key, and the head JCS, digest and input.
def test_trust_and_head_example() -> None:
    trust, genesis = V["trust"], CHAIN[0]
    assert (trust["tenant_id"], trust["genesis_hash"]) == (genesis["tenant_id"], genesis["hash"])
    assert [{"key_id": trust["key_id"], "public_key": trust["public_key"]}] == genesis["payload"]["signing_keys"]
    example, post = V["heads"]["example"], V["heads"]["values"]["post"]
    assert jcs(post["head"]).decode("utf-8") == example["head_jcs"]
    assert hashlib.sha256(jcs(post["head"])).hexdigest() == example["head_digest"] == post["head_digest"]
    message = signing_input("impact.registry-head-signature.v1", example["head_digest"])
    assert message.decode("utf-8") == example["signing_input"]
    assert post["head"]["registry_hash"] == POST.registry_hash
    assert V["heads"]["values"]["reviewed"]["head"]["registry_hash"] == REVIEWED.registry_hash


# SPEC-006 R81-R84, R89: A1-A8, with every attestation of the pool supplied.
@pytest.mark.parametrize("case", V["admissions"], ids=lambda c: c["id"])
def test_admissions(case: dict[str, Any]) -> None:
    evidence = FieldEvidence(
        head=V["heads"]["values"][case["head"]],
        registry=REGISTRIES[case["registry"]],
        records=case["records"],
        attestations=list(POOL.values()),
        dtc_set=V["dtc_set"]["value"],
        commitment_epoch=EPOCH,
    )
    admission = evidence_admission(
        evidence, V["trust"], V["head_policy"]["value"], case["as_of"], VERIFIER, test_mode=case["test_mode"]
    )
    assert as_json(admission.to_json()) == case["expect"]
    assert plain(admission.to_json()) == case["expect"]
