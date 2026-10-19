"""Test-only builders for SPEC-006 evidence: vector keys, attestations, registry chains, heads and reviews.

Hashes and signing inputs are computed with third-party `rfc8785` and signatures with `cryptography`, never with
`core.evidence`, so a test that compares against them is not comparing the core with itself. Keys named after the
vectors are R66 test keys (test mode only); `dev_key` keys work outside test mode.
"""

import copy
import hashlib
from collections.abc import Sequence
from typing import Any, cast

import rfc8785

from core.evidence import AttesterRegistry, attester_registry
from core.provenance import Actor, Draft, Event, append, sign_key_event
from tests.unit.provenance_support import (
    SPEC006,
    USER,
    VERIFIER,
    Ed25519Signer,
    _plain,
    add,
    add_signed,
    dev_key,
    next_meta,
    raw,
    start,
)

V = SPEC006
ATTESTATION_DOMAIN = "impact.field-attestation-signature.v1"
HEAD_DOMAIN = "impact.registry-head-signature.v1"
REVIEW_DOMAIN = "impact.review-signature.v1"
ROTATION_DOMAIN = "impact.attester-rotation-signature.v1"

KEYS = {
    name: Ed25519Signer(hashlib.sha256(entry["seed_text"].encode("utf-8")).digest())
    for name, entry in V["keys"]["keys"].items()
}
A, A2, B, C, D, E, F, R = (
    KEYS[name]
    for name in (
        "attester-a",
        "attester-a2",
        "attester-b",
        "attester-c",
        "attester-d",
        "attester-e",
        "reviewer-f",
        "attester-r",
    )
)
REGISTRY_KEY = KEYS["registry"]

EPOCH: str = V["commitment_service"]["epoch"]
EPOCH2: str = V["commitment_service"]["second_epoch"]["epoch"]
UNITS: dict[str, str] = {unit["unit"]: unit["ecu_commitment"] for unit in V["commitment_service"]["units"]}
GOLDEN: str = V["spec001_inputs"]["golden_image_hash"]
OTHER: str = V["spec001_inputs"]["other_image_hash"]
DTC_SET: dict[str, Any] = V["dtc_set"]["value"]
POLICY: dict[str, Any] = V["head_policy"]["value"]
TRUST: dict[str, Any] = V["trust"]
POOL: dict[str, Any] = V["attestations"]
CHAIN: list[Any] = [entry["event"] for entry in V["registry_chain"]["events"]]
TEMPLATE: dict[str, Any] = POOL["AX"]["attestation"]
RECORD: dict[str, Any] = V["evaluations"][0]["record"]


def sha(value: object) -> str:
    return hashlib.sha256(rfc8785.dumps(cast(Any, value))).hexdigest()


def signing_input(domain: str, hash_hex: str) -> bytes:
    return rfc8785.dumps({"domain": domain, "hash": hash_hex})


def vector_registry(seq: int, *, test_mode: bool = True) -> AttesterRegistry:
    """The registry of the SPEC-006 vector chain at `seq` (pre = 9, post = 12, reviewed = 13)."""
    return attester_registry(CHAIN[: seq + 1], [], VERIFIER, test_mode=test_mode)


PRE = vector_registry(9)
POST = vector_registry(12)
REVIEWED = vector_registry(13)


def attestation(key: Ed25519Signer = A, unit: str | None = "X", **changes: object) -> dict[str, Any]:
    """The AX template for `key` and `unit` (None: a unit without a serial), with `changes` applied."""
    value = copy.deepcopy(TEMPLATE)
    value["attester_key_id"] = key.key_id
    value["ecu_commitment"] = None if unit is None else UNITS[unit]
    value["ecu_commitment_epoch"] = None if unit is None else EPOCH
    value.update(changes)
    return value


def signed(value: dict[str, Any], signer: Ed25519Signer | None = None) -> dict[str, Any]:
    """A `SignedFieldAttestation`, signed by `signer` (default: the key the attestation names)."""
    signer = signer or next(key for key in KEYS.values() if key.key_id == value["attester_key_id"])
    digest = sha(value)
    return {
        "attestation": value,
        "attestation_hash": digest,
        "signature": signer.sign(signing_input(ATTESTATION_DOMAIN, digest)).hex(),
    }


def record(*hashes: str, tools: list[dict[str, Any]] | None = None, **changes: object) -> dict[str, Any]:
    value = copy.deepcopy(RECORD)
    value["oracle"] = {"tools": tools or [], "attestations": sorted(hashes)}
    value.update(changes)
    return value


def tool(name: str, image_hash: str = GOLDEN, version: str = "1.0") -> dict[str, Any]:
    return {"name": name, "version": version, "image_hash": image_hash, "date": "2026-10-18"}


def sign_head(head: dict[str, Any], signer: Ed25519Signer = REGISTRY_KEY) -> dict[str, Any]:
    digest = sha(head)
    return {
        "head": head,
        "head_digest": digest,
        "key_id": signer.key_id,
        "signature": signer.sign(signing_input(HEAD_DOMAIN, digest)).hex(),
    }


def head_for(registry: AttesterRegistry, **changes: object) -> dict[str, Any]:
    """A `RegistryHead` for `registry`, valid on 2026-10-19 (the vector heads' window), with `changes`."""
    value = {
        "schema": "impact.registry-head.v1",
        "tenant_id": registry.tenant_id,
        "genesis_hash": registry.genesis_hash,
        "seq": registry.head.seq,
        "head_hash": registry.head.hash,
        "registry_hash": sha(_plain(registry.to_json())),
        "issued_at": "2026-10-19T00:00:00Z",
        "expires_at": "2026-10-20T00:00:00Z",
    }
    value.update(changes)
    return value


# --- custom registry chains (dev keys, outside test mode) ---

SIGNER = dev_key("registry-signer")
DEV = {name: dev_key(f"attester {name}") for name in ("p", "q", "s", "t", "u")}
REASON = "cc" * 32


def registry_chain(signer: Ed25519Signer = SIGNER, *, role: str = "server") -> list[Event]:
    return [start(signer, role=role)]


def enrollment(
    chain: list[Event],
    key: Ed25519Signer,
    roles: tuple[str, ...],
    rotates: Ed25519Signer | None,
    rotation_by: Ed25519Signer | None,
) -> dict[str, Any]:
    """An `attester_enrolled` payload; a rotation is signed by `rotation_by` (default: the old key)."""
    rotation_signature = None
    if rotates is not None:
        rotation_hash = sha(
            {
                "schema": "impact.attester-rotation.v1",
                "tenant_id": chain[0].tenant_id,
                "genesis_hash": chain[0].hash,
                "old_key_id": rotates.key_id,
                "new_key_id": key.key_id,
                "new_public_key": key.public_key,
            }
        )
        rotation_signature = (rotation_by or rotates).sign(signing_input(ROTATION_DOMAIN, rotation_hash)).hex()
    return {
        "attester_key_id": key.key_id,
        "public_key": key.public_key,
        "roles": list(roles),
        "rotates": None if rotates is None else rotates.key_id,
        "rotation_signature": rotation_signature,
        "reason_commitment": REASON,
        "signer_key_id": SIGNER.key_id,
    }


def enroll(
    chain: list[Event],
    key: Ed25519Signer,
    roles: tuple[str, ...] = ("attester",),
    *,
    rotates: Ed25519Signer | None = None,
    rotation_by: Ed25519Signer | None = None,
    actor: Actor = USER,
) -> Event:
    """`attester_enrolled`, signed per SPEC-005 R57 by the registry chain's key."""
    return signed_event(chain, "attester_enrolled", enrollment(chain, key, roles, rotates, rotation_by), actor)


def signed_event(chain: list[Event], event_type: str, payload: dict[str, Any], actor: Actor = USER) -> Event:
    """An R57 event signed by the registry chain's key, with `actor`."""
    last = chain[-1]
    draft = Draft(next_meta(last.seq + 1, actor), event_type, payload)
    event = append(last, sign_key_event(last, chain[0].hash, draft, SIGNER))
    chain.append(event)
    return event


def revoke(chain: list[Event], key: Ed25519Signer, reason: str = "compromised") -> Event:
    payload = {"attester_key_id": key.key_id, "reason": reason, "reason_commitment": REASON}
    return add_signed(chain, "attester_revoked", payload, SIGNER)


def include(chain: list[Event], attestation_hash: str, key: Ed25519Signer) -> Event:
    payload = {"attestation_hash": attestation_hash, "attester_key_id": key.key_id}
    return add_signed(chain, "attestation_included", payload, SIGNER)


def review_payload(
    chain: Sequence[Event],
    reviewer: Ed25519Signer,
    subject_hash: str,
    *,
    decision: str = "approved",
    export_ref: dict[str, Any] | None = None,
    signer: Ed25519Signer | None = None,
) -> dict[str, Any]:
    """A `review` payload for `chain` (of an export when `export_ref` is given, else of a golden record), signed per
    SPEC-006 R91 by `signer` (default: the reviewer)."""
    subject_kind = "golden_record" if export_ref is None else "export"
    review_hash = sha(
        {
            "schema": "impact.review.v1",
            "tenant_id": chain[0].tenant_id,
            "genesis_hash": chain[0].hash,
            "subject_kind": subject_kind,
            "export_ref": export_ref,
            "subject_hash": subject_hash,
            "decision": decision,
        }
    )
    return {
        "subject_kind": subject_kind,
        "export_ref": export_ref,
        "subject_hash": subject_hash,
        "decision": decision,
        "reviewer_key_id": reviewer.key_id,
        "signature": (signer or reviewer).sign(signing_input(REVIEW_DOMAIN, review_hash)).hex(),
    }


def review_record(
    chain: list[Event],
    reviewer: Ed25519Signer,
    subject_hash: str,
    *,
    decision: str = "approved",
    signer: Ed25519Signer | None = None,
) -> Event:
    payload = review_payload(chain, reviewer, subject_hash, decision=decision, signer=signer)
    return add(chain, "review", payload)


def build(chain: list[Event]) -> AttesterRegistry:
    return attester_registry(raw(chain), [], VERIFIER)
