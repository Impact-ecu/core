"""SPEC-006 §6: the attester registry from a SPEC-005 chain, outside test mode, with every finding of R62-R68."""

import random
from typing import Any

import pytest

from core.evidence import AttesterRegistry, EvidenceError, attester_registry
from core.provenance import Event, verify_chain
from tests.unit.evidence_support import (
    DEV,
    SIGNER,
    A,
    build,
    enroll,
    enrollment,
    include,
    registry_chain,
    review_payload,
    review_record,
    revoke,
    signed_event,
)
from tests.unit.provenance_support import SYSTEM, VERIFIER, add, raw

P, Q, S, T, U = (DEV[name] for name in ("p", "q", "s", "t", "u"))
HASH_1, HASH_2 = "11" * 32, "22" * 32


def findings(registry: AttesterRegistry) -> list[tuple[int, str]]:
    return [(finding.seq, finding.reason) for finding in registry.findings]


def broken(events: list[Any], *, test_mode: bool = False) -> str:
    with pytest.raises(EvidenceError) as caught:
        attester_registry(events, [], VERIFIER, test_mode=test_mode)
    return caught.value.reason


# SPEC-006 R60, R61, R65: the genesis enrolls no attester; head, tenant and genesis come from the chain.
def test_empty_registry() -> None:
    chain = registry_chain()
    registry = build(chain)
    assert registry.attesters == ()
    assert registry.inclusions == ()
    assert registry.record_reviews == ()
    assert registry.findings == ()
    assert (registry.tenant_id, registry.genesis_hash) == (chain[0].tenant_id, chain[0].hash)
    assert (registry.head.seq, registry.head.hash) == (0, chain[0].hash)
    assert registry.to_json()["schema"] == "impact.attester-registry.v1"


# SPEC-006 R61: the chain's own signing key is no attester unless enrolled by `attester_enrolled`.
def test_chain_key_is_not_an_attester() -> None:
    chain = registry_chain()
    include(chain, HASH_1, SIGNER)
    assert findings(build(chain)) == [(1, "unknown_attester")]
    enroll(chain, SIGNER)
    include(chain, HASH_1, SIGNER)
    registry = build(chain)
    assert [entry.seq for entry in registry.inclusions] == [3]


# SPEC-006 R62: roles, identity and `enrolled_seq`; enrolling a key already in the registry has no effect.
def test_enrollment_and_already_enrolled() -> None:
    chain = registry_chain()
    enroll(chain, P, ("attester", "reviewer"))
    enroll(chain, P, ("reviewer",))
    revoke(chain, Q)
    enroll(chain, Q)
    revoke(chain, Q, "retired")
    enroll(chain, Q)
    registry = build(chain)
    entry = registry.attester(P.key_id)
    assert entry is not None
    assert (entry.roles, entry.identity, entry.enrolled_seq, entry.revoked) == (
        ("attester", "reviewer"),
        P.key_id,
        1,
        None,
    )
    assert findings(registry) == [(2, "already_enrolled"), (3, "unknown_attester"), (6, "already_enrolled")]


# SPEC-006 R62: an enrollment is a human decision for exactly the named key; anything else breaks the registry.
def test_enrollment_preconditions() -> None:
    chain = registry_chain()
    enroll(chain, P, actor=SYSTEM)
    assert broken(raw(chain)) == "registry_broken"
    chain = registry_chain()
    signed_event(
        chain, "attester_enrolled", {**enrollment(chain, P, ("attester",), None, None), "public_key": Q.public_key}
    )
    assert broken(raw(chain)) == "registry_broken"


# SPEC-006 R63: revocation reasons, permanence, `unknown_attester` and `already_revoked`.
def test_revocation() -> None:
    chain = registry_chain()
    enroll(chain, P)
    revoke(chain, P, "misconduct")
    revoke(chain, P, "retired")
    revoke(chain, Q, "error")
    registry = build(chain)
    entry = registry.attester(P.key_id)
    assert entry is not None
    assert entry.revoked is not None
    assert (entry.revoked.seq, entry.revoked.reason) == (2, "misconduct")
    assert findings(registry) == [(3, "already_revoked"), (4, "unknown_attester")]


# SPEC-006 R64: a rotation keeps the identity; a retired old key may still be rotated.
def test_rotation() -> None:
    chain = registry_chain()
    enroll(chain, P)
    revoke(chain, P, "retired")
    enroll(chain, Q, rotates=P)
    enroll(chain, S, rotates=Q)
    registry = build(chain)
    identities = {entry.attester_key_id: entry.identity for entry in registry.attesters}
    assert identities == {P.key_id: P.key_id, Q.key_id: P.key_id, S.key_id: P.key_id}
    assert registry.findings == ()


# SPEC-006 R64: unsigned by the old key, from an unknown key, a second successor, or from a compromised key.
def test_bad_rotation() -> None:
    chain = registry_chain()
    enroll(chain, P)
    enroll(chain, Q, rotates=P, rotation_by=Q)
    enroll(chain, Q, rotates=T)
    enroll(chain, S, rotates=P)
    enroll(chain, T, rotates=P)
    enroll(chain, U)
    revoke(chain, U, "compromised")
    enroll(chain, Q, rotates=U)
    registry = build(chain)
    assert findings(registry) == [(2, "bad_rotation"), (3, "bad_rotation"), (5, "bad_rotation"), (8, "bad_rotation")]
    assert registry.attester(Q.key_id) is None
    assert registry.attester(T.key_id) is None
    s_entry = registry.attester(S.key_id)
    assert s_entry is not None
    assert s_entry.identity == P.key_id


# SPEC-006 R67: inclusion findings, and the first inclusion stands.
def test_inclusions() -> None:
    chain = registry_chain()
    enroll(chain, P)
    enroll(chain, Q, ("reviewer",))
    include(chain, HASH_1, P)
    include(chain, HASH_1, P)
    include(chain, HASH_2, Q)
    include(chain, HASH_2, T)
    revoke(chain, P, "retired")
    include(chain, HASH_2, P)
    registry = build(chain)
    assert [(i.attestation_hash, i.attester_key_id, i.seq) for i in registry.inclusions] == [(HASH_1, P.key_id, 3)]
    assert findings(registry) == [
        (4, "already_included"),
        (5, "not_attester"),
        (6, "unknown_attester"),
        (8, "revoked_attester"),
    ]


# SPEC-006 R68, R89, R91: record reviews take effect only from an unrevoked reviewer with a valid signature;
# a `review` of an export has no effect on the registry.
def test_record_reviews() -> None:
    chain = registry_chain()
    enroll(chain, P, ("reviewer",))
    enroll(chain, Q)
    enroll(chain, S, ("reviewer",))
    revoke(chain, S, "retired")
    review_record(chain, P, HASH_1)
    review_record(chain, P, HASH_1, decision="rejected")
    review_record(chain, Q, HASH_1)
    review_record(chain, S, HASH_1)
    review_record(chain, T, HASH_1)
    review_record(chain, P, HASH_2, signer=Q)
    export_ref = {"event_id": chain[1].event_id, "seq": 1, "hash": chain[1].hash}
    export_review = review_payload(chain, P, HASH_2, export_ref=export_ref)
    add(chain, "review", export_review)
    registry = build(chain)
    assert [(r.golden_record_hash, r.decision, r.reviewer_key_id, r.seq) for r in registry.record_reviews] == [
        (HASH_1, "approved", P.key_id, 5),
        (HASH_1, "rejected", P.key_id, 6),
    ]
    assert findings(registry) == [
        (7, "not_reviewer"),
        (8, "revoked_reviewer"),
        (9, "unknown_reviewer"),
        (10, "bad_signature"),
    ]


# SPEC-006 R65: the registry is a pure function of the chain, whatever order the events are stored in.
def test_order_of_events_does_not_matter() -> None:
    chain = registry_chain()
    enroll(chain, P)
    enroll(chain, Q, rotates=P)
    include(chain, HASH_1, Q)
    revoke(chain, P, "retired")
    events = raw(chain)
    shuffled = list(events)
    random.Random(6).shuffle(shuffled)
    assert build(chain) == attester_registry(shuffled, [], VERIFIER)
    assert build(chain).registry_hash == attester_registry(shuffled, [], VERIFIER).registry_hash


# SPEC-006 R60, R65, R80 `registry_broken`: a broken chain, an empty one, or a CLI chain gives no registry.
def test_registry_broken() -> None:
    chain = registry_chain()
    enroll(chain, P)
    tampered = raw(chain)
    tampered[1]["payload"]["roles"] = ["attester", "reviewer"]
    assert broken(tampered) == "registry_broken"
    assert broken([]) == "registry_broken"
    cli: list[Event] = registry_chain(role="cli")
    assert verify_chain(raw(cli), [], VERIFIER).status == "intact"
    assert broken(raw(cli)) == "registry_broken"
    unsigned_rotation = raw(chain)
    unsigned_rotation[1]["payload"]["rotation_signature"] = "00" * 64
    assert broken(unsigned_rotation) == "registry_broken"


# SPEC-006 R66: outside test mode, enrolling a test key (A) is SPEC-005 R56 `test_key`, so `verify_chain` reports
# the chain broken and the registry raises `registry_broken` (the finding `test_key` cannot be reached here).
def test_test_key_enrollment_outside_test_mode() -> None:
    chain = registry_chain()
    enroll(chain, A)
    report = verify_chain(raw(chain), [], VERIFIER)
    assert [(finding.seq, finding.reason) for finding in report.findings] == [(1, "test_key")]
    assert broken(raw(chain)) == "registry_broken"
    registry = attester_registry(raw(chain), [], VERIFIER, test_mode=True)
    assert registry.attester(A.key_id) is not None
