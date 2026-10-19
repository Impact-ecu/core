"""SPEC-006 §9 R90-R93: `review_status` of an export, with every reason of R92."""

from collections.abc import Callable
from dataclasses import replace
from typing import Any

import pytest

from core.evidence import EvidenceError, review_status
from core.provenance import Actor, Event
from tests.unit.evidence_support import DEV, build, enroll, registry_chain, review_payload, revoke
from tests.unit.provenance_support import VERIFIER, Ed25519Signer, add, dev_key, start

P, Q, S, T, U = (DEV[name] for name in ("p", "q", "s", "t", "u"))
REPORT = "ab" * 32
EXPORTER = dev_key("exporting cli")

# The registry: S and U are reviewers, P only an attester, T a reviewer revoked as retired.
_registry_chain = registry_chain()
enroll(_registry_chain, S, ("reviewer",))
enroll(_registry_chain, U, ("attester", "reviewer"))
enroll(_registry_chain, P)
enroll(_registry_chain, T, ("reviewer",))
revoke(_registry_chain, T, "retired")
REGISTRY = build(_registry_chain)

# The export chain: genesis, an import and the export, by the exporting user.
CHAIN = [start(EXPORTER, role="cli")]
add(
    CHAIN,
    "import",
    {"artifact_sha256": "bb" * 32, "image_hash": "aa" * 32, "dump_kind": "bench_full", "origin": "bench_read"},
)
EXPORT = add(
    CHAIN,
    "export",
    {"provenance_hash": "cd" * 32, "report_hash": REPORT, "key_id": EXPORTER.key_id, "signature": "ef" * 64},
)
GENESIS = CHAIN[0].hash
REVIEWER_ACTOR = Actor("user", "user-reviewer")


def review(
    reviewer: Ed25519Signer = S,
    *,
    decision: str = "approved",
    actor: Actor = REVIEWER_ACTOR,
    export_ref: dict[str, Any] | None = None,
    subject_hash: str = REPORT,
    signer: Ed25519Signer | None = None,
) -> Event:
    """A review of EXPORT appended to the export chain, signed per R91."""
    payload = review_payload(
        CHAIN,
        reviewer,
        subject_hash,
        decision=decision,
        export_ref=export_ref or dict(EXPORT.ref),
        signer=signer,
    )
    return add(list(CHAIN), "review", payload, actor=actor)


def status(*reviews: Event) -> tuple[str, list[tuple[int, str]]]:
    result = review_status(EXPORT, REPORT, list(reviews), REGISTRY, VERIFIER, genesis_hash=GENESIS)
    return result.status, [(finding.seq, finding.reason) for finding in result.reasons]


def reason_of(call: Callable[[], object]) -> str:
    with pytest.raises(EvidenceError) as caught:
        call()
    return caught.value.reason


# SPEC-006 R90, R92: no review is `none`; a valid approval is `approved`. R93: distinct keys and actor ids are all
# `core` can check; that they are two humans is the operator's enrollment decision.
def test_status() -> None:
    assert status() == ("none", [])
    assert status(review()) == ("approved", [])
    approval = review_status(EXPORT, REPORT, [review()], REGISTRY, VERIFIER, genesis_hash=GENESIS)
    assert approval.to_json() == {"status": "approved", "reasons": []}


# SPEC-006 R89, R92: any valid rejection wins, before or after an approval; a new export is needed.
def test_rejection_wins() -> None:
    assert status(review(), review(U, decision="rejected")) == ("rejected", [])
    assert status(review(U, decision="rejected"), review()) == ("rejected", [])


# SPEC-006 R92: each invalid review is listed with its first failed check and ignored.
def test_invalid_reviews() -> None:
    wrong_seq = {**EXPORT.ref, "seq": EXPORT.seq - 1}
    early = replace(review(), seq=EXPORT.seq)
    cases = [
        (review(export_ref=wrong_seq), "bad_export_ref"),
        (review(export_ref={**EXPORT.ref, "hash": "00" * 32}), "bad_export_ref"),
        (early, "bad_export_ref"),
        (review(subject_hash="00" * 32), "report_mismatch"),
        (review(Q), "unknown_reviewer"),
        (review(T), "revoked_reviewer"),
        (review(P), "not_reviewer"),
        (review(actor=Actor("user", "user-1")), "same_person"),
        (review(signer=U), "bad_signature"),
    ]
    for event, reason in cases:
        assert status(event) == ("none", [(event.seq, reason)]), reason
    assert status(review(decision="rejected", signer=U), review()) == ("approved", [(3, "bad_signature")])


# SPEC-006 R92 `same_person`: the reviewer key may not be the exporting key.
def test_same_key() -> None:
    chain = registry_chain()
    enroll(chain, EXPORTER, ("reviewer",))
    registry = build(chain)
    payload = review_payload(CHAIN, EXPORTER, REPORT, export_ref=dict(EXPORT.ref))
    event = add(list(CHAIN), "review", payload, actor=REVIEWER_ACTOR)
    result = review_status(EXPORT, REPORT, [event], registry, VERIFIER, genesis_hash=GENESIS)
    assert (result.status, [(f.seq, f.reason) for f in result.reasons]) == ("none", [(3, "same_person")])


# SPEC-006 R91, R92: reviews of other exports, golden-record reviews and other events are not considered.
def test_unrelated_events() -> None:
    other_ref = {**EXPORT.ref, "event_id": "f" * 32}
    golden = review_payload(CHAIN, S, REPORT)
    assert status(review(export_ref=other_ref), add(list(CHAIN), "review", golden), CHAIN[1]) == ("none", [])


# SPEC-006 R92, R80 `bad_shape`: the export event, its report hash and the export chain's genesis hash.
def test_preconditions() -> None:
    assert (
        reason_of(lambda: review_status(CHAIN[1], REPORT, [], REGISTRY, VERIFIER, genesis_hash=GENESIS)) == "bad_shape"
    )
    assert reason_of(lambda: review_status(EXPORT, "ab", [], REGISTRY, VERIFIER, genesis_hash=GENESIS)) == "bad_shape"
    assert reason_of(lambda: review_status(EXPORT, REPORT, [], REGISTRY, VERIFIER, genesis_hash="x")) == "bad_shape"
