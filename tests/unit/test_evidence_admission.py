"""SPEC-006 §7.3, §9: signed registry heads, freshness and variant admission beyond A1-A8."""

from collections.abc import Callable
from functools import partial
from typing import Any

import pytest

from core.evidence import AttesterRegistry, EvidenceAdmission, EvidenceError, FieldEvidence, evidence_admission
from core.provenance import Raw
from tests.unit.evidence_support import (
    DEV,
    DTC_SET,
    EPOCH,
    GOLDEN,
    POLICY,
    POOL,
    POST,
    SIGNER,
    TRUST,
    V,
    attestation,
    build,
    enroll,
    head_for,
    include,
    record,
    registry_chain,
    review_record,
    revoke,
    sha,
    sign_head,
    signed,
)
from tests.unit.provenance_support import VERIFIER, Ed25519Signer

AS_OF = "2026-10-19T12:00:00Z"
GOOD = record(POOL["AX"]["attestation_hash"], POOL["BY"]["attestation_hash"])
P, Q, S, T, U = (DEV[name] for name in ("p", "q", "s", "t", "u"))


def reason_of(call: Callable[[], object]) -> str:
    with pytest.raises(EvidenceError) as caught:
        call()
    return caught.value.reason


def evidence(head: Raw, *, records: list[Any] | None = None, registry: AttesterRegistry = POST) -> FieldEvidence:
    return FieldEvidence(head, registry, [GOOD] if records is None else records, list(POOL.values()), DTC_SET, EPOCH)


def admit(
    value: FieldEvidence | None, *, as_of: str = AS_OF, test_mode: bool = True, trust: Raw = TRUST, policy: Raw = POLICY
) -> EvidenceAdmission:
    return evidence_admission(value, trust, policy, as_of, VERIFIER, test_mode=test_mode)


def current(**changes: object) -> dict[str, Any]:
    return sign_head(head_for(POST, **changes))


# SPEC-006 R83: without evidence the status is `unavailable` and nothing is admitted.
def test_missing_evidence() -> None:
    admission = admit(None)
    assert admission.to_json() == {
        "schema": "impact.evidence-admission.v1",
        "status": "unavailable",
        "reasons": ["missing_evidence"],
        "head_digest": None,
        "variants": [],
    }
    assert admission.golden_field("synthetic.family", "synthetic.variant.1") is False


# SPEC-006 R82, R80 `unpublished_head_policy`: only a published policy is used.
@pytest.mark.parametrize(
    "policy",
    [{**POLICY, "max_validity_s": 172800}, {**POLICY, "version": 2}, {**POLICY, "max_validity_s": 86400.0}, None],
)
def test_unpublished_head_policy(policy: Raw) -> None:
    assert reason_of(lambda: admit(evidence(current()), policy=policy)) == "unpublished_head_policy"
    assert reason_of(lambda: admit(None, policy=policy)) == "unpublished_head_policy"


# SPEC-006 R60, R80 `bad_shape`: the trust anchor's key_id is the hash of its public key.
@pytest.mark.parametrize(
    "trust",
    [{**TRUST, "key_id": SIGNER.key_id}, {**TRUST, "tenant_id": "Tenant"}, {**TRUST, "extra": 1}, "trust"],
)
def test_bad_trust(trust: Raw) -> None:
    assert reason_of(lambda: admit(None, trust=trust)) == "bad_shape"


# SPEC-005 R5, SPEC-006 R82: `as_of` and head times are real UTC seconds.
@pytest.mark.parametrize(
    "as_of",
    [
        "2026-02-29T00:00:00Z",
        "2026-04-31T00:00:00Z",
        "2026-13-01T00:00:00Z",
        "2026-00-01T00:00:00Z",
        "0000-01-01T00:00:00Z",
        "2026-10-19T24:00:00Z",
        "2026-10-19T00:60:00Z",
        "2026-10-19T00:00:60Z",
        "2026-10-19T00:00:00Z\n",
        "2026-10-19T00:00:00",
    ],
)
def test_bad_as_of(as_of: str) -> None:
    assert reason_of(lambda: admit(None, as_of=as_of)) == "bad_shape"


# SPEC-006 R82: leap days and the Gregorian century rule are UTC instants like any other.
def test_calendar_instants() -> None:
    assert admit(None, as_of="2028-02-29T23:59:59Z").reasons == ("missing_evidence",)
    assert admit(None, as_of="2000-02-29T00:00:00Z").reasons == ("missing_evidence",)
    assert reason_of(lambda: admit(None, as_of="2100-02-29T00:00:00Z")) == "bad_shape"
    leap = sign_head(head_for(POST, issued_at="2028-02-28T12:00:00Z", expires_at="2028-02-29T12:00:00Z"))
    assert admit(evidence(leap), as_of="2028-02-29T11:59:59Z").status == "current"
    across = sign_head(head_for(POST, issued_at="2026-12-31T12:00:00Z", expires_at="2027-01-01T12:00:00Z"))
    assert admit(evidence(across), as_of="2027-01-01T00:00:00Z").status == "current"


def _signed_with(**changes: object) -> dict[str, Any]:
    return {**current(), **changes}


# SPEC-006 R2, R81, R80 `bad_shape`: a signed head of any other shape.
@pytest.mark.parametrize(
    "head",
    [
        None,
        _signed_with(extra=1),
        _signed_with(signature="00" * 63),
        _signed_with(head_digest="AB" * 32),
        _signed_with(key_id=None),
        current(seq=-1),
        current(schema="impact.registry-head.v2"),
        current(tenant_id="Tenant"),
        current(head_hash="00"),
        current(issued_at="2026-10-19"),
        current(expires_at="2026-02-30T00:00:00Z"),
        current(extra=None),
    ],
)
def test_bad_head_shape(head: Raw) -> None:
    assert reason_of(lambda: admit(evidence(head))) == "bad_shape"


# SPEC-006 R66, R82: `untrusted_head` stops the checks, and a test-key head is untrusted outside test mode.
@pytest.mark.parametrize(
    ("head", "test_mode"),
    [
        (current(tenant_id="tenant-other"), True),
        (current(genesis_hash="00" * 32), True),
        (sign_head(head_for(POST), SIGNER), True),
        (V["heads"]["values"]["post"], False),
        ({**current(), "head": head_for(POST, seq=11)}, True),
        (V["heads"]["values"]["bad_signature"], True),
        ({**current(), "signature": sign_head(head_for(POST), SIGNER)["signature"]}, True),
        ({**sign_head(head_for(POST, expires_at="2030-01-01T00:00:00Z")), "key_id": "00" * 32}, True),
    ],
)
def test_untrusted_head(head: Raw, test_mode: bool) -> None:
    admission = admit(evidence(head), test_mode=test_mode)
    assert (admission.status, admission.reasons, admission.head_digest, admission.variants) == (
        "unavailable",
        ("untrusted_head",),
        None,
        (),
    )


# SPEC-006 R82: boundaries `issued_at <= as_of < expires_at` and `expires_at - issued_at <= max_validity_s`.
def test_freshness_boundaries() -> None:
    assert admit(evidence(current()), as_of="2026-10-19T00:00:00Z").status == "current"
    assert admit(evidence(current()), as_of="2026-10-19T23:59:59Z").status == "current"
    assert admit(evidence(current()), as_of="2026-10-18T23:59:59Z").reasons == ("head_not_yet_valid",)
    assert admit(evidence(current()), as_of="2026-10-20T00:00:00Z").reasons == ("head_expired",)
    exact = current(issued_at="2026-10-19T00:00:00Z", expires_at="2026-10-20T00:00:00Z")
    assert admit(evidence(exact)).status == "current"
    long = current(expires_at="2026-10-20T00:00:01Z")
    assert admit(evidence(long)).reasons == ("head_validity_too_long",)


# SPEC-006 R82, R83: every reason that applies after the head is trusted, sorted.
def test_all_freshness_reasons() -> None:
    head = current(issued_at="2026-10-21T00:00:00Z", expires_at="2026-10-10T00:00:00Z", registry_hash="00" * 32)
    assert admit(evidence(head)).reasons == ("head_expired", "head_not_yet_valid", "registry_mismatch")
    stale = current(seq=11)
    assert admit(evidence(stale)).reasons == ("registry_mismatch",)
    other_hash = current(head_hash="00" * 32)
    assert admit(evidence(other_hash)).reasons == ("registry_mismatch",)


# SPEC-006 R70, R83, R80 `duplicate_record`: two records with one key, even with different oracles.
def test_duplicate_record() -> None:
    other_oracle = record(POOL["AX"]["attestation_hash"])
    assert reason_of(lambda: admit(evidence(current(), records=[GOOD, other_oracle]))) == "duplicate_record"
    assert reason_of(lambda: admit(evidence(current(), records=[GOOD, GOOD]))) == "duplicate_record"
    assert admit(evidence(current(), records=[GOOD, {**GOOD, "version_hash": "00" * 32}])).status == "current"


# SPEC-006 R83: variants sorted by (family, variant); one without a golden_field record is `no_golden_field`;
# a malformed record is `bad_shape`.
def test_variants() -> None:
    records = [
        {**GOOD, "checksum_variant_id": "b.variant"},
        {**GOOD, "family": "a.family"},
        GOOD,
    ]
    admission = admit(evidence(current(), records=records))
    assert [(v.family, v.checksum_variant_id, v.golden_field, v.reasons) for v in admission.variants] == [
        ("a.family", "synthetic.variant.1", False, ("no_golden_field",)),
        ("synthetic.family", "b.variant", False, ("no_golden_field",)),
        ("synthetic.family", "synthetic.variant.1", True, ()),
    ]
    assert admission.golden_field("synthetic.family", "synthetic.variant.1") is True
    assert admission.golden_field("synthetic.family", "b.variant") is False
    assert admission.golden_field("synthetic.family", "unknown") is False
    assert admit(evidence(current(), records=[])).variants == ()
    assert reason_of(lambda: admit(evidence(current(), records=[{**GOOD, "level": "golden_field"}]))) == "bad_shape"


# --- R83, R89 outside test mode: a negative needs a valid approval by an independent reviewer ---

SECOND = "77" * 32


def _field(key: Ed25519Signer, unit: str | None, subject: str = GOLDEN, **changes: object) -> dict[str, Any]:
    return signed(attestation(key, unit, subject_image_hash=subject, readback_image_hash=subject, **changes), key)


PX, QY, UZ = _field(P, "X"), _field(Q, "Y"), _field(U, "Z", communicates=False)
PX2, QY2 = _field(P, "X", SECOND), _field(Q, "Y", SECOND)
NEGATIVE = record(PX["attestation_hash"], QY["attestation_hash"], UZ["attestation_hash"])
RENEWED = record(PX2["attestation_hash"], QY2["attestation_hash"], version_hash="88" * 32, expected_image_hash=SECOND)
NEGATIVE_HASH = sha(NEGATIVE)
APPROVE = partial(review_record, reviewer=S, subject_hash=NEGATIVE_HASH)


def scenario(*steps: Callable[[list[Any]], object], as_of: str = AS_OF) -> EvidenceAdmission:
    """The registry chain with P, Q, U attesters, S a reviewer and T a reviewer rotated from P, then `steps`."""
    chain = registry_chain()
    for key in (P, Q, U):
        enroll(chain, key)
    enroll(chain, S, ("reviewer",))
    enroll(chain, T, ("reviewer",), rotates=P)
    for step in steps:
        step(chain)
    registry = build(chain)
    head = sign_head(head_for(registry), SIGNER)
    trust = {
        "tenant_id": chain[0].tenant_id,
        "genesis_hash": chain[0].hash,
        "key_id": SIGNER.key_id,
        "public_key": SIGNER.public_key,
    }
    bundle = FieldEvidence(head, registry, [NEGATIVE, RENEWED], [PX, QY, UZ, PX2, QY2], DTC_SET, EPOCH)
    return evidence_admission(bundle, trust, POLICY, as_of, VERIFIER)


def _reasons(admission: EvidenceAdmission) -> tuple[bool, tuple[str, ...]]:
    (variant,) = admission.variants
    return variant.golden_field, variant.reasons


def test_negative_needs_review() -> None:
    assert _reasons(scenario()) == (False, ("unreviewed_negative",))
    assert _reasons(scenario(APPROVE)) == (True, ())
    other = partial(review_record, reviewer=S, subject_hash="00" * 32)
    assert _reasons(scenario(other)) == (False, ("unreviewed_negative",))


# SPEC-006 R89: a rejection wins over any approval, before or after it.
def test_rejection_wins() -> None:
    reject = partial(review_record, reviewer=S, subject_hash=NEGATIVE_HASH, decision="rejected")
    assert _reasons(scenario(reject, APPROVE)) == (False, ("rejected_negative",))
    assert _reasons(scenario(APPROVE, reject)) == (False, ("rejected_negative",))


# SPEC-006 R83, R64: a reviewer whose identity attested in the record does not count, even through a rotation.
def test_reviewer_independent_of_attesters() -> None:
    by_rotated_attester = partial(review_record, reviewer=T, subject_hash=NEGATIVE_HASH)
    assert _reasons(scenario(by_rotated_attester)) == (False, ("unreviewed_negative",))


# SPEC-006 R77 applied to reviews: a compromised reviewer's approval is void; a retired one's earlier approval stands.
def test_revoked_reviewer() -> None:
    compromised, retired = partial(revoke, key=S, reason="compromised"), partial(revoke, key=S, reason="retired")
    assert _reasons(scenario(APPROVE, compromised)) == (False, ("unreviewed_negative",))
    assert _reasons(scenario(APPROVE, retired)) == (True, ())


# SPEC-006 R74: a negative is never resolved by more positives alone, and evaluations are listed sorted.
def test_negative_blocks_record_but_not_renewed_evidence() -> None:
    admission = scenario(partial(include, attestation_hash=PX["attestation_hash"], key=P))
    (variant,) = admission.variants
    assert variant.evaluations == tuple(sorted(variant.evaluations))
    assert len(variant.evaluations) == 2
    assert admission.status == "current"
    assert admission.head_digest is not None


# SPEC-006 R83: attesters outside the registry contribute no identity; the negative still needs a review.
def test_unknown_attester_in_a_negative_record() -> None:
    hashes = [POOL[label]["attestation_hash"] for label in ("AX", "BY", "EZ_NOCOMM", "DY")]
    admission = admit(evidence(current(), records=[record(*hashes)]))
    assert [(v.golden_field, v.reasons) for v in admission.variants] == [
        (False, ("no_golden_field", "unreviewed_negative"))
    ]
