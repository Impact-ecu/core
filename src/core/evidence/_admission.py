"""Signed registry heads, their freshness and variant admission (SPEC-006 §7.3, R81-R83).

`core` has no clock: `as_of` is supplied by the caller. An expired head is never used, even when nothing newer is
reachable, so withholding a revocation cannot outlive one validity period (R82).
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from core.evidence._errors import EvidenceError, ensure
from core.evidence._golden import GoldenEvaluation, GoldenRecord, evaluate, parse_golden_record
from core.evidence._json import (
    HEX32,
    SIG,
    TENANT_ID,
    digest,
    exact,
    instant,
    matches,
    sha256_hex,
    try_jcs,
    uint,
    verified,
)
from core.evidence._published import PUBLISHED_HEAD_POLICIES, E, K, N
from core.evidence._registry import AttesterRegistry
from core.provenance import TEST_KEY_IDS, Head, Raw, Verifier

ADMISSION_SCHEMA = "impact.evidence-admission.v1"
HEAD_SCHEMA = "impact.registry-head.v1"
HEAD_DOMAIN = "impact.registry-head-signature.v1"
HEAD_KEYS = frozenset(
    {"schema", "tenant_id", "genesis_hash", "seq", "head_hash", "registry_hash", "issued_at", "expires_at"}
)
SIGNED_HEAD_KEYS = frozenset({"head", "head_digest", "key_id", "signature"})
TRUST_KEYS = frozenset({"tenant_id", "genesis_hash", "key_id", "public_key"})

Status = Literal["current", "unavailable"]


@dataclass(frozen=True, slots=True)
class FieldEvidence:
    """The bundle the gate receives (R83): a signed head, the registry at it, records and their attestations."""

    head: Raw
    registry: AttesterRegistry
    records: Sequence[Raw]
    attestations: Sequence[Raw]
    dtc_set: Raw
    commitment_epoch: str


@dataclass(frozen=True, slots=True)
class VariantAdmission:
    family: str
    checksum_variant_id: str
    golden_field: bool
    reasons: tuple[str, ...]
    evaluations: tuple[str, ...]

    def to_json(self) -> Mapping[str, Raw]:
        return {
            "family": self.family,
            "checksum_variant_id": self.checksum_variant_id,
            "golden_field": self.golden_field,
            "reasons": list(self.reasons),
            "evaluations": list(self.evaluations),
        }


@dataclass(frozen=True, slots=True)
class EvidenceAdmission:
    """R83. `variants` is empty unless `status` is `current`."""

    status: Status
    reasons: tuple[str, ...]
    head_digest: str | None
    variants: tuple[VariantAdmission, ...]

    def to_json(self) -> Mapping[str, Raw]:
        return {
            "schema": ADMISSION_SCHEMA,
            "status": self.status,
            "reasons": list(self.reasons),
            "head_digest": self.head_digest,
            "variants": [variant.to_json() for variant in self.variants],
        }

    def golden_field(self, family: str, checksum_variant_id: str) -> bool:
        """R84: true only for a variant reported with `golden_field: true` under status `current`."""
        return self.status == "current" and any(
            (v.family, v.checksum_variant_id) == (family, checksum_variant_id) and v.golden_field for v in self.variants
        )


def _unavailable(reasons: Sequence[str]) -> EvidenceAdmission:
    return EvidenceAdmission("unavailable", tuple(sorted(reasons)), None, ())


def _max_validity(policy: Raw) -> int:
    """R82: a published `HeadPolicy`, else `unpublished_head_policy`."""
    encoded = try_jcs(policy)
    if encoded is None or sha256_hex(encoded) not in PUBLISHED_HEAD_POLICIES:
        raise EvidenceError("unpublished_head_policy", "the head policy is not one core publishes")
    value = policy.get("max_validity_s") if isinstance(policy, Mapping) else None
    return value if isinstance(value, int) else 0


def _trust(trust: Raw) -> Mapping[str, Raw]:
    """R60: the pinned `RegistryTrust`; its `key_id` is the SHA-256 of its public key (SPEC-005 R50)."""
    if not (
        exact(trust, TRUST_KEYS)
        and matches(trust["tenant_id"], TENANT_ID)
        and all(matches(trust[key], HEX32) for key in ("genesis_hash", "key_id", "public_key"))
        and sha256_hex(bytes.fromhex(str(trust["public_key"]))) == trust["key_id"]
    ):
        raise EvidenceError("bad_shape", "not a RegistryTrust (SPEC-006 R60)")
    return trust


def _signed_head(value: Raw) -> tuple[Mapping[str, Raw], int, int]:
    """R2, R81: the `SignedRegistryHead` and its two instants, else `bad_shape`."""
    head = value.get("head") if isinstance(value, Mapping) else None
    issued = instant(head.get("issued_at")) if isinstance(head, Mapping) else None
    expires = instant(head.get("expires_at")) if isinstance(head, Mapping) else None
    if not (
        exact(value, SIGNED_HEAD_KEYS)
        and exact(head, HEAD_KEYS)
        and head["schema"] == HEAD_SCHEMA
        and matches(head["tenant_id"], TENANT_ID)
        and uint(head["seq"])
        and all(matches(head[key], HEX32) for key in ("genesis_hash", "head_hash", "registry_hash"))
        and matches(value["head_digest"], HEX32)
        and matches(value["key_id"], HEX32)
        and matches(value["signature"], SIG)
        and issued is not None
        and expires is not None
    ):
        raise EvidenceError("bad_shape", "not a SignedRegistryHead with UTC timestamps (SPEC-006 R81)")
    return value, issued, expires


def _head_reasons(
    evidence: FieldEvidence, trust: Mapping[str, Raw], max_validity: int, now: int, verifier: Verifier, test_mode: bool
) -> tuple[list[str], str]:
    """R82: `untrusted_head` alone, or every freshness and binding reason that applies; and the `head_digest`."""
    signed, issued, expires = _signed_head(evidence.head)
    head = signed["head"]
    head_map = head if isinstance(head, Mapping) else {}
    key_id, head_digest = str(signed["key_id"]), str(signed["head_digest"])
    trusted = (
        (head_map["tenant_id"], head_map["genesis_hash"], key_id)
        == (trust["tenant_id"], trust["genesis_hash"], trust["key_id"])
        and (test_mode or key_id not in TEST_KEY_IDS)
        and digest(head) == head_digest
        and verified(verifier, str(trust["public_key"]), HEAD_DOMAIN, head_digest, str(signed["signature"]))
    )
    if not trusted:
        return ["untrusted_head"], head_digest
    registry = evidence.registry
    seq = head_map["seq"]
    named = Head(seq if isinstance(seq, int) else -1, str(head_map["head_hash"]))
    bound = registry.registry_hash == head_map["registry_hash"] and registry.head == named
    reasons = [
        reason
        for reason, applies in (
            ("head_not_yet_valid", not issued <= now),
            ("head_expired", not now < expires),
            ("head_validity_too_long", expires - issued > max_validity),
            ("registry_mismatch", not bound),
        )
        if applies
    ]
    return reasons, head_digest


def _attesting_identities(record: GoldenRecord, evidence: FieldEvidence) -> set[str]:
    """R83, R89: identities of the keys of every supplied attestation the record lists."""
    identities: set[str] = set()
    for supplied in evidence.attestations:
        if not isinstance(supplied, Mapping) or supplied.get("attestation_hash") not in record.attestations:
            continue
        attestation = supplied.get("attestation")
        key_id = attestation.get("attester_key_id") if isinstance(attestation, Mapping) else None
        entry = evidence.registry.attester(key_id) if isinstance(key_id, str) else None
        if entry is not None:
            identities.add(entry.identity)
    return identities


def _review_reason(record: GoldenRecord, evaluation: GoldenEvaluation, evidence: FieldEvidence) -> str | None:
    """R83, R89: a record holding a negative needs a valid approval and no valid rejection."""
    if "negative_field_evidence" not in evaluation.reasons:
        return None
    attesting = _attesting_identities(record, evidence)
    registry = evidence.registry
    decisions: set[str] = set()
    for review in registry.record_reviews:
        reviewer = registry.attester(review.reviewer_key_id)
        if review.golden_record_hash != record.golden_record_hash or reviewer is None:
            continue
        # R77 applied to reviews: a retroactive revocation voids the key's earlier decisions too.
        if reviewer.counts_at(review.seq) and reviewer.identity not in attesting:
            decisions.add(review.decision)
    if "rejected" in decisions:
        return "rejected_negative"
    return None if "approved" in decisions else "unreviewed_negative"


def _meets_thresholds(evaluation: GoldenEvaluation) -> bool:
    counts = evaluation.counts
    return (
        min(counts.attestations - N, counts.attesters - K, counts.units - E) >= 0
        and "negative_field_evidence" not in evaluation.reasons
    )


def _variant(records: Sequence[GoldenRecord], evidence: FieldEvidence, verifier: Verifier) -> VariantAdmission:
    evaluations = [
        evaluate(
            record, evidence.attestations, evidence.registry, evidence.dtc_set, evidence.commitment_epoch, verifier
        )
        for record in records
    ]
    reasons = {
        reason
        for record, evaluation in zip(records, evaluations, strict=True)
        if (reason := _review_reason(record, evaluation, evidence)) is not None
    }
    if not any(evaluation.level == "golden_field" for evaluation in evaluations):
        reasons.add("no_golden_field")
    # R83, R75: an admitted variant has a record whose counts meet N, K and E with no negative evidence.
    ensure(bool(reasons) or any(_meets_thresholds(evaluation) for evaluation in evaluations), "SPEC-006 R83")
    return VariantAdmission(
        family=records[0].family,
        checksum_variant_id=records[0].checksum_variant_id,
        golden_field=not reasons,
        reasons=tuple(sorted(reasons)),
        evaluations=tuple(sorted(evaluation.evaluation_hash for evaluation in evaluations)),
    )


def evidence_admission(
    evidence: FieldEvidence | None,
    trust: Raw,
    policy: Raw,
    as_of: str,
    verifier: Verifier,
    *,
    test_mode: bool = False,
) -> EvidenceAdmission:
    """R83: pure; `unavailable` admits nothing, `current` reports every variant of `evidence.records`."""
    max_validity = _max_validity(policy)
    anchor = _trust(trust)
    now = instant(as_of)
    if now is None:
        raise EvidenceError("bad_shape", "as_of is a UTC Timestamp (SPEC-005 R5)")
    if evidence is None:
        return _unavailable(["missing_evidence"])
    reasons, head_digest = _head_reasons(evidence, anchor, max_validity, now, verifier, test_mode)
    if reasons:
        return _unavailable(reasons)
    records = [parse_golden_record(record) for record in evidence.records]
    if len({record.key for record in records}) != len(records):
        raise EvidenceError("duplicate_record", "two golden records share one R70 key")
    groups: dict[tuple[str, str], list[GoldenRecord]] = {}
    for record in records:
        groups.setdefault((record.family, record.checksum_variant_id), []).append(record)
    variants = tuple(_variant(groups[key], evidence, verifier) for key in sorted(groups))
    return EvidenceAdmission("current", (), head_digest, variants)
