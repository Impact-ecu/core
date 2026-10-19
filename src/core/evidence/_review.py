"""Review of an export by a second enrolled key (SPEC-006 §9, R90-R93)."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from core.evidence._errors import EvidenceError
from core.evidence._json import HEX32, matches, verified
from core.evidence._registry import REVIEW_DOMAIN, REVIEWER_REASONS, AttesterRegistry, RegistryAttester, review_hash
from core.provenance import Event, Json, Verifier

ReviewDecision = Literal["approved", "rejected", "none"]


@dataclass(frozen=True, slots=True)
class ReviewFinding:
    seq: int
    reason: str


@dataclass(frozen=True, slots=True)
class ReviewStatus:
    """R92. A rejection is never overridden by a later approval."""

    status: ReviewDecision
    reasons: tuple[ReviewFinding, ...]

    def to_json(self) -> Mapping[str, Json]:
        return {"status": self.status, "reasons": [{"seq": f.seq, "reason": f.reason} for f in self.reasons]}


def _names_export(review: Event, export_event: Event) -> bool:
    payload = review.payload
    ref = payload.get("export_ref")
    return (
        review.type == "review"
        and payload.get("subject_kind") == "export"
        and isinstance(ref, Mapping)
        and ref.get("event_id") == export_event.event_id
    )


def _reason(
    review: Event,
    export_event: Event,
    report_hash: str,
    registry: AttesterRegistry,
    verifier: Verifier,
    genesis_hash: str,
) -> str | None:
    """R92: the first failed check of one review, in the order the rule lists them."""
    payload = review.payload
    ref = payload.get("export_ref")
    if not isinstance(ref, Mapping) or dict(ref) != dict(export_event.ref) or review.seq <= export_event.seq:
        return "bad_export_ref"
    if payload.get("subject_hash") != report_hash:
        return "report_mismatch"
    reviewer_key_id = str(payload.get("reviewer_key_id"))
    entry = registry.attester(reviewer_key_id)
    reason = _reviewer_reason(entry)
    if reason is not None or entry is None:
        return reason
    if reviewer_key_id == export_event.payload.get("key_id") or review.actor.id == export_event.actor.id:
        return "same_person"
    signed_hash = review_hash(export_event.tenant_id, genesis_hash, payload)
    if not verified(verifier, entry.public_key, REVIEW_DOMAIN, signed_hash, str(payload.get("signature"))):
        return "bad_signature"
    return None


def _reviewer_reason(entry: RegistryAttester | None) -> str | None:
    """R92: enrolled, never revoked, with the `reviewer` role."""
    if entry is None:
        return REVIEWER_REASONS["unknown"]
    if entry.revoked is not None:
        return REVIEWER_REASONS["revoked"]
    return None if "reviewer" in entry.roles else REVIEWER_REASONS["role"]


def review_status(
    export_event: Event,
    report_hash: str,
    reviews: Sequence[Event],
    registry: AttesterRegistry,
    verifier: Verifier,
    *,
    genesis_hash: str,
) -> ReviewStatus:
    """R92 over every `review` with `subject_kind: export` whose `export_ref` names `export_event` by `event_id`.

    `genesis_hash` is the export chain's: R91 binds the review signature to it and an `Event` does not carry it.
    """
    if export_event.type != "export" or not matches(report_hash, HEX32) or not matches(genesis_hash, HEX32):
        raise EvidenceError("bad_shape", "an export event, its report_hash and its chain's genesis_hash")
    findings: list[ReviewFinding] = []
    decisions: set[str] = set()
    for review in reviews:
        if not _names_export(review, export_event):
            continue
        reason = _reason(review, export_event, report_hash, registry, verifier, genesis_hash)
        if reason is None:
            decisions.add(str(review.payload.get("decision")))
        else:
            findings.append(ReviewFinding(review.seq, reason))
    status: ReviewDecision = (
        "rejected" if "rejected" in decisions else "approved" if "approved" in decisions else "none"
    )
    return ReviewStatus(status, tuple(sorted(findings, key=_finding_order)))


def _finding_order(finding: ReviewFinding) -> tuple[int, str]:
    return finding.seq, finding.reason
