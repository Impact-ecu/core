"""Field evidence (SPEC-006 §4-§11): attestations, the attester registry, `golden_field`, heads and reviews.

Pure (R4): imports `core.kernel` and `core.provenance` only. Events, anchors, the `Verifier`, `as_of` and every
identifier are inputs; `core` never holds an attester's private key or the commitment secret (R46, R49).
"""

from core.evidence._admission import EvidenceAdmission, FieldEvidence, VariantAdmission, evidence_admission
from core.evidence._attestation import (
    FieldAttestation,
    attestation_hash,
    canonical_dtcs,
    canonical_unit_id,
    parse_attestation,
    verify_attestation,
)
from core.evidence._errors import EvidenceError
from core.evidence._golden import (
    AttestationEntry,
    Counts,
    GoldenEvaluation,
    GoldenRecord,
    OracleTool,
    evaluate_golden,
    parse_golden_record,
)
from core.evidence._published import (
    DTC_SET_V1,
    HEAD_POLICY_V1,
    PUBLISHED_DTC_SETS,
    PUBLISHED_HEAD_POLICIES,
    E,
    K,
    N,
)
from core.evidence._registry import (
    AttesterRegistry,
    Inclusion,
    RecordReview,
    RegistryAttester,
    RegistryFinding,
    Revocation,
    attester_registry,
)
from core.evidence._review import ReviewFinding, ReviewStatus, review_status

__all__ = [
    "DTC_SET_V1",
    "HEAD_POLICY_V1",
    "PUBLISHED_DTC_SETS",
    "PUBLISHED_HEAD_POLICIES",
    "AttestationEntry",
    "AttesterRegistry",
    "Counts",
    "E",
    "EvidenceAdmission",
    "EvidenceError",
    "FieldAttestation",
    "FieldEvidence",
    "GoldenEvaluation",
    "GoldenRecord",
    "Inclusion",
    "K",
    "N",
    "OracleTool",
    "RecordReview",
    "RegistryAttester",
    "RegistryFinding",
    "ReviewFinding",
    "ReviewStatus",
    "Revocation",
    "VariantAdmission",
    "attestation_hash",
    "attester_registry",
    "canonical_dtcs",
    "canonical_unit_id",
    "evaluate_golden",
    "evidence_admission",
    "parse_attestation",
    "parse_golden_record",
    "review_status",
    "verify_attestation",
]
