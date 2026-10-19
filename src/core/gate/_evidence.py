"""Field evidence at the gate (SPEC-004 R16; SPEC-006 R60, R82-R84).

The gate runs `core.evidence.evidence_admission` itself, with the registry trust anchor and the head policy
published with the core release, and never takes an admission or a level from the caller (R16). Fail-closed:
without evidence, without a verifier, without a published trust anchor, or with evidence that `core.evidence`
rejects, the admission is `unavailable`, no variant is admitted, and the run blocks through R13 and R26.
"""

from collections.abc import Callable

from core.evidence import HEAD_POLICY_V1, EvidenceAdmission, EvidenceError, FieldEvidence, evidence_admission
from core.provenance import Raw, Verifier

# SPEC-006 R60: `RegistryTrust` of the operator's registry chain, published with each core release. None is
# published yet (the registry does not exist), so the published gate admits no variant for recalculation.
REGISTRY_TRUST: Raw = None

type EvidenceAdmissionFn = Callable[[FieldEvidence | None, str, Verifier | None], EvidenceAdmission]


def _unavailable(reason: str) -> EvidenceAdmission:
    return EvidenceAdmission("unavailable", (reason,), None, ())


def admission_with(trust: Raw) -> EvidenceAdmissionFn:
    """SPEC-006 R83 under `trust` and the published head policy, outside `test_mode` (R66)."""

    def admit(evidence: FieldEvidence | None, as_of: str, verifier: Verifier | None) -> EvidenceAdmission:
        if evidence is None:
            return _unavailable("missing_evidence")
        if trust is None or verifier is None:
            return _unavailable("untrusted_head")
        try:
            return evidence_admission(evidence, trust, HEAD_POLICY_V1, as_of, verifier)
        except EvidenceError as error:
            return _unavailable(error.reason)

    return admit


published_admission = admission_with(REGISTRY_TRUST)


def admitted_by_evidence(admission: EvidenceAdmission, family: str, variant: str | None) -> bool:
    """SPEC-006 R84: listed with `golden_field: true` under status `current`."""
    return variant is not None and admission.golden_field(family, variant)
