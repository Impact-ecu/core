"""Field evidence at the gate (SPEC-004 R16; SPEC-006 R83, R84): the seam to `core.evidence`.

The gate runs `evidence_admission` itself and never takes an admission or a level from the caller (R16). The
SPEC-006 implementation is not in this tree yet, so `evidence_admission` below is the fail-closed stand-in:
every call is `unavailable` and no variant is admitted for `verify` or recalculation, which makes every variant
`unknown_variant` exactly as R16 prescribes for missing evidence (the run blocks through R13 and R26).

To wire `core.evidence`, replace the body of `evidence_admission` with a call to SPEC-006
`evidence_admission(evidence, trust, policy, as_of, verifier)`, binding the registry trust anchor and the head
policy published with the core release (SPEC-006 R60, R82), and map its result onto `EvidenceAdmission`. Nothing
else in the gate changes: `admitted_by_evidence` is the only reader.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, Protocol

# SPEC-006 §7.3 `FieldEvidence`; opaque to the gate, which only hands it to `evidence_admission`.
type FieldEvidence = object
# SPEC-006 `Timestamp` (SPEC-005 R5), e.g. "2026-10-19T00:00:00Z": the caller's clock (SPEC-004 R80).
type Timestamp = str


@dataclass(frozen=True, slots=True)
class VariantEvidence:
    """One `variants` entry of SPEC-006 R83 `EvidenceAdmission`."""

    family: str
    checksum_variant_id: str
    golden_field: bool
    reasons: tuple[str, ...]
    evaluations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EvidenceAdmission:
    """SPEC-006 R83 `EvidenceAdmission` (`schema: impact.evidence-admission.v1`)."""

    status: Literal["current", "unavailable"]
    reasons: tuple[str, ...]
    head_digest: str | None
    variants: tuple[VariantEvidence, ...]


class EvidenceAdmissionFn(Protocol):
    def __call__(self, evidence: FieldEvidence | None, as_of: Timestamp) -> EvidenceAdmission: ...


def evidence_admission(evidence: FieldEvidence | None, as_of: Timestamp) -> EvidenceAdmission:
    """Fail-closed until `core.evidence` (SPEC-006 R83) is wired here; see the module docstring."""
    del as_of
    reason = "missing_evidence" if evidence is None else "evidence_admission_not_wired"
    return EvidenceAdmission("unavailable", (reason,), None, ())


def admitted_by_evidence(admission: EvidenceAdmission, family: str) -> frozenset[str]:
    """SPEC-006 R84: the variants of `family` listed with `golden_field: true` under status `current`."""
    if admission.status != "current":
        return frozenset()
    variants: Sequence[VariantEvidence] = admission.variants
    return frozenset(v.checksum_variant_id for v in variants if v.family == family and v.golden_field)
