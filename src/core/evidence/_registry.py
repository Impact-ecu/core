"""The attester registry built from one SPEC-005 server chain (SPEC-006 §6, R60-R68).

Chain integrity, event hashes, links and R57 signatures are SPEC-005 `verify_chain`'s; this module only gives the
registry events their meaning, so a registry is a pure function of the chain up to its head (R65).
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Literal

from core.evidence._errors import EvidenceError
from core.evidence._json import digest, sha256_hex, verified
from core.provenance import AnchorFile, Event, Head, Json, Raw, Verifier, parse_event, verify_chain

REGISTRY_SCHEMA = "impact.attester-registry.v1"
ROTATION_DOMAIN = "impact.attester-rotation-signature.v1"
REVIEW_DOMAIN = "impact.review-signature.v1"
# R63: these reasons void every claim of the key; `retired` does not (R77).
RETROACTIVE = frozenset({"compromised", "misconduct", "error"})

Unusable = Literal["unknown", "revoked", "role"]
ATTESTER_REASONS: Mapping[Unusable, str] = {
    "unknown": "unknown_attester",
    "revoked": "revoked_attester",
    "role": "not_attester",
}
REVIEWER_REASONS: Mapping[Unusable, str] = {
    "unknown": "unknown_reviewer",
    "revoked": "revoked_reviewer",
    "role": "not_reviewer",
}


@dataclass(frozen=True, slots=True)
class Revocation:
    seq: int
    reason: str


@dataclass(frozen=True, slots=True)
class RegistryAttester:
    attester_key_id: str
    public_key: str
    roles: tuple[str, ...]
    identity: str
    enrolled_seq: int
    revoked: Revocation | None

    def to_json(self) -> Mapping[str, Json]:
        revoked: Json = None if self.revoked is None else {"seq": self.revoked.seq, "reason": self.revoked.reason}
        return {
            "attester_key_id": self.attester_key_id,
            "public_key": self.public_key,
            "roles": list(self.roles),
            "identity": self.identity,
            "enrolled_seq": self.enrolled_seq,
            "revoked": revoked,
        }

    def counts_at(self, seq: int) -> bool:
        """R77: a claim at trusted time `seq` stands unless the key is revoked, except a `retired` key's before it."""
        revoked = self.revoked
        return revoked is None or (revoked.reason == "retired" and seq < revoked.seq)


@dataclass(frozen=True, slots=True)
class Inclusion:
    attestation_hash: str
    attester_key_id: str
    seq: int

    def to_json(self) -> Mapping[str, Json]:
        return {"attestation_hash": self.attestation_hash, "attester_key_id": self.attester_key_id, "seq": self.seq}


@dataclass(frozen=True, slots=True)
class RecordReview:
    golden_record_hash: str
    decision: str
    reviewer_key_id: str
    seq: int

    def to_json(self) -> Mapping[str, Json]:
        return {
            "golden_record_hash": self.golden_record_hash,
            "decision": self.decision,
            "reviewer_key_id": self.reviewer_key_id,
            "seq": self.seq,
        }


@dataclass(frozen=True, slots=True)
class RegistryFinding:
    seq: int
    reason: str


@dataclass(frozen=True, slots=True)
class AttesterRegistry:
    """R65. Built only by `attester_registry`; its lists are sorted as the spec states."""

    tenant_id: str
    genesis_hash: str
    head: Head
    attesters: tuple[RegistryAttester, ...]
    inclusions: tuple[Inclusion, ...]
    record_reviews: tuple[RecordReview, ...]
    findings: tuple[RegistryFinding, ...]

    def to_json(self) -> Mapping[str, Json]:
        return {
            "schema": REGISTRY_SCHEMA,
            "tenant_id": self.tenant_id,
            "genesis_hash": self.genesis_hash,
            "head": {"seq": self.head.seq, "hash": self.head.hash},
            "attesters": [entry.to_json() for entry in self.attesters],
            "inclusions": [entry.to_json() for entry in self.inclusions],
            "record_reviews": [entry.to_json() for entry in self.record_reviews],
            "findings": [{"seq": entry.seq, "reason": entry.reason} for entry in self.findings],
        }

    @property
    def registry_hash(self) -> str:
        return digest(self.to_json())

    def attester(self, key_id: str) -> RegistryAttester | None:
        return next((entry for entry in self.attesters if entry.attester_key_id == key_id), None)

    def inclusion(self, attestation_hash: str) -> Inclusion | None:
        return next((entry for entry in self.inclusions if entry.attestation_hash == attestation_hash), None)


def review_hash(tenant_id: str, genesis_hash: str, payload: Mapping[str, Json]) -> str:
    """SPEC-006 R91: the hash a reviewer signs, binding chain, subject and decision."""
    return digest(
        {
            "schema": "impact.review.v1",
            "tenant_id": tenant_id,
            "genesis_hash": genesis_hash,
            "subject_kind": payload.get("subject_kind"),
            "export_ref": payload.get("export_ref"),
            "subject_hash": payload.get("subject_hash"),
            "decision": payload.get("decision"),
        }
    )


def unusable(entry: RegistryAttester | None, role: str, seq: int) -> Unusable | None:
    """R67, R68, R92: why a key may not act in `role` at `seq` (revoked at a lower `seq`), or None."""
    if entry is None:
        return "unknown"
    if entry.revoked is not None and entry.revoked.seq < seq:
        return "revoked"
    if role not in entry.roles:
        return "role"
    return None


def _text(payload: Mapping[str, Json], key: str) -> str:
    value = payload.get(key)
    return value if isinstance(value, str) else ""


@dataclass(slots=True)
class _Builder:
    tenant_id: str
    genesis_hash: str
    verifier: Verifier
    attesters: dict[str, RegistryAttester] = field(default_factory=dict)
    successors: set[str] = field(default_factory=set)
    inclusions: dict[str, Inclusion] = field(default_factory=dict)
    reviews: list[RecordReview] = field(default_factory=list)
    findings: list[RegistryFinding] = field(default_factory=list)

    def note(self, seq: int, reason: str) -> None:
        self.findings.append(RegistryFinding(seq, reason))

    def apply(self, event: Event) -> None:
        if event.type == "attester_enrolled":
            self.enroll(event)
        elif event.type == "attester_revoked":
            self.revoke(event)
        elif event.type == "attestation_included":
            self.include(event)
        elif event.type == "review" and event.payload.get("subject_kind") == "golden_record":
            self.review(event)

    def enroll(self, event: Event) -> None:
        payload, seq = event.payload, event.seq
        key_id, public_key = _text(payload, "attester_key_id"), _text(payload, "public_key")
        # R62: a human decision for exactly the named key; SPEC-005 R36 does not check either.
        if event.actor.kind != "user" or sha256_hex(bytes.fromhex(public_key)) != key_id:
            raise EvidenceError("registry_broken", f"attester_enrolled at seq {seq} is not a valid enrollment")
        if key_id in self.attesters:
            self.note(seq, "already_enrolled")
            return
        identity = key_id
        rotates = payload.get("rotates")
        if isinstance(rotates, str):
            old = self.attesters.get(rotates)
            if old is None or not self.rotation_ok(old, payload):
                self.note(seq, "bad_rotation")
                return
            self.successors.add(rotates)
            identity = old.identity
        self.attesters[key_id] = RegistryAttester(key_id, public_key, _roles(payload), identity, seq, None)

    def rotation_ok(self, old: RegistryAttester, payload: Mapping[str, Json]) -> bool:
        """R64: no other successor, not revoked retroactively, and signed by the old key."""
        if old.attester_key_id in self.successors or (old.revoked is not None and old.revoked.reason in RETROACTIVE):
            return False
        rotation_hash = digest(
            {
                "schema": "impact.attester-rotation.v1",
                "tenant_id": self.tenant_id,
                "genesis_hash": self.genesis_hash,
                "old_key_id": old.attester_key_id,
                "new_key_id": payload.get("attester_key_id"),
                "new_public_key": payload.get("public_key"),
            }
        )
        signature = _text(payload, "rotation_signature")
        return verified(self.verifier, old.public_key, ROTATION_DOMAIN, rotation_hash, signature)

    def revoke(self, event: Event) -> None:
        key_id = _text(event.payload, "attester_key_id")
        entry = self.attesters.get(key_id)
        if entry is None:
            self.note(event.seq, "unknown_attester")
        elif entry.revoked is not None:
            self.note(event.seq, "already_revoked")
        else:
            revocation = Revocation(event.seq, _text(event.payload, "reason"))
            self.attesters[key_id] = replace(entry, revoked=revocation)

    def include(self, event: Event) -> None:
        payload, seq = event.payload, event.seq
        key_id, attestation_hash = _text(payload, "attester_key_id"), _text(payload, "attestation_hash")
        reason = unusable(self.attesters.get(key_id), "attester", seq)
        if reason is not None:
            self.note(seq, ATTESTER_REASONS[reason])
        elif attestation_hash in self.inclusions:
            self.note(seq, "already_included")
        else:
            self.inclusions[attestation_hash] = Inclusion(attestation_hash, key_id, seq)

    def review(self, event: Event) -> None:
        payload, seq = event.payload, event.seq
        entry = self.attesters.get(_text(payload, "reviewer_key_id"))
        reason = unusable(entry, "reviewer", seq)
        if entry is None or reason is not None:
            self.note(seq, REVIEWER_REASONS[reason or "unknown"])
            return
        signed_hash = review_hash(self.tenant_id, self.genesis_hash, payload)
        if not verified(self.verifier, entry.public_key, REVIEW_DOMAIN, signed_hash, _text(payload, "signature")):
            self.note(seq, "bad_signature")
            return
        decision = _text(payload, "decision")
        self.reviews.append(RecordReview(_text(payload, "subject_hash"), decision, entry.attester_key_id, seq))

    def build(self, head: Head) -> AttesterRegistry:
        return AttesterRegistry(
            tenant_id=self.tenant_id,
            genesis_hash=self.genesis_hash,
            head=head,
            attesters=tuple(self.attesters[key] for key in sorted(self.attesters)),
            inclusions=tuple(self.inclusions[key] for key in sorted(self.inclusions)),
            record_reviews=tuple(sorted(self.reviews, key=_review_order)),
            findings=tuple(sorted(self.findings, key=_finding_order)),
        )


def _roles(payload: Mapping[str, Json]) -> tuple[str, ...]:
    roles = payload.get("roles")
    return tuple(role for role in roles if isinstance(role, str)) if isinstance(roles, tuple) else ()


def _review_order(review: RecordReview) -> tuple[str, int]:
    return review.golden_record_hash, review.seq


def _finding_order(finding: RegistryFinding) -> tuple[int, str]:
    return finding.seq, finding.reason


def _seq(event: Event) -> int:
    return event.seq


def attester_registry(
    events: Sequence[Raw], anchors: Sequence[AnchorFile], verifier: Verifier, *, test_mode: bool = False
) -> AttesterRegistry:
    """R65: `registry_broken` unless SPEC-005 `verify_chain` finds the chain intact, then R61-R68 in `seq` order."""
    report = verify_chain(events, anchors, verifier, test_mode=test_mode)
    if report.status == "broken":
        reasons = ", ".join(sorted({finding.reason for finding in report.findings}))
        raise EvidenceError("registry_broken", reasons)
    chain = sorted((parse_event(event) for event in events), key=_seq)
    genesis = chain[0]
    # R60: the registry is read from a server chain only.
    if genesis.payload.get("role") != "server":
        raise EvidenceError("registry_broken", "the registry chain is not a role: server chain")
    builder = _Builder(genesis.tenant_id, genesis.hash, verifier)
    for event in chain[1:]:
        builder.apply(event)
    return builder.build(Head(chain[-1].seq, chain[-1].hash))
