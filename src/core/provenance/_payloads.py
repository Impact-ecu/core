"""Event payload shapes: SPEC-005 R36 is their only definition (decision D5)."""

from collections.abc import Mapping

from core.provenance._json import (
    DUMP_KINDS,
    EVENT_REF_CHECK,
    HEX32_CHECK,
    ORIGINS,
    SIGNATURE_CHECK,
    VERIFY_STATUSES,
    Check,
    Raw,
    anything,
    array,
    as_str,
    items,
    member,
    nullable,
    obj,
    one_of,
    text,
    uint,
)
from core.provenance._signing import key_id_of

KEY = obj({"key_id": HEX32_CHECK, "public_key": HEX32_CHECK})
VERIFY_STATUS = one_of(*VERIFY_STATUSES)

PAYLOADS: Mapping[str, Mapping[str, Check]] = {
    # The count of `signing_keys` is checked by R40 step 1 as `not_genesis`, never as `bad_payload`.
    "genesis": {"role": one_of("server", "cli"), "signing_keys": array(KEY, sort_key="key_id")},
    "key_enrolled": {
        "key_id": HEX32_CHECK,
        "public_key": HEX32_CHECK,
        "signer_key_id": HEX32_CHECK,
        "signature": SIGNATURE_CHECK,
    },
    "key_revoked": {
        "key_id": HEX32_CHECK,
        "reason": one_of("compromised", "retired"),
        "signer_key_id": HEX32_CHECK,
        "signature": SIGNATURE_CHECK,
    },
    "import": {
        "artifact_sha256": HEX32_CHECK,
        "image_hash": HEX32_CHECK,
        "dump_kind": one_of(*DUMP_KINDS),
        "origin": one_of(*ORIGINS),
    },
    "identification_confirmed": {
        "artifact_sha256": HEX32_CHECK,
        "image_hash": HEX32_CHECK,
        "family": text,
        "plugin_version": text,
        "hw_id": nullable(text),
        "sw_id": nullable(text),
        "checksum_variant_id": nullable(text),
    },
    "suspect_ack": {
        "artifact_sha256": HEX32_CHECK,
        "image_hash": HEX32_CHECK,
        "input_report_hash": HEX32_CHECK,
        "verify_status": VERIFY_STATUS,
    },
    "alert_ack": {
        "image_hash_release": HEX32_CHECK,
        "gate_report_hash": HEX32_CHECK,
        "warnings": array(obj({"finding_id": HEX32_CHECK, "rule_id": text, "text": text})),
        "presented_ms": uint,
        "confirmed_ms": uint,
    },
    "rule_silence": {"rule_id": text, "justification_commitment": nullable(HEX32_CHECK)},
    "chain_ref": {
        "chain_signer_key_id": HEX32_CHECK,
        "genesis_hash": HEX32_CHECK,
        "seq": uint,
        "head_hash": HEX32_CHECK,
        "signer_key_id": HEX32_CHECK,
        "signature": SIGNATURE_CHECK,
    },
    "export": {
        "provenance_hash": HEX32_CHECK,
        "report_hash": HEX32_CHECK,
        "key_id": HEX32_CHECK,
        "signature": SIGNATURE_CHECK,
    },
    "audit": {
        "audit_hash": HEX32_CHECK,
        "report_hash": HEX32_CHECK,
        "key_id": HEX32_CHECK,
        "signature": SIGNATURE_CHECK,
    },
    "consent_granted": {
        "artifact_sha256": HEX32_CHECK,
        "purpose": one_of("corpus"),
        "legal_basis": one_of("consent", "legitimate_interest"),
        "record_commitment": HEX32_CHECK,
    },
    "consent_revoked": {"artifact_sha256": HEX32_CHECK, "purpose": one_of("corpus"), "record_commitment": HEX32_CHECK},
    "erasure": {
        "subject": one_of("artifact", "record"),
        "ref": HEX32_CHECK,
        "reason": one_of("data_subject_request", "consent_revoked", "retention_expired"),
    },
    "attester_enrolled": {
        "attester_key_id": HEX32_CHECK,
        "public_key": HEX32_CHECK,
        "roles": array(one_of("attester", "reviewer"), sorted_unique=True, nonempty=True),
        "rotates": nullable(HEX32_CHECK),
        "rotation_signature": nullable(SIGNATURE_CHECK),
        "reason_commitment": HEX32_CHECK,
        "signer_key_id": HEX32_CHECK,
        "signature": SIGNATURE_CHECK,
    },
    "attester_revoked": {
        "attester_key_id": HEX32_CHECK,
        "reason": one_of("compromised", "misconduct", "retired", "error"),
        "reason_commitment": HEX32_CHECK,
        "signer_key_id": HEX32_CHECK,
        "signature": SIGNATURE_CHECK,
    },
    "attestation_included": {
        "attestation_hash": HEX32_CHECK,
        "attester_key_id": HEX32_CHECK,
        "signer_key_id": HEX32_CHECK,
        "signature": SIGNATURE_CHECK,
    },
    "review": {
        "subject_kind": one_of("export", "golden_record"),
        "export_ref": nullable(EVENT_REF_CHECK),
        "subject_hash": HEX32_CHECK,
        "decision": one_of("approved", "rejected"),
        "reviewer_key_id": HEX32_CHECK,
        "signature": SIGNATURE_CHECK,
    },
}

EVENT_TYPES = frozenset(PAYLOADS)
# R57: events signed by `signer_key_id` over the key-event hash.
KEY_EVENT_TYPES = frozenset(
    {"key_enrolled", "key_revoked", "attester_enrolled", "attester_revoked", "attestation_included", "chain_ref"}
)
REPORT_EVENT_TYPES = frozenset({"export", "audit"})


def _ack_times(payload: Raw) -> bool:
    presented, confirmed = member(payload, "presented_ms"), member(payload, "confirmed_ms")
    return isinstance(presented, int) and isinstance(confirmed, int) and presented <= confirmed


def _rotation(payload: Raw) -> bool:
    return (member(payload, "rotates") is None) == (member(payload, "rotation_signature") is None)


def _review_subject(payload: Raw) -> bool:
    return (member(payload, "subject_kind") == "export") == (member(payload, "export_ref") is not None)


def _same_key(key: Raw) -> bool:
    """R50: `key_id` is the SHA-256 of the public key it names."""
    return key_id_of(as_str(member(key, "public_key"))) == member(key, "key_id")


def _genesis_keys(payload: Raw) -> bool:
    return all(map(_same_key, items(member(payload, "signing_keys"))))


# Cross-field rules of R36 that a per-field check cannot express.
_CROSS: Mapping[str, Check] = {
    "alert_ack": _ack_times,
    "attester_enrolled": _rotation,
    "review": _review_subject,
    "genesis": _genesis_keys,
    "key_enrolled": _same_key,
}


def payload_ok(event_type: str, payload: Raw) -> bool:
    """R36 for a known `event_type`: key set, value types, list order and the cross-field rules."""
    return obj(PAYLOADS[event_type])(payload) and _CROSS.get(event_type, anything)(payload)
