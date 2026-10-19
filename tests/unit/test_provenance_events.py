"""SPEC-005 §5 events: shapes (R3, R30, R36), genesis (R32), append (R33, R34), key events (R57), commitments (R82)."""

import hashlib
from typing import Any

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from core.provenance import (
    Actor,
    Draft,
    Event,
    EventError,
    EventMeta,
    ShapeError,
    append,
    commitment,
    event_hash,
    genesis,
    key_event_hash,
    parse_event,
    sign_key_event,
)
from core.provenance._json import member, to_json
from core.provenance._payloads import PAYLOADS, payload_ok
from tests.unit.provenance_support import (
    OTHER,
    SERVER,
    SYSTEM,
    TENANT,
    TEST_SIGNER,
    USER,
    add,
    add_signed,
    meta,
    raw,
    start,
)

HEX = "ab" * 32
SIG = "cd" * 64
REF = {"event_id": "00" * 16, "seq": 1, "hash": HEX}

# One valid payload per R36 type; the cross-field rules are exercised below.
VALID: dict[str, dict[str, Any]] = {
    "genesis": {"role": "server", "signing_keys": [{"key_id": SERVER.key_id, "public_key": SERVER.public_key}]},
    "key_enrolled": {"key_id": OTHER.key_id, "public_key": OTHER.public_key, "signer_key_id": HEX, "signature": SIG},
    "key_revoked": {"key_id": HEX, "reason": "retired", "signer_key_id": HEX, "signature": SIG},
    "import": {"artifact_sha256": HEX, "image_hash": HEX, "dump_kind": "obd_partial", "origin": "virtual_read"},
    "identification_confirmed": {
        "artifact_sha256": HEX,
        "image_hash": HEX,
        "family": "synthetic.family",
        "plugin_version": "1.0.0",
        "hw_id": None,
        "sw_id": "sw",
        "checksum_variant_id": None,
    },
    "suspect_ack": {"artifact_sha256": HEX, "image_hash": HEX, "input_report_hash": HEX, "verify_status": "bypassed"},
    "alert_ack": {
        "image_hash_release": HEX,
        "gate_report_hash": HEX,
        "warnings": [{"finding_id": HEX, "rule_id": "r", "text": "t"}],
        "presented_ms": 5,
        "confirmed_ms": 5,
    },
    "rule_silence": {"rule_id": "r", "justification_commitment": None},
    "chain_ref": {
        "chain_signer_key_id": HEX,
        "genesis_hash": HEX,
        "seq": 3,
        "head_hash": HEX,
        "signer_key_id": HEX,
        "signature": SIG,
    },
    "export": {"provenance_hash": HEX, "report_hash": HEX, "key_id": HEX, "signature": SIG},
    "audit": {"audit_hash": HEX, "report_hash": HEX, "key_id": HEX, "signature": SIG},
    "consent_granted": {
        "artifact_sha256": HEX,
        "purpose": "corpus",
        "legal_basis": "legitimate_interest",
        "record_commitment": HEX,
    },
    "consent_revoked": {"artifact_sha256": HEX, "purpose": "corpus", "record_commitment": HEX},
    "erasure": {"subject": "record", "ref": HEX, "reason": "retention_expired"},
    "attester_enrolled": {
        "attester_key_id": HEX,
        "public_key": HEX,
        "roles": ["attester", "reviewer"],
        "rotates": HEX,
        "rotation_signature": SIG,
        "reason_commitment": HEX,
        "signer_key_id": HEX,
        "signature": SIG,
    },
    "attester_revoked": {
        "attester_key_id": HEX,
        "reason": "misconduct",
        "reason_commitment": HEX,
        "signer_key_id": HEX,
        "signature": SIG,
    },
    "attestation_included": {"attestation_hash": HEX, "attester_key_id": HEX, "signer_key_id": HEX, "signature": SIG},
    "review": {
        "subject_kind": "export",
        "export_ref": REF,
        "subject_hash": HEX,
        "decision": "rejected",
        "reviewer_key_id": HEX,
        "signature": SIG,
    },
}


# SPEC-005 R36: the table is complete and every valid example passes.
def test_payload_table_is_r36() -> None:
    assert set(PAYLOADS) == set(VALID)
    for event_type, payload in VALID.items():
        assert payload_ok(event_type, payload), event_type
        assert set(PAYLOADS[event_type]) == set(payload)


# SPEC-005 R3, R36: a missing key, an extra key, and a wrong value type are each `bad_payload`.
@pytest.mark.parametrize("event_type", sorted(VALID))
def test_payload_key_set_and_types(event_type: str) -> None:
    payload = VALID[event_type]
    first = min(payload)
    assert not payload_ok(event_type, {k: v for k, v in payload.items() if k != first})
    assert not payload_ok(event_type, {**payload, "extra": None})
    assert not payload_ok(event_type, {**payload, first: True})
    assert not payload_ok(event_type, [payload])


BAD_CROSS_FIELD = [
    ("alert_ack", {"presented_ms": 6, "confirmed_ms": 5}),
    ("alert_ack", {"presented_ms": 2**53, "confirmed_ms": 2**53}),
    ("attester_enrolled", {"rotation_signature": None}),
    ("attester_enrolled", {"rotates": None}),
    ("attester_enrolled", {"roles": []}),
    ("attester_enrolled", {"roles": ["reviewer", "attester"]}),
    ("attester_enrolled", {"roles": ["attester", "attester"]}),
    ("review", {"export_ref": None}),
    ("review", {"subject_kind": "golden_record"}),
    ("review", {"export_ref": {**REF, "seq": -1}}),
    ("genesis", {"signing_keys": [{"key_id": HEX, "public_key": SERVER.public_key}]}),
    ("genesis", {"role": "admin"}),
    ("key_enrolled", {"key_id": HEX}),
    ("key_enrolled", {"signature": "cd" * 63}),
    ("rule_silence", {"rule_id": ""}),
    ("identification_confirmed", {"hw_id": ""}),
    ("identification_confirmed", {"family": "\ud800"}),
    ("chain_ref", {"seq": 2**53}),
    ("import", {"origin": "partner"}),
]


# SPEC-005 R36: list order, size and the cross-field rules.
@pytest.mark.parametrize(("event_type", "change"), BAD_CROSS_FIELD)
def test_payload_cross_field_rules(event_type: str, change: dict[str, Any]) -> None:
    assert not payload_ok(event_type, {**VALID[event_type], **change})


# SPEC-005 R36: `null` rotation together is fine; `golden_record` without export_ref is fine.
def test_payload_cross_field_accepts() -> None:
    assert payload_ok("attester_enrolled", {**VALID["attester_enrolled"], "rotates": None, "rotation_signature": None})
    assert payload_ok("review", {**VALID["review"], "subject_kind": "golden_record", "export_ref": None})
    two = [SERVER, OTHER] if SERVER.key_id < OTHER.key_id else [OTHER, SERVER]
    keys = [{"key_id": s.key_id, "public_key": s.public_key} for s in two]
    assert payload_ok("genesis", {"role": "cli", "signing_keys": keys})
    assert not payload_ok("genesis", {"role": "cli", "signing_keys": keys[::-1]})


# SPEC-005 R2, R30, R31, R32: genesis shape and hash, checked with an independent JCS.
def test_genesis() -> None:
    event = start()
    body = {k: v for k, v in raw([event])[0].items() if k != "hash"}
    assert event.hash == hashlib.sha256(rfc8785.dumps(body)).hexdigest() == event_hash(event.to_json())
    assert body["schema"] == "impact.event.v1"
    assert (event.seq, event.prev_hash, event.project_id, event.actor.kind) == (0, "0" * 64, None, "system")
    assert event.payload["signing_keys"] == ({"key_id": SERVER.key_id, "public_key": SERVER.public_key},)
    assert event.ref == {"event_id": event.event_id, "seq": 0, "hash": event.hash}


# SPEC-005 R32: a genesis needs a system actor and no project.
@pytest.mark.parametrize("bad_meta", [meta(0, USER, None), meta(0, SYSTEM, "project-a")])
def test_genesis_not_genesis(bad_meta: EventMeta) -> None:
    with pytest.raises(EventError) as caught:
        genesis(TENANT, bad_meta, role="server", public_key=SERVER.public_key)
    assert caught.value.reason == "not_genesis"


# SPEC-005 R50: the enrolled public key is 32 bytes of lowercase hex.
def test_genesis_bad_public_key() -> None:
    with pytest.raises(EventError) as caught:
        genesis(TENANT, meta(0, SYSTEM, None), role="server", public_key="AB" * 32)
    assert caught.value.reason == "bad_payload"


# SPEC-005 R56: the vector key is never enrolled outside test mode.
def test_genesis_test_key() -> None:
    with pytest.raises(EventError) as caught:
        genesis(TENANT, meta(0, SYSTEM, None), role="server", public_key=TEST_SIGNER.public_key)
    assert caught.value.reason == "test_key"
    assert genesis(TENANT, meta(0, SYSTEM, None), role="cli", public_key=TEST_SIGNER.public_key, test_mode=True)


# SPEC-005 R33, R34: append links, never mutates the head, and leaves (genesis_hash, seq) uniqueness to storage.
def test_append_links_and_is_pure() -> None:
    head = start()
    before = raw([head])
    draft = Draft(meta(1), "import", VALID["import"])
    first, second = append(head, draft), append(head, draft)
    assert raw([head]) == before
    assert first == second
    assert (first.seq, first.prev_hash, first.tenant_id) == (1, head.hash, head.tenant_id)
    field_name = "seq"
    with pytest.raises(AttributeError):
        setattr(first, field_name, 2)


def test_append_rejections() -> None:
    head = start()
    stored: Any = raw([head])[0]
    with pytest.raises(ShapeError) as shape:
        append(stored, Draft(meta(1), "import", VALID["import"]))
    assert shape.value.reason == "bad_shape"
    with pytest.raises(EventError) as again:
        append(head, Draft(meta(1, SYSTEM, None), "genesis", VALID["genesis"]))
    assert again.value.reason == "not_genesis"
    with pytest.raises(EventError) as unknown:
        append(head, Draft(meta(1), "note", {}))
    assert unknown.value.reason == "unknown_type"
    with pytest.raises(EventError) as payload:
        append(head, Draft(meta(1), "import", {**VALID["import"], "vin": "WVWZZZ"}))
    assert payload.value.reason == "bad_payload"
    floating_payload: Any = {**VALID["import"], "dump_kind": 1.5}
    with pytest.raises(EventError) as floating:
        append(head, Draft(meta(1), "import", floating_payload))
    assert floating.value.reason == "bad_payload"
    with pytest.raises(ShapeError) as envelope:
        append(head, Draft(EventMeta("not-hex", None, USER, "2026-10-18T12:00:00Z"), "import", VALID["import"]))
    assert envelope.value.reason == "bad_shape"


# SPEC-005 R56: `key_enrolled` of the vector key outside test mode.
def test_append_test_key() -> None:
    chain = [start()]
    payload = {"key_id": TEST_SIGNER.key_id, "public_key": TEST_SIGNER.public_key}
    head = chain[-1]
    draft = Draft(meta(1), "key_enrolled", {**payload, "signer_key_id": SERVER.key_id})
    signed = sign_key_event(head, head.hash, draft, SERVER)
    with pytest.raises(EventError) as caught:
        append(head, signed)
    assert caught.value.reason == "test_key"
    assert append(head, signed, test_mode=True).type == "key_enrolled"


# SPEC-005 R30: an `Event` holds a frozen payload and an `Actor`.
def test_event_constructor_checks() -> None:
    event = start()
    with pytest.raises(ShapeError):
        Event(**{**_fields(event), "actor": {"kind": "system", "id": "system"}})
    with pytest.raises(EventError) as caught:
        Event(**{**_fields(event), "payload": {"role": "server", "signing_keys": {1, 2}}})
    assert caught.value.reason == "bad_payload"
    payload: Any = event.payload
    with pytest.raises(TypeError):
        payload["role"] = "cli"


def _fields(event: Event) -> dict[str, Any]:
    return {name: getattr(event, name) for name in Event.__dataclass_fields__}


# SPEC-005 R3, R30, R36: parsing a stored event.
def test_parse_event() -> None:
    chain = [start()]
    add(chain, "import", VALID["import"])
    stored = raw(chain)
    assert [parse_event(e) for e in stored] == chain
    cases: list[tuple[Any, str]] = [
        ({**stored[1], "extra": 1}, "bad_shape"),
        ({k: v for k, v in stored[1].items() if k != "ts"}, "bad_shape"),
        ({**stored[1], "seq": True}, "bad_shape"),
        ({**stored[1], "ts": "2026-10-18 12:00:00"}, "bad_shape"),
        ({**stored[1], "actor": {"kind": "admin", "id": "x"}}, "bad_shape"),
        ({**stored[1], "tenant_id": "Tenant"}, "bad_shape"),
        ({**stored[1], "type": "note"}, "unknown_type"),
        ({**stored[1], "payload": {}}, "bad_payload"),
        ({**stored[1], "payload": "text"}, "bad_payload"),
        ("event", "bad_shape"),
    ]
    for value, reason in cases:
        with pytest.raises((ShapeError, EventError)) as caught:
            parse_event(value)
        assert caught.value.reason == reason, value


# SPEC-005 R57: the key-event hash binds tenant, chain, position, type and payload without the signature.
def test_key_event_hash_and_signature() -> None:
    chain = [start()]
    event = add_signed(chain, "key_enrolled", {"key_id": OTHER.key_id, "public_key": OTHER.public_key}, SERVER)
    payload = {k: v for k, v in raw([event])[0]["payload"].items() if k != "signature"}
    expected: dict[str, Any] = {
        "schema": "impact.key-event.v1",
        "tenant_id": TENANT,
        "genesis_hash": chain[0].hash,
        "seq": 1,
        "type": "key_enrolled",
        "payload": payload,
    }
    digest = key_event_hash(
        tenant_id=TENANT, genesis_hash=chain[0].hash, seq=1, event_type="key_enrolled", payload=event.payload
    )
    assert digest == hashlib.sha256(rfc8785.dumps(expected)).hexdigest()
    message = rfc8785.dumps({"domain": "impact.key-event-signature.v1", "hash": digest})
    signature = member(event.payload, "signature")
    assert isinstance(signature, str)
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(SERVER.public_key)).verify(bytes.fromhex(signature), message)


def test_sign_key_event_rejections() -> None:
    head = start()
    with pytest.raises(EventError) as not_key:
        sign_key_event(head, head.hash, Draft(meta(1), "import", VALID["import"]), SERVER)
    assert not_key.value.reason == "bad_payload"
    draft = Draft(meta(1), "key_revoked", {"key_id": HEX, "reason": "retired", "signer_key_id": OTHER.key_id})
    with pytest.raises(EventError) as wrong_signer:
        sign_key_event(head, head.hash, draft, SERVER)
    assert wrong_signer.value.reason == "bad_payload"


# SPEC-005 R82, checked with an independent JCS.
def test_commitment() -> None:
    content: dict[str, Any] = {"text": "justification", "n": 3}
    nonce = "0f" * 32
    want: dict[str, Any] = {"schema": "impact.commitment.v1", "nonce": nonce, "content": content}
    assert commitment(nonce, content) == hashlib.sha256(rfc8785.dumps(want)).hexdigest()
    for bad_nonce in ("0f" * 31, "0F" * 32):
        with pytest.raises(ShapeError) as caught:
            commitment(bad_nonce, content)
        assert caught.value.reason == "bad_shape"
    with pytest.raises(ShapeError) as content_error:
        commitment(nonce, {"x": -1})
    assert content_error.value.reason == "bad_shape"


# SPEC-005 R1, R4: the hashable domain.
def test_to_json_domain() -> None:
    assert to_json({"a": [1, "x", None]}) == {"a": (1, "x", None)}
    bad_values: list[Any] = [True, 1.0, -1, 2**53, "\udc00", {"é": 1}, {1: 1}, {1, 2}]
    for bad in bad_values:
        with pytest.raises(ValueError, match=r"\w"):
            to_json(bad)


# SPEC-005 R37, R80, R81: no payload field holds free text typed by a person, a VIN or a name.
def test_payloads_hold_no_personal_fields() -> None:
    forbidden = {"vin", "plate", "name", "email", "e_mail", "phone", "justification", "note", "comment"}
    fields = {key for shape in PAYLOADS.values() for key in shape}
    assert not fields & forbidden
    assert Actor("user", "user-1").id == USER.id
