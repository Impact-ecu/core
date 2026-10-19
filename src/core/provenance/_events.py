"""`Event`, the per-signer chain and its pure append (SPEC-005 §5), key events (R57) and commitments (R82)."""

from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Literal, NoReturn

from core.provenance._errors import EventError, ShapeError
from core.provenance._json import (
    EVENT_ID_CHECK,
    HEX32_CHECK,
    ID_CHECK,
    TIMESTAMP,
    ZERO_HASH,
    Json,
    Raw,
    anything,
    as_int,
    as_str,
    hash_json,
    matches,
    member,
    nullable,
    obj,
    one_of,
    text,
    to_json,
    uint,
)
from core.provenance._payloads import EVENT_TYPES, KEY_EVENT_TYPES, payload_ok
from core.provenance._signing import KEY_EVENT_DOMAIN, TEST_KEY_IDS, Signer, key_id_of, sign

EVENT_SCHEMA = "impact.event.v1"
ActorKind = Literal["user", "system"]

# R30: exactly these keys. The payload is checked by R36 (`bad_payload`), not here.
ENVELOPE = obj(
    {
        "schema": one_of(EVENT_SCHEMA),
        "tenant_id": ID_CHECK,
        "seq": uint,
        "event_id": EVENT_ID_CHECK,
        "project_id": nullable(ID_CHECK),
        "type": text,
        "payload": anything,
        "actor": obj({"kind": one_of("user", "system"), "id": ID_CHECK}),
        "ts": matches(TIMESTAMP),
        "prev_hash": HEX32_CHECK,
        "hash": HEX32_CHECK,
    }
)


def event_defect(value: Raw) -> str | None:
    """The first R30/R36 defect of a raw event (`bad_shape`, `unknown_type`, `bad_payload`), or None."""
    if not ENVELOPE(value):
        return "bad_shape"
    event_type = as_str(member(value, "type"))
    if event_type not in EVENT_TYPES:
        return "unknown_type"
    if not payload_ok(event_type, member(value, "payload")):
        return "bad_payload"
    return None


def _raise(defect: str, detail: str) -> NoReturn:
    raise (ShapeError if defect == "bad_shape" else EventError)(defect, detail)


def event_hash(value: Mapping[str, Json]) -> str:
    """R31: `sha256(JCS(event without "hash"))`."""
    return hash_json({key: item for key, item in value.items() if key != "hash"})


@dataclass(frozen=True, slots=True)
class Actor:
    kind: ActorKind
    id: str


@dataclass(frozen=True, slots=True)
class Event:
    """A well-formed event (R30, R36). Its `hash` is not checked here: `verify_chain` recomputes it (R31)."""

    tenant_id: str
    seq: int
    event_id: str
    project_id: str | None
    type: str
    payload: Mapping[str, Json]
    actor: Actor
    ts: str
    prev_hash: str
    hash: str

    def __post_init__(self) -> None:
        if not isinstance(self.actor, Actor):
            raise ShapeError("bad_shape", "actor must be an Actor")
        try:
            frozen = to_json(self.payload)
        except ValueError as error:
            raise EventError("bad_payload", str(error)) from error
        object.__setattr__(self, "payload", frozen)
        defect = event_defect(self.to_json())
        if defect is not None:
            _raise(defect, f"{self.type} at seq {self.seq}")

    def to_json(self) -> Mapping[str, Json]:
        return {
            "schema": EVENT_SCHEMA,
            "tenant_id": self.tenant_id,
            "seq": self.seq,
            "event_id": self.event_id,
            "project_id": self.project_id,
            "type": self.type,
            "payload": self.payload,
            "actor": {"kind": self.actor.kind, "id": self.actor.id},
            "ts": self.ts,
            "prev_hash": self.prev_hash,
            "hash": self.hash,
        }

    @property
    def ref(self) -> Mapping[str, Json]:
        """The `EventRef` of §3."""
        return {"event_id": self.event_id, "seq": self.seq, "hash": self.hash}


def parse_event(value: Raw) -> Event:
    """A stored event as an `Event`; `ShapeError` or `EventError` for any R30 or R36 defect."""
    defect = event_defect(value)
    if defect is not None:
        _raise(defect, "stored event")
    actor = member(value, "actor")
    project_id = member(value, "project_id")
    payload = to_json(member(value, "payload"))
    return Event(
        tenant_id=as_str(member(value, "tenant_id")),
        seq=as_int(member(value, "seq")),
        event_id=as_str(member(value, "event_id")),
        project_id=None if project_id is None else as_str(project_id),
        type=as_str(member(value, "type")),
        payload=payload if isinstance(payload, Mapping) else {},
        actor=Actor("user" if member(actor, "kind") == "user" else "system", as_str(member(actor, "id"))),
        ts=as_str(member(value, "ts")),
        prev_hash=as_str(member(value, "prev_hash")),
        hash=as_str(member(value, "hash")),
    )


@dataclass(frozen=True, slots=True)
class EventMeta:
    """What the caller supplies for every new event (R5): ids and time are never generated in `core`."""

    event_id: str
    project_id: str | None
    actor: Actor
    ts: str


@dataclass(frozen=True, slots=True)
class Draft:
    """A new event before `append` adds `tenant_id`, `seq`, `prev_hash` and `hash`."""

    meta: EventMeta
    type: str
    payload: Mapping[str, Json]


def _seal(tenant_id: str, seq: int, prev_hash: str, draft: Draft) -> Event:
    meta = draft.meta
    unsealed = Event(
        tenant_id,
        seq,
        meta.event_id,
        meta.project_id,
        draft.type,
        draft.payload,
        meta.actor,
        meta.ts,
        prev_hash,
        ZERO_HASH,
    )
    return replace(unsealed, hash=event_hash(unsealed.to_json()))


def _check_test_key(key_id: str, test_mode: bool) -> None:
    # R56: the synthetic vector keys are never enrolled in a real chain.
    if key_id in TEST_KEY_IDS and not test_mode:
        raise EventError("test_key", key_id)


def genesis(
    tenant_id: str, meta: EventMeta, *, role: Literal["server", "cli"], public_key: str, test_mode: bool = False
) -> Event:
    """R32: `seq = 0`, zero `prev_hash`, no project, a system actor and exactly the signer's key."""
    if meta.project_id is not None or meta.actor.kind != "system":
        raise EventError("not_genesis", "a genesis event has no project and a system actor")
    if not HEX32_CHECK(public_key):
        raise EventError("bad_payload", "public_key must be 32 bytes in lowercase hex")
    key_id = key_id_of(public_key)
    _check_test_key(key_id, test_mode)
    payload: dict[str, Json] = {"role": role, "signing_keys": [{"key_id": key_id, "public_key": public_key}]}
    return _seal(tenant_id, 0, ZERO_HASH, Draft(meta, "genesis", payload))


def append(head: Event, draft: Draft, *, test_mode: bool = False) -> Event:
    """R34: `seq = head.seq + 1`, `prev_hash = head.hash`, same tenant (R33); never mutates `head`.

    Uniqueness of `(genesis_hash, seq)` is the storage's job (R34): two appends to one head both succeed here.
    """
    if not isinstance(head, Event) or not isinstance(draft, Draft):
        raise ShapeError("bad_shape", "append takes an Event head and a Draft")
    if draft.type == "genesis":
        raise EventError("not_genesis", "a genesis event is only ever seq 0 (R32)")
    if draft.type == "key_enrolled":
        _check_test_key(as_str(member(draft.payload, "key_id")), test_mode)
    return _seal(head.tenant_id, head.seq + 1, head.hash, draft)


def key_event_hash(*, tenant_id: str, genesis_hash: str, seq: int, event_type: str, payload: Mapping[str, Json]) -> str:
    """R57: the hash a key or reference event is signed over; `payload` is taken without `signature`."""
    unsigned = {key: value for key, value in payload.items() if key != "signature"}
    return hash_json(
        {
            "schema": "impact.key-event.v1",
            "tenant_id": tenant_id,
            "genesis_hash": genesis_hash,
            "seq": seq,
            "type": event_type,
            "payload": unsigned,
        }
    )


def sign_key_event(head: Event, genesis_hash: str, draft: Draft, signer: Signer) -> Draft:
    """R57: `draft` with its `signature`, made by `signer` for the position after `head` in that chain."""
    if draft.type not in KEY_EVENT_TYPES:
        raise EventError("bad_payload", f"{draft.type} is not signed per R57")
    if draft.payload.get("signer_key_id") != signer.key_id:
        raise EventError("bad_payload", "signer_key_id must name the signer's key")
    digest = key_event_hash(
        tenant_id=head.tenant_id,
        genesis_hash=genesis_hash,
        seq=head.seq + 1,
        event_type=draft.type,
        payload=draft.payload,
    )
    return replace(draft, payload={**draft.payload, "signature": sign(signer, KEY_EVENT_DOMAIN, digest)})


def commitment(nonce: str, content: Json) -> str:
    """R82: `sha256(JCS({schema, nonce, content}))`; `nonce` is 32 caller-supplied random bytes in hex."""
    if not HEX32_CHECK(nonce):
        raise ShapeError("bad_shape", "nonce must be 32 bytes in lowercase hex")
    try:
        return hash_json({"schema": "impact.commitment.v1", "nonce": nonce, "content": to_json(content)})
    except ValueError as error:
        raise ShapeError("bad_shape", str(error)) from error
