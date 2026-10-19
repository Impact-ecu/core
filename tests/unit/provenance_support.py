"""Test-only Ed25519 `Signer`/`Verifier` (third-party `cryptography`, pinned in the dev group) and chain builders.

`core.provenance` holds no Ed25519 code (SPEC-005 R55); these adapters are what a consumer would inject.
Every key here is synthetic. `dev_key` seeds are not R56 test keys, so they work outside test mode.
"""

import hashlib
import json
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from itertools import count
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from core.provenance import (
    Actor,
    Draft,
    Event,
    EventMeta,
    ProvenanceError,
    RecordError,
    append,
    genesis,
    sign_key_event,
)

ROOT = Path(__file__).resolve().parents[2]
SPEC005: dict[str, Any] = json.loads((ROOT / "specs" / "vectors" / "spec-005" / "vectors.json").read_text("utf-8"))
SPEC006: dict[str, Any] = json.loads((ROOT / "specs" / "vectors" / "spec-006" / "vectors.json").read_text("utf-8"))

TENANT = "tenant-a"
SYSTEM = Actor("system", "system")
USER = Actor("user", "user-1")


class Ed25519Signer:
    def __init__(self, seed: bytes) -> None:
        self._key = Ed25519PrivateKey.from_private_bytes(seed)
        self.public_key = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        self._key_id = hashlib.sha256(bytes.fromhex(self.public_key)).hexdigest()

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)


class Ed25519Verifier:
    def __init__(self) -> None:
        self.calls = 0

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        self.calls += 1
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        except (InvalidSignature, ValueError):
            return False
        return True


def dev_key(name: str) -> Ed25519Signer:
    return Ed25519Signer(hashlib.sha256(f"impact core provenance tests: {name}".encode()).digest())


TEST_SIGNER = Ed25519Signer(bytes.fromhex(SPEC005["key"]["seed_hex"]))
SERVER = dev_key("server")
CLI = dev_key("cli")
OTHER = dev_key("other")
VERIFIER = Ed25519Verifier()


def event_id(n: int) -> str:
    return f"{n:032x}"


def ts(n: int) -> str:
    return f"2026-10-18T{12 + n // 3600 % 12:02d}:{n // 60 % 60:02d}:{n % 60:02d}Z"


_IDS = count(1)


def next_meta(seq: int, actor: Actor = USER) -> EventMeta:
    """A fresh event id (R35) and a timestamp that grows with `seq` (R38)."""
    return EventMeta(event_id(next(_IDS)), "project-a", actor, ts(seq))


def meta(n: int, actor: Actor = USER, project_id: str | None = "project-a") -> EventMeta:
    return EventMeta(event_id(n), project_id, actor, ts(n))


def start(
    signer: Ed25519Signer = SERVER, *, role: str = "server", tenant: str = TENANT, test_mode: bool = False
) -> Event:
    return genesis(
        tenant,
        EventMeta(event_id(next(_IDS)), None, SYSTEM, ts(0)),
        role="cli" if role == "cli" else "server",
        public_key=signer.public_key,
        test_mode=test_mode,
    )


def import_payload(image_hash: str = "aa" * 32, origin: str = "bench_read") -> dict[str, Any]:
    return {"artifact_sha256": "bb" * 32, "image_hash": image_hash, "dump_kind": "bench_full", "origin": origin}


def add(chain: list[Event], event_type: str, payload: dict[str, Any], *, actor: Actor = USER) -> Event:
    head = chain[-1]
    event = append(head, Draft(next_meta(head.seq + 1, actor), event_type, payload))
    chain.append(event)
    return event


def add_signed(
    chain: list[Event], event_type: str, payload: dict[str, Any], signer: Ed25519Signer, *, test_mode: bool = False
) -> Event:
    """Append an R57 event signed by `signer` (its `signer_key_id` is set here)."""
    head = chain[-1]
    draft = Draft(next_meta(head.seq + 1), event_type, {**payload, "signer_key_id": signer.key_id})
    event = append(head, sign_key_event(head, chain[0].hash, draft, signer), test_mode=test_mode)
    chain.append(event)
    return event


def raw(chain: list[Event]) -> list[Any]:
    """The chain as a JSON parser would return it: plain dicts and lists."""
    return [json.loads(json.dumps(_plain(event.to_json()))) for event in chain]


def _plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_plain(item) for item in value]
    return value


@contextmanager
def expect(reason: str, error: type[ProvenanceError] = RecordError) -> Iterator[None]:
    """`pytest.raises` that also checks the stable `reason` (SPEC-005 R91)."""
    with pytest.raises(error) as caught:
        yield
    assert caught.value.reason == reason
