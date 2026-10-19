"""Anchors of a server chain's head (SPEC-005 R42); their external location is the consumer's (R43)."""

from collections.abc import Mapping
from dataclasses import dataclass

from core.provenance._errors import ShapeError
from core.provenance._events import Event
from core.provenance._json import (
    DAY,
    HEX32_CHECK,
    ID_CHECK,
    SIGNATURE_CHECK,
    Json,
    Raw,
    hash_json,
    matches,
    member,
    obj,
    one_of,
    uint,
)
from core.provenance._signing import ANCHOR_DOMAIN, Signer, sign

ANCHOR_SCHEMA = "impact.anchor.v1"

STATEMENT_SHAPE = obj(
    {
        "schema": one_of(ANCHOR_SCHEMA),
        "tenant_id": ID_CHECK,
        "genesis_hash": HEX32_CHECK,
        "seq": uint,
        "head_hash": HEX32_CHECK,
        "day": matches(DAY),
    }
)
ANCHOR_FILE_SHAPE = obj(
    {"statement": STATEMENT_SHAPE, "statement_hash": HEX32_CHECK, "key_id": HEX32_CHECK, "signature": SIGNATURE_CHECK}
)


@dataclass(frozen=True, slots=True)
class AnchorStatement:
    tenant_id: str
    genesis_hash: str
    seq: int
    head_hash: str
    day: str

    def __post_init__(self) -> None:
        if not STATEMENT_SHAPE(self.to_json()):
            raise ShapeError("bad_shape", "AnchorStatement")

    def to_json(self) -> Mapping[str, Json]:
        return {
            "schema": ANCHOR_SCHEMA,
            "tenant_id": self.tenant_id,
            "genesis_hash": self.genesis_hash,
            "seq": self.seq,
            "head_hash": self.head_hash,
            "day": self.day,
        }

    @property
    def statement_hash(self) -> str:
        """R42: `sha256(JCS(statement))`."""
        return hash_json(self.to_json())


@dataclass(frozen=True, slots=True)
class AnchorFile:
    """R42. `statement_hash` is stored as given: `verify_chain` recomputes it (`bad_anchor`)."""

    statement: AnchorStatement
    statement_hash: str
    key_id: str
    signature: str

    def __post_init__(self) -> None:
        if not isinstance(self.statement, AnchorStatement) or not ANCHOR_FILE_SHAPE(self.to_json()):
            raise ShapeError("bad_shape", "AnchorFile")

    def to_json(self) -> Mapping[str, Json]:
        return {
            "statement": self.statement.to_json(),
            "statement_hash": self.statement_hash,
            "key_id": self.key_id,
            "signature": self.signature,
        }


def make_anchor(*, tenant_id: str, genesis_hash: str, head: Event, day: str, signer: Signer) -> AnchorFile:
    """Anchor `head` of the chain `genesis_hash`, signed per R51 by `signer`."""
    statement = AnchorStatement(tenant_id, genesis_hash, head.seq, head.hash, day)
    digest = statement.statement_hash
    return AnchorFile(statement, digest, signer.key_id, sign(signer, ANCHOR_DOMAIN, digest))


def parse_anchor(value: Raw) -> AnchorFile:
    """A stored `AnchorFile`; `ShapeError` (`bad_shape`) unless it has exactly the R42 form."""
    if not ANCHOR_FILE_SHAPE(value):
        raise ShapeError("bad_shape", "AnchorFile")
    statement = member(value, "statement")
    return AnchorFile(
        AnchorStatement(
            _str(member(statement, "tenant_id")),
            _str(member(statement, "genesis_hash")),
            _int(member(statement, "seq")),
            _str(member(statement, "head_hash")),
            _str(member(statement, "day")),
        ),
        _str(member(value, "statement_hash")),
        _str(member(value, "key_id")),
        _str(member(value, "signature")),
    )


def _str(value: Raw) -> str:
    return value if isinstance(value, str) else ""


def _int(value: Raw) -> int:
    return value if isinstance(value, int) else 0
