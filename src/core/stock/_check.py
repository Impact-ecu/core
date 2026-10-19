"""`stock_check` (SPEC-008 R20-R26): stock, modified or unknown, per memory and for the dump.

Information only: no gate rule reads it (R26). The trust anchor and the policy are published with the core
release (R14, R15); none is published yet, so the published lookup is `unknown` until Luiz publishes them.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from core.kernel import Dump, Memory
from core.plugins import Identification, PluginContractError, check_identification
from core.provenance import Json, Raw, Verifier
from core.stock._registry import (
    HEX32,
    POLICY_SCHEMA,
    SignedStockRegistry,
    StockEntry,
    StockError,
    exact,
    instant,
    kept_sha256,
    matches,
    parse_signed_registry,
    registry_hash,
    signing_input,
    uint,
)

CHECK_SCHEMA = "impact.stock-check.v1"
Status = Literal["stock", "modified", "unknown"]

# R14 (pending author decision): the operator's `StockTrust`, published with each core release. None yet.
STOCK_TRUST: Raw = None
# R15 (pending author decision): the `StockPolicy` with the registry's maximum validity. None yet.
STOCK_POLICY: Raw = None

_TRUST_KEYS = frozenset({"key_id", "public_key"})
_POLICY_KEYS = frozenset({"schema", "version", "max_validity_s"})


@dataclass(frozen=True, slots=True)
class Published:
    """The trust anchor and the policy a lookup runs under (R14, R15)."""

    trust: Raw
    policy: Raw


@dataclass(frozen=True, slots=True)
class MemoryStock:
    """R23."""

    memory_id: str
    status: Status
    reason: str | None


@dataclass(frozen=True, slots=True)
class StockCheck:
    """R25."""

    status: Status
    reasons: tuple[str, ...]
    registry_hash: str | None
    registry_version: int | None
    family: str | None
    sw_id: str | None
    memories: tuple[MemoryStock, ...]


def stock_check_json(check: StockCheck) -> dict[str, Json]:
    """R25."""
    memories: list[Json] = [{"memory_id": m.memory_id, "status": m.status, "reason": m.reason} for m in check.memories]
    return {
        "schema": CHECK_SCHEMA,
        "status": check.status,
        "reasons": list(check.reasons),
        "registry_hash": check.registry_hash,
        "registry_version": check.registry_version,
        "family": check.family,
        "sw_id": check.sw_id,
        "memories": memories,
    }


def _identification(value: object, dump: Dump) -> Identification | None:
    """R20: None, or an identification satisfying SPEC-002 §2.1 and R4 for `dump`."""
    if value is None:
        return None
    if not isinstance(value, Identification):
        raise StockError("bad_identification", f"not an Identification: {type(value).__name__}")
    try:
        check_identification(value, dump, value.family)
    except PluginContractError as error:
        raise StockError("bad_identification", f"SPEC-002 {error.reason}") from error
    return value


def _trusted(signed: SignedStockRegistry, trust: Raw, verifier: Verifier | None) -> bool:
    """R13, R14, R21: the published key, a hash that recomputes and a signature the verifier accepts."""
    if verifier is None or not exact(trust, _TRUST_KEYS):
        return False
    key_id, public_key = trust["key_id"], trust["public_key"]
    if not (matches(key_id, HEX32) and matches(public_key, HEX32) and key_id == signed.key_id):
        return False
    if registry_hash(signed.registry) != signed.registry_hash:
        return False
    message = signing_input(signed.registry_hash)
    return verifier.verify(bytes.fromhex(public_key), message, bytes.fromhex(signed.signature)) is True


def _max_validity(policy: Raw) -> int | None:
    if not (exact(policy, _POLICY_KEYS) and policy["schema"] == POLICY_SCHEMA and uint(policy["version"])):
        return None
    validity = policy["max_validity_s"]
    return validity if uint(validity) else None


def _unusable(signed: SignedStockRegistry, published: Published, as_of: int, verifier: Verifier | None) -> list[str]:
    """R21, in its order; empty when the registry is used."""
    if not _trusted(signed, published.trust, verifier):
        return ["untrusted_registry"]
    validity = _max_validity(published.policy)
    if validity is None:
        return ["unpublished_stock_policy"]
    registry = signed.registry
    issued, expires = instant(registry.issued_at) or 0, instant(registry.expires_at) or 0
    reasons = []
    if as_of < issued:
        reasons.append("registry_not_yet_valid")
    if as_of >= expires:
        reasons.append("registry_expired")
    if expires - issued > validity:
        reasons.append("registry_validity_too_long")
    return reasons


def _covers(entry: StockEntry, ident: Identification, memory_id: str) -> bool:
    """R23: every pii range of the memory lies inside one excluded range (consecutive ranges never touch)."""
    return all(
        any(start <= pii.start and pii.end <= end for start, end in entry.excluded)
        for pii in ident.pii_locations
        if pii.memory_id == memory_id
    )


def _memory(memory: Memory, ident: Identification, entries: Sequence[StockEntry]) -> MemoryStock:
    """R23."""
    size = len(memory.data)
    candidates = [
        e
        for e in entries
        if (e.family, e.sw_id, e.memory_id, e.size) == (ident.family, ident.sw_id, memory.memory_id, size)
    ]
    usable = [e for e in candidates if _covers(e, ident, memory.memory_id)]
    if not candidates:
        return MemoryStock(memory.memory_id, "unknown", "not_registered")
    if not usable:
        return MemoryStock(memory.memory_id, "unknown", "pii_not_excluded")
    if any(kept_sha256(memory.data, e.excluded) == e.kept_sha256 for e in usable):
        return MemoryStock(memory.memory_id, "stock", None)
    return MemoryStock(memory.memory_id, "modified", None)


def _memory_id(memory: Memory) -> str:
    return memory.memory_id


def _overall(memories: Sequence[MemoryStock]) -> tuple[Status, tuple[str, ...]]:
    """R24."""
    statuses = {m.status for m in memories}
    if "modified" in statuses:
        return "modified", ()
    if statuses == {"stock"}:
        return "stock", ()
    return "unknown", tuple(sorted({m.reason for m in memories if m.reason is not None}))


def run_stock_check(
    dump: Dump,
    identification: Identification | None,
    registry: Raw,
    as_of: str,
    verifier: Verifier | None,
    published: Published,
) -> StockCheck:
    """`stock_check` under `published` (tests; R14, R15)."""
    signed = parse_signed_registry(registry)
    moment = instant(as_of)
    if moment is None:
        raise StockError("bad_shape", "as_of is a Timestamp")
    ident = _identification(identification, dump)
    family = None if ident is None else ident.family
    sw_id = None if ident is None else ident.sw_id
    reasons = _unusable(signed, published, moment, verifier)
    if reasons:
        return StockCheck("unknown", tuple(reasons), None, None, family, sw_id, ())

    def used(status: Status, why: tuple[str, ...], memories: tuple[MemoryStock, ...]) -> StockCheck:
        return StockCheck(status, why, signed.registry_hash, signed.registry.version, family, sw_id, memories)

    if ident is None:
        return used("unknown", ("not_identified",), ())
    if ident.sw_id is None:
        return used("unknown", ("no_sw_id",), ())
    memories = tuple(_memory(m, ident, signed.registry.entries) for m in sorted(dump.memories, key=_memory_id))
    status, why = _overall(memories)
    return used(status, why, memories)


def stock_check(
    dump: Dump, identification: Identification | None, registry: Raw, as_of: str, verifier: Verifier | None
) -> StockCheck:
    """SPEC-008 R20: the published lookup, under the trust anchor and policy published with this core."""
    return run_stock_check(dump, identification, registry, as_of, verifier, Published(STOCK_TRUST, STOCK_POLICY))
