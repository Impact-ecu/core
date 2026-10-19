"""SPEC-008 R1, R11, R23, R24 as properties, against fingerprints (hashlib) and a registry hash (third-party rfc8785)
computed here, not by the core."""

import hashlib
from typing import Any

import rfc8785
from hypothesis import given
from hypothesis import strategies as st

from core.kernel import Dump, Memory
from core.plugins import Identification, PiiLocation, PresentMemory
from core.stock._check import Published, run_stock_check
from core.stock._registry import signing_input
from tests.unit.provenance_support import VERIFIER, Ed25519Signer
from tests.unit.provenance_support import _plain as plain

SIGNER = Ed25519Signer(hashlib.sha256(b"impact core stock property tests: registry").digest())
PUBLISHED = Published(
    {"key_id": SIGNER.key_id, "public_key": SIGNER.public_key},
    {"schema": "impact.stock-policy.v1", "version": 0, "max_validity_s": 86400},
)
FAMILY, SW = "synthetic.stock", "SYN-PROP"


def oracle_kept(data: bytes, excluded: list[tuple[int, int]]) -> str:
    masked = {offset for start, end in excluded for offset in range(start, end)}
    return hashlib.sha256(bytes(b for i, b in enumerate(data) if i not in masked)).hexdigest()


def signed(entries: list[dict[str, Any]]) -> dict[str, Any]:
    registry: dict[str, Any] = {
        "schema": "impact.stock-registry.v1",
        "version": 1,
        "issued_at": "2026-10-19T00:00:00Z",
        "expires_at": "2026-10-20T00:00:00Z",
        "entries": sorted(
            entries, key=lambda e: (e["family"], e["sw_id"], e["memory_id"], e["size"], e["kept_sha256"])
        ),
    }
    digest = hashlib.sha256(rfc8785.dumps(registry)).hexdigest()
    signature = SIGNER.sign(signing_input(digest)).hex()
    return {"registry": registry, "registry_hash": digest, "key_id": SIGNER.key_id, "signature": signature}


@st.composite
def memories(draw: st.DrawFn) -> tuple[bytes, list[tuple[int, int]]]:
    size = draw(st.integers(2, 64))
    data = draw(st.binary(min_size=size, max_size=size))
    cuts = sorted(draw(st.sets(st.integers(0, size), max_size=6)))
    # Distinct sorted cuts paired in order: every range is non-empty and the next one starts after it ends.
    return data, [(cuts[i], cuts[i + 1]) for i in range(0, len(cuts) - 1, 2)]


def classify(stock: bytes, excluded: list[tuple[int, int]], seen: bytes, pii: list[tuple[int, int]]) -> str:
    entry = {
        "family": FAMILY,
        "sw_id": SW,
        "memory_id": "pflash",
        "size": len(stock),
        "excluded": [{"start": s, "end": e} for s, e in excluded],
        "kept_sha256": oracle_kept(stock, excluded),
    }
    dump = Dump("bench_full", (Memory("pflash", 0x1000, seen),))
    locations = tuple(PiiLocation("pflash", s, e, "serial") for s, e in pii)
    ident = Identification(
        FAMILY, None, SW, None, None, (PresentMemory("pflash", 0x1000, len(seen)),), (), locations, (), 900
    )
    result = run_stock_check(dump, ident, signed([entry]), "2026-10-19T12:00:00Z", VERIFIER, PUBLISHED)
    return str(plain(result.status))


# SPEC-008 R1, R11, R23: the registry hash is sha256 of its RFC 8785 JCS; any change inside the excluded ranges
# keeps `stock`; a change outside makes `modified`.
@given(memories(), st.data())
def test_excluded_bytes_never_count(case: tuple[bytes, list[tuple[int, int]]], data: st.DataObject) -> None:
    stock, excluded = case
    other = bytearray(stock)
    masked = [i for s, e in excluded for i in range(s, e)]
    for offset in data.draw(st.lists(st.sampled_from(masked), max_size=4)) if masked else []:
        other[offset] ^= 0xFF
    assert classify(stock, excluded, bytes(other), excluded) == "stock"
    kept = [i for i in range(len(stock)) if i not in set(masked)]
    if kept:
        other[data.draw(st.sampled_from(kept))] ^= data.draw(st.integers(1, 255))
        assert classify(stock, excluded, bytes(other), excluded) == "modified"


# SPEC-008 R23: a pii range not inside an excluded range gives `unknown`, never `modified`.
@given(memories(), st.data())
def test_uncovered_pii_is_unknown(case: tuple[bytes, list[tuple[int, int]]], data: st.DataObject) -> None:
    stock, excluded = case
    masked = {i for s, e in excluded for i in range(s, e)}
    outside = [i for i in range(len(stock)) if i not in masked]
    if outside:
        offset = data.draw(st.sampled_from(outside))
        assert classify(stock, excluded, stock, [(offset, offset + 1)]) == "unknown"
