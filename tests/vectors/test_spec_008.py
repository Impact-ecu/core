"""SPEC-008 vectors: fingerprints, the registry hash and signature, and every lookup case K01-K15."""

import hashlib
from typing import Any

import pytest

from core.kernel import canonical_json
from core.stock import kept_sha256, parse_signed_registry, registry_hash, stock_check_json
from core.stock._check import Published, run_stock_check
from core.stock._registry import signing_input
from tests.unit.provenance_support import Ed25519Signer
from tests.unit.provenance_support import _plain as plain
from tests.unit.stock_support import CASES, MAIN, POLICY, VERIFIER, V, dump_of, ident_of


# SPEC-008 R13, R14: the vector key is derived from its published seed.
def test_key() -> None:
    signer = Ed25519Signer(hashlib.sha256(V["key"]["seed_text"].encode()).digest())
    assert (signer.public_key, signer.key_id) == (V["key"]["public_key"], V["key"]["key_id"])
    assert V["trusts"]["main"] == {"key_id": signer.key_id, "public_key": signer.public_key}


# SPEC-008 R11: kept_sha256 with and without excluded ranges.
@pytest.mark.parametrize("value", V["fingerprints"]["values"], ids=lambda f: f["id"])
def test_fingerprints(value: dict[str, Any]) -> None:
    excluded = tuple((start, end) for start, end in value["excluded"])
    assert kept_sha256(bytes.fromhex(value["data_hex"]), excluded) == value["kept_sha256"]


# SPEC-008 R10, R12, R13: registry JCS, hash, signing input and a signature that re-signs byte for byte.
def test_registry() -> None:
    signed = parse_signed_registry(MAIN)
    assert canonical_json(signed.registry.to_json()).decode() == V["registry"]["jcs"]
    assert registry_hash(signed.registry) == V["registry"]["registry_hash"] == MAIN["registry_hash"]
    assert signing_input(signed.registry_hash).decode() == V["registry"]["signing_input"]
    signer = Ed25519Signer(hashlib.sha256(V["key"]["seed_text"].encode()).digest())
    assert signer.sign(signing_input(signed.registry_hash)).hex() == MAIN["signature"]


# SPEC-008 R20-R25: every case gives exactly the hand-written StockCheck, whatever the memory order.
@pytest.mark.parametrize("case", list(CASES.values()), ids=lambda c: c["id"])
def test_cases(case: dict[str, Any]) -> None:
    dump = dump_of(case["dump"])
    published = Published(V["trusts"][case["trust"]], POLICY)
    registry = V["registries"][case["registry"]]
    result = run_stock_check(dump, ident_of(case["identification"], dump), registry, case["as_of"], VERIFIER, published)
    assert plain(stock_check_json(result)) == case["expect"]
