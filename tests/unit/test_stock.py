"""SPEC-008: shape errors, identification checks, the unpublished anchor and policy, and usability reasons."""

import ast
import copy
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

import core.stock
from core.kernel import Dump, Memory
from core.plugins import Identification, PresentMemory
from core.provenance import Raw, Verifier
from core.stock import StockError, kept_sha256, parse_signed_registry, stock_check
from core.stock._check import STOCK_POLICY, STOCK_TRUST, Published, run_stock_check
from tests.unit.stock_support import AS_OF, CASES, MAIN, POLICY, TEST_PUBLISHED, TRUST, VERIFIER, V, dump_of, ident_of

K01 = CASES["K01-stock"]
DUMP = dump_of(K01["dump"])
IDENT = ident_of(K01["identification"], DUMP)


def check(
    registry: Raw = MAIN,
    *,
    ident: object = IDENT,
    as_of: str = AS_OF,
    verifier: Verifier | None = VERIFIER,
    published: Published = TEST_PUBLISHED,
) -> core.stock.StockCheck:
    return run_stock_check(DUMP, cast("Identification | None", ident), registry, as_of, verifier, published)


def edited(path: list[str | int], value: object) -> dict[str, Any]:
    """MAIN with the member at `path` set to `value` (or deleted when `value` is the `Ellipsis`)."""
    registry: dict[str, Any] = copy.deepcopy(MAIN)
    target: Any = registry
    for step in path[:-1]:
        target = target[step]
    if value is Ellipsis:
        del target[path[-1]]
    else:
        target[path[-1]] = value
    return registry


# SPEC-008 R2, R3, R10, R12, R13, R41: every malformed registry is `bad_shape`.
@pytest.mark.parametrize(
    ("path", "value"),
    [
        (["signature"], ...),
        (["key_id"], "AB" * 32),
        (["signature"], "00" * 63),
        (["registry", "schema"], "impact.stock-registry.v2"),
        (["registry", "version"], 0),
        (["registry", "version"], True),
        (["registry", "issued_at"], "2026-02-30T00:00:00Z"),
        (["registry", "expires_at"], "2026-10-20T24:00:00Z"),
        (["registry", "entries"], "none"),
        (["registry", "entries", 0, "family"], "Synthetic"),
        (["registry", "entries", 0, "sw_id"], ""),
        (["registry", "entries", 0, "sw_id"], "SW\n1"),
        (["registry", "entries", 0, "memory_id"], "DFlash"),
        (["registry", "entries", 0, "size"], 0),
        (["registry", "entries", 0, "kept_sha256"], "zz" * 32),
        (["registry", "entries", 0, "extra"], 1),
        (["registry", "entries", 0, "excluded"], {"start": 0, "end": 1}),
        (["registry", "entries", 0, "excluded", 0], [16, 24]),
        (["registry", "entries", 0, "excluded", 0, "start"], -1),
        (["registry", "entries", 0, "excluded", 0, "end"], 33),
        (["registry", "entries", 0, "excluded", 0, "end"], 16),
    ],
)
def test_bad_shape(path: list[str | int], value: object) -> None:
    with pytest.raises(StockError) as raised:
        check(edited(path, value))
    assert raised.value.reason == "bad_shape"


# SPEC-008 R10: excluded ranges are sorted and never touch; R12: entries sorted and unique.
@pytest.mark.parametrize(
    "excluded",
    [
        [{"start": 4, "end": 8}, {"start": 8, "end": 9}],
        [{"start": 8, "end": 9}, {"start": 4, "end": 6}],
    ],
)
def test_excluded_ranges_must_be_apart(excluded: list[dict[str, int]]) -> None:
    with pytest.raises(StockError) as raised:
        check(edited(["registry", "entries", 0, "excluded"], excluded))
    assert raised.value.reason == "bad_shape"


def test_entries_sorted_and_unique() -> None:
    registry = copy.deepcopy(MAIN)
    entries = registry["registry"]["entries"]
    for listed in (list(reversed(entries)), [entries[0], entries[0]]):
        registry["registry"]["entries"] = listed
        with pytest.raises(StockError) as raised:
            check(registry)
        assert raised.value.reason == "bad_shape"


def test_not_an_object() -> None:
    with pytest.raises(StockError) as raised:
        parse_signed_registry([MAIN])
    assert raised.value.reason == "bad_shape"


# SPEC-008 R20: a malformed `as_of` is `bad_shape`.
def test_bad_as_of() -> None:
    with pytest.raises(StockError) as raised:
        check(as_of="2026-10-19 12:00:00")
    assert raised.value.reason == "bad_shape"


# SPEC-008 R20: the identification must be SPEC-002's, and an identification of this dump (R4).
@pytest.mark.parametrize(
    "ident",
    [
        {"family": "synthetic.stock", "sw_id": "SYN-SW-1"},
        replace(IDENT or cast("Identification", None), memories_present=(PresentMemory("pflash", 0x80000000, 64),)),
    ],
)
def test_bad_identification(ident: object) -> None:
    with pytest.raises(StockError) as raised:
        check(ident=ident)
    assert raised.value.reason == "bad_identification"


# SPEC-008 R11: kept_sha256 refuses excluded ranges outside the data.
def test_kept_sha256_refuses_ranges_outside() -> None:
    with pytest.raises(StockError) as raised:
        kept_sha256(b"\x00" * 4, ((2, 5),))
    assert raised.value.reason == "bad_shape"


# SPEC-008 R14, R15, R21: nothing is published yet, so the published lookup trusts no registry.
def test_published_lookup_is_unknown() -> None:
    result = stock_check(DUMP, IDENT, MAIN, AS_OF, VERIFIER)
    assert (result.status, result.reasons, result.registry_hash, result.memories) == (
        "unknown",
        ("untrusted_registry",),
        None,
        (),
    )
    assert STOCK_TRUST is None
    assert STOCK_POLICY is None


# SPEC-008 R14: the synthetic vector key is never the published anchor.
def test_vector_key_not_published() -> None:
    source = (Path(core.stock.__file__).parent / "_check.py").read_text(encoding="utf-8")
    assert V["key"]["public_key"] not in source
    assert V["key"]["key_id"] not in source


# SPEC-008 R21: no verifier, a malformed anchor, or a registry that does not recompute is untrusted.
@pytest.mark.parametrize(
    ("registry", "verifier", "trust"),
    [
        (MAIN, None, TRUST),
        (MAIN, VERIFIER, {"key_id": TRUST["key_id"]}),
        (MAIN, VERIFIER, {"key_id": TRUST["key_id"], "public_key": "XY"}),
        (edited(["registry", "version"], 4), VERIFIER, TRUST),
    ],
)
def test_untrusted(registry: dict[str, Any], verifier: Verifier | None, trust: dict[str, Any]) -> None:
    result = check(registry, verifier=verifier, published=Published(trust, POLICY))
    assert (result.status, result.reasons, result.registry_version) == ("unknown", ("untrusted_registry",), None)


# SPEC-008 R15, R21: a trusted registry without a published policy is not used.
@pytest.mark.parametrize(
    "policy",
    [
        None,
        {"schema": "impact.head-policy.v1", "version": 1, "max_validity_s": 86400},
        {"schema": "impact.stock-policy.v1", "version": 1, "max_validity_s": -1},
        {"schema": "impact.stock-policy.v1", "version": True, "max_validity_s": 86400},
    ],
)
def test_unpublished_policy(policy: dict[str, Any] | None) -> None:
    result = check(published=Published(TRUST, policy))
    assert (result.status, result.reasons) == ("unknown", ("unpublished_stock_policy",))


# SPEC-008 R21: freshness reasons are all reported together.
def test_every_freshness_reason() -> None:
    result = check(V["registries"]["too_long"], as_of="2026-10-20T00:00:01Z")
    assert result.reasons == ("registry_expired", "registry_validity_too_long")


# SPEC-008 R23, R24: a dump with one memory registered and one not is unknown, never stock.
def test_unregistered_memory_keeps_unknown() -> None:
    dump = Dump("bench_full", (*DUMP.memories, Memory("eeprom", None, b"\x01\x02")))
    ident = ident_of(K01["identification"], dump)
    result = run_stock_check(dump, ident, MAIN, AS_OF, VERIFIER, TEST_PUBLISHED)
    assert (result.status, result.reasons) == ("unknown", ("not_registered",))
    assert [(m.memory_id, m.status) for m in result.memories] == [
        ("dflash", "stock"),
        ("eeprom", "unknown"),
        ("pflash", "stock"),
    ]


# SPEC-008 R26: the public API offers nothing that reads or writes a verdict.
def test_information_only() -> None:
    assert not any("verdict" in name.lower() for name in core.stock.__all__)


# SPEC-008 R22: with a usable registry, no identification or no sw_id is unknown with the registry named.
def test_identification_reasons() -> None:
    no_ident = check(ident=None)
    assert (no_ident.status, no_ident.reasons, no_ident.family) == ("unknown", ("not_identified",), None)
    assert no_ident.registry_hash == MAIN["registry_hash"]
    no_sw = check(ident=replace(IDENT or cast("Identification", None), sw_id=None))
    assert (no_sw.status, no_sw.reasons, no_sw.sw_id, no_sw.memories) == ("unknown", ("no_sw_id",), None, ())


# SPEC-008 R30: no registry or check field names personal data, and no dump byte is carried.
def test_no_personal_data_fields() -> None:
    def keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return set(value) | {key for item in value.values() for key in keys(item)}
        if isinstance(value, list):
            return {key for item in value for key in keys(item)}
        return set()

    found = keys(MAIN) | keys(V["cases"][0]["expect"])
    for word in ("vin", "serial", "owner", "customer", "person", "file", "data", "bytes"):
        assert not any(word in key for key in found), word


# SPEC-008 R40: core.stock imports only the public kernel, provenance and plugins APIs and its own modules.
def test_placement() -> None:
    for path in sorted(Path(core.stock.__file__).parent.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("core"):
                module = node.module or ""
                assert module in {"core.kernel", "core.provenance", "core.plugins"} or module.startswith(
                    "core.stock."
                ), module
