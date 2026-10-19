"""SPEC-005 R73, R74: each way a bundle fails to reproduce names its step and field.

Every mutated bundle starts from the SPEC-005 `report_file` vector bundle; when the record changes, the report
is re-signed with `rfc8785` and `cryptography` (tests/reproduce/bundles.py), never with the script.
"""

import json
from collections.abc import Callable
from typing import Any

import pytest

import reproduce
from tests.reproduce.bundles import original, patch, rehash_event, resign, vector_bundle
from tests.unit.provenance_support import SPEC005
from tests.vectors.test_spec_001 import VECTORS as SPEC001

type Bundle = dict[str, Any]

P1 = SPEC001["patches"]["P1"]["patch_hash"]
P2 = SPEC001["patches"]["P2"]["patch_hash"]
EVENT_HASH = SPEC005["report_file"]["value"]["event"]["hash"]


def mismatches(data: bytes) -> list[tuple[int, str, object]]:
    result = reproduce.reproduce(data)
    found = result["mismatches"]
    assert isinstance(found, list)
    assert result["status"] == ("not_reproduced" if found else "reproduced")
    return [(m["step"], m["field"], m["got"]) for m in found]


def encoded(bundle: Bundle) -> bytes:
    return json.dumps(bundle).encode("utf-8")


# SPEC-005 R1, R3, R74: the bundle is UTF-8 JSON without floats, non-finite numbers or duplicate keys.
@pytest.mark.parametrize(
    ("data", "got"),
    [
        (b"\xff", "UnicodeDecodeError"),
        (b"{", "JSONDecodeError"),
        (b'{"a": 1.5}', "1.5"),
        (b'{"a": NaN}', "NaN"),
        (b'{"a": 1, "a": 2}', "a"),
        (b"[]", "list"),
        (b'{"schema": "impact.reproduction-bundle.v1"}', ["schema"]),
    ],
)
def test_unreadable_bundle(data: bytes, got: object) -> None:
    assert mismatches(data) == [(0, "bundle", got)]
    assert reproduce.reproduce(data)["reproducibility"] is None


def _record(bundle: Bundle) -> Bundle:
    record: Bundle = bundle["report_file"]["report"]["record"]
    return record


def _event(bundle: Bundle) -> Bundle:
    event: Bundle = bundle["report_file"]["event"]
    return event


def _set_record(key: str, value: object) -> Callable[[Bundle], None]:
    def mutate(bundle: Bundle) -> None:
        _record(bundle)[key] = value
        resign(bundle["report_file"])

    return mutate


def _set_event(*path: str, value: object, rehash: bool = True) -> Callable[[Bundle], None]:
    def mutate(bundle: Bundle) -> None:
        target = _event(bundle)
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        if rehash:
            rehash_event(_event(bundle))

    return mutate


def _set(path: tuple[str | int, ...], value: object) -> Callable[[Bundle], None]:
    def mutate(bundle: Bundle) -> None:
        target: Any = bundle
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value

    return mutate


def _delete(path: tuple[str | int, ...]) -> Callable[[Bundle], None]:
    def mutate(bundle: Bundle) -> None:
        target: Any = bundle
        for key in path[:-1]:
            target = target[key]
        del target[path[-1]]

    return mutate


def _append(path: tuple[str, ...], value: object) -> Callable[[Bundle], None]:
    def mutate(bundle: Bundle) -> None:
        target: Any = bundle
        for key in path:
            target = target[key]
        target.append(value)

    return mutate


def _flip_original(offset: int) -> Callable[[Bundle], None]:
    def mutate(bundle: Bundle) -> None:
        memory = bundle["original"]["memories"][0]
        assert memory["memory_id"] == "pflash"
        data = bytearray.fromhex(memory["data"])
        data[offset] ^= 0xFF
        memory["data"] = data.hex()

    return mutate


def _null_pflash_base(bundle: Bundle) -> None:
    bundle["original"]["memories"][0]["base_address"] = None
    pflash = next(m for m in bundle["layout"]["memories"] if m["memory_id"] == "pflash")
    pflash["base_address"] = None


def _with_patch(key: str, **change: object) -> Callable[[Bundle], None]:
    def mutate(bundle: Bundle) -> None:
        bundle[key].append({**patch("P1"), **change})

    return mutate


IMAGE_CHAIN = [(4, "version_hash"), (5, "image_hash_apply"), (6, "image_hash_release")]
PFLASH = "layout.memories[1]"
DFLASH = "original.memories[1]"
PFLASH_LAYOUT = SPEC001["layouts"]["base"]["value"]["memories"][1]
REPORT_FIELDS_FOR_KEY_ID = ["report_file.report_hash", "report.signer.key_id", "event.payload.key_id"]

CASES: list[tuple[str, Callable[[Bundle], None], list[tuple[int, str] | tuple[int, str, object]]]] = [
    ("schema", _set(("schema",), "x"), [(0, "bundle.schema", "x")]),
    # Step 1: SPEC-005 R61.
    ("report-file-not-object", _set(("report_file",), []), [(1, "report_file", "list")]),
    ("kind-missing", _delete(("report_file", "report", "kind")), [(1, "report.kind", None)]),
    ("record-not-object", _set(("report_file", "report", "record"), []), [(1, "report.record", "list")]),
    ("report-hash-not-hex", _set(("report_file", "report_hash"), "XYZ"), [(1, "report_file.report_hash", "XYZ")]),
    (
        "public-key-not-hex",
        _set(("report_file", "report", "signer", "public_key"), "zz"),
        [(1, "report.signer.public_key", "not lowercase hex")],
    ),
    (
        "key-id",
        _set(("report_file", "report", "signer", "key_id"), "00" * 32),
        [(1, field) for field in REPORT_FIELDS_FOR_KEY_ID],
    ),
    ("event-not-object", _set(("report_file", "event"), "x"), [(1, "event", "str")]),
    ("event-hash", _set_event("hash", value="00" * 32, rehash=False), [(1, "event.hash", EVENT_HASH)]),
    ("event-type", _set_event("type", value="audit"), [(1, "event.type", "audit")]),
    ("event-tenant", _set_event("tenant_id", value="other"), [(1, "event.tenant_id", "other")]),
    ("payload-report-hash", _set_event("payload", "report_hash", value="00" * 32), [(1, "event.payload.report_hash")]),
    (
        "payload-record-hash",
        _set_event("payload", "provenance_hash", value="00" * 32),
        [(1, "event.payload.provenance_hash")],
    ),
    ("record-non-ascii-key", _set(("report_file", "report", "record", "é"), 1), [(1, "report.record", "é")]),
    # Step 2: SPEC-001 R1, R62.
    ("dump-kind", _set(("original", "dump_kind"), "full"), [(2, "original.dump_kind", "full")]),
    ("memories-not-list", _set(("original", "memories"), {}), [(2, "original.memories", "dict")]),
    ("no-memories", _set(("original", "memories"), []), [(2, "original.memories", 0)]),
    ("memory-keys", _delete(("original", "memories", 0, "data")), [(2, "original.memories[0]")]),
    ("memory-id", _set(("original", "memories", 0, "memory_id"), "Pflash"), [(2, "original.memories[0].memory_id")]),
    ("duplicate-memory", _set(("original", "memories", 1, "memory_id"), "pflash"), [(2, "original.memories[1]")]),
    ("empty-data", _set(("original", "memories", 1, "data"), ""), [(2, "original.memories[1]", "dflash")]),
    ("upper-hex", _set(("original", "memories", 1, "data"), "FF" * 16), [(2, f"{DFLASH}.data", "not lowercase hex")]),
    ("bool-base", _set(("original", "memories", 1, "base_address"), True), [(2, "original.memories[1].base_address")]),
    ("protected-byte", _flip_original(0), [(2, "image_hash_original"), *IMAGE_CHAIN]),
    # Step 3: SPEC-001 R4, R5, R63.
    ("layout-size", _set(("layout", "memories", 1, "size"), 63), [(3, PFLASH, "shape_mismatch")]),
    ("layout-unknown", _set(("layout", "memories", 0, "memory_id"), "eeprom"), [(3, "layout.memories[0]")]),
    ("layout-twice", _append(("layout", "memories"), PFLASH_LAYOUT), [(3, "layout.memories[2]", "shape_mismatch")]),
    ("layout-missing", _delete(("layout", "memories", 0)), [(3, "layout.memories", ["pflash"])]),
    ("region-kind", _set(("layout", "memories", 1, "regions", 0, "kind"), "code"), [(3, f"{PFLASH}.regions[0]")]),
    ("region-gap", _set(("layout", "memories", 1, "regions", 1, "start"), 17), [(3, f"{PFLASH}.regions[1]")]),
    (
        "region-empty",
        _append(("layout", "memories"), {}),
        [(3, "layout.memories[2]")],
    ),
    (
        "region-zero-length",
        _set(("layout", "memories", 0, "regions"), [{"kind": "protected", "start": 0, "end": 0, "name": ""}]),
        [(3, "layout.memories[0].regions[0]", "bad_cover")],
    ),
    ("region-short", _delete(("layout", "memories", 1, "regions", 4)), [(3, f"{PFLASH}.regions", "bad_cover")]),
    (
        "region-name",
        _set(("layout", "memories", 1, "regions", 0, "name"), "x"),
        [(3, "layout_hash"), (4, "version_hash")],
    ),
    # Step 4: SPEC-001 R10, R12, R14, R22, R25, R64.
    ("bad-length", _set(("patches", 0, "length"), 3), [(4, "patches[0]", "bad_length")]),
    ("noop", _set(("patches", 0, "after"), patch("P2")["before"]), [(4, "patches[0]", "noop_patch")]),
    ("duplicate-patch", _append(("patches",), patch("P1")), [(4, "patches", P1)]),
    ("pair-size", _set(("overlaps",), [[P1]]), [(4, "overlaps[0]", 1)]),
    ("pair-unknown", _set(("overlaps",), [["00" * 32, P1]]), [(4, "overlaps[0]", "spurious_order")]),
    ("pair-self", _set(("overlaps",), [[P1, P1]]), [(4, "overlaps[0]", "spurious_order")]),
    ("pair-disjoint", _set(("overlaps",), [[P1, P2]]), [(4, "overlaps[0]", "spurious_order")]),
    ("patch-missing", _delete(("patches", 0)), [(4, "patch_hashes"), *IMAGE_CHAIN]),
    ("patch-order", _set_record("patch_hashes", [P2, P1]), [(4, "patch_order", [P1, P2])]),
    ("record-overlaps", _set_record("overlaps", [[P1, P2]]), [(4, "overlaps", [])]),
    # Step 5: SPEC-001 R2, R21, R23.
    (
        "unknown-base-address",
        _null_pflash_base,
        [(2, "image_hash_original"), (3, "layout_hash"), (4, "version_hash"), (5, "original.memories")],
    ),
    (
        "before-mismatch",
        _flip_original(17),
        [(2, "image_hash_original"), (4, "version_hash"), (5, f"patch {P1}", "before_mismatch")],
    ),
    (
        "out-of-region",
        _with_patch("patches", offset=0, before="00", after="01", length=1),
        [(4, "patch_hashes"), (4, "version_hash"), (5, "patch ", "out_of_region")],
    ),
    (
        "unknown-memory",
        _with_patch("patches", memory_id="eeprom"),
        [(4, "patch_hashes"), (4, "version_hash"), (5, "patch ", "unknown_memory")],
    ),
    ("record-hash-type", _set_record("image_hash_apply", 5), [(5, "report.record.image_hash_apply", 5)]),
    # Step 6: SPEC-001 R40, R21.
    ("checksum-dropped", _set(("checksum_patches",), []), [(6, "checksum_patch_hashes"), (6, "image_hash_release")]),
    (
        "checksum-out-of-region",
        _set(("checksum_patches",), [patch("P1")]),
        [(6, "checksum_patch_hashes"), (6, f"patch {P1}", "checksum_out_of_region")],
    ),
    (
        "checksum-overlap",
        _append(("checksum_patches",), {**patch("Q1"), "offset": 62, "length": 1, "before": "3e", "after": "00"}),
        [(6, "checksum_patch_hashes"), (6, "checksum_patches")],
    ),
    (
        "checksum-before",
        _set(("checksum_patches", 0, "before"), "00000000"),
        [(6, "checksum_patch_hashes"), (6, "patch ", "before_mismatch")],
    ),
    # Step 7: SPEC-005 R1, R4, SPEC-001 R60.
    ("gate-report", _set(("gate_report", "verdict"), "block"), [(7, "gate_report_hash")]),
    ("gate-surrogate", _set(("gate_report", "x"), "\ud800"), [(7, "gate_report.x", "lone surrogate")]),
    ("gate-big-int", _set(("gate_report", "x"), [2**60]), [(7, "gate_report.x[0]", str(2**60))]),
    ("gate-key", _set(("gate_report", "é"), 1), [(7, "gate_report", "é")]),
]


@pytest.mark.parametrize(("mutate", "expected"), [c[1:] for c in CASES], ids=[c[0] for c in CASES])
def test_mismatch(mutate: Callable[[Bundle], None], expected: list[tuple[Any, ...]]) -> None:
    bundle = vector_bundle()
    mutate(bundle)
    found = mismatches(encoded(bundle))
    assert len(found) == len(expected), found
    for (step, field, got), want in zip(found, expected, strict=True):
        assert step == want[0]
        assert field.startswith(want[1]) if want[1].endswith(" ") else field == want[1]
        if len(want) == 3:
            assert got == want[2]


# SPEC-005 R74: `full` only for a `full` record that ran in a released image (R16, R17); never upgraded.
@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ({}, "full"),
        ({"build": None}, "best_effort"),
        ({"reproducibility": "best_effort"}, "best_effort"),
        ({"build": {"kind": "lockfile"}}, "best_effort"),
    ],
)
def test_reproducibility_is_never_upgraded(change: Bundle, expected: str) -> None:
    bundle = vector_bundle()
    _record(bundle).update(change)
    resign(bundle["report_file"])
    result = reproduce.reproduce(encoded(bundle))
    assert result["status"] == "reproduced"
    assert result["reproducibility"] == expected


# SPEC-005 R74: once the record is read, a later stop still reports its reproducibility.
def test_reproducibility_after_a_stop() -> None:
    bundle = vector_bundle()
    bundle["original"] = original() | {"dump_kind": "x"}
    assert reproduce.reproduce(encoded(bundle))["reproducibility"] == "full"


# SPEC-005 R1, R72: no float is ever hashed.
def test_float_is_never_hashed() -> None:
    with pytest.raises(reproduce.Malformed) as caught:
        reproduce.sha256_jcs({"a": 1.5})
    assert (caught.value.field, caught.value.got) == ("value.a", "float")
