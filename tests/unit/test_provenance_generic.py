"""SPEC-005 §4.2 R110-R114 at the provenance level: changed ranges, the record and its consistency checks."""

import json
from types import MappingProxyType
from typing import Any, cast

import pytest

from core.kernel import Dump, DumpKind, Memory, canonical_json, image_hash
from core.provenance import (
    Build,
    ChangedRun,
    GenericAuditInputs,
    GenericAuditRecord,
    Json,
    KnownMaps,
    PluginReason,
    RecordError,
    changed_ranges,
    generic_audit_record,
)
from core.provenance import ShapeError as RecordShapeError

BUILD = Build("lockfile", "sha256:" + "ab" * 32, "linux/amd64", None)
DEFINITION_HASH = "cd" * 32


def dump(*memories: tuple[str, int | None, bytes], dump_kind: DumpKind = "bench_full") -> Dump:
    return Dump(dump_kind, tuple(Memory(m, base, data) for m, base, data in memories))


ORIGINAL = dump(("pflash", 0x8000, bytes(range(32))), ("dflash", 0x1000, bytes(16)))
# pflash 2..5 and 10, dflash 15: three changes in memory_id order (dflash first).
CANDIDATE = dump(
    ("pflash", 0x8000, bytes([0, 1, 99, 99, 99, *range(5, 10), 77, *range(11, 32)])),
    ("dflash", 0x1000, bytes(15) + b"\x01"),
)


def spans(patches: tuple[Any, ...]) -> list[tuple[str, int, int]]:
    return [(p.memory_id, p.offset, p.length) for p in patches]


def plain(value: Json) -> dict[str, Any]:
    return cast("dict[str, Any]", json.loads(canonical_json(value)))


def inputs(known: KnownMaps | None, reason: PluginReason = "no_admitted_plugin") -> GenericAuditInputs:
    return GenericAuditInputs(ORIGINAL, CANDIDATE, "file_service", known, reason, "9.9.9", BUILD)


def known(
    map_ids: dict[str, tuple[str, ...]] | None = None,
    outside: tuple[ChangedRun, ...] | None = None,
    unbound: tuple[str, ...] = (),
) -> KnownMaps:
    patches = changed_ranges(ORIGINAL, CANDIDATE)
    ids = {p.patch_hash: ("m.a",) if p.memory_id == "pflash" else () for p in patches}
    default_outside = (ChangedRun("dflash", 15, 1), ChangedRun("pflash", 4, 1))
    return KnownMaps(
        DEFINITION_HASH,
        MappingProxyType(ids if map_ids is None else map_ids),
        default_outside if outside is None else outside,
        unbound,
    )


# SPEC-005 R111: maximal differing runs per memory, in (memory_id, offset) order, with SPEC-001 R61 hashes.
def test_changed_ranges() -> None:
    patches = changed_ranges(ORIGINAL, CANDIDATE)
    assert spans(patches) == [("dflash", 15, 1), ("pflash", 2, 3), ("pflash", 10, 1)]
    assert patches[1].before == bytes([2, 3, 4])
    assert patches[1].after == bytes([99, 99, 99])


# SPEC-005 R111: equal dumps have no change; a long equal prefix is skipped in chunks.
def test_no_change_and_long_runs() -> None:
    big = dump(("pflash", 0, bytes(300)))
    assert changed_ranges(big, big) == ()
    edited = dump(("pflash", 0, bytes(200) + b"\x01" * 100))
    assert spans(changed_ranges(big, edited)) == [("pflash", 200, 100)]


# SPEC-005 R111: an unknown base address is allowed (no layout, no address is used).
def test_unknown_base_address_is_allowed() -> None:
    a, b = dump(("pflash", None, b"\x00\x00")), dump(("pflash", None, b"\x00\x01"))
    assert spans(changed_ranges(a, b)) == [("pflash", 1, 1)]


# SPEC-005 R111, SPEC-001 R31: another shape is `shape_mismatch`.
@pytest.mark.parametrize(
    "other",
    [
        dump(("pflash", 0x8000, bytes(range(32))), ("dflash", 0x1000, bytes(16)), dump_kind="obd_full"),
        dump(("pflash", 0x8000, bytes(range(32))), ("dflash", 0x2000, bytes(16))),
        dump(("pflash", 0x8000, bytes(range(31))), ("dflash", 0x1000, bytes(16))),
        dump(("pflash", 0x8000, bytes(range(32)))),
    ],
)
def test_shape_mismatch(other: Dump) -> None:
    with pytest.raises(RecordError) as raised:
        changed_ranges(ORIGINAL, other)
    assert raised.value.reason == "shape_mismatch"
    with pytest.raises(RecordError) as record:
        generic_audit_record(GenericAuditInputs(ORIGINAL, other, "file_service", None, "no_rule_table", "1", BUILD))
    assert record.value.reason == "shape_mismatch"


# SPEC-005 R112, R113, R114: without a definition every change is outside every known map.
def test_record_without_definition() -> None:
    record = generic_audit_record(inputs(None))
    value = plain(record.value)
    assert value["schema"] == "impact.generic-audit-record.v1"
    assert value["image_hash_original"] == image_hash(ORIGINAL)
    assert value["image_hash_candidate"] == image_hash(CANDIDATE)
    assert value["definition_hash"] is None
    assert [c["map_ids"] for c in value["changes"]] == [[], [], []]
    assert value["outside_known_maps"] == [
        {"memory_id": "dflash", "offset": 15, "length": 1},
        {"memory_id": "pflash", "offset": 2, "length": 3},
        {"memory_id": "pflash", "offset": 10, "length": 1},
    ]
    assert value["unbound_maps"] == []
    assert value["not_evaluated"] == [
        {"check": "identification", "reason": "no_admitted_plugin"},
        {"check": "layout", "reason": "no_admitted_plugin"},
        {"check": "map_rules", "reason": "no_definition"},
        {"check": "verify", "reason": "no_admitted_plugin"},
    ]
    assert value["checksum_status"] == "not_verified"
    assert value["versions"] == {"core": "9.9.9"}
    assert value["reproducibility"] == "best_effort"
    assert record.generic_audit_hash == GenericAuditRecord(record.value).generic_audit_hash


# SPEC-005 R112, R113: with attribution data from the gate, copied as given once checked (R110).
def test_record_with_known_maps() -> None:
    value = plain(generic_audit_record(inputs(known(unbound=("m.z",)), "no_rule_table")).value)
    assert value["definition_hash"] == DEFINITION_HASH
    assert [c["map_ids"] for c in value["changes"]] == [[], ["m.a"], ["m.a"]]
    assert value["outside_known_maps"] == [
        {"memory_id": "dflash", "offset": 15, "length": 1},
        {"memory_id": "pflash", "offset": 4, "length": 1},
    ]
    assert value["unbound_maps"] == ["m.z"]
    assert [e["reason"] for e in value["not_evaluated"]] == ["no_rule_table"] * 4


def _unmapped_ids() -> dict[str, tuple[str, ...]]:
    return {p.patch_hash: () for p in changed_ranges(ORIGINAL, CANDIDATE)}


# SPEC-005 R110: attribution data that does not describe exactly these changes is `inconsistent_record`.
@pytest.mark.parametrize(
    "bad",
    [
        known(map_ids={"ee" * 32: ()}),
        known(outside=(ChangedRun("pflash", 4, 1), ChangedRun("dflash", 15, 1))),
        known(outside=(ChangedRun("dflash", 15, 1), ChangedRun("pflash", 2, 3), ChangedRun("pflash", 3, 1))),
        known(outside=(ChangedRun("dflash", 15, 1), ChangedRun("pflash", 5, 1))),
        known(outside=(ChangedRun("pflash", 4, 1),)),
        known(map_ids=_unmapped_ids(), outside=(ChangedRun("dflash", 15, 1), ChangedRun("pflash", 2, 3))),
    ],
    ids=["unknown_change", "unsorted", "overlapping", "outside_any_change", "unmapped_not_outside", "partial"],
)
def test_inconsistent_attribution(bad: KnownMaps) -> None:
    with pytest.raises(RecordError) as raised:
        generic_audit_record(inputs(bad))
    assert raised.value.reason == "inconsistent_record"


def _valid() -> dict[str, Any]:
    return plain(generic_audit_record(inputs(known())).value)


def _with(path: tuple[Any, ...], value: object) -> dict[str, Any]:
    record = _valid()
    target: Any = record
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return record


# SPEC-005 R3, R113: shape violations are `bad_shape`.
@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("checksum_status",), "ok"),
        (("not_evaluated",), "none"),
        (("not_evaluated", 0, "check"), "verify"),
        (("not_evaluated", 0, "reason"), "no_rule_table"),
        (("not_evaluated", 2, "reason"), "no_admitted_plugin"),
        (("not_evaluated", 0, "reason"), "no_definition"),
        (("changes", 0, "map_ids"), ["b", "a"]),
        (("unbound_maps",), ["z", "z"]),
        (("versions",), {"core": "1", "plugins": []}),
        (("definition_hash",), "x"),
    ],
)
def test_bad_shape(path: tuple[Any, ...], value: object) -> None:
    with pytest.raises(RecordShapeError) as raised:
        GenericAuditRecord(_with(path, value))
    assert raised.value.reason == "bad_shape"


# SPEC-005 R112, R113: `no_definition` if and only if `definition_hash` is null, and then nothing is attributed.
@pytest.mark.parametrize(
    "record",
    [
        _with(("definition_hash",), None),
        _with(("not_evaluated", 2, "reason"), "no_definition"),
    ],
)
def test_definition_and_map_rules_reason_agree(record: dict[str, Any]) -> None:
    with pytest.raises(RecordError) as raised:
        GenericAuditRecord(record)
    assert raised.value.reason == "inconsistent_record"


def test_no_definition_attributes_nothing() -> None:
    bare = plain(generic_audit_record(inputs(None)).value)
    for path, value in ((("unbound_maps",), ["m.z"]), (("changes", 1, "map_ids"), ["m.a"])):
        record = json.loads(json.dumps(bare))
        target: Any = record
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        with pytest.raises(RecordError):
            GenericAuditRecord(record)


# SPEC-005 R16, R17: reproducibility follows the build.
def test_reproducibility_follows_build() -> None:
    with pytest.raises(RecordError):
        GenericAuditRecord(_with(("reproducibility",), "full"))
