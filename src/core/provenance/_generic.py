"""`GenericAuditRecord` (SPEC-005 §4.2, R110-R116): the audit without a family plugin, built by the core."""

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from itertools import pairwise
from typing import Literal

from core.kernel import Dump, Memory, Patch, image_hash
from core.provenance._errors import RecordError
from core.provenance._json import (
    HEX32_CHECK,
    ORIGINS,
    Json,
    Raw,
    array,
    hash_json,
    items,
    member,
    nullable,
    obj,
    one_of,
    text,
    uint,
)
from core.provenance._records import _COMMON, Build, _frozen
from core.provenance._runtime import python_info

GENERIC_AUDIT_SCHEMA = "impact.generic-audit-record.v1"
CHECKS = ("identification", "layout", "map_rules", "verify")

# R113: why each check was not evaluated.
PluginReason = Literal["no_admitted_plugin", "no_rule_table"]
_PLUGIN_REASONS = ("no_admitted_plugin", "no_rule_table")
_MAP_REASONS = ("no_definition", "no_rule_table")

# Equal chunks are passed over whole; only a chunk holding a difference is walked byte by byte.
_CHUNK = 64


@dataclass(frozen=True, slots=True)
class ChangedRun:
    """`{memory_id, offset, length}` of R112 `outside_known_maps`."""

    memory_id: str
    offset: int
    length: int

    @property
    def end(self) -> int:
        return self.offset + self.length


@dataclass(frozen=True, slots=True)
class KnownMaps:
    """R112, computed by the gate from the definition (SPEC-003 R52, R100, R101) and passed as data (R110):
    `map_ids` by the `patch_hash` of each change, the changed bytes outside every resolved span, the unbound maps."""

    definition_hash: str
    map_ids: Mapping[str, tuple[str, ...]]
    outside: tuple[ChangedRun, ...]
    unbound: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GenericAuditInputs:
    """What a generic audit holds (R110). `reason` is why identification, layout and verify were not evaluated."""

    original: Dump
    candidate: Dump
    candidate_origin: str
    known_maps: KnownMaps | None
    reason: PluginReason
    core_version: str
    build: Build


def _not_evaluated(value: Raw) -> bool:
    """R113: the four checks in order; one plugin reason for identification, layout and verify."""
    if not array(obj({"check": text, "reason": text}))(value):
        return False
    pairs = [(member(entry, "check"), member(entry, "reason")) for entry in items(value)]
    plugin = {reason for check, reason in pairs if check != "map_rules"}
    return (
        tuple(check for check, _ in pairs) == CHECKS
        and len(plugin) == 1
        and plugin <= set(_PLUGIN_REASONS)
        and pairs[2][1] in _MAP_REASONS
    )


_RUN = {"memory_id": text, "offset": uint, "length": uint}
GENERIC_AUDIT_SHAPE = obj(
    {
        **{key: _COMMON[key] for key in ("dump_kind", "image_hash_original", "python", "build", "reproducibility")},
        "schema": one_of(GENERIC_AUDIT_SCHEMA),
        "image_hash_candidate": HEX32_CHECK,
        "candidate_origin": one_of(*ORIGINS),
        "definition_hash": nullable(HEX32_CHECK),
        "changes": array(obj({**_RUN, "patch_hash": HEX32_CHECK, "map_ids": array(text, sorted_unique=True)})),
        "outside_known_maps": array(obj(_RUN)),
        "unbound_maps": array(text, sorted_unique=True),
        "not_evaluated": _not_evaluated,
        "checksum_status": one_of("not_verified"),
        "versions": obj({"core": text}),
    }
)


def _without_definition_is_unattributed(value: Mapping[str, Json]) -> bool:
    """R112, R113: `no_definition` if and only if `definition_hash` is null, and then nothing is attributed."""
    no_definition = member(value, "definition_hash") is None
    if (member(items(member(value, "not_evaluated"))[2], "reason") == "no_definition") != no_definition:
        return False
    return not no_definition or (
        not items(member(value, "unbound_maps"))
        and all(not items(member(change, "map_ids")) for change in items(member(value, "changes")))
    )


@dataclass(frozen=True, slots=True)
class GenericAuditRecord:
    """SPEC-005 §4.2 as validated, frozen JSON. `generic_audit_hash` is R114."""

    value: Mapping[str, Json]

    def __post_init__(self) -> None:
        frozen = _frozen(self.value, GENERIC_AUDIT_SHAPE, "GenericAuditRecord")
        if not _without_definition_is_unattributed(frozen):
            raise RecordError("inconsistent_record", "map_rules reason, definition_hash and attribution (R112, R113)")
        object.__setattr__(self, "value", frozen)

    @property
    def generic_audit_hash(self) -> str:
        return hash_json(self.value)


def _shape(dump: Dump) -> tuple[str, list[tuple[str, int | None, int]]]:
    memories = sorted((memory.memory_id, memory.base_address, len(memory.data)) for memory in dump.memories)
    return dump.dump_kind, memories


def _runs(a: bytes, b: bytes) -> Iterator[tuple[int, int]]:
    """R111: the maximal runs `[i, j)` of positions where `a` and `b` differ (same length)."""
    i, end = 0, len(a)
    while i < end:
        while i + _CHUNK <= end and a[i : i + _CHUNK] == b[i : i + _CHUNK]:
            i += _CHUNK
        while i < end and a[i] == b[i]:
            i += 1
        if i == end:
            return
        j = i + 1
        while j < end and a[j] != b[j]:
            j += 1
        yield i, j
        i = j


def _memory_id(memory: Memory) -> str:
    return memory.memory_id


def changed_ranges(original: Dump, candidate: Dump) -> tuple[Patch, ...]:
    """R111: every differing byte of every memory, as maximal runs sorted by `(memory_id, offset)`. Raises
    `RecordError` (`shape_mismatch`, SPEC-001 R31's reason) when the dumps differ in shape."""
    if _shape(original) != _shape(candidate):
        raise RecordError("shape_mismatch", f"{_shape(original)} vs {_shape(candidate)}")
    other = {memory.memory_id: memory.data for memory in candidate.memories}
    return tuple(
        Patch(memory.memory_id, start, end - start, memory.data[start:end], other[memory.memory_id][start:end])
        for memory in sorted(original.memories, key=_memory_id)
        for start, end in _runs(memory.data, other[memory.memory_id])
    )


def _run_key(run: ChangedRun) -> tuple[str, int]:
    return (run.memory_id, run.offset)


def _consistent(patches: tuple[Patch, ...], known: KnownMaps) -> bool:
    """R110: the gate's attribution describes exactly these changes. Every outside run lies inside one change,
    the runs are sorted and disjoint, and a change in no map is outside every known map as a whole."""
    if set(known.map_ids) != {patch.patch_hash for patch in patches}:
        return False
    if list(known.outside) != sorted(known.outside, key=_run_key) or any(
        a.memory_id == b.memory_id and b.offset < a.end for a, b in pairwise(known.outside)
    ):
        return False
    for run in known.outside:
        if not any(p.memory_id == run.memory_id and p.offset <= run.offset and run.end <= p.end for p in patches):
            return False
    unmapped = [p for p in patches if not known.map_ids[p.patch_hash]]
    return all(ChangedRun(p.memory_id, p.offset, p.length) in known.outside for p in unmapped)


def _run_json(memory_id: str, offset: int, length: int) -> dict[str, Json]:
    return {"memory_id": memory_id, "offset": offset, "length": length}


def generic_audit_record(inputs: GenericAuditInputs) -> GenericAuditRecord:
    """R110-R114: the changes are recomputed here; the attribution data must describe exactly them."""
    patches = changed_ranges(inputs.original, inputs.candidate)
    known = inputs.known_maps
    if known is not None and not _consistent(patches, known):
        raise RecordError("inconsistent_record", "the attribution does not describe these changes (R110)")
    outside = (
        [_run_json(p.memory_id, p.offset, p.length) for p in patches]
        if known is None
        else [_run_json(run.memory_id, run.offset, run.length) for run in known.outside]
    )
    reason = inputs.reason
    return GenericAuditRecord(
        {
            "schema": GENERIC_AUDIT_SCHEMA,
            "dump_kind": inputs.original.dump_kind,
            "image_hash_original": image_hash(inputs.original),
            "image_hash_candidate": image_hash(inputs.candidate),
            "candidate_origin": inputs.candidate_origin,
            "definition_hash": None if known is None else known.definition_hash,
            "changes": [
                {
                    **_run_json(p.memory_id, p.offset, p.length),
                    "patch_hash": p.patch_hash,
                    "map_ids": [] if known is None else list(known.map_ids[p.patch_hash]),
                }
                for p in patches
            ],
            "outside_known_maps": list[Json](outside),
            "unbound_maps": [] if known is None else list(known.unbound),
            "not_evaluated": [
                {"check": "identification", "reason": reason},
                {"check": "layout", "reason": reason},
                {"check": "map_rules", "reason": "no_definition" if known is None else "no_rule_table"},
                {"check": "verify", "reason": reason},
            ],
            "checksum_status": "not_verified",
            "versions": {"core": inputs.core_version},
            "python": python_info(),
            "build": inputs.build.to_json(),
            "reproducibility": inputs.build.reproducibility,
        }
    )
