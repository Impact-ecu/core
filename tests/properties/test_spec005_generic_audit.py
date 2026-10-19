"""SPEC-005 R111-R114 as properties: the generic audit's ranges cover every changed byte exactly once, the
attribution partitions them, swapping the files mirrors the record, and the same inputs give the same hash."""

import json
from fractions import Fraction
from itertools import pairwise
from typing import Any, cast

from hypothesis import given
from hypothesis import strategies as st

from core.definitions import Definition, Dtype, License, MapDef, Origin, Scaling, SoftwareVersion
from core.gate._generic import GenericArgs, run_generic
from core.kernel import Dump, Memory, canonical_json
from core.provenance import Build, Json, changed_ranges

BUILD = Build("lockfile", "sha256:" + "ab" * 32, "linux/amd64", None)
U8 = Dtype("uint", 8, "none")
ONE = Scaling(Fraction(1), Fraction(0))
SIZE = 160


@st.composite
def pairs(draw: st.DrawFn) -> tuple[Dump, Dump]:
    """Two dumps of the same shape; the candidate differs at a few drawn runs (possibly touching or overlapping)."""
    names = draw(st.lists(st.sampled_from(["dflash", "eeprom", "pflash"]), min_size=1, max_size=3, unique=True))
    originals, candidates = [], []
    for name in sorted(names):
        size = draw(st.integers(1, SIZE))
        data = bytes(draw(st.lists(st.integers(0, 255), min_size=size, max_size=size)))
        edited = bytearray(data)
        for _ in range(draw(st.integers(0, 5))):
            start = draw(st.integers(0, size - 1))
            for i in range(start, min(size, start + draw(st.integers(1, 70)))):
                edited[i] ^= draw(st.integers(0, 255))
        base = draw(st.none() | st.integers(0, 2**32))
        originals.append(Memory(name, base, data))
        candidates.append(Memory(name, base, bytes(edited)))
    return Dump("bench_full", tuple(originals)), Dump("bench_full", tuple(candidates))


def differing(original: Dump, candidate: Dump) -> set[tuple[str, int]]:
    other = {m.memory_id: m.data for m in candidate.memories}
    return {
        (m.memory_id, i) for m in original.memories for i in range(len(m.data)) if m.data[i] != other[m.memory_id][i]
    }


# SPEC-005 R111: every differing byte lies in exactly one range; ranges hold only differing bytes, are sorted,
# never overlap or touch, and never cross a memory.
@given(pairs())
def test_every_changed_byte_in_exactly_one_range(pair: tuple[Dump, Dump]) -> None:
    original, candidate = pair
    patches = changed_ranges(original, candidate)
    covered = [(p.memory_id, i) for p in patches for i in range(p.offset, p.end)]
    assert len(covered) == len(set(covered))
    assert set(covered) == differing(original, candidate)
    keys = [(p.memory_id, p.offset) for p in patches]
    assert keys == sorted(keys)
    for a, b in pairwise(patches):
        assert a.memory_id != b.memory_id or a.end < b.offset


def mapdef(index: int, memory_id: str, offset: int, cols: int) -> MapDef:
    return MapDef(
        map_id=f"m.{index:02d}",
        name=f"M{index}",
        category=None,
        map_type=None,
        state="imported",
        memory_id=memory_id,
        offset=offset,
        rows=1,
        cols=cols,
        cell_order="x_fastest",
        dtype=U8,
        scaling=ONE,
        unit=None,
        unit_text="raw",
        x=None,
        y=None,
    )


@st.composite
def definitions(draw: st.DrawFn) -> tuple[Definition, dict[str, tuple[str, int, int]]]:
    """1xN maps of drawn extents; some fall outside their memory or name a missing one (unbound)."""
    maps: list[MapDef] = []
    extents: dict[str, tuple[str, int, int]] = {}
    for index in range(draw(st.integers(0, 6))):
        memory_id = draw(st.sampled_from(["dflash", "eeprom", "pflash", "nowhere"]))
        offset, cols = draw(st.integers(0, SIZE)), draw(st.integers(1, 40))
        made = mapdef(index, memory_id, offset, cols)
        maps.append(made)
        extents[made.map_id] = (memory_id, offset, offset + cols)
    definition = Definition(
        "synthetic.properties",
        SoftwareVersion("exact", ("SYN0001",)),
        (),
        tuple(maps),
        Origin("platform", ()),
        License("platform_created", None),
        500,
    )
    return definition, extents


def plain(value: Json) -> dict[str, Any]:
    return cast("dict[str, Any]", json.loads(canonical_json(value)))


def args(definition: Definition | None) -> GenericArgs:
    return {"definition": definition, "candidate_origin": "file_service", "build": BUILD}


def _fits(dump: Dump, extent: tuple[str, int, int]) -> bool:
    sizes = {m.memory_id: len(m.data) for m in dump.memories}
    memory_id, _, end = extent
    return memory_id in sizes and end <= sizes[memory_id]


# SPEC-005 R112: every changed byte is either in a span of a map its change names, or outside every known map,
# never both; a map that does not fit the file is unbound and hides nothing.
@given(pairs(), definitions())
def test_attribution_partitions_the_changes(pair: tuple[Dump, Dump], made: tuple[Definition, Any]) -> None:
    original, candidate = pair
    definition, extents = made
    value = run_generic(original, candidate, args(definition), "no_admitted_plugin", "9.9.9").record.value
    value = plain(value)
    bound = {map_id: e for map_id, e in extents.items() if _fits(original, e)}
    assert list(value["unbound_maps"]) == sorted(set(extents) - set(bound))
    outside = {
        (r["memory_id"], i) for r in value["outside_known_maps"] for i in range(r["offset"], r["offset"] + r["length"])
    }
    for change in value["changes"]:
        names = set(change["map_ids"])
        memory_id = change["memory_id"]
        for i in range(change["offset"], change["offset"] + change["length"]):
            inside = {m for m, (mem, start, end) in bound.items() if mem == memory_id and start <= i < end}
            assert inside <= names
            assert (memory_id, i) in outside or inside
            assert not ((memory_id, i) in outside and inside)
        assert names == {
            m
            for m, (mem, start, end) in bound.items()
            if mem == memory_id and start < change["offset"] + change["length"] and change["offset"] < end
        }


# SPEC-005 R114: swapping the files gives the same ranges, maps and outside runs, with before and after exchanged.
@given(pairs(), definitions())
def test_swapping_mirrors(pair: tuple[Dump, Dump], made: tuple[Definition, Any]) -> None:
    original, candidate = pair
    forward = changed_ranges(original, candidate)
    backward = changed_ranges(candidate, original)
    assert [(p.memory_id, p.offset, p.before, p.after) for p in forward] == [
        (p.memory_id, p.offset, p.after, p.before) for p in backward
    ]
    a = plain(run_generic(original, candidate, args(made[0]), "no_admitted_plugin", "9.9.9").record.value)
    b = plain(run_generic(candidate, original, args(made[0]), "no_admitted_plugin", "9.9.9").record.value)
    strip = ("patch_hash",)
    assert [{k: v for k, v in c.items() if k not in strip} for c in a["changes"]] == [
        {k: v for k, v in c.items() if k not in strip} for c in b["changes"]
    ]
    assert a["outside_known_maps"] == b["outside_known_maps"]
    assert (a["image_hash_original"], a["image_hash_candidate"]) == (
        b["image_hash_candidate"],
        b["image_hash_original"],
    )


# SPEC-005 R114: the same inputs give the same generic_audit_hash.
@given(pairs(), st.booleans())
def test_determinism(pair: tuple[Dump, Dump], with_definition: bool) -> None:
    definition = (
        Definition(
            "synthetic.properties",
            SoftwareVersion("exact", ("SYN0001",)),
            (),
            (mapdef(0, "pflash", 0, 8),),
            Origin("platform", ()),
            License("platform_created", None),
            500,
        )
        if with_definition
        else None
    )
    first = run_generic(*pair, args(definition), "no_rule_table", "9.9.9").record
    second = run_generic(*pair, args(definition), "no_rule_table", "9.9.9").record
    assert first.generic_audit_hash == second.generic_audit_hash
