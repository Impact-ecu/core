"""SPEC-003 R100-R102 as properties, against a byte-set oracle that shares no code with `map_attribution`."""

from dataclasses import replace

from hypothesis import given
from hypothesis import strategies as st

from core.definitions import (
    ByteRun,
    Definition,
    InlineAxis,
    MapDef,
    map_attribution,
    report_map_ids,
)
from core.kernel import Dump, Memory, Patch
from tests.properties.definition_strategies import xdf_definitions

SIZE = 512


def bytes_of(mapdef: MapDef) -> set[int]:
    """The bytes a map reads (SPEC-003 R30) for the inline and fixed axes these definitions use."""
    used = set(range(mapdef.offset, mapdef.offset + mapdef.rows * mapdef.cols * mapdef.dtype.size))
    for axis in (mapdef.x, mapdef.y):
        if isinstance(axis, InlineAxis):
            used |= set(range(axis.offset, axis.offset + axis.count * axis.dtype.size))
    return used


def runs_of(offsets: set[int]) -> tuple[ByteRun, ...]:
    runs: list[ByteRun] = []
    for offset in sorted(offsets):
        if runs and runs[-1].offset + runs[-1].length == offset:
            runs[-1] = replace(runs[-1], length=runs[-1].length + 1)
        else:
            runs.append(ByteRun("cal", offset, 1))
    return tuple(runs)


@st.composite
def patch_sets(draw: st.DrawFn) -> list[Patch]:
    patches: list[Patch] = []
    for _ in range(draw(st.integers(0, 5))):
        offset = draw(st.integers(0, SIZE - 1))
        length = draw(st.integers(1, min(24, SIZE - offset)))
        before = draw(st.binary(min_size=length, max_size=length))
        patches.append(Patch("cal", offset, length, before, bytes(b ^ 0x5A for b in before)))
    return patches


DUMP = Dump("virtual", (Memory("cal", 0x1000, bytes(SIZE)),))


# SPEC-003 R100-R102: each patch's maps, each map's runs, the unmapped runs and the report ids equal the
# byte-set oracle, and no input order changes the result.
@given(xdf_definitions(), patch_sets(), st.data())
def test_attribution_matches_byte_sets(definition: Definition, patches: list[Patch], data: st.DataObject) -> None:
    result = map_attribution(patches, definition, [DUMP])
    reads = {m.map_id: bytes_of(m) for m in definition.mapdefs}
    unique = {p.patch_hash: p for p in patches}
    ordered = sorted(unique.values(), key=lambda p: (p.memory_id, p.offset, p.patch_hash))
    written = {b for p in ordered for b in range(p.offset, p.end)}
    expected_lines = [
        (p.patch_hash, tuple(sorted(i for i, r in reads.items() if r & set(range(p.offset, p.end))))) for p in ordered
    ]
    assert [(line.patch_hash, line.map_ids) for line in result.patches] == expected_lines
    expected_maps = [(i, runs_of(reads[i] & written)) for i in sorted(reads) if reads[i] & written]
    assert [(m.map_id, m.runs) for m in result.maps] == expected_maps
    covered = set().union(*reads.values()) if reads else set()
    assert result.unmapped == runs_of(written - covered)
    assert result.unbound == ()
    assert report_map_ids(result) == {h: ids[0] if len(ids) == 1 else None for h, ids in expected_lines}
    shuffled = replace(definition, mapdefs=tuple(data.draw(st.permutations(definition.mapdefs))))
    assert map_attribution(data.draw(st.permutations(patches)), shuffled, [DUMP, DUMP]) == result
