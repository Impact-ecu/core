"""SPEC-003 R100-R102: patches attributed to the maps of a definition, on the synthetic two-memory fixture."""

from dataclasses import replace

import pytest

from core.definitions import (
    ByteRun,
    DefinitionError,
    MapAttribution,
    MapRuns,
    PatchMaps,
    map_attribution,
    report_map_ids,
)
from core.kernel import Dump, Memory, Patch
from tests.unit.definitions_fixtures import AXIS_DEF, CAL, DUMP, PFLASH, POINTER, SCALAR, SHARED_MAP, TABLE, definition

# Spans on DUMP (SPEC-003 R30): scalar cal [0, 1); table cal [8, 20) and its inline axis [32, 36); shared map
# cal [40, 44) and the shared axis [32, 36); the pointer map cal [50, 54), its pointer cell pflash [0, 4) and
# its breakpoints at cal [16, 20) (pointer 0x80001010 against base 0x80001000).
POINTER_MAP = replace(SCALAR, map_id="syn.ptr", name="SYN_PTR", offset=50, cols=4, x=POINTER)
DEFINITION = definition(SCALAR, TABLE, SHARED_MAP, POINTER_MAP, axes=(AXIS_DEF,))


def patch(memory_id: str, offset: int, length: int) -> Patch:
    data = CAL if memory_id == "cal" else PFLASH
    before = data[offset : offset + length]
    return Patch(memory_id, offset, length, before, bytes(b ^ 0xFF for b in before))


def attribute(*patches: Patch, dumps: tuple[Dump, ...] = (DUMP,)) -> MapAttribution:
    return map_attribution(patches, DEFINITION, dumps)


# SPEC-003 R100, R101, R102: a patch inside one map's cells belongs to that map only.
def test_patch_in_one_map() -> None:
    p = patch("cal", 0, 1)
    result = attribute(p)
    assert result == MapAttribution(
        (PatchMaps(p.patch_hash, ("syn.scalar",)),), (MapRuns("syn.scalar", (ByteRun("cal", 0, 1),)),), (), ()
    )
    assert report_map_ids(result) == {p.patch_hash: "syn.scalar"}


# SPEC-003 R30, R100, R102: a shared axis byte belongs to every map that reads it, so the report line is null.
def test_shared_axis_belongs_to_every_reader() -> None:
    p = patch("cal", 33, 1)
    result = attribute(p)
    assert result.patches == (PatchMaps(p.patch_hash, ("syn.shared", "syn.table")),)
    assert result.maps == (
        MapRuns("syn.shared", (ByteRun("cal", 33, 1),)),
        MapRuns("syn.table", (ByteRun("cal", 33, 1),)),
    )
    assert report_map_ids(result) == {p.patch_hash: None}


# SPEC-003 R101: a maximal diff run across two maps is split per map, and the gap between them is unmapped.
def test_run_across_maps_is_split() -> None:
    p = patch("cal", 0, 10)
    result = attribute(p)
    assert result.patches == (PatchMaps(p.patch_hash, ("syn.scalar", "syn.table")),)
    assert result.maps == (
        MapRuns("syn.scalar", (ByteRun("cal", 0, 1),)),
        MapRuns("syn.table", (ByteRun("cal", 8, 2),)),
    )
    assert result.unmapped == (ByteRun("cal", 1, 7),)
    assert report_map_ids(result) == {p.patch_hash: None}


# SPEC-003 R101, SPEC-004 R31: bytes in no span are unmapped, as maximal runs sorted by (memory_id, offset).
def test_unmapped_runs() -> None:
    a, b = patch("cal", 20, 4), patch("cal", 24, 4)
    result = attribute(b, a)
    assert result.patches == (PatchMaps(a.patch_hash, ()), PatchMaps(b.patch_hash, ()))
    assert result.maps == ()
    assert result.unmapped == (ByteRun("cal", 20, 8),)
    assert report_map_ids(result) == {a.patch_hash: None, b.patch_hash: None}


# SPEC-003 R30, R100: a pointer cell belongs to the map whose axis it addresses.
def test_pointer_cell() -> None:
    p = patch("pflash", 2, 1)
    assert attribute(p).patches == (PatchMaps(p.patch_hash, ("syn.ptr",)),)


# SPEC-003 R100: spans are taken on every dump, so a pointer moved in the candidate counts on both sides.
def test_spans_on_every_dump() -> None:
    moved = Dump(
        "virtual",
        (Memory("cal", 0x8000_1000, CAL), Memory("pflash", 0x8000_0000, bytes.fromhex("80001018") + bytes(12))),
    )
    p = patch("cal", 25, 1)
    assert attribute(p).patches == (PatchMaps(p.patch_hash, ()),)
    assert attribute(p, dumps=(DUMP, moved)).patches == (PatchMaps(p.patch_hash, ("syn.ptr",)),)


# SPEC-003 R100, R55: a map that does not fit one of the dumps is unbound and contributes no span.
def test_unbound_map() -> None:
    short = Dump("virtual", (Memory("cal", 0x8000_1000, CAL[:42]), Memory("pflash", 0x8000_0000, PFLASH)))
    p = patch("cal", 40, 1)
    result = attribute(p, dumps=(DUMP, short))
    assert result.unbound == ("syn.ptr", "syn.shared")
    assert result.patches == (PatchMaps(p.patch_hash, ()),)
    assert result.unmapped == (ByteRun("cal", 40, 1),)


# SPEC-003 R100, SPEC-001 R11: two patches with one hash are one patch.
def test_same_patch_once() -> None:
    p = patch("cal", 0, 1)
    assert attribute(p, p) == attribute(p)


# SPEC-003 R100: at least one dump is required.
def test_no_dump_is_refused() -> None:
    with pytest.raises(DefinitionError) as raised:
        attribute(patch("cal", 0, 1), dumps=())
    assert raised.value.reason == "bad_shape"


# SPEC-003 R101: no patches, no lines.
def test_no_patches() -> None:
    assert attribute() == MapAttribution((), (), (), ())
