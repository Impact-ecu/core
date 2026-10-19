"""Shared Hypothesis strategies. Every byte is synthetic; nothing comes from real firmware."""

from dataclasses import dataclass
from itertools import pairwise

from hypothesis import strategies as st

from core.kernel import (
    Dump,
    DumpKind,
    LayoutMemory,
    Memory,
    MemoryLayout,
    Patch,
    Region,
    RegionKind,
    Version,
    image_hash,
    layout_hash,
)

MEMORY_IDS = ("dflash", "eeprom", "pflash")
DUMP_KIND_VALUES: tuple[DumpKind, ...] = ("bench_full", "boot_full", "obd_full", "obd_partial", "virtual")
REGION_KIND_VALUES: tuple[RegionKind, ...] = ("calibration", "checksum", "protected")
MAX_PATCH_LENGTH = 8


@dataclass(frozen=True)
class Scenario:
    """A valid version over a dump, with the bytes expected from applying it."""

    dump: Dump
    layout: MemoryLayout
    version: Version
    expected: dict[str, bytes]


def regions_for(size: int, cuts: set[int], kinds: list[RegionKind], names: list[str]) -> tuple[Region, ...]:
    bounds = [0, *sorted(cuts), size]
    return tuple(
        Region(kinds[i % len(kinds)], start, end, names[i % len(names)])
        for i, (start, end) in enumerate(pairwise(bounds))
    )


@st.composite
def region_tuples(draw: st.DrawFn, size: int, *, first: RegionKind | None = None) -> tuple[Region, ...]:
    cuts = draw(st.sets(st.integers(1, size - 1), max_size=6)) if size > 1 else set()
    kinds = draw(st.lists(st.sampled_from(REGION_KIND_VALUES), min_size=1, max_size=7))
    if first is not None:
        kinds[0] = first
    names = draw(st.lists(st.sampled_from(("", "maps", "crc", "boot")), min_size=1, max_size=3))
    return regions_for(size, cuts, kinds, names)


@st.composite
def dumps_and_layouts(
    draw: st.DrawFn, *, max_memories: int = 3, max_size: int = 160, first_kind: RegionKind | None = None
) -> tuple[Dump, MemoryLayout]:
    """A dump and a layout describing it. `first_kind` forces the kind of each memory's first region."""
    ids = draw(st.lists(st.sampled_from(MEMORY_IDS), min_size=1, max_size=max_memories, unique=True))
    memories: list[Memory] = []
    layout_memories: list[LayoutMemory] = []
    for memory_id in ids:
        size = draw(st.integers(1, max_size))
        data = draw(st.binary(min_size=size, max_size=size))
        base = draw(st.integers(0, 2**53 - 1))
        memories.append(Memory(memory_id, base, data))
        layout_memories.append(LayoutMemory(memory_id, base, size, draw(region_tuples(size, first=first_kind))))
    dump = Dump(draw(st.sampled_from(DUMP_KIND_VALUES)), tuple(memories))
    return dump, MemoryLayout(tuple(draw(st.permutations(layout_memories))))


def calibration_slots(layout: MemoryLayout, kind: RegionKind = "calibration") -> list[tuple[str, Region]]:
    return [(m.memory_id, r) for m in layout.memories for r in m.regions if r.kind == kind]


@st.composite
def patch_in(draw: st.DrawFn, memory_id: str, region: Region, current: bytes | bytearray) -> Patch:
    """A patch inside `region` whose `before` is the current content."""
    offset = draw(st.integers(region.start, region.end - 1))
    length = draw(st.integers(1, min(MAX_PATCH_LENGTH, region.end - offset)))
    before = bytes(current[offset : offset + length])
    after = bytearray(draw(st.binary(min_size=length, max_size=length)))
    if after == before:
        after[draw(st.integers(0, length - 1))] ^= 0xFF
    return Patch(memory_id, offset, length, before, bytes(after))


def intersects(a: Patch, b: Patch) -> bool:
    return a.memory_id == b.memory_id and a.offset < b.offset + b.length and b.offset < a.offset + a.length


@st.composite
def scenarios(draw: st.DrawFn, *, min_patches: int = 0, max_patches: int = 6, max_memories: int = 3) -> Scenario:
    """Patches generated one after another on a running copy, so each `before` is what the patch
    overwrites; every overlapping pair is ordered as generated. The version lists patches and
    pairs in a shuffled order."""
    first_kind: RegionKind | None = "calibration" if min_patches else None
    dump, layout = draw(dumps_and_layouts(max_memories=max_memories, first_kind=first_kind))
    buffers = {m.memory_id: bytearray(m.data) for m in dump.memories}
    slots = calibration_slots(layout)
    patches: list[Patch] = []
    if slots:
        # Only an exact repeat is dropped, never the first patch: at least one patch when min_patches > 0.
        for _ in range(draw(st.integers(min_patches, max_patches))):
            memory_id, region = draw(st.sampled_from(slots))
            patch = draw(patch_in(memory_id, region, buffers[memory_id]))
            if any(p.patch_hash == patch.patch_hash for p in patches):
                continue
            buffers[memory_id][patch.offset : patch.offset + patch.length] = patch.after
            patches.append(patch)
    pairs = [(a.patch_hash, b.patch_hash) for i, a in enumerate(patches) for b in patches[i + 1 :] if intersects(a, b)]
    version = Version(
        image_hash(dump),
        layout_hash(layout),
        tuple(draw(st.permutations(patches))),
        tuple(draw(st.permutations(pairs))),
    )
    return Scenario(dump, layout, version, {k: bytes(v) for k, v in buffers.items()})
