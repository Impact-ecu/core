"""Pure checks the release steps run on kernel and definition objects (SPEC-004 R23, R24, R25, R31)."""

from collections.abc import Sequence

from core.definitions import AxisRef, ByteRange, Decoded, Definition, MapDef, SharedAxis, Value
from core.gate._maps import AxisView, MapView
from core.gate._model import Run, run_key
from core.gate._output import KernelOutcome
from core.kernel import Dump, LayoutMemory, MemoryLayout, Patch, Region


def _single_region(memory: LayoutMemory | None, start: int, end: int) -> Region | None:
    regions = () if memory is None else memory.regions
    return next((region for region in regions if region.start <= start and end <= region.end), None)


def patch_run(patch: Patch) -> Run:
    return Run(patch.memory_id, patch.offset, patch.length)


def outside_calibration(patches: Sequence[Patch], layout: MemoryLayout) -> list[Patch]:
    """SPEC-001 R23: patches not inside one single `calibration` region (an unknown memory included),
    sorted by `(memory_id, offset)`."""
    memories = {memory.memory_id: memory for memory in layout.memories}
    outside = []
    for patch in patches:
        region = _single_region(memories.get(patch.memory_id), patch.offset, patch.end)
        if region is None or region.kind != "calibration":
            outside.append(patch)
    return sorted(outside, key=run_key)


def _touches(memory: LayoutMemory | None, patch: Patch) -> bool:
    """A patch intersecting a `protected` or `checksum` region (R24); an unknown memory is all protected."""
    if memory is None:
        return True
    return any(r.kind != "calibration" and r.start < patch.end and patch.offset < r.end for r in memory.regions)


def _shape(dump: Dump) -> tuple[str, list[tuple[str, int | None, int]]]:
    return dump.dump_kind, sorted((m.memory_id, m.base_address, len(m.data)) for m in dump.memories)


def _unchanged_outside(original: Dump, image: Dump, patches: Sequence[Patch]) -> bool:
    """SPEC-001 R24: bytes outside the union of patch ranges are equal. Shapes are already equal."""
    after = {memory.memory_id: memory.data for memory in image.memories}
    for memory in original.memories:
        data, written, position = memory.data, after[memory.memory_id], 0
        for patch in sorted((p for p in patches if p.memory_id == memory.memory_id), key=run_key):
            if data[position : patch.offset] != written[position : patch.offset]:
                return False
            position = max(position, patch.end)
        if data[position:] != written[position:]:
            return False
    return True


def kernel_check(original: Dump, image: Dump, layout: MemoryLayout, patches: Sequence[Patch]) -> KernelOutcome:
    """R24 on `(original, u)`: SPEC-001 R23 containment, R24 locality and R26 shape, re-checked independently.

    A patch touching a `protected` or `checksum` region is `G-PROTECTED`; any other violation is a kernel bug.
    """
    memories = {memory.memory_id: memory for memory in layout.memories}
    outside = outside_calibration(patches, layout)
    protected = tuple(patch_run(p) for p in outside if _touches(memories.get(p.memory_id), p))
    same_shape = _shape(original) == _shape(image)
    invariant = len(protected) != len(outside) or not same_shape or not _unchanged_outside(original, image, patches)
    return KernelOutcome(protected, invariant)


def outside_checksum_unchanged(before: Dump, after: Dump, layout: MemoryLayout) -> bool:
    """SPEC-001 R41, re-asserted by the gate on `(u, r)` (R25)."""
    data = {memory.memory_id: memory.data for memory in after.memories}
    regions = {memory.memory_id: memory.regions for memory in layout.memories}
    return all(
        memory.data[r.start : r.end] == data[memory.memory_id][r.start : r.end]
        for memory in before.memories
        for r in regions[memory.memory_id]
        if r.kind != "checksum"
    )


def _merge(intervals: Sequence[tuple[int, int]]) -> list[tuple[int, int]]:
    """Sorted, with overlapping and adjacent intervals joined, so the runs built from them are maximal."""
    merged: list[tuple[int, int]] = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def uncovered(patches: Sequence[Patch], covered: Sequence[ByteRange]) -> tuple[Run, ...]:
    """R31: patch bytes in no resolved span, as maximal runs sorted by `(memory_id, offset)`."""
    runs: list[Run] = []
    for memory_id in sorted({patch.memory_id for patch in patches}):
        have = _merge([(c.start, c.end) for c in covered if c.memory_id == memory_id])
        for start, end in _merge([(p.offset, p.end) for p in patches if p.memory_id == memory_id]):
            position = start
            for low, high in have:
                if high <= position or low >= end:
                    continue
                if low > position:
                    runs.append(Run(memory_id, position, low - position))
                position = high
            if position < end:
                runs.append(Run(memory_id, position, end - position))
    return tuple(runs)


def edited(ranges: Sequence[ByteRange], patches: Sequence[Patch]) -> bool:
    """R31: a span intersecting a patch range of the version in the same memory."""
    return any(r.memory_id == p.memory_id and r.start < p.end and p.offset < r.end for r in ranges for p in patches)


def _axis_view(axis: AxisRef | None, definition: Definition, values: tuple[Value, ...] | None) -> AxisView | None:
    if axis is None or values is None:
        return None
    stored = definition.axis_def(axis.axis_id).axis if isinstance(axis, SharedAxis) else axis
    return AxisView(stored.unit, values)


def map_view(mapdef: MapDef, definition: Definition, decoded: Decoded, is_edited: bool) -> MapView:
    """R31: the decoded map with the keys R32 matches on (`unit` is SPEC-003 R16's canonical unit)."""
    return MapView(
        map_id=mapdef.map_id,
        state=mapdef.state,
        category=mapdef.category,
        map_type=mapdef.map_type,
        unit=mapdef.unit,
        cells=decoded.cells,
        x=_axis_view(mapdef.x, definition, decoded.x),
        y=_axis_view(mapdef.y, definition, decoded.y),
        edited=is_edited,
    )
