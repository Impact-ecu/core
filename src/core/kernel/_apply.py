"""`apply` (SPEC-001 §3), `invert` (R30), the checksum step (§5) and `migrate` (§6)."""

from bisect import bisect_right
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from core.kernel._errors import ContainmentError, LayoutError, PreconditionConflict, ShapeError, ensure
from core.kernel._image import UnverifiedImage, as_dump, image_hash, require_known_base
from core.kernel._model import (
    Dump,
    LayoutMemory,
    Memory,
    MemoryLayout,
    Patch,
    Region,
    RegionKind,
    Version,
    layout_hash,
    start_of,
)
from core.kernel._order import canonical_order, order_key, ordered, reject_duplicates

type Buffers = dict[str, bytearray]


@dataclass(frozen=True, slots=True)
class Conflict:
    """A patch that `migrate` did not carry over, and why (SPEC-001 R50)."""

    patch_hash: str
    reason: Literal["before_mismatch", "out_of_region"]


@dataclass(frozen=True, slots=True)
class MigrationResult:
    version: Version
    conflicts: tuple[Conflict, ...]


def check_layout(dump: Dump, layout: MemoryLayout) -> dict[str, LayoutMemory]:
    """The layout describes exactly the memories of the dump (SPEC-001 R5)."""
    by_id = {memory.memory_id: memory for memory in layout.memories}
    described = {memory_id: (memory.base_address, memory.size) for memory_id, memory in by_id.items()}
    actual = {memory.memory_id: (memory.base_address, len(memory.data)) for memory in dump.memories}
    if described != actual:
        raise LayoutError("shape_mismatch", f"layout {sorted(described.items())}, dump {sorted(actual.items())}")
    return by_id


def containing_region(memory: LayoutMemory, patch: Patch) -> Region | None:
    """The single region holding the whole patch range, or None if it crosses a boundary."""
    # Regions cover [0, size) from 0 (R4) and offsets are non-negative, so the index is >= 0.
    region = memory.regions[bisect_right(memory.regions, patch.offset, key=start_of) - 1]
    return region if patch.end <= region.end else None


def contained(by_id: dict[str, LayoutMemory], patch: Patch, kind: RegionKind) -> bool:
    memory = by_id.get(patch.memory_id)
    region = None if memory is None else containing_region(memory, patch)
    return region is not None and region.kind == kind


def _buffers(dump: Dump) -> Buffers:
    return {memory.memory_id: bytearray(memory.data) for memory in dump.memories}


def _write(buffers: Buffers, patch: Patch) -> bool:
    """Write `patch` if its `before` matches the current bytes (SPEC-001 R21)."""
    buffer = buffers[patch.memory_id]
    if buffer[patch.offset : patch.end] != patch.before:
        return False
    buffer[patch.offset : patch.end] = patch.after
    return True


def _freeze(dump: Dump, buffers: Buffers) -> Dump:
    return Dump(
        dump.dump_kind,
        tuple(Memory(m.memory_id, m.base_address, bytes(buffers[m.memory_id])) for m in dump.memories),
    )


def _unchanged_outside(before: bytes, after: bytes, ranges: list[tuple[int, int]]) -> bool:
    gaps: list[tuple[int, int]] = []
    position = 0
    for start, end in sorted(ranges):
        gaps.append((position, start))
        position = max(position, end)
    gaps.append((position, len(before)))
    return all(before[start:end] == after[start:end] for start, end in gaps)


def _materialize(dump: Dump, patches: Sequence[Patch]) -> Dump:
    """Apply `patches` in the given order to a copy of `dump` (SPEC-001 R20, R21)."""
    buffers = _buffers(dump)
    for index, patch in enumerate(patches):
        if not _write(buffers, patch):
            raise PreconditionConflict(index, patch.patch_hash)
    result = _freeze(dump, buffers)
    for original, written in zip(dump.memories, result.memories, strict=True):
        ranges = [(p.offset, p.end) for p in patches if p.memory_id == original.memory_id]
        # Invariant 8, R13, R26: same memories, base addresses and sizes.
        ensure(len(written.data) == len(original.data), "SPEC-001 R26")
        # Invariant 5, R24: nothing outside the union of patch ranges changed.
        ensure(_unchanged_outside(original.data, written.data, ranges), "SPEC-001 R24")
    return result


def _check_base(dump: Dump, version: Version) -> None:
    if image_hash(dump) != version.base_image_hash:
        raise ShapeError("wrong_base", f"image {image_hash(dump)}, version expects {version.base_image_hash}")


def apply(o: Dump | UnverifiedImage, v: Version, layout: MemoryLayout) -> UnverifiedImage:
    """SPEC-001 §3. Pure; `o` is never mutated."""
    dump = require_known_base(as_dump(o))
    _check_base(dump, v)
    if layout_hash(layout) != v.layout_hash:
        raise ShapeError("wrong_layout", f"layout {layout_hash(layout)}, version expects {v.layout_hash}")
    by_id = check_layout(dump, layout)
    reject_duplicates(v.patches)
    for patch in sorted(v.patches, key=order_key):
        if patch.memory_id not in by_id:
            raise ContainmentError("unknown_memory", f"{patch.memory_id} ({patch.patch_hash})")
        # Invariant 3, R23: one single calibration region, checked before any write.
        if not contained(by_id, patch, "calibration"):
            raise ContainmentError("out_of_region", patch.patch_hash)
    return UnverifiedImage(_materialize(dump, ordered(v.patches, v.overlaps)))


def invert(o: Dump | UnverifiedImage, v: Version) -> Version:
    """SPEC-001 R30: swap `before`/`after`, reverse every overlap pair, rebase on `apply(o, v)`."""
    dump = require_known_base(as_dump(o))
    _check_base(dump, v)
    sizes = {memory.memory_id: len(memory.data) for memory in dump.memories}
    reject_duplicates(v.patches)
    for patch in sorted(v.patches, key=order_key):
        if patch.memory_id not in sizes:
            raise ContainmentError("unknown_memory", f"{patch.memory_id} ({patch.patch_hash})")
        if patch.end > sizes[patch.memory_id]:
            raise ContainmentError("out_of_region", patch.patch_hash)
    applied = _materialize(dump, ordered(v.patches, v.overlaps))
    swapped = {p.patch_hash: Patch(p.memory_id, p.offset, p.length, before=p.after, after=p.before) for p in v.patches}
    inverse = Version(
        base_image_hash=image_hash(applied),
        layout_hash=v.layout_hash,
        patches=tuple(swapped[p.patch_hash] for p in v.patches),
        overlaps=tuple((swapped[second].patch_hash, swapped[first].patch_hash) for first, second in v.overlaps),
    )
    # Invariant 6: the inverse restores `o` exactly.
    ensure(image_hash(_materialize(applied, canonical_order(inverse))) == image_hash(dump), "SPEC-001 R30")
    return inverse


def apply_checksum_patches(u: UnverifiedImage, q: Sequence[Patch], layout: MemoryLayout) -> UnverifiedImage:
    """SPEC-001 §5: the only kernel operation the gate uses to build a release candidate."""
    if not isinstance(u, UnverifiedImage):
        raise ShapeError("bad_type", "the checksum step applies only to an UnverifiedImage")
    dump = as_dump(u)
    by_id = check_layout(dump, layout)
    patches = tuple(q)
    if not all(isinstance(patch, Patch) for patch in patches):
        # q comes from a plugin (SPEC-002 R10): only validated Patch objects cross that boundary.
        raise ShapeError("bad_type", "every checksum patch must be a Patch")
    for patch in sorted(patches, key=order_key):
        # Invariant 9, R40: one outside patch rejects the whole set.
        if not contained(by_id, patch, "checksum"):
            raise ContainmentError("checksum_out_of_region", patch.patch_hash)
    result = _materialize(dump, ordered(patches, ()))
    for original, written in zip(dump.memories, result.memories, strict=True):
        for region in by_id[original.memory_id].regions:
            if region.kind != "checksum":
                # Invariant 9, R41: the result differs from `u` only in checksum regions.
                same = original.data[region.start : region.end] == written.data[region.start : region.end]
                ensure(same, "SPEC-001 R41")
    return UnverifiedImage(result)


def migrate(o: Dump | UnverifiedImage, v: Version, new_layout: MemoryLayout) -> MigrationResult:
    """SPEC-001 R50: keep what still holds under `new_layout`; every other patch is a conflict."""
    dump = require_known_base(as_dump(o))
    _check_base(dump, v)
    by_id = check_layout(dump, new_layout)
    buffers = _buffers(dump)
    kept: list[Patch] = []
    conflicts: list[Conflict] = []
    for patch in canonical_order(v):
        if not contained(by_id, patch, "calibration"):
            conflicts.append(Conflict(patch.patch_hash, "out_of_region"))
        elif not _write(buffers, patch):
            conflicts.append(Conflict(patch.patch_hash, "before_mismatch"))
        else:
            kept.append(patch)
    kept_hashes = {patch.patch_hash for patch in kept}
    version = Version(
        base_image_hash=image_hash(dump),
        layout_hash=layout_hash(new_layout),
        patches=tuple(kept),
        overlaps=tuple(pair for pair in v.overlaps if pair[0] in kept_hashes and pair[1] in kept_hashes),
    )
    # Invariant 11: the migrated version is valid under the new layout and yields what was kept.
    expected = image_hash(_freeze(dump, buffers))
    ensure(apply(dump, version, new_layout).image_hash == expected, "SPEC-001 R50")
    return MigrationResult(version, tuple(conflicts))
