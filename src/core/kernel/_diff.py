"""`diff` (SPEC-001 R31) and foreign changes (R32)."""

from collections.abc import Iterator
from dataclasses import dataclass

from core.kernel._apply import check_layout
from core.kernel._errors import ShapeError, ensure
from core.kernel._image import UnverifiedImage, as_dump, image_hash, require_known_base
from core.kernel._model import Dump, MemoryLayout, Patch, RegionKind, Version, layout_hash, memory_id_of

# Equal chunks are passed over whole; only a chunk holding a difference is walked byte by byte.
_CHUNK = 64


@dataclass(frozen=True, slots=True)
class ForeignRun:
    """A maximal run of differing bytes outside `calibration` regions (SPEC-001 R32)."""

    memory_id: str
    offset: int
    length: int
    region_kind: RegionKind
    region_name: str


@dataclass(frozen=True, slots=True)
class DiffResult:
    """Patches in `(memory_id, offset)` order, pairwise disjoint, and the foreign runs."""

    base_image_hash: str
    layout_hash: str
    patches: tuple[Patch, ...]
    foreign: tuple[ForeignRun, ...]

    def as_version(self) -> Version:
        return Version(self.base_image_hash, self.layout_hash, self.patches, ())


def _shape(dump: Dump) -> tuple[str, list[tuple[str, int | None, int]]]:
    return (
        dump.dump_kind,
        sorted((memory.memory_id, memory.base_address, len(memory.data)) for memory in dump.memories),
    )


def _runs(a: bytes, b: bytes, start: int, end: int) -> Iterator[tuple[int, int]]:
    """Maximal runs `[i, j)` of differing bytes inside `[start, end)`."""
    i = start
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


def diff(o: Dump | UnverifiedImage, x: Dump | UnverifiedImage, layout: MemoryLayout) -> DiffResult:
    """SPEC-001 R31, R32: changes inside `calibration` become patches; the rest is reported."""
    original = require_known_base(as_dump(o))
    other = require_known_base(as_dump(x))
    if _shape(original) != _shape(other):
        raise ShapeError("shape_mismatch", f"{_shape(original)} vs {_shape(other)}")
    by_id = check_layout(original, layout)
    new_data = {memory.memory_id: memory.data for memory in other.memories}
    patches: list[Patch] = []
    foreign: list[ForeignRun] = []
    for memory in sorted(original.memories, key=memory_id_of):
        old, new = memory.data, new_data[memory.memory_id]
        for region in by_id[memory.memory_id].regions:
            for start, end in _runs(old, new, region.start, region.end):
                if region.kind == "calibration":
                    patches.append(Patch(memory.memory_id, start, end - start, old[start:end], new[start:end]))
                else:
                    foreign.append(ForeignRun(memory.memory_id, start, end - start, region.kind, region.name))
        # Invariant 6, R31: the patches reproduce every calibration byte of `x`.
        rebuilt = bytearray(old)
        for patch in patches:
            if patch.memory_id == memory.memory_id:
                rebuilt[patch.offset : patch.end] = patch.after
        for region in by_id[memory.memory_id].regions:
            if region.kind == "calibration":
                ensure(rebuilt[region.start : region.end] == new[region.start : region.end], "SPEC-001 R31")
    return DiffResult(image_hash(original), layout_hash(layout), tuple(patches), tuple(foreign))
