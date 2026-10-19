"""Patches attributed to the maps of a definition (SPEC-003 R100-R102): spans only, no decoding, no rule."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from core.definitions._bind import ByteRange, span
from core.definitions._errors import DefinitionError
from core.definitions._model import Definition
from core.kernel import Dump, Patch

type Interval = tuple[int, int]


@dataclass(frozen=True, slots=True)
class ByteRun:
    """`{memory_id, offset, length}` of R101."""

    memory_id: str
    offset: int
    length: int


@dataclass(frozen=True, slots=True)
class PatchMaps:
    """R101: the maps holding at least one byte of the patch, sorted."""

    patch_hash: str
    map_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class MapRuns:
    """R101: the patch bytes inside one map's span, as maximal runs."""

    map_id: str
    runs: tuple[ByteRun, ...]


@dataclass(frozen=True, slots=True)
class MapAttribution:
    """R101."""

    patches: tuple[PatchMaps, ...]
    maps: tuple[MapRuns, ...]
    unmapped: tuple[ByteRun, ...]
    unbound: tuple[str, ...]


def _merge(intervals: Sequence[Interval]) -> list[Interval]:
    """Sorted, overlapping and touching intervals joined, so runs built from them are maximal."""
    merged: list[Interval] = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _intersection(a: Sequence[Interval], b: Sequence[Interval]) -> list[Interval]:
    """Both merged; the pieces are disjoint and never touch, so they are maximal."""
    return [(max(s, t), min(e, f)) for s, e in a for t, f in b if max(s, t) < min(e, f)]


def _difference(a: Sequence[Interval], b: Sequence[Interval]) -> list[Interval]:
    """Bytes of `a` in no interval of `b`; both merged."""
    pieces: list[Interval] = []
    for start, end in a:
        position = start
        for low, high in b:
            if high <= position or low >= end:
                continue
            if low > position:
                pieces.append((position, low))
            position = max(position, high)
        if position < end:
            pieces.append((position, end))
    return pieces


def _patch_key(patch: Patch) -> tuple[str, int, str]:
    return (patch.memory_id, patch.offset, patch.patch_hash)


def _runs(per_memory: Mapping[str, Sequence[Interval]]) -> tuple[ByteRun, ...]:
    return tuple(
        ByteRun(memory_id, start, end - start)
        for memory_id in sorted(per_memory)
        for start, end in per_memory[memory_id]
    )


def _within(ranges: Sequence[ByteRange], memory_id: str) -> list[Interval]:
    return _merge([(r.start, r.end) for r in ranges if r.memory_id == memory_id])


def map_attribution(patches: Sequence[Patch], definition: Definition, dumps: Sequence[Dump]) -> MapAttribution:
    """R100, R101: which maps hold the bytes of each patch, over the spans on every dump in `dumps`."""
    if not dumps:
        raise DefinitionError("bad_shape", "map_attribution needs at least one dump (R100)")
    ordered = sorted({patch.patch_hash: patch for patch in patches}.values(), key=_patch_key)
    written = {
        memory_id: _merge([(p.offset, p.end) for p in ordered if p.memory_id == memory_id])
        for memory_id in {patch.memory_id for patch in ordered}
    }
    spans: dict[str, list[ByteRange]] = {}
    unbound: list[str] = []
    for mapdef in definition.mapdefs:
        try:
            spans[mapdef.map_id] = [r for dump in dumps for r in span(mapdef, definition, dump)]
        except DefinitionError:
            unbound.append(mapdef.map_id)
    lines = tuple(
        PatchMaps(
            patch.patch_hash,
            tuple(
                sorted(
                    map_id
                    for map_id, ranges in spans.items()
                    if _intersection(_within(ranges, patch.memory_id), [(patch.offset, patch.end)])
                )
            ),
        )
        for patch in ordered
    )
    maps: list[MapRuns] = []
    for map_id in sorted(spans):
        inside = {m: _intersection(_within(spans[map_id], m), intervals) for m, intervals in written.items()}
        runs = _runs({m: pieces for m, pieces in inside.items() if pieces})
        if runs:
            maps.append(MapRuns(map_id, runs))
    covered = [r for ranges in spans.values() for r in ranges]
    outside = {m: _difference(intervals, _within(covered, m)) for m, intervals in written.items()}
    unmapped = _runs({m: pieces for m, pieces in outside.items() if pieces})
    return MapAttribution(lines, tuple(maps), unmapped, tuple(sorted(unbound)))


def report_map_ids(attribution: MapAttribution) -> dict[str, str | None]:
    """R102: the one map of a patch, or None when it has none or several."""
    return {line.patch_hash: line.map_ids[0] if len(line.map_ids) == 1 else None for line in attribution.patches}
