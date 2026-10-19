"""Overlap validation (SPEC-001 R14, R22), canonical order (R25) and `version_hash` (R64)."""

import heapq
from collections.abc import Sequence

from core.kernel._canonical import hash_json
from core.kernel._errors import OverlapError, ShapeError, ensure
from core.kernel._model import Patch, Version

type OrderKey = tuple[str, int, str]


def order_key(patch: Patch) -> OrderKey:
    return (patch.memory_id, patch.offset, patch.patch_hash)


def reject_duplicates(patches: Sequence[Patch]) -> None:
    """SPEC-001 R14."""
    seen: set[str] = set()
    for patch in patches:
        if patch.patch_hash in seen:
            raise ShapeError("duplicate_patch", patch.patch_hash)
        seen.add(patch.patch_hash)


def overlapping_pairs(patches: Sequence[Patch]) -> set[frozenset[str]]:
    """Every pair of patches with the same memory and intersecting ranges (SPEC-001 R22)."""
    by_memory: dict[str, list[Patch]] = {}
    for patch in patches:
        by_memory.setdefault(patch.memory_id, []).append(patch)
    pairs: set[frozenset[str]] = set()
    for group in by_memory.values():
        group.sort(key=order_key)
        for index, patch in enumerate(group):
            later = index + 1
            while later < len(group) and group[later].offset < patch.end:
                pairs.add(frozenset((patch.patch_hash, group[later].patch_hash)))
                later += 1
    return pairs


def ordered(patches: Sequence[Patch], overlaps: Sequence[tuple[str, str]]) -> list[Patch]:
    """Validate `overlaps` against `patches` (R22) and return the canonical order (R25).

    `patches` must not hold the same patch twice; callers check R14 first where it applies.
    """
    by_hash = {patch.patch_hash: patch for patch in patches}
    required = overlapping_pairs(patches)
    given: set[frozenset[str]] = set()
    successors: dict[str, list[str]] = {patch_hash: [] for patch_hash in by_hash}
    pending = dict.fromkeys(by_hash, 0)
    for first, second in overlaps:
        pair = frozenset((first, second))
        # Covers unknown hashes, non-overlapping pairs, self-pairs and repeats in either order.
        if pair not in required or pair in given:
            raise OverlapError("spurious_order", f"[{first}, {second}]")
        given.add(pair)
        successors[first].append(second)
        pending[second] += 1
    missing = sorted(sorted(pair) for pair in required - given)
    if missing:
        raise OverlapError("missing_order", f"{missing[0]}")

    # Kahn's algorithm with a min-heap on (memory_id, offset, patch_hash): the lexicographically
    # smallest topological order. Keys are unique because patch hashes are.
    heap = [order_key(patch) for patch in patches if pending[patch.patch_hash] == 0]
    heapq.heapify(heap)
    result: list[Patch] = []
    while heap:
        patch = by_hash[heapq.heappop(heap)[2]]
        result.append(patch)
        for successor in successors[patch.patch_hash]:
            pending[successor] -= 1
            if pending[successor] == 0:
                heapq.heappush(heap, order_key(by_hash[successor]))
    if len(result) != len(patches):
        raise OverlapError("cycle", f"{len(patches) - len(result)} patches are on or after a cycle")
    position = {patch.patch_hash: index for index, patch in enumerate(result)}
    # Invariant 7, R25: every ordered pair is respected by the emitted order.
    ensure(all(position[first] < position[second] for first, second in overlaps), "SPEC-001 R25")
    return result


def canonical_order(version: Version) -> tuple[Patch, ...]:
    """The application order of `version.patches` (SPEC-001 R25), after R14 and R22."""
    reject_duplicates(version.patches)
    return tuple(ordered(version.patches, version.overlaps))


def version_hash(version: Version) -> str:
    """SPEC-001 R64."""
    order = canonical_order(version)
    return hash_json(
        {
            "base_image_hash": version.base_image_hash,
            "layout_hash": version.layout_hash,
            "patches": [patch.patch_hash for patch in order],
            "overlaps": sorted([first, second] for first, second in version.overlaps),
        }
    )
