"""Naive reference `apply` (SPEC-000 §"Done" criteria, kernel row): stdlib only, <= 50 lines.

Written from SPEC-001 R25 and R21 without importing the core. Patches are plain tuples
(memory_id, offset, before, after); overlaps are pairs of indices into that list.
"""

import heapq
from collections.abc import Callable

RefPatch = tuple[str, int, bytes, bytes]


def reference_apply(
    memories: dict[str, bytes],
    patches: list[RefPatch],
    overlaps: list[tuple[int, int]],
    tie_break: Callable[[int], str],
) -> dict[str, bytes]:
    predecessors = [0] * len(patches)
    successors: list[list[int]] = [[] for _ in patches]
    for first, second in overlaps:
        successors[first].append(second)
        predecessors[second] += 1
    heap = [(patches[i][0], patches[i][1], tie_break(i), i) for i in range(len(patches)) if predecessors[i] == 0]
    heapq.heapify(heap)
    out = {name: bytearray(data) for name, data in memories.items()}
    while heap:
        *_, i = heapq.heappop(heap)
        memory_id, offset, before, after = patches[i]
        buffer = out[memory_id]
        if bytes(buffer[offset : offset + len(before)]) != before:
            raise ValueError(f"precondition failed at patch {i}")
        buffer[offset : offset + len(after)] = after
        for successor in successors[i]:
            predecessors[successor] -= 1
            if predecessors[successor] == 0:
                p = patches[successor]
                heapq.heappush(heap, (p[0], p[1], tie_break(successor), successor))
    return {name: bytes(data) for name, data in out.items()}
