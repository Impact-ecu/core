"""SPEC-000 invariant 7 (Canonical order): SPEC-001 R22, R25, R64."""

from itertools import permutations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from core.kernel import OverlapError, Patch, Version, apply, canonical_order, version_hash
from tests.properties.strategies import Scenario, intersects, scenarios


def smallest_topological_order(patches: tuple[Patch, ...], pairs: tuple[tuple[str, str], ...]) -> list[Patch]:
    """Brute force: the lexicographically smallest order, by key list, among those respecting `pairs`."""
    best: list[Patch] | None = None
    for candidate in permutations(patches):
        position = {p.patch_hash: i for i, p in enumerate(candidate)}
        if all(position[a] < position[b] for a, b in pairs):
            keys = [(p.memory_id, p.offset, p.patch_hash) for p in candidate]
            if best is None or keys < [(p.memory_id, p.offset, p.patch_hash) for p in best]:
                best = list(candidate)
    assert best is not None
    return best


# SPEC-001 R25: Kahn min-heap order equals the brute-force lexicographically smallest topological order.
@given(scenarios(max_patches=5))
def test_canonical_order_is_the_smallest_topological_order(s: Scenario) -> None:
    assert list(canonical_order(s.version)) == smallest_topological_order(s.version.patches, s.version.overlaps)


# SPEC-001 R25, R64: input order of patches and of pairs changes neither the result nor version_hash.
@given(scenarios(), st.data())
def test_input_order_never_matters(s: Scenario, data: st.DataObject) -> None:
    shuffled = Version(
        s.version.base_image_hash,
        s.version.layout_hash,
        tuple(data.draw(st.permutations(s.version.patches))),
        tuple(data.draw(st.permutations(s.version.overlaps))),
    )
    assert version_hash(shuffled) == version_hash(s.version)
    assert apply(s.dump, shuffled, s.layout).image_hash == apply(s.dump, s.version, s.layout).image_hash


# SPEC-001 R22: dropping any required pair is `missing_order`; adding a non-overlapping one is `spurious_order`.
@given(scenarios(min_patches=1), st.data())
def test_every_overlapping_pair_needs_exactly_one_order(s: Scenario, data: st.DataObject) -> None:
    if s.version.overlaps:
        drop = data.draw(st.integers(0, len(s.version.overlaps) - 1))
        fewer = s.version.overlaps[:drop] + s.version.overlaps[drop + 1 :]
        with pytest.raises(OverlapError) as caught:
            canonical_order(Version(s.version.base_image_hash, s.version.layout_hash, s.version.patches, fewer))
        assert caught.value.reason == "missing_order"
        a, b = s.version.overlaps[drop]
        with pytest.raises(OverlapError) as caught:
            canonical_order(
                Version(
                    s.version.base_image_hash, s.version.layout_hash, s.version.patches, (*s.version.overlaps, (b, a))
                )
            )
        assert caught.value.reason == "spurious_order"
    disjoint = [
        (a.patch_hash, b.patch_hash)
        for a in s.version.patches
        for b in s.version.patches
        if a.patch_hash != b.patch_hash and not intersects(a, b)
    ]
    if disjoint:
        extra = data.draw(st.sampled_from(disjoint))
        with pytest.raises(OverlapError) as caught:
            canonical_order(
                Version(
                    s.version.base_image_hash, s.version.layout_hash, s.version.patches, (*s.version.overlaps, extra)
                )
            )
        assert caught.value.reason == "spurious_order"
