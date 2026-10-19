"""SPEC-000 invariant 2 (Composition): SPEC-001 R27."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from core.kernel import Patch, PreconditionConflict, Version, apply, canonical_order
from tests.properties.strategies import Scenario, scenarios


def sub_version(s: Scenario, base: str, patches: tuple[Patch, ...]) -> Version:
    hashes = {p.patch_hash for p in patches}
    pairs = tuple(pair for pair in s.version.overlaps if pair[0] in hashes and pair[1] in hashes)
    return Version(base, s.version.layout_hash, patches, pairs)


# SPEC-001 R27
@given(scenarios(), st.data())
def test_apply_composes_at_every_split(s: Scenario, data: st.DataObject) -> None:
    order = canonical_order(s.version)
    k = data.draw(st.integers(0, len(order)))
    middle = apply(s.dump, sub_version(s, s.version.base_image_hash, order[:k]), s.layout)
    rest = sub_version(s, middle.image_hash, order[k:])
    assert apply(middle, rest, s.layout).image_hash == apply(s.dump, s.version, s.layout).image_hash


# SPEC-001 R27: reapplying an already applied patch fails the precondition (R21).
@given(scenarios(min_patches=1), st.data())
def test_reapplying_an_applied_patch_conflicts(s: Scenario, data: st.DataObject) -> None:
    order = canonical_order(s.version)
    k = data.draw(st.integers(1, len(order)))
    middle = apply(s.dump, sub_version(s, s.version.base_image_hash, order[:k]), s.layout)
    again = Version(middle.image_hash, s.version.layout_hash, (order[k - 1],))
    with pytest.raises(PreconditionConflict) as caught:
        apply(middle, again, s.layout)
    assert caught.value.reason == "before_mismatch"
    assert caught.value.patch_hash == order[k - 1].patch_hash
