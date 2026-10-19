"""SPEC-000 invariant 4 (Patch precondition): SPEC-001 R21."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from core.kernel import Dump, Memory, Patch, PreconditionConflict, Version, apply, canonical_order, image_hash
from tests.properties.strategies import Scenario, scenarios


# SPEC-001 R21: `before` of P[i] equals the bytes of apply(o, P[:i]), which may differ from o.
@given(scenarios())
def test_each_before_matches_the_partially_applied_image(s: Scenario) -> None:
    current = {m.memory_id: bytearray(m.data) for m in s.dump.memories}
    for patch in canonical_order(s.version):
        buffer = current[patch.memory_id]
        assert bytes(buffer[patch.offset : patch.end]) == patch.before
        buffer[patch.offset : patch.end] = patch.after
    assert {k: bytes(v) for k, v in current.items()} == s.expected
    expected = Dump(
        s.dump.dump_kind, tuple(Memory(m.memory_id, m.base_address, s.expected[m.memory_id]) for m in s.dump.memories)
    )
    assert apply(s.dump, s.version, s.layout).image_hash == image_hash(expected)


# SPEC-001 R21: a wrong `before` is a conflict carrying its index and patch hash, never an overwrite.
@given(scenarios(min_patches=1), st.data())
def test_a_wrong_before_is_a_conflict(s: Scenario, data: st.DataObject) -> None:
    target = data.draw(st.sampled_from(s.version.patches))
    flip = data.draw(st.integers(0, target.length - 1))
    wrong = bytearray(target.before)
    # The mask keeps `wrong` different from `before` (mask != 0) and from `after` at `flip`, so the
    # broken patch is never a no-op and never equal to the target.
    forbidden = target.before[flip] ^ target.after[flip]
    wrong[flip] ^= data.draw(st.integers(1, 255).filter(lambda mask: mask != forbidden))
    assert bytes(wrong) not in (target.before, target.after)
    broken = Patch(target.memory_id, target.offset, target.length, bytes(wrong), target.after)
    rename = {target.patch_hash: broken.patch_hash}
    version = Version(
        s.version.base_image_hash,
        s.version.layout_hash,
        tuple(broken if p == target else p for p in s.version.patches),
        tuple((rename.get(a, a), rename.get(b, b)) for a, b in s.version.overlaps),
    )
    with pytest.raises(PreconditionConflict) as caught:
        apply(s.dump, version, s.layout)
    assert caught.value.reason == "before_mismatch"
    assert caught.value.patch_hash == broken.patch_hash
    assert caught.value.index == canonical_order(version).index(broken)
