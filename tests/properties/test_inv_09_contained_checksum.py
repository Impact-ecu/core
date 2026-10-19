"""SPEC-000 invariant 9 (Contained checksum and release locality): SPEC-001 R6, R40, R41."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from core.kernel import ContainmentError, Patch, apply, apply_checksum_patches
from core.kernel._internal import view
from tests.properties.strategies import Scenario, calibration_slots, intersects, patch_in, scenarios


def checksum_patches(s: Scenario, data: st.DataObject, current: dict[str, bytes]) -> list[Patch]:
    q: list[Patch] = []
    slots = calibration_slots(s.layout, "checksum")
    if slots:
        for _ in range(data.draw(st.integers(0, 4))):
            memory_id, region = data.draw(st.sampled_from(slots))
            patch = data.draw(patch_in(memory_id, region, current[memory_id]))
            if not any(intersects(patch, other) for other in q):
                q.append(patch)
    return q


# SPEC-001 R40, R41: the result differs from u only inside checksum regions.
@given(scenarios(), st.data())
def test_checksum_step_changes_only_checksum_regions(s: Scenario, data: st.DataObject) -> None:
    u = apply(s.dump, s.version, s.layout)
    before = {m.memory_id: m.data for m in view(u).memories}
    q = checksum_patches(s, data, before)
    after = {m.memory_id: m.data for m in view(apply_checksum_patches(u, q, s.layout)).memories}
    for lm in s.layout.memories:
        for r in lm.regions:
            if r.kind != "checksum":
                assert after[lm.memory_id][r.start : r.end] == before[lm.memory_id][r.start : r.end]
    for p in q:
        assert after[p.memory_id][p.offset : p.end] == p.after


# SPEC-001 R6, R40: one patch outside a checksum region rejects the whole set.
@given(scenarios(), st.data())
def test_one_patch_outside_a_checksum_region_rejects_the_set(s: Scenario, data: st.DataObject) -> None:
    u = apply(s.dump, s.version, s.layout)
    current = {m.memory_id: m.data for m in view(u).memories}
    q = checksum_patches(s, data, current)
    other_kinds = [(m.memory_id, r) for m in s.layout.memories for r in m.regions if r.kind != "checksum"]
    if not other_kinds:
        return
    memory_id, region = data.draw(st.sampled_from(other_kinds))
    outsider = data.draw(patch_in(memory_id, region, current[memory_id]))
    position = data.draw(st.integers(0, len(q)))
    with pytest.raises(ContainmentError) as caught:
        apply_checksum_patches(u, [*q[:position], outsider, *q[position:]], s.layout)
    assert caught.value.reason == "checksum_out_of_region"
