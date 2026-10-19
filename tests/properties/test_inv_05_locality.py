"""SPEC-000 invariant 5 (Locality): SPEC-001 R24."""

from hypothesis import given

from core.kernel import apply
from core.kernel._internal import view
from tests.properties.strategies import Scenario, scenarios


# SPEC-001 R24
@given(scenarios())
def test_bytes_outside_the_patch_ranges_are_unchanged(s: Scenario) -> None:
    result = {m.memory_id: m.data for m in view(apply(s.dump, s.version, s.layout)).memories}
    for memory in s.dump.memories:
        touched = {i for p in s.version.patches if p.memory_id == memory.memory_id for i in range(p.offset, p.end)}
        outside = [i for i in range(len(memory.data)) if i not in touched]
        assert [result[memory.memory_id][i] for i in outside] == [memory.data[i] for i in outside]
