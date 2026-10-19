"""SPEC-000 invariant 8 (Preserved shape): SPEC-001 R13, R26."""

from hypothesis import given

from core.kernel import MemoryShape, apply, apply_checksum_patches, invert
from core.kernel._internal import view
from tests.properties.strategies import Scenario, scenarios


# SPEC-001 R13, R26: same dump_kind (a partial stays partial), memories, base addresses and sizes.
@given(scenarios())
def test_apply_preserves_the_shape(s: Scenario) -> None:
    result = apply(s.dump, s.version, s.layout)
    shapes = tuple(MemoryShape(m.memory_id, m.base_address or 0, len(m.data)) for m in s.dump.memories)
    assert result.dump_kind == s.dump.dump_kind
    assert result.memories == shapes
    assert [(m.memory_id, m.base_address, len(m.data)) for m in view(result).memories] == [
        (m.memory_id, m.base_address, len(m.data)) for m in s.dump.memories
    ]
    back = apply(result, invert(s.dump, s.version), s.layout)
    assert back.memories == shapes
    assert apply_checksum_patches(result, [], s.layout).memories == shapes
