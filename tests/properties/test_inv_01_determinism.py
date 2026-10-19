"""SPEC-000 invariant 1 (Determinism): SPEC-001 R70, R71.

Same inputs, same bytes and hashes. Cross-machine agreement (x86-64 and arm64) is checked by the CI
matrix, which runs this suite and the fixed-hash vectors on both architectures. R70 (no float, no
native byte order) is checked statically in tests/architecture/test_purity.py.
"""

from hypothesis import given

from core.kernel import apply, canonical_order, diff, invert, version_hash
from core.kernel._internal import view
from tests.properties.strategies import Scenario, scenarios


# SPEC-001 R71
@given(scenarios())
def test_apply_is_deterministic_and_does_not_mutate_inputs(s: Scenario) -> None:
    before = {m.memory_id: m.data for m in s.dump.memories}
    first = apply(s.dump, s.version, s.layout)
    second = apply(s.dump, s.version, s.layout)
    assert first.image_hash == second.image_hash
    assert view(first) == view(second)
    assert {m.memory_id: m.data for m in view(first).memories} == s.expected
    assert {m.memory_id: m.data for m in s.dump.memories} == before


# SPEC-001 R71
@given(scenarios())
def test_derived_operations_are_deterministic(s: Scenario) -> None:
    applied = apply(s.dump, s.version, s.layout)
    assert version_hash(s.version) == version_hash(s.version)
    assert canonical_order(s.version) == canonical_order(s.version)
    assert invert(s.dump, s.version) == invert(s.dump, s.version)
    assert diff(s.dump, applied, s.layout) == diff(s.dump, applied, s.layout)
