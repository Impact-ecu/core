"""Differential test: the kernel's `apply` agrees byte for byte with the naive reference.

SPEC-000 §"Done" criteria (kernel); SPEC-001 R20, R21, R25.
"""

from hypothesis import given

from core.kernel import apply
from core.kernel._internal import view
from tests.differential.reference import reference_apply
from tests.properties.strategies import Scenario, scenarios


# SPEC-001 R21, R25
@given(scenarios())
def test_kernel_apply_matches_reference(s: Scenario) -> None:
    patches = list(s.version.patches)
    index = {p.patch_hash: i for i, p in enumerate(patches)}
    expected = reference_apply(
        {m.memory_id: m.data for m in s.dump.memories},
        [(p.memory_id, p.offset, p.before, p.after) for p in patches],
        [(index[a], index[b]) for a, b in s.version.overlaps],
        lambda i: patches[i].patch_hash,
    )
    got = {m.memory_id: m.data for m in view(apply(s.dump, s.version, s.layout)).memories}
    assert got == expected == s.expected
