"""SPEC-000 invariant 11 (Patch migration): SPEC-001 R50."""

from hypothesis import given
from hypothesis import strategies as st

from core.kernel import LayoutMemory, MemoryLayout, apply, canonical_order, image_hash, layout_hash, migrate
from core.kernel._internal import view
from tests.properties.strategies import Scenario, region_tuples, scenarios


def naive_migration(s: Scenario, new_layout: MemoryLayout) -> tuple[list[str], list[tuple[str, str]], dict[str, bytes]]:
    """Walk the canonical order; drop what leaves calibration or no longer matches (as crosscheck.py)."""
    regions = {m.memory_id: m.regions for m in new_layout.memories}
    current = {m.memory_id: bytearray(m.data) for m in s.dump.memories}
    kept: list[str] = []
    conflicts: list[tuple[str, str]] = []
    for p in canonical_order(s.version):
        if not any(r.kind == "calibration" and r.start <= p.offset and p.end <= r.end for r in regions[p.memory_id]):
            conflicts.append((p.patch_hash, "out_of_region"))
        elif bytes(current[p.memory_id][p.offset : p.end]) != p.before:
            conflicts.append((p.patch_hash, "before_mismatch"))
        else:
            current[p.memory_id][p.offset : p.end] = p.after
            kept.append(p.patch_hash)
    return kept, conflicts, {k: bytes(v) for k, v in current.items()}


# SPEC-001 R50
@given(scenarios(), st.data())
def test_migration_keeps_exactly_what_still_holds(s: Scenario, data: st.DataObject) -> None:
    new_layout = MemoryLayout(
        tuple(
            LayoutMemory(m.memory_id, m.base_address, m.size, data.draw(region_tuples(m.size)))
            for m in s.layout.memories
        )
    )
    result = migrate(s.dump, s.version, new_layout)
    kept, conflicts, expected = naive_migration(s, new_layout)
    assert [p.patch_hash for p in result.version.patches] == kept
    assert [(c.patch_hash, c.reason) for c in result.conflicts] == conflicts
    assert result.version.base_image_hash == image_hash(s.dump)
    assert result.version.layout_hash == layout_hash(new_layout)
    kept_set = set(kept)
    assert set(result.version.overlaps) == {(a, b) for a, b in s.version.overlaps if a in kept_set and b in kept_set}
    migrated = view(apply(s.dump, result.version, new_layout))
    assert {m.memory_id: m.data for m in migrated.memories} == expected
