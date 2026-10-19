"""SPEC-000 invariant 6 (Invertibility): SPEC-001 R30, R31, R32."""

from hypothesis import given
from hypothesis import strategies as st

from core.kernel import Dump, Memory, MemoryLayout, apply, diff, image_hash, invert
from core.kernel._internal import view
from tests.properties.strategies import Scenario, dumps_and_layouts, scenarios


# SPEC-001 R30
@given(scenarios())
def test_invert_restores_the_original(s: Scenario) -> None:
    applied = apply(s.dump, s.version, s.layout)
    inverse = invert(s.dump, s.version)
    assert inverse.base_image_hash == applied.image_hash
    assert inverse.layout_hash == s.version.layout_hash
    assert apply(applied, inverse, s.layout).image_hash == image_hash(s.dump)
    swapped = {(p.memory_id, p.offset, p.after, p.before) for p in s.version.patches}
    assert {(p.memory_id, p.offset, p.before, p.after) for p in inverse.patches} == swapped
    by_swapped = {(p.memory_id, p.offset, p.after, p.before): p.patch_hash for p in s.version.patches}
    original_of = {p.patch_hash: by_swapped[(p.memory_id, p.offset, p.before, p.after)] for p in inverse.patches}
    assert sorted((original_of[b], original_of[a]) for a, b in inverse.overlaps) == sorted(s.version.overlaps)


# SPEC-001 R31: diff(o, apply(o, v)) gives disjoint ordered patches that reproduce apply(o, v).
@given(scenarios())
def test_diff_of_apply_reproduces_it(s: Scenario) -> None:
    applied = apply(s.dump, s.version, s.layout)
    result = diff(s.dump, applied, s.layout)
    assert result.foreign == ()
    keys = [(p.memory_id, p.offset) for p in result.patches]
    assert keys == sorted(keys)
    for a, b in zip(result.patches, result.patches[1:], strict=False):
        assert a.memory_id != b.memory_id or a.end <= b.offset
    assert apply(s.dump, result.as_version(), s.layout).image_hash == applied.image_hash


def naive_runs(a: bytes, b: bytes, start: int, end: int) -> list[tuple[int, int]]:
    runs: list[tuple[int, int]] = []
    for i in range(start, end):
        if a[i] != b[i]:
            if runs and runs[-1][1] == i:
                runs[-1] = (runs[-1][0], i + 1)
            else:
                runs.append((i, i + 1))
    return runs


# SPEC-001 R31, R32: for any x of the same shape, calibration runs become patches, others foreign runs.
@given(dumps_and_layouts(), st.data())
def test_diff_of_any_image_splits_patches_and_foreign_runs(dl: tuple[Dump, MemoryLayout], data: st.DataObject) -> None:
    dump, layout = dl
    changed: list[Memory] = []
    for m in dump.memories:
        mutated = bytearray(m.data)
        for i in data.draw(st.sets(st.integers(0, len(m.data) - 1), max_size=40)):
            mutated[i] ^= data.draw(st.integers(1, 255))
        changed.append(Memory(m.memory_id, m.base_address, bytes(mutated)))
    x = Dump(dump.dump_kind, tuple(changed))
    result = diff(dump, x, layout)
    old = {m.memory_id: m.data for m in dump.memories}
    new = {m.memory_id: m.data for m in x.memories}
    want_patches: list[tuple[str, int, bytes, bytes]] = []
    want_foreign: list[tuple[str, int, int, str, str]] = []
    for lm in sorted(layout.memories, key=lambda m: m.memory_id):
        a, b = old[lm.memory_id], new[lm.memory_id]
        for r in lm.regions:
            for start, end in naive_runs(a, b, r.start, r.end):
                if r.kind == "calibration":
                    want_patches.append((lm.memory_id, start, a[start:end], b[start:end]))
                else:
                    want_foreign.append((lm.memory_id, start, end - start, r.kind, r.name))
    assert [(p.memory_id, p.offset, p.before, p.after) for p in result.patches] == want_patches
    assert [(f.memory_id, f.offset, f.length, f.region_kind, f.region_name) for f in result.foreign] == want_foreign
    rebuilt = {m.memory_id: m.data for m in view(apply(dump, result.as_version(), layout)).memories}
    for lm in layout.memories:
        for r in lm.regions:
            if r.kind == "calibration":
                assert rebuilt[lm.memory_id][r.start : r.end] == new[lm.memory_id][r.start : r.end]
