"""SPEC-000 invariant 3 (Containment): SPEC-001 R10, R23."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from core.kernel import (
    ContainmentError,
    Dump,
    MemoryLayout,
    Patch,
    ShapeError,
    Version,
    apply,
    image_hash,
    layout_hash,
)
from tests.properties.strategies import MEMORY_IDS, dumps_and_layouts


def inside_one_calibration_region(layout: MemoryLayout, memory_id: str, start: int, end: int) -> bool:
    return any(
        r.kind == "calibration" and r.start <= start and end <= r.end
        for m in layout.memories
        if m.memory_id == memory_id
        for r in m.regions
    )


# SPEC-001 R23: accepted iff the whole range lies in one single calibration region of a known memory.
@given(dumps_and_layouts(), st.data())
def test_apply_accepts_exactly_the_patches_inside_one_calibration_region(
    dl: tuple[Dump, MemoryLayout], data: st.DataObject
) -> None:
    dump, layout = dl
    memory_id = data.draw(st.sampled_from((*MEMORY_IDS, "nvram")))
    contents = {m.memory_id: m.data for m in dump.memories}
    size = len(contents.get(memory_id, b""))
    offset = data.draw(st.integers(0, size + 4))
    length = data.draw(st.integers(1, 12))
    current = contents.get(memory_id, b"")[offset : offset + length]
    before = current + bytes(length - len(current))
    patch = Patch(memory_id, offset, length, before, bytes(b ^ 0x5A for b in before))
    version = Version(image_hash(dump), layout_hash(layout), (patch,))
    if memory_id not in contents:
        with pytest.raises(ContainmentError) as caught:
            apply(dump, version, layout)
        assert caught.value.reason == "unknown_memory"
    elif inside_one_calibration_region(layout, memory_id, offset, offset + length):
        assert apply(dump, version, layout).image_hash != image_hash(dump)
    else:
        with pytest.raises(ContainmentError) as caught:
            apply(dump, version, layout)
        assert caught.value.reason == "out_of_region"


# SPEC-001 R10, R12
@given(st.integers(0, 16), st.binary(max_size=16), st.binary(max_size=16))
def test_patch_shape_requires_equal_positive_lengths(length: int, before: bytes, after: bytes) -> None:
    if length == 0 or not len(before) == len(after) == length:
        with pytest.raises(ShapeError) as caught:
            Patch("pflash", 0, length, before, after)
        assert caught.value.reason == "bad_length"
    elif before == after:
        with pytest.raises(ShapeError) as caught:
            Patch("pflash", 0, length, before, after)
        assert caught.value.reason == "noop_patch"
    else:
        assert Patch("pflash", 0, length, before, after).length == length
