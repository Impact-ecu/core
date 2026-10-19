"""Error paths and structural rules of apply, invert, diff, migrate and the checksum step (SPEC-001 §3-§6)."""

import pickle
from collections.abc import Callable
from types import SimpleNamespace
from typing import cast

import pytest

from core.kernel import (
    ContainmentError,
    Dump,
    LayoutError,
    LayoutMemory,
    Memory,
    MemoryLayout,
    OverlapError,
    Patch,
    PreconditionConflict,
    Region,
    ShapeError,
    UnverifiedImage,
    Version,
    apply,
    apply_checksum_patches,
    canonical_order,
    diff,
    image_hash,
    invert,
    layout_hash,
    migrate,
    version_hash,
)
from core.kernel._internal import view
from tests.unit.fixtures import DUMP, EEPROM, LAYOUT, PFLASH, patch, version

PARTIAL = Dump("obd_partial", (Memory("pflash", None, PFLASH), Memory("eeprom", 0x0, EEPROM)))
OTHER_LAYOUT = MemoryLayout((LAYOUT.memories[0],))


# SPEC-001 R2: unknown base address can be hashed, but apply, diff, migrate (and invert) reject it.
def test_unknown_base_address_is_rejected_by_operations() -> None:
    assert image_hash(PARTIAL) != image_hash(DUMP)
    v = version(dump=PARTIAL)
    calls: list[Callable[[], object]] = [
        lambda: apply(PARTIAL, v, LAYOUT),
        lambda: diff(PARTIAL, DUMP, LAYOUT),
        lambda: diff(DUMP, PARTIAL, LAYOUT),
        lambda: migrate(PARTIAL, v, LAYOUT),
        lambda: invert(PARTIAL, v),
        lambda: UnverifiedImage(PARTIAL),
    ]
    for call in calls:
        with pytest.raises(ShapeError) as caught:
            call()
        assert caught.value.reason == "unknown_base_address"
        assert caught.value.detail == "pflash"


# SPEC-001 R20: apply accepts an UnverifiedImage as its base, and never mutates its input.
def test_apply_chains_on_an_unverified_image() -> None:
    first = apply(DUMP, version(patch(8, b"\x01")), LAYOUT)
    second_patch = patch(9, b"\x02")
    second = apply(first, Version(first.image_hash, layout_hash(LAYOUT), (second_patch,)), LAYOUT)
    assert view(second).memories[0].data[8:10] == b"\x01\x02"
    assert view(first).memories[0].data[8:10] == b"\x01" + PFLASH[9:10]
    assert DUMP.memories[0].data == PFLASH
    assert image_hash(first) == first.image_hash == image_hash(view(first))


# SPEC-001 R7: an UnverifiedImage cannot be changed after construction.
def test_unverified_image_is_immutable() -> None:
    u = apply(DUMP, version(), LAYOUT)
    with pytest.raises(AttributeError):
        u._dump = DUMP
    with pytest.raises(AttributeError):
        delattr(u, "_image_hash")
    assert repr(u) == f"UnverifiedImage(dump_kind='bench_full', image_hash='{u.image_hash}')"
    assert [m.memory_id for m in u.memories] == ["pflash", "eeprom"]
    with pytest.raises(TypeError):
        pickle.dumps(u)
    with pytest.raises(TypeError):
        u.__getstate__()


# SPEC-001 R22, R25: a patch with two predecessors waits for both.
def test_patch_with_two_predecessors() -> None:
    a = Patch("pflash", 8, 3, PFLASH[8:11], b"\x01\x01\x01")
    b = Patch("pflash", 9, 3, b"\x01\x01" + PFLASH[11:12], b"\x02\x02\x02")
    c = Patch("pflash", 9, 1, b"\x02", b"\x03")
    pairs = ((a.patch_hash, b.patch_hash), (a.patch_hash, c.patch_hash), (b.patch_hash, c.patch_hash))
    assert canonical_order(version(c, b, a, overlaps=pairs)) == (a, b, c)
    result = view(apply(DUMP, version(c, b, a, overlaps=pairs), LAYOUT))
    assert result.memories[0].data[8:12] == b"\x01\x03\x02\x02"


# SPEC-001 R31: patches of an earlier memory do not leak into the next one.
def test_diff_over_two_memories() -> None:
    x = apply(DUMP, version(patch(8, b"\x00"), patch(1, b"\x00", memory_id="eeprom", current=EEPROM)), LAYOUT)
    result = diff(DUMP, x, LAYOUT)
    assert [(p.memory_id, p.offset) for p in result.patches] == [("eeprom", 1), ("pflash", 8)]


# SPEC-001 R20: an empty version reproduces the original.
def test_empty_version_is_identity() -> None:
    assert apply(DUMP, version(), LAYOUT).image_hash == image_hash(DUMP)


RESIZED = MemoryLayout((LAYOUT.memories[0], LayoutMemory("eeprom", 0x0, 4, (Region("protected", 0, 4),))))
MOVED = MemoryLayout((LAYOUT.memories[0], LayoutMemory("eeprom", 0x10, 8, LAYOUT.memories[1].regions)))


# SPEC-001 R5: the layout must describe the dump exactly (memory set, base addresses, sizes).
@pytest.mark.parametrize("layout", [OTHER_LAYOUT, RESIZED, MOVED], ids=["missing", "resized", "moved"])
def test_layout_must_match_the_dump(layout: MemoryLayout) -> None:
    v = Version(image_hash(DUMP), layout_hash(layout), ())
    u = apply(DUMP, version(), LAYOUT)
    calls: list[Callable[[], object]] = [
        lambda: apply(DUMP, v, layout),
        lambda: diff(DUMP, DUMP, layout),
        lambda: migrate(DUMP, v, layout),
        lambda: apply_checksum_patches(u, [], layout),
    ]
    for call in calls:
        with pytest.raises(LayoutError) as caught:
            call()
        assert caught.value.reason == "shape_mismatch"


# SPEC-001 R14
def test_duplicate_patch_is_rejected_everywhere_a_version_is_read() -> None:
    p = patch(8, b"\x01")
    v = version(p, p)
    for call in (
        lambda: apply(DUMP, v, LAYOUT),
        lambda: invert(DUMP, v),
        lambda: migrate(DUMP, v, LAYOUT),
        lambda: canonical_order(v),
        lambda: version_hash(v),
    ):
        with pytest.raises(ShapeError) as caught:
            call()
        assert caught.value.reason == "duplicate_patch"


# SPEC-001 R20, R50: invert and migrate check the base image too.
def test_wrong_base_in_invert_and_migrate() -> None:
    v = Version("0" * 64, layout_hash(LAYOUT), ())
    for call in (lambda: invert(DUMP, v), lambda: migrate(DUMP, v, LAYOUT)):
        with pytest.raises(ShapeError) as caught:
            call()
        assert caught.value.reason == "wrong_base"


# SPEC-001 R22: a self-pair is spurious; so is a pair naming an unknown patch.
def test_spurious_pairs() -> None:
    p = patch(8, b"\x01")
    for pairs in (((p.patch_hash, p.patch_hash),), ((p.patch_hash, "f" * 64),)):
        with pytest.raises(OverlapError) as caught:
            canonical_order(version(p, overlaps=pairs))
        assert caught.value.reason == "spurious_order"


# SPEC-001 R22: two patches in different memories at the same offset do not overlap.
def test_same_offset_in_different_memories_is_not_an_overlap() -> None:
    a = patch(0, b"\x00", memory_id="eeprom", current=EEPROM)
    b = patch(8, b"\x00")
    assert canonical_order(version(b, a)) == (a, b)
    with pytest.raises(OverlapError):
        canonical_order(version(a, b, overlaps=((a.patch_hash, b.patch_hash),)))


# SPEC-001 R22, R25: a cycle among three overlapping patches.
def test_cycle() -> None:
    a = Patch("pflash", 8, 2, PFLASH[8:10], b"\x00\x00")
    b = Patch("pflash", 9, 2, PFLASH[9:11], b"\x01\x01")
    c = Patch("pflash", 8, 3, PFLASH[8:11], b"\x02\x02\x02")
    pairs = ((a.patch_hash, b.patch_hash), (b.patch_hash, c.patch_hash), (c.patch_hash, a.patch_hash))
    with pytest.raises(OverlapError) as caught:
        apply(DUMP, version(a, b, c, overlaps=pairs), LAYOUT)
    assert caught.value.reason == "cycle"


# SPEC-001 R23: a patch past the end of its memory is out of region.
def test_patch_past_end_of_memory() -> None:
    p = Patch("eeprom", 3, 2, b"\xff\xff", b"\x00\x00")
    with pytest.raises(ContainmentError) as caught:
        apply(DUMP, version(p), LAYOUT)
    assert caught.value.reason == "out_of_region"


# SPEC-001 R30: invert has no layout; it still rejects patches outside the dump's memories.
def test_invert_rejects_patches_outside_the_dump() -> None:
    cases = {
        "unknown_memory": Patch("nvram", 0, 1, b"\x00", b"\x01"),
        "out_of_region": Patch("eeprom", 7, 2, b"\xff\xff", b"\x00\x00"),
    }
    for reason, p in cases.items():
        with pytest.raises(ContainmentError) as caught:
            invert(DUMP, version(p))
        assert caught.value.reason == reason


# SPEC-001 R21, R30: invert applies the version, so a precondition failure surfaces there.
def test_invert_reports_precondition_conflicts() -> None:
    p = Patch("pflash", 8, 1, b"\x77", b"\x01")
    with pytest.raises(PreconditionConflict) as caught:
        invert(DUMP, version(p))
    assert caught.value.index == 0


# SPEC-001 R31: same shape means same dump_kind, memory ids, base addresses and sizes.
def test_diff_shape_mismatch() -> None:
    others = [
        Dump("obd_full", DUMP.memories),
        Dump("bench_full", (DUMP.memories[0],)),
        Dump("bench_full", (DUMP.memories[0], Memory("eeprom", 0x4, EEPROM))),
    ]
    for other in others:
        with pytest.raises(ShapeError) as caught:
            diff(DUMP, other, LAYOUT)
        assert caught.value.reason == "shape_mismatch"


# SPEC-001 R31: chunked comparison finds runs on both sides of a chunk boundary and at the very end.
def test_diff_runs_across_chunks() -> None:
    size = 200
    original = Dump("virtual", (Memory("pflash", 0, bytes(size)),))
    layout = MemoryLayout((LayoutMemory("pflash", 0, size, (Region("calibration", 0, size),)),))
    changed = bytearray(size)
    for i in (0, 63, 64, 65, 130, 199):
        changed[i] = 1
    result = diff(original, Dump("virtual", (Memory("pflash", 0, bytes(changed)),)), layout)
    assert [(p.offset, p.length) for p in result.patches] == [(0, 1), (63, 3), (130, 1), (199, 1)]
    assert result.as_version().overlaps == ()


# SPEC-001 R50: unknown memory and broken precondition become conflicts, never errors.
def test_migrate_reports_conflicts() -> None:
    first = Patch("pflash", 8, 2, PFLASH[8:10], b"\xaa\xaa")
    second = Patch("pflash", 9, 2, b"\xaa" + PFLASH[10:11], b"\xbb\xbb")
    pairs = ((first.patch_hash, second.patch_hash),)
    narrow = MemoryLayout(
        (
            LayoutMemory(
                "pflash",
                0x8000_0000,
                32,
                (Region("protected", 0, 9), Region("calibration", 9, 24), Region("checksum", 24, 32)),
            ),
            LAYOUT.memories[1],
        )
    )
    result = migrate(DUMP, version(first, second, overlaps=pairs), narrow)
    assert [(c.patch_hash, c.reason) for c in result.conflicts] == [
        (first.patch_hash, "out_of_region"),
        (second.patch_hash, "before_mismatch"),
    ]
    assert result.version.patches == ()
    assert result.version.overlaps == ()
    stray = Patch("nvram", 0, 1, b"\x00", b"\x01")
    result = migrate(DUMP, version(stray), LAYOUT)
    assert [(c.patch_hash, c.reason) for c in result.conflicts] == [(stray.patch_hash, "out_of_region")]


# SPEC-001 R40: unknown memory and overlapping checksum patches are rejected; an empty set is identity.
def test_checksum_step_edges() -> None:
    u = apply(DUMP, version(), LAYOUT)
    assert apply_checksum_patches(u, [], LAYOUT).image_hash == u.image_hash
    stray = Patch("nvram", 0, 1, b"\x00", b"\x01")
    with pytest.raises(ContainmentError) as caught:
        apply_checksum_patches(u, [stray], LAYOUT)
    assert caught.value.reason == "checksum_out_of_region"
    a = patch(24, b"\x00\x00")
    b = patch(25, b"\x09")
    for q in ([a, b], [a, a]):
        with pytest.raises(OverlapError) as caught_overlap:
            apply_checksum_patches(u, q, LAYOUT)
        assert caught_overlap.value.reason == "missing_order"
    forged = SimpleNamespace(memory_id="pflash", offset=24, length=0, before=b"", after=b"", patch_hash="forged")
    with pytest.raises(ShapeError) as caught_type:
        apply_checksum_patches(u, [cast(Patch, forged)], LAYOUT)  # a plugin q is checked item by item
    assert caught_type.value.reason == "bad_type"
    with pytest.raises(ShapeError) as caught_type:
        apply_checksum_patches(cast(UnverifiedImage, DUMP), [], LAYOUT)
    assert caught_type.value.reason == "bad_type"
    stale = Patch("pflash", 24, 1, b"\x77", b"\x00")
    with pytest.raises(PreconditionConflict):
        apply_checksum_patches(u, [stale], LAYOUT)
