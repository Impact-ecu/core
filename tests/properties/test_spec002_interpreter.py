"""SPEC-002 §4.4-§4.5 properties of the interpreter on the synthetic 512-byte fixture.

Byte writes, containment and the released image are computed test-side; the interpreter is never used
to compute its own expected value, except where a property compares it with itself on purpose (R82).
"""

import hashlib
from dataclasses import replace

import rfc8785
from hypothesis import given
from hypothesis import strategies as st

from core.kernel import Patch
from core.plugins import (
    ChecksumDescriptor,
    ChecksumRegion,
    Crc32,
    Descriptor,
    DescriptorError,
    descriptor_hash,
    descriptor_json,
)
from core.plugins.descriptor import interpret_patches, interpret_verify
from core.plugins.descriptor._interpret import _resolve, chain_stores
from tests.properties.descriptor_strategies import descriptors
from tests.unit.plugin_fixtures import DESCRIPTORS, LAYOUT, ORIGINAL, REGIONS, dump_of, edited, regions_of

RESOLUTION = {
    "unknown_base_address",
    "table_out_of_bounds",
    "empty_range",
    "overlapping_ranges",
    "misaligned_piece",
    "partial_self",
    "skip_self_without_self",
    "self_reference",
    "compensate_outside_message",
    "dependency_cycle",
}


@st.composite
def calibration_edits(draw: st.DrawFn) -> bytes:
    """The original with 1 to 4 random writes inside the calibration region [32, 256)."""
    data = ORIGINAL
    for _ in range(draw(st.integers(1, 4))):
        offset = draw(st.integers(32, 255))
        after = draw(st.binary(min_size=1, max_size=min(16, 256 - offset)))
        data = edited(data, offset, after)
    return data


def write(data: bytes, patches: tuple[Patch, ...]) -> bytes:
    out = bytearray(data)
    for patch in patches:
        assert out[patch.offset : patch.end] == patch.before
        out[patch.offset : patch.end] = patch.after
    return bytes(out)


# SPEC-002 R51-R54, R73, R76: after the derived patches every region verifies ok, and it is a fixed point.
@given(calibration_edits())
def test_recalculation_verifies_and_is_a_fixed_point(data: bytes) -> None:
    dump = dump_of(data)
    patches = interpret_patches(REGIONS, dump, LAYOUT)
    assert [(p.memory_id, p.offset) for p in patches] == sorted((p.memory_id, p.offset) for p in patches)
    assert all(p.offset >= 256 and p.end <= 288 for p in patches)
    released = write(data, patches)
    assert released[:256] == data[:256]
    assert released[288:] == data[288:]
    results = interpret_verify(REGIONS, dump_of(released), LAYOUT)
    assert {r.status for r in results.values()} == {"ok"}
    assert interpret_patches(REGIONS, dump_of(released), LAYOUT) == ()


# SPEC-002 R75: every order of the region list yields the same bytes; the min-heap order is the reference.
@given(calibration_edits(), st.permutations(REGIONS))
def test_region_order_does_not_matter(data: bytes, permuted: list[ChecksumRegion]) -> None:
    dump = dump_of(data)
    assert interpret_patches(tuple(permuted), dump, LAYOUT) == interpret_patches(REGIONS, dump, LAYOUT)
    assert interpret_verify(tuple(permuted), dump, LAYOUT) == interpret_verify(REGIONS, dump, LAYOUT)


# SPEC-002 R65: the pointer table is protected, so an edit can never move a checksum's coverage.
@given(calibration_edits())
def test_table_coverage_is_fixed_by_protected_bytes(data: bytes) -> None:
    f_table = next(d for d in DESCRIPTORS if d.name == "f_table")
    stores = {name: span for (memory_id, name), span in chain_stores(DESCRIPTORS).items() if name != "f_table"}
    base = 0x8000_0000
    assert _resolve(f_table, data, base, stores) == _resolve(f_table, ORIGINAL, base, stores)


# SPEC-002 R63-R66: whatever the table bytes say, verify never raises and patches raise only DescriptorError.
@given(st.binary(min_size=16, max_size=16))
def test_any_table_bytes_resolve_or_fail_with_a_reason(table: bytes) -> None:
    dump = dump_of(edited(ORIGINAL, 400, table))
    results = interpret_verify(REGIONS, dump, LAYOUT)
    for result in results.values():
        assert result.status in {"ok", "fail"}
        assert result.reason is None or (result.reason in RESOLUTION and result.computed is None)
    assert results["e_crc"].status == "ok"
    reason = None
    try:
        patches = interpret_patches(REGIONS, dump, LAYOUT)
    except DescriptorError as failure:
        reason = failure.reason
    else:
        assert all(p.offset >= 256 and p.end <= 288 for p in patches)
    assert reason is None or reason in RESOLUTION


# SPEC-002 R78, R9: descriptor_hash is sha256 of the RFC 8785 serialization (third-party rfc8785).
@given(descriptors)
def test_descriptor_hash_is_jcs_sha256(descriptor: Descriptor) -> None:
    assert descriptor_hash(descriptor) == hashlib.sha256(rfc8785.dumps(descriptor_json(descriptor))).hexdigest()


# SPEC-002 R101: the same inputs give the same results, however often they are evaluated.
@given(calibration_edits())
def test_determinism(data: bytes) -> None:
    dump = dump_of(data)
    assert interpret_verify(REGIONS, dump, LAYOUT) == interpret_verify(REGIONS, dump, LAYOUT)
    assert interpret_patches(REGIONS, dump, LAYOUT) == interpret_patches(REGIONS, dump, LAYOUT)


# SPEC-002 R82: a wrong but self-consistent descriptor agrees with itself; only the oracle can catch it.
@given(calibration_edits(), st.integers(1, 2**32 - 1))
def test_dual_check_cannot_catch_a_wrong_descriptor(data: bytes, poly: int) -> None:
    def wrong(d: Descriptor) -> Descriptor:
        if isinstance(d, ChecksumDescriptor) and isinstance(d.algorithm, Crc32):
            return replace(d, algorithm=replace(d.algorithm, poly=poly))
        return d

    regions = regions_of([wrong(d) for d in DESCRIPTORS])
    released = write(data, interpret_patches(regions, dump_of(data), LAYOUT))
    assert {r.status for r in interpret_verify(regions, dump_of(released), LAYOUT).values()} == {"ok"}
