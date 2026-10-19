"""SPEC-002 §10: every value in specs/vectors/spec-002/vectors.json, against the core.

Expected values come from generate.py (zlib, a table engine and literal offsets) and are cross-checked
by crosscheck.py (the R62 bitwise loop, struct, an independent interpreter); nothing here is computed by
the core and then compared with itself.
"""

import hashlib
from importlib.metadata import version
from typing import Any

import pytest
import rfc8785

from core.kernel import (
    Dump,
    LayoutMemory,
    MemoryLayout,
    Patch,
    Version,
    apply,
    apply_checksum_patches,
    image_hash,
    layout_hash,
)
from core.kernel._internal import view
from core.plugins import (
    Crc32,
    DescriptorError,
    WordAlgorithm,
    aggregate,
    descriptor_from_json,
    descriptor_hash,
    descriptor_json,
    verify_report_json,
)
from core.plugins.descriptor import _engines, interpret_patches, interpret_verify, validate_variant
from tests.unit.plugin_fixtures import (
    DESCRIPTORS,
    FIXTURE,
    LAYOUT,
    MEMORY,
    ORIGINAL,
    REGIONS,
    VECTORS,
    dump_of,
    layout_from_json,
    regions_of,
    report_of,
)


def algorithm_of(value: dict[str, Any]) -> Crc32 | WordAlgorithm:
    if value["name"] == "crc32":
        return Crc32(value["poly"], value["init"], value["xor_out"], value["reflect_in"], value["reflect_out"])
    return WordAlgorithm(value["name"], value["word_size"], value["endianness"], value["init"], value["xor_out"])


def patch_of(value: dict[str, Any]) -> Patch:
    return Patch(
        value["memory_id"],
        value["offset"],
        value["length"],
        bytes.fromhex(value["before"]),
        bytes.fromhex(value["after"]),
    )


def verify_json(dump: Dump) -> dict[str, Any]:
    return dict(verify_report_json(report_of(interpret_verify(REGIONS, dump, LAYOUT))))


def test_header() -> None:
    assert VECTORS["spec"] == "SPEC-002"
    # §10: the JCS implementation used by generate.py is the one pinned in the dev group.
    assert VECTORS["generator"]["jcs"] == f"rfc8785 {version('rfc8785')}"
    assert set(VECTORS["generator"]) == {"jcs", "sha256", "crc", "python"}


# SPEC-002 R62, R81: both engines reproduce every algorithm vector and every catalogue check value.
@pytest.mark.parametrize("vector", VECTORS["algorithms"], ids=lambda v: v["id"])
def test_algorithms(vector: dict[str, Any]) -> None:
    algorithm = algorithm_of(vector["algorithm"])
    message = bytes.fromhex(vector["message_hex"])
    assert _engines.value(algorithm, [message], vector["id"]) == vector["expected"]
    if isinstance(algorithm, Crc32):
        assert _engines.crc32_a(message, algorithm) == _engines.crc32_b(message, algorithm) == vector["expected"]
    else:
        raw = vector["expected"] ^ algorithm.xor_out
        assert _engines.words_a(algorithm, [message]) == _engines.words_b(algorithm, [message]) == raw
    if "catalogue_check" in vector:
        assert vector["expected"] == vector["catalogue_check"]
        assert _engines.value(algorithm, [b"123456789"], vector["id"]) == vector["catalogue_check"]
    assert vector["rules"] == ["R62"]


# SPEC-002 R60, R78: the fixture descriptors parse, serialize back to the same object and hash as given.
def test_fixture_descriptors() -> None:
    for entry, descriptor in zip(FIXTURE["descriptors"], DESCRIPTORS, strict=True):
        assert descriptor_json(descriptor) == entry["value"]
        assert descriptor_hash(descriptor) == entry["descriptor_hash"]
        assert descriptor_hash(descriptor) == hashlib.sha256(rfc8785.dumps(entry["value"])).hexdigest()
    assert [r.descriptor_hash for r in REGIONS] == [e["descriptor_hash"] for e in FIXTURE["descriptors"]]


# SPEC-002 R63-R65, R69-R74, R79: the fixture is a valid variant over its layout.
def test_fixture_layout_and_static_validation() -> None:
    assert FIXTURE["dump_kind"] == "bench_full"
    assert (MEMORY["memory_id"], MEMORY["base_address"], MEMORY["size"]) == ("pflash", 0x8000_0000, 512)
    assert layout_hash(LAYOUT) == FIXTURE["layout_hash"]
    validate_variant(REGIONS, LAYOUT)
    assert set(FIXTURE["rules"]) == {"R60", "R63", "R64", "R65", "R69", "R70", "R71", "R72", "R73", "R74", "R77", "R78"}


# SPEC-002 R54, R77: the original verifies ok and needs no checksum patch.
def test_fixture_original() -> None:
    original = FIXTURE["original"]
    dump = dump_of(ORIGINAL)
    assert len(ORIGINAL) == 512
    assert image_hash(dump) == original["image_hash"]
    assert verify_json(dump) == original["verify"]
    assert interpret_patches(REGIONS, dump, LAYOUT) == ()
    assert original["checksum_patches"] == []


# SPEC-002 R43, R51-R54, R63, R70-R72, R75-R77: edit, verify, recalculate, release, verify again, fixed point.
@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["id"])
def test_cases(case: dict[str, Any]) -> None:
    dump = dump_of(ORIGINAL)
    edits = [patch_of(e["value"]) for e in case["edits"]]
    assert [p.patch_hash for p in edits] == [e["patch_hash"] for e in case["edits"]]
    u = apply(dump, Version(image_hash(dump), layout_hash(LAYOUT), tuple(edits)), LAYOUT)
    unverified = view(u)
    assert unverified.memories[0].data.hex() == case["unverified"]["bytes_hex"]
    assert u.image_hash == case["unverified"]["image_hash"]
    assert verify_json(unverified) == case["verify_before_fix"]
    q = interpret_patches(REGIONS, unverified, LAYOUT)
    assert [p.patch_hash for p in q] == [e["patch_hash"] for e in case["checksum_patches"]]
    assert list(q) == [patch_of(e["value"]) for e in case["checksum_patches"]]
    released = apply_checksum_patches(u, q, LAYOUT)
    assert released.image_hash == case["released"]["image_hash"]
    assert verify_json(view(released)) == case["verify_after_fix"]
    assert interpret_patches(REGIONS, view(released), LAYOUT) == ()
    assert "R76" in case["rules"]


# SPEC-002 R43, R65, R66: a table out of bounds fails only its region, with the reason.
@pytest.mark.parametrize("vector", VECTORS["resolution_failures"], ids=lambda v: v["id"])
def test_resolution_failures(vector: dict[str, Any]) -> None:
    dump = dump_of(bytes.fromhex(vector["bytes_hex"]))
    assert image_hash(dump) == vector["image_hash"]
    assert verify_json(dump) == vector["verify"]
    with pytest.raises(DescriptorError) as caught:
        interpret_patches(REGIONS, dump, LAYOUT)
    reasons = [r["reason"] for r in vector["verify"]["regions"] if r["reason"] is not None]
    assert [caught.value.reason] == reasons
    assert set(vector["rules"]) == {"R43", "R65", "R66"}


# SPEC-002 R60, R61, R65, R67-R69, R71, R73-R75, R79: one reason per invalid set.
@pytest.mark.parametrize("vector", VECTORS["invalid_descriptor_sets"], ids=lambda v: v["id"])
def test_invalid_descriptor_sets(vector: dict[str, Any]) -> None:
    layout: MemoryLayout = layout_from_json(vector["layout"])
    assert all(isinstance(m, LayoutMemory) for m in layout.memories)
    with pytest.raises(DescriptorError) as caught:
        validate_variant(regions_of([descriptor_from_json(d) for d in vector["descriptors"]]), layout)
    assert caught.value.reason == vector["reason"]
    assert "R79" in vector["rules"]


# SPEC-002 R43: status precedence and `no_checksum_regions`.
@pytest.mark.parametrize("vector", VECTORS["aggregation"], ids=lambda v: v["id"])
def test_aggregation(vector: dict[str, Any]) -> None:
    status, reason = aggregate(vector["regions"])
    assert status == vector["expected"]
    assert reason == ("no_checksum_regions" if status == "not_applicable" else None)
    assert vector["rules"] == ["R43"]
