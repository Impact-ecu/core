"""SPEC-001 §9: every vector in specs/vectors/spec-001/vectors.json, against the core.

Expected values come from generate.py (third-party rfc8785, hand-built images) and are cross-checked
by crosscheck.py; nothing here is computed by the core and then compared with itself.
"""

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from core.kernel import (
    ContainmentError,
    Dump,
    KernelError,
    LayoutError,
    LayoutMemory,
    Memory,
    MemoryLayout,
    OverlapError,
    Patch,
    PreconditionConflict,
    Region,
    ShapeError,
    Version,
    apply,
    apply_checksum_patches,
    canonical_json,
    canonical_order,
    diff,
    image_hash,
    invert,
    layout_hash,
    migrate,
    version_hash,
)
from core.kernel._canonical import Json

VECTORS_PATH = Path(__file__).resolve().parents[2] / "specs" / "vectors" / "spec-001" / "vectors.json"
VECTORS: dict[str, Any] = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))

ERRORS: dict[str, type[KernelError]] = {
    "ShapeError": ShapeError,
    "LayoutError": LayoutError,
    "OverlapError": OverlapError,
    "ContainmentError": ContainmentError,
    "PreconditionConflict": PreconditionConflict,
}


def make_patch(value: dict[str, Any]) -> Patch:
    return Patch(
        value["memory_id"],
        value["offset"],
        value["length"],
        bytes.fromhex(value["before"]),
        bytes.fromhex(value["after"]),
    )


def make_layout(value: dict[str, Any]) -> MemoryLayout:
    return MemoryLayout(
        tuple(
            LayoutMemory(
                m["memory_id"],
                m["base_address"],
                m["size"],
                tuple(Region(r["kind"], r["start"], r["end"], r["name"]) for r in m["regions"]),
            )
            for m in value["memories"]
        )
    )


def make_dump(overrides: dict[str, str] | None = None) -> Dump:
    original = VECTORS["original"]
    overrides = overrides or {}
    return Dump(
        original["dump_kind"],
        tuple(
            Memory(memory_id, m["base_address"], bytes.fromhex(overrides.get(memory_id, m["bytes_hex"])))
            for memory_id, m in original["memories"].items()
        ),
    )


PATCHES = {name: make_patch(p["value"]) for name, p in VECTORS["patches"].items()}
ORIGINAL = make_dump()
BASE = make_layout(VECTORS["layouts"]["base"]["value"])


def version_of(case: dict[str, Any], layout: MemoryLayout = BASE) -> Version:
    patches = [PATCHES[name] for name in case.get("patches", [])]
    if "patch" in case:
        patches.append(make_patch(case["patch"]))
    return Version(
        case.get("version_base_image_hash", image_hash(ORIGINAL)),
        case.get("version_layout_hash", layout_hash(layout)),
        tuple(patches),
        tuple((PATCHES[a].patch_hash, PATCHES[b].patch_hash) for a, b in case.get("overlaps", [])),
    )


def case_by_id(case_id: str) -> dict[str, Any]:
    matches: list[dict[str, Any]] = [case for case in VECTORS["cases"] if case["id"] == case_id]
    assert len(matches) == 1
    return matches[0]


def run_error_case(case: dict[str, Any]) -> KernelError:
    want = case["expect"]

    def run() -> object:
        if "checksum_patch" in case:
            base = apply(ORIGINAL, version_of(case_by_id(case["base_case"])), BASE)
            return apply_checksum_patches(base, [make_patch(case["checksum_patch"])], BASE)
        if case.get("operation") == "diff(o, x)":
            return diff(ORIGINAL, make_dump({"pflash": case["x_pflash_hex"]}), BASE)
        return apply(ORIGINAL, version_of(case), BASE)

    with pytest.raises(ERRORS[want["error"]]) as caught:
        run()
    assert caught.value.reason == want["reason"]
    return caught.value


def check_case(case: dict[str, Any]) -> int:
    """Check every expected value of one case; return how many were checked."""
    want = case["expect"]
    if "error" in want:
        run_error_case(case)
        return 2
    op = case.get("operation")
    if "checksum_patches" in case:
        base = apply(ORIGINAL, version_of(case_by_id(case["base_case"])), BASE)
        q = [PATCHES[name] for name in case["checksum_patches"]]
        # Success means every patch of q lies in a checksum region (R40), as crosscheck.py asserts.
        assert apply_checksum_patches(base, q, BASE).image_hash == want["image_hash"]
        return 2
    if "new_layout" in case:
        new_layout = make_layout(VECTORS["layouts"][case["new_layout"]]["value"])
        migrated = migrate(ORIGINAL, version_of(case), new_layout)
        assert version_hash(migrated.version) == want["version_hash"]
        got = [{"patch_hash": c.patch_hash, "reason": c.reason} for c in migrated.conflicts]
        assert got == want["conflicts"]
        return 2
    if op in ("diff(o, x)", "diff(o, apply(o, v))"):
        if op == "diff(o, x)":
            overrides = {m: case[f"x_{m}_hex"] for m in ("pflash", "dflash") if f"x_{m}_hex" in case}
            result = diff(ORIGINAL, make_dump(overrides), BASE)
        else:
            result = diff(ORIGINAL, apply(ORIGINAL, version_of(case), BASE), BASE)
        assert [p.patch_hash for p in result.patches] == want["patch_hashes"]
        got_foreign = [
            {
                "memory_id": f.memory_id,
                "offset": f.offset,
                "length": f.length,
                "region_kind": f.region_kind,
                "region_name": f.region_name,
            }
            for f in result.foreign
        ]
        assert got_foreign == want["foreign"]
        return 2
    v = version_of(case)
    if op == "apply(apply(o, v), invert(o, v))":
        inverse = invert(ORIGINAL, v)
        assert inverse.base_image_hash == want["invert_base_image_hash"]
        assert sorted([a, b] for a, b in inverse.overlaps) == want["invert_overlaps"]
        back = apply(apply(ORIGINAL, v, BASE), inverse, BASE)
        assert back.image_hash == want["image_hash"]
        return 3
    checked = 2
    if "canonical_order" in want:
        names = {p.patch_hash: name for name, p in PATCHES.items()}
        assert [names[p.patch_hash] for p in canonical_order(v)] == want["canonical_order"]
        checked += 1
    assert apply(ORIGINAL, v, BASE).image_hash == want["image_hash"]
    assert version_hash(v) == want["version_hash"]
    return checked


# SPEC-001 R60, R61
@pytest.mark.parametrize("name", sorted(VECTORS["patches"]))
def test_patch_vector(name: str) -> None:
    vector = VECTORS["patches"][name]
    patch = PATCHES[name]
    payload: Json = {
        "memory_id": patch.memory_id,
        "offset": patch.offset,
        "length": patch.length,
        "before": patch.before.hex(),
        "after": patch.after.hex(),
    }
    assert canonical_json(payload).decode("utf-8") == vector["jcs"]
    assert patch.patch_hash == vector["patch_hash"]


# SPEC-001 R60, R62
def test_original_image_vector() -> None:
    original = VECTORS["original"]
    payload: Json = {
        "dump_kind": ORIGINAL.dump_kind,
        "memories": [
            {
                "memory_id": m.memory_id,
                "base_address": m.base_address,
                "size": len(m.data),
                "sha256": hashlib.sha256(m.data).hexdigest(),
            }
            for m in sorted(ORIGINAL.memories, key=lambda m: m.memory_id)
        ],
    }
    assert canonical_json(payload).decode("utf-8") == original["image_jcs"]
    assert image_hash(ORIGINAL) == original["image_hash"]


# SPEC-001 R60, R63
@pytest.mark.parametrize("name", ["base", "migrated"])
def test_layout_hash_vector(name: str) -> None:
    vector = VECTORS["layouts"][name]
    layout = make_layout(vector["value"])
    assert layout_hash(layout) == vector["layout_hash"]
    assert canonical_json(vector["value"]).decode("utf-8") == vector["jcs"]


# SPEC-001 R4
def test_layout_gap_is_bad_cover() -> None:
    with pytest.raises(LayoutError) as caught:
        make_layout(VECTORS["layouts"]["gap"]["value"])
    assert caught.value.reason == VECTORS["layouts"]["gap"]["expect"]["reason"] == "bad_cover"


# SPEC-001 R5
def test_layout_missing_memory_is_shape_mismatch() -> None:
    layout = make_layout(VECTORS["layouts"]["missing_memory"]["value"])
    v = Version(image_hash(ORIGINAL), layout_hash(layout), (PATCHES["P1"],))
    with pytest.raises(LayoutError) as caught:
        apply(ORIGINAL, v, layout)
    assert caught.value.reason == VECTORS["layouts"]["missing_memory"]["expect"]["reason"] == "shape_mismatch"


# SPEC-001 R10, R12, R14, R20-R26, R30-R32, R40, R41, R50, R64
@pytest.mark.parametrize("case_id", [case["id"] for case in VECTORS["cases"]])
def test_case_vector(case_id: str) -> None:
    assert check_case(case_by_id(case_id)) >= 1


# SPEC-001 R21: the conflict carries the index in canonical order and the patch hash.
def test_precondition_vector_carries_index_and_hash() -> None:
    case = case_by_id("R-precondition-mismatch")
    error = run_error_case(case)
    assert isinstance(error, PreconditionConflict)
    assert error.index == 0
    assert error.patch_hash == make_patch(case["patch"]).patch_hash


def test_every_vector_value_is_checked() -> None:
    # crosscheck.py checks 47 expected values; this suite checks the same 47 (hashes and JCS of every
    # patch and named layout, the original image, every non-error case) plus the original's JCS and
    # the error type and reason of every error case and error layout.
    hash_values = 2 * len(VECTORS["patches"]) + 2 * 2 + 1
    case_values = sum(check_case(case) for case in VECTORS["cases"] if "error" not in case["expect"])
    assert hash_values + case_values == 47
    error_values = sum(check_case(case) for case in VECTORS["cases"] if "error" in case["expect"])
    assert error_values == 2 * 16
