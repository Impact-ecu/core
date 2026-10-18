"""Generate SPEC-001 test vectors.

Independent of the core: uses the third-party `rfc8785` package for JCS and hashlib for SHA-256.
Expected images are built by explicit per-case byte edits, never by a generic apply.
Run: python -I generate.py > vectors.json
"""
from __future__ import annotations

import hashlib
import json
import sys

import rfc8785


def h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def jcs(obj: object) -> str:
    return rfc8785.dumps(obj).decode("utf-8")


def patch_obj(memory_id: str, offset: int, before: bytes, after: bytes) -> dict[str, object]:
    return {"memory_id": memory_id, "offset": offset, "length": len(before), "before": before.hex(), "after": after.hex()}


def patch_hash(p: dict[str, object]) -> str:
    return h(rfc8785.dumps(p))


def image_obj(dump_kind: str, memories: dict[str, tuple[int, bytes]]) -> dict[str, object]:
    return {
        "dump_kind": dump_kind,
        "memories": [
            {"memory_id": mid, "base_address": base, "size": len(data), "sha256": h(data)}
            for mid, (base, data) in sorted(memories.items())
        ],
    }


def image_hash(dump_kind: str, memories: dict[str, tuple[int, bytes]]) -> str:
    return h(rfc8785.dumps(image_obj(dump_kind, memories)))


PFLASH_BASE = 0x80000000
DFLASH_BASE = 0xAF000000
pflash = bytes(range(64))
dflash = b"\xff" * 16
original = {"pflash": (PFLASH_BASE, pflash), "dflash": (DFLASH_BASE, dflash)}
DUMP_KIND = "bench_full"

layout = {
    "memories": [
        {
            "memory_id": "dflash",
            "base_address": DFLASH_BASE,
            "size": 16,
            "regions": [{"kind": "protected", "start": 0, "end": 16, "name": "vin_immo"}],
        },
        {
            "memory_id": "pflash",
            "base_address": PFLASH_BASE,
            "size": 64,
            "regions": [
                {"kind": "protected", "start": 0, "end": 16, "name": "boot"},
                {"kind": "calibration", "start": 16, "end": 40, "name": "maps_a"},
                {"kind": "calibration", "start": 40, "end": 48, "name": "maps_b"},
                {"kind": "protected", "start": 48, "end": 60, "name": ""},
                {"kind": "checksum", "start": 60, "end": 64, "name": "block_crc"},
            ],
        },
    ]
}
layout_hash = h(rfc8785.dumps(layout))
base_image_hash = image_hash(DUMP_KIND, original)

p1 = patch_obj("pflash", 16, bytes.fromhex("10111213"), bytes.fromhex("0a0b0c0d"))
p2 = patch_obj("pflash", 32, bytes.fromhex("2021"), bytes.fromhex("ffff"))
p3 = patch_obj("pflash", 18, bytes.fromhex("0c0d1415"), bytes.fromhex("aaaaaaaa"))


def version_hash(patches: list[dict[str, object]], overlaps: list[list[str]]) -> str:
    return h(
        rfc8785.dumps(
            {
                "base_image_hash": base_image_hash,
                "layout_hash": layout_hash,
                "patches": [patch_hash(p) for p in patches],
                "overlaps": overlaps,
            }
        )
    )


# V4: P1 + P2, disjoint. Expected image built by hand.
v4 = bytearray(pflash)
v4[16:20] = bytes.fromhex("0a0b0c0d")
v4[32:34] = bytes.fromhex("ffff")
v4_hash = image_hash(DUMP_KIND, {"pflash": (PFLASH_BASE, bytes(v4)), "dflash": (DFLASH_BASE, dflash)})

# V5: P1 then P3 (overlapping, ordered by overlaps [[P1, P3]]).
v5 = bytearray(pflash)
v5[16:22] = bytes.fromhex("0a0baaaaaaaa")
v5_hash = image_hash(DUMP_KIND, {"pflash": (PFLASH_BASE, bytes(v5)), "dflash": (DFLASH_BASE, dflash)})

# V7: diff across the maps_a/maps_b boundary: bytes 38..41 changed.
v7 = bytearray(pflash)
v7[38:42] = bytes.fromhex("01020304")
v7_patches = [
    patch_obj("pflash", 38, bytes.fromhex("2627"), bytes.fromhex("0102")),
    patch_obj("pflash", 40, bytes.fromhex("2829"), bytes.fromhex("0304")),
]

# V8: diff with changes outside calibration: byte 5 (protected boot), byte 62 (checksum), dflash byte 0 (protected).
v8_pflash = bytearray(pflash)
v8_pflash[5] = 0x00
v8_pflash[62] = 0x99
v8_pflash[20] = 0x77
v8_dflash = bytearray(dflash)
v8_dflash[0] = 0x00

# V9: checksum patch inside the checksum region, applied to the V4 image.
q1 = patch_obj("pflash", 60, bytes.fromhex("3c3d3e3f"), bytes.fromhex("deadbeef"))
v9 = bytearray(v4)
v9[60:64] = bytes.fromhex("deadbeef")
v9_hash = image_hash(DUMP_KIND, {"pflash": (PFLASH_BASE, bytes(v9)), "dflash": (DFLASH_BASE, dflash)})

vectors = {
    "generator": {
        "jcs": f"rfc8785 {rfc8785.__version__}" if hasattr(rfc8785, "__version__") else "rfc8785 0.1.4",
        "sha256": "python hashlib",
        "python": sys.version.split()[0],
    },
    "original": {
        "dump_kind": DUMP_KIND,
        "memories": {
            "pflash": {"base_address": PFLASH_BASE, "bytes_hex": pflash.hex()},
            "dflash": {"base_address": DFLASH_BASE, "bytes_hex": dflash.hex()},
        },
        "image_jcs": jcs(image_obj(DUMP_KIND, original)),
        "image_hash": base_image_hash,
    },
    "layout": {"value": layout, "jcs": jcs(layout), "layout_hash": layout_hash},
    "patches": {
        name: {"value": p, "jcs": jcs(p), "patch_hash": patch_hash(p)}
        for name, p in (("P1", p1), ("P2", p2), ("P3", p3), ("Q1", q1))
    },
    "cases": [
        {
            "id": "V4-apply-disjoint",
            "rules": ["R20", "R21", "R24", "R26"],
            "patches": ["P1", "P2"],
            "overlaps": [],
            "expect": {"image_hash": v4_hash, "version_hash": version_hash([p1, p2], [])},
        },
        {
            "id": "V4b-apply-disjoint-reordered",
            "rules": ["R25"],
            "patches": ["P2", "P1"],
            "overlaps": [],
            "expect": {"image_hash": v4_hash, "version_hash": version_hash([p1, p2], [])},
        },
        {
            "id": "V5-apply-overlap-ordered",
            "rules": ["R22", "R25"],
            "patches": ["P3", "P1"],
            "overlaps": [["P1", "P3"]],
            "expect": {
                "image_hash": v5_hash,
                "version_hash": version_hash([p1, p3], [[patch_hash(p1), patch_hash(p3)]]),
            },
        },
        {
            "id": "V5b-overlap-without-order",
            "rules": ["R22"],
            "patches": ["P1", "P3"],
            "overlaps": [],
            "expect": {"error": "OverlapError", "reason": "missing_order"},
        },
        {
            "id": "V6-invert-roundtrip",
            "rules": ["R30"],
            "patches": ["P1", "P2"],
            "overlaps": [],
            "operation": "apply(apply(o, P), invert(P))",
            "expect": {"image_hash": base_image_hash},
        },
        {
            "id": "V6b-diff-of-apply",
            "rules": ["R31"],
            "patches": ["P1", "P2"],
            "overlaps": [],
            "operation": "diff(o, apply(o, P))",
            "expect": {"patch_hashes": [patch_hash(p1), patch_hash(p2)], "foreign": []},
        },
        {
            "id": "V6c-diff-merges-overlap",
            "rules": ["R31"],
            "patches": ["P1", "P3"],
            "overlaps": [["P1", "P3"]],
            "operation": "diff(o, apply(o, P))",
            "expect": {
                "patch_hashes": [
                    patch_hash(patch_obj("pflash", 16, bytes.fromhex("101112131415"), bytes.fromhex("0a0baaaaaaaa"))),
                ],
                "foreign": [],
            },
        },
        {
            "id": "V7-diff-splits-at-region-boundary",
            "rules": ["R31"],
            "operation": "diff(o, x)",
            "x_pflash_hex": bytes(v7).hex(),
            "expect": {"patch_hashes": [patch_hash(p) for p in v7_patches], "foreign": []},
        },
        {
            "id": "V8-diff-reports-foreign-changes",
            "rules": ["R32"],
            "operation": "diff(o, x)",
            "x_pflash_hex": bytes(v8_pflash).hex(),
            "x_dflash_hex": bytes(v8_dflash).hex(),
            "expect": {
                "patch_hashes": [patch_hash(patch_obj("pflash", 20, bytes([0x14]), bytes([0x77])))],
                "foreign": [
                    {"memory_id": "dflash", "offset": 0, "length": 1, "region_kind": "protected", "region_name": "vin_immo"},
                    {"memory_id": "pflash", "offset": 5, "length": 1, "region_kind": "protected", "region_name": "boot"},
                    {"memory_id": "pflash", "offset": 62, "length": 1, "region_kind": "checksum", "region_name": "block_crc"},
                ],
            },
        },
        {
            "id": "V9-checksum-patch",
            "rules": ["R40", "R41"],
            "base": "V4-apply-disjoint",
            "checksum_patches": ["Q1"],
            "expect": {"image_hash": v9_hash},
        },
        {
            "id": "R-containment-crosses-protected",
            "rules": ["R23"],
            "patch": patch_obj("pflash", 14, bytes.fromhex("0e0f1011"), bytes.fromhex("00000000")),
            "expect": {"error": "ContainmentError", "reason": "out_of_region"},
        },
        {
            "id": "R-containment-crosses-calibration-boundary",
            "rules": ["R23"],
            "patch": patch_obj("pflash", 38, bytes.fromhex("26272829"), bytes.fromhex("00000000")),
            "expect": {"error": "ContainmentError", "reason": "out_of_region"},
        },
        {
            "id": "R-precondition-mismatch",
            "rules": ["R21"],
            "patch": patch_obj("pflash", 16, bytes.fromhex("00000000"), bytes.fromhex("0a0b0c0d")),
            "expect": {"error": "PreconditionConflict", "reason": "before_mismatch"},
        },
        {
            "id": "R-noop-patch",
            "rules": ["R12"],
            "patch": patch_obj("pflash", 16, bytes.fromhex("10111213"), bytes.fromhex("10111213")),
            "expect": {"error": "ShapeError", "reason": "noop_patch"},
        },
        {
            "id": "R-checksum-patch-outside-checksum-region",
            "rules": ["R40"],
            "base": "V4-apply-disjoint",
            "checksum_patch": patch_obj("pflash", 44, bytes.fromhex("2c2d"), bytes.fromhex("0000")),
            "expect": {"error": "ContainmentError", "reason": "checksum_out_of_region"},
        },
    ],
}

json.dump(vectors, sys.stdout, indent=2, sort_keys=False)
sys.stdout.write("\n")
