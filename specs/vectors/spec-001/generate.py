"""Generate SPEC-001 test vectors.

Independent of the core: JCS comes from the third-party `rfc8785` package (pinned in requirements.txt),
SHA-256 from hashlib. Expected images are built by explicit per-case byte edits, never by a generic apply.
Run: python -I generate.py > vectors.json   then   python -I crosscheck.py vectors.json
"""
from __future__ import annotations

import hashlib
import importlib.metadata
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


def image_hash(memories: dict[str, tuple[int, bytes]]) -> str:
    return h(rfc8785.dumps(image_obj(DUMP_KIND, memories)))


def with_pflash(data: bytearray) -> dict[str, tuple[int, bytes]]:
    return {"pflash": (PFLASH_BASE, bytes(data)), "dflash": (DFLASH_BASE, dflash)}


def layout_obj(pflash_regions: list[dict[str, object]]) -> dict[str, object]:
    return {
        "memories": [
            {
                "memory_id": "dflash",
                "base_address": DFLASH_BASE,
                "size": 16,
                "regions": [{"kind": "protected", "start": 0, "end": 16, "name": "vin_immo"}],
            },
            {"memory_id": "pflash", "base_address": PFLASH_BASE, "size": 64, "regions": pflash_regions},
        ]
    }


def region(kind: str, start: int, end: int, name: str) -> dict[str, object]:
    return {"kind": kind, "start": start, "end": end, "name": name}


PFLASH_BASE = 0x80000000
DFLASH_BASE = 0xAF000000
DUMP_KIND = "bench_full"
pflash = bytes(range(64))
dflash = b"\xff" * 16
original = {"pflash": (PFLASH_BASE, pflash), "dflash": (DFLASH_BASE, dflash)}

layout = layout_obj(
    [
        region("protected", 0, 16, "boot"),
        region("calibration", 16, 40, "maps_a"),
        region("calibration", 40, 48, "maps_b"),
        region("protected", 48, 60, ""),
        region("checksum", 60, 64, "block_crc"),
    ]
)
layout_hash = h(rfc8785.dumps(layout))
base_image_hash = image_hash(original)

# Migration target: maps_a shrinks to [16, 30); [30, 40) becomes protected.
layout_migrated = layout_obj(
    [
        region("protected", 0, 16, "boot"),
        region("calibration", 16, 30, "maps_a"),
        region("protected", 30, 40, "reserved"),
        region("calibration", 40, 48, "maps_b"),
        region("protected", 48, 60, ""),
        region("checksum", 60, 64, "block_crc"),
    ]
)
layout_migrated_hash = h(rfc8785.dumps(layout_migrated))

layout_gap = layout_obj(
    [
        region("protected", 0, 16, "boot"),
        region("calibration", 16, 40, "maps_a"),
        region("protected", 48, 60, ""),
        region("checksum", 60, 64, "block_crc"),
    ]
)
layout_missing_memory = {"memories": [layout["memories"][1]]}

P = {
    "P1": patch_obj("pflash", 16, bytes.fromhex("10111213"), bytes.fromhex("0a0b0c0d")),
    "P2": patch_obj("pflash", 32, bytes.fromhex("2021"), bytes.fromhex("ffff")),
    "P3": patch_obj("pflash", 18, bytes.fromhex("0c0d1415"), bytes.fromhex("aaaaaaaa")),
    "P4": patch_obj("pflash", 18, bytes.fromhex("12131415"), bytes.fromhex("bbbbbbbb")),
    "P5": patch_obj("pflash", 16, bytes.fromhex("1011bbbb"), bytes.fromhex("cccccccc")),
    "Q1": patch_obj("pflash", 60, bytes.fromhex("3c3d3e3f"), bytes.fromhex("deadbeef")),
    "CA": patch_obj("pflash", 16, bytes.fromhex("10111213"), bytes.fromhex("01010101")),
    "CB": patch_obj("pflash", 18, bytes.fromhex("12131415"), bytes.fromhex("02020202")),
    "CC": patch_obj("pflash", 17, bytes.fromhex("11121314"), bytes.fromhex("03030303")),
}
PH = {name: patch_hash(p) for name, p in P.items()}


def swapped(name: str) -> dict[str, object]:
    p = P[name]
    return {**p, "before": p["after"], "after": p["before"]}


def version_hash(base: str, lay: str, patch_names: list[str], overlap_names: list[list[str]]) -> str:
    return h(
        rfc8785.dumps(
            {
                "base_image_hash": base,
                "layout_hash": lay,
                "patches": [PH[n] for n in patch_names],
                "overlaps": sorted([PH[a], PH[b]] for a, b in overlap_names),
            }
        )
    )


v4 = bytearray(pflash)
v4[16:20] = bytes.fromhex("0a0b0c0d")
v4[32:34] = bytes.fromhex("ffff")
v4_hash = image_hash(with_pflash(v4))

v5 = bytearray(pflash)
v5[16:22] = bytes.fromhex("0a0baaaaaaaa")
v5_hash = image_hash(with_pflash(v5))

v5c = bytearray(pflash)
v5c[16:22] = bytes.fromhex("ccccccccbbbb")
v5c_hash = image_hash(with_pflash(v5c))

v7 = bytearray(pflash)
v7[38:42] = bytes.fromhex("01020304")

v8_pflash = bytearray(pflash)
v8_pflash[5] = 0x00
v8_pflash[20] = 0x77
v8_pflash[62] = 0x99
v8_dflash = bytearray(dflash)
v8_dflash[0] = 0x00

v9 = bytearray(v4)
v9[60:64] = bytes.fromhex("deadbeef")
v9_hash = image_hash(with_pflash(v9))

inverted_overlaps = sorted([patch_hash(swapped("P3")), patch_hash(swapped("P1"))] for _ in [0])

vectors = {
    "generator": {
        "jcs": f"rfc8785 {importlib.metadata.version('rfc8785')}",
        "sha256": "python hashlib",
        "python": sys.version.split()[0],
    },
    "original": {
        "dump_kind": DUMP_KIND,
        "memories": {
            "pflash": {"base_address": PFLASH_BASE, "bytes_hex": pflash.hex()},
            "dflash": {"base_address": DFLASH_BASE, "bytes_hex": dflash.hex()},
        },
        "rules": ["R60", "R62"],
        "image_jcs": jcs(image_obj(DUMP_KIND, original)),
        "image_hash": base_image_hash,
    },
    "layouts": {
        "base": {"rules": ["R60", "R63"], "value": layout, "jcs": jcs(layout), "layout_hash": layout_hash},
        "migrated": {
            "rules": ["R60", "R63"],
            "value": layout_migrated,
            "jcs": jcs(layout_migrated),
            "layout_hash": layout_migrated_hash,
        },
        "gap": {"rules": ["R4"], "value": layout_gap, "expect": {"error": "LayoutError", "reason": "bad_cover"}},
        "missing_memory": {
            "rules": ["R5"],
            "value": layout_missing_memory,
            "expect": {"error": "LayoutError", "reason": "shape_mismatch"},
        },
    },
    "patches": {
        name: {"rules": ["R60", "R61"], "value": p, "jcs": jcs(p), "patch_hash": PH[name]} for name, p in P.items()
    },
    "cases": [
        {
            "id": "V4-apply-disjoint",
            "rules": ["R20", "R21", "R24", "R26", "R64"],
            "patches": ["P1", "P2"],
            "overlaps": [],
            "expect": {"image_hash": v4_hash, "version_hash": version_hash(base_image_hash, layout_hash, ["P1", "P2"], [])},
        },
        {
            "id": "V4b-apply-disjoint-reordered",
            "rules": ["R25", "R64"],
            "patches": ["P2", "P1"],
            "overlaps": [],
            "expect": {"image_hash": v4_hash, "version_hash": version_hash(base_image_hash, layout_hash, ["P1", "P2"], [])},
        },
        {
            "id": "V5-apply-overlap-ordered",
            "rules": ["R22", "R25", "R64"],
            "patches": ["P3", "P1"],
            "overlaps": [["P1", "P3"]],
            "expect": {
                "image_hash": v5_hash,
                "version_hash": version_hash(base_image_hash, layout_hash, ["P1", "P3"], [["P1", "P3"]]),
            },
        },
        {
            "id": "V5c-overlap-order-contradicts-offset-order",
            "rules": ["R22", "R25", "R64"],
            "patches": ["P5", "P4"],
            "overlaps": [["P4", "P5"]],
            "expect": {
                "canonical_order": ["P4", "P5"],
                "image_hash": v5c_hash,
                "version_hash": version_hash(base_image_hash, layout_hash, ["P4", "P5"], [["P4", "P5"]]),
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
            "id": "V5d-spurious-order",
            "rules": ["R22"],
            "patches": ["P1", "P2"],
            "overlaps": [["P1", "P2"]],
            "expect": {"error": "OverlapError", "reason": "spurious_order"},
        },
        {
            "id": "V5e-cycle",
            "rules": ["R22"],
            "patches": ["CA", "CB", "CC"],
            "overlaps": [["CA", "CB"], ["CB", "CC"], ["CC", "CA"]],
            "expect": {"error": "OverlapError", "reason": "cycle"},
        },
        {
            "id": "V6-invert-roundtrip",
            "rules": ["R30"],
            "patches": ["P1", "P3"],
            "overlaps": [["P1", "P3"]],
            "operation": "apply(apply(o, v), invert(o, v))",
            "expect": {
                "invert_base_image_hash": v5_hash,
                "invert_overlaps": inverted_overlaps,
                "image_hash": base_image_hash,
            },
        },
        {
            "id": "V6b-diff-of-apply",
            "rules": ["R31"],
            "patches": ["P1", "P2"],
            "overlaps": [],
            "operation": "diff(o, apply(o, v))",
            "expect": {"patch_hashes": [PH["P1"], PH["P2"]], "foreign": []},
        },
        {
            "id": "V6c-diff-merges-overlap",
            "rules": ["R31"],
            "patches": ["P1", "P3"],
            "overlaps": [["P1", "P3"]],
            "operation": "diff(o, apply(o, v))",
            "expect": {
                "patch_hashes": [
                    patch_hash(patch_obj("pflash", 16, bytes.fromhex("101112131415"), bytes.fromhex("0a0baaaaaaaa")))
                ],
                "foreign": [],
            },
        },
        {
            "id": "V7-diff-splits-at-region-boundary",
            "rules": ["R31"],
            "operation": "diff(o, x)",
            "x_pflash_hex": bytes(v7).hex(),
            "expect": {
                "patch_hashes": [
                    patch_hash(patch_obj("pflash", 38, bytes.fromhex("2627"), bytes.fromhex("0102"))),
                    patch_hash(patch_obj("pflash", 40, bytes.fromhex("2829"), bytes.fromhex("0304"))),
                ],
                "foreign": [],
            },
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
            "id": "V8b-diff-shape-mismatch",
            "rules": ["R31"],
            "operation": "diff(o, x)",
            "x_pflash_hex": bytes(pflash[:32]).hex(),
            "expect": {"error": "ShapeError", "reason": "shape_mismatch"},
        },
        {
            "id": "V9-checksum-patch",
            "rules": ["R40", "R41"],
            "base_case": "V4-apply-disjoint",
            "checksum_patches": ["Q1"],
            "expect": {"image_hash": v9_hash},
        },
        {
            "id": "V9b-checksum-patch-outside-checksum-region",
            "rules": ["R40"],
            "base_case": "V4-apply-disjoint",
            "checksum_patch": patch_obj("pflash", 44, bytes.fromhex("2c2d"), bytes.fromhex("0000")),
            "expect": {"error": "ContainmentError", "reason": "checksum_out_of_region"},
        },
        {
            "id": "V10-migrate",
            "rules": ["R50", "R64"],
            "patches": ["P1", "P2"],
            "overlaps": [],
            "new_layout": "migrated",
            "expect": {
                "version_hash": version_hash(base_image_hash, layout_migrated_hash, ["P1"], []),
                "conflicts": [{"patch_hash": PH["P2"], "reason": "out_of_region"}],
            },
        },
        {
            "id": "V11-wrong-base",
            "rules": ["R20"],
            "patches": ["P1"],
            "version_base_image_hash": "00" * 32,
            "expect": {"error": "ShapeError", "reason": "wrong_base"},
        },
        {
            "id": "V11b-wrong-layout",
            "rules": ["R20"],
            "patches": ["P1"],
            "version_layout_hash": layout_migrated_hash,
            "expect": {"error": "ShapeError", "reason": "wrong_layout"},
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
            "id": "R-unknown-memory",
            "rules": ["R23"],
            "patch": patch_obj("eeprom", 0, bytes.fromhex("00"), bytes.fromhex("01")),
            "expect": {"error": "ContainmentError", "reason": "unknown_memory"},
        },
        {
            "id": "R-precondition-mismatch",
            "rules": ["R21"],
            "patch": patch_obj("pflash", 16, bytes.fromhex("00000000"), bytes.fromhex("0a0b0c0d")),
            "expect": {"error": "PreconditionConflict", "reason": "before_mismatch"},
        },
        {
            "id": "R-bad-length",
            "rules": ["R10"],
            "patch": {"memory_id": "pflash", "offset": 16, "length": 4, "before": "101112", "after": "0a0b0c"},
            "expect": {"error": "ShapeError", "reason": "bad_length"},
        },
        {
            "id": "R-noop-patch",
            "rules": ["R12"],
            "patch": patch_obj("pflash", 16, bytes.fromhex("10111213"), bytes.fromhex("10111213")),
            "expect": {"error": "ShapeError", "reason": "noop_patch"},
        },
    ],
}

json.dump(vectors, sys.stdout, indent=2)
sys.stdout.write("\n")
