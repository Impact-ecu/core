"""Recompute every hash in vectors.json with a second, stdlib-only canonicalization.

For the objects in these vectors (ASCII strings, non-negative integers, no floats), RFC 8785 output equals
json.dumps with sorted keys and no whitespace. Exit status 1 on any disagreement.
Run: python -I crosscheck.py vectors.json
"""
from __future__ import annotations

import hashlib
import json
import sys


def canon(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def main(path: str) -> int:
    v = json.load(open(path, encoding="utf-8"))
    failures: list[str] = []

    for name, p in v["patches"].items():
        if canon(p["value"]) != p["jcs"] or sha(p["jcs"]) != p["patch_hash"]:
            failures.append(f"patch {name}")

    for name, lay in v["layouts"].items():
        if "layout_hash" in lay and (canon(lay["value"]) != lay["jcs"] or sha(lay["jcs"]) != lay["layout_hash"]):
            failures.append(f"layout {name}")

    o = v["original"]
    image = {
        "dump_kind": o["dump_kind"],
        "memories": [
            {
                "memory_id": mid,
                "base_address": m["base_address"],
                "size": len(bytes.fromhex(m["bytes_hex"])),
                "sha256": hashlib.sha256(bytes.fromhex(m["bytes_hex"])).hexdigest(),
            }
            for mid, m in sorted(o["memories"].items())
        ],
    }
    if canon(image) != o["image_jcs"] or sha(o["image_jcs"]) != o["image_hash"]:
        failures.append("original image")

    for failure in failures:
        print(f"DISAGREE: {failure}")
    checked = len(v["patches"]) + sum("layout_hash" in x for x in v["layouts"].values()) + 1
    print(f"checked {checked} hashed objects, {len(failures)} disagreements")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
