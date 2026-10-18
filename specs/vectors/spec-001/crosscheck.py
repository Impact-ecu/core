"""Second, independent implementation that recomputes every expected hash in vectors.json.

Stdlib only and independent of the core and of generate.py:
- canonical JSON: for these objects (ASCII strings, non-negative integers, no floats), RFC 8785 output equals
  json.dumps with sorted keys and no whitespace;
- naive apply in Kahn min-heap order (SPEC-001 R25), naive diff (R31, R32), naive migration (R50).
Error cases are not checked here: they carry no hash.
Run: python -I crosscheck.py vectors.json   (exit status 1 on any disagreement)
"""
from __future__ import annotations

import hashlib
import heapq
import json
import sys

Memories = dict[str, tuple[int, bytearray]]


def canon(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha_obj(obj: object) -> str:
    return sha_text(canon(obj))


class Checker:
    def __init__(self, v: dict) -> None:
        self.v = v
        self.patches: dict[str, dict] = {n: p["value"] for n, p in v["patches"].items()}
        self.hash_of = {n: sha_obj(p) for n, p in self.patches.items()}
        self.layouts = {n: lay["value"] for n, lay in v["layouts"].items()}
        o = v["original"]
        self.dump_kind = o["dump_kind"]
        self.original: Memories = {
            mid: (m["base_address"], bytearray.fromhex(m["bytes_hex"])) for mid, m in o["memories"].items()
        }
        self.failures: list[str] = []
        self.checked = 0

    def expect(self, label: str, got: object, want: object) -> None:
        self.checked += 1
        if got != want:
            self.failures.append(f"{label}: got {got!r}, want {want!r}")

    def image_hash(self, mem: Memories) -> str:
        return sha_obj(
            {
                "dump_kind": self.dump_kind,
                "memories": [
                    {"memory_id": mid, "base_address": base, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                    for mid, (base, data) in sorted(mem.items())
                ],
            }
        )

    def copy(self, mem: Memories) -> Memories:
        return {mid: (base, bytearray(data)) for mid, (base, data) in mem.items()}

    def order(self, names: list[str], overlaps: list[list[str]], patches: dict[str, dict]) -> list[str]:
        preds = {n: 0 for n in names}
        succs: dict[str, list[str]] = {n: [] for n in names}
        for a, b in overlaps:
            succs[a].append(b)
            preds[b] += 1

        def key(n: str) -> tuple[str, int, str]:
            p = patches[n]
            return (p["memory_id"], p["offset"], sha_obj(p))

        heap = [(key(n), n) for n in names if preds[n] == 0]
        heapq.heapify(heap)
        out: list[str] = []
        while heap:
            _, n = heapq.heappop(heap)
            out.append(n)
            for s in succs[n]:
                preds[s] -= 1
                if preds[s] == 0:
                    heapq.heappush(heap, (key(s), s))
        return out

    def apply(self, mem: Memories, ordered: list[str], patches: dict[str, dict]) -> Memories:
        out = self.copy(mem)
        for n in ordered:
            p = patches[n]
            _, data = out[p["memory_id"]]
            start, end = p["offset"], p["offset"] + p["length"]
            if data[start:end].hex() != p["before"]:
                raise ValueError(f"precondition failed for {n}")
            data[start:end] = bytes.fromhex(p["after"])
        return out

    def version_hash(self, base: str, layout_name: str, ordered: list[str], overlaps: list[list[str]], patches: dict[str, dict]) -> str:
        return sha_obj(
            {
                "base_image_hash": base,
                "layout_hash": sha_obj(self.layouts[layout_name]),
                "patches": [sha_obj(patches[n]) for n in ordered],
                "overlaps": sorted([sha_obj(patches[a]), sha_obj(patches[b])] for a, b in overlaps),
            }
        )

    def regions(self, layout_name: str, memory_id: str) -> list[dict]:
        for m in self.layouts[layout_name]["memories"]:
            if m["memory_id"] == memory_id:
                return m["regions"]
        raise KeyError(memory_id)

    def diff(self, o: Memories, x: Memories, layout_name: str) -> tuple[list[str], list[dict]]:
        patch_hashes: list[str] = []
        foreign: list[dict] = []
        for mid in sorted(o):
            a, b = o[mid][1], x[mid][1]
            for r in self.regions(layout_name, mid):
                i = r["start"]
                while i < r["end"]:
                    if a[i] == b[i]:
                        i += 1
                        continue
                    j = i
                    while j < r["end"] and a[j] != b[j]:
                        j += 1
                    if r["kind"] == "calibration":
                        patch_hashes.append(
                            sha_obj({"memory_id": mid, "offset": i, "length": j - i, "before": a[i:j].hex(), "after": b[i:j].hex()})
                        )
                    else:
                        foreign.append(
                            {"memory_id": mid, "offset": i, "length": j - i, "region_kind": r["kind"], "region_name": r["name"]}
                        )
                    i = j
        return patch_hashes, foreign

    def contained(self, p: dict, layout_name: str, kind: str) -> bool:
        start, end = p["offset"], p["offset"] + p["length"]
        return any(r["kind"] == kind and r["start"] <= start and end <= r["end"] for r in self.regions(layout_name, p["memory_id"]))

    def run(self) -> None:
        for name, p in self.v["patches"].items():
            self.expect(f"patch {name} jcs", canon(p["value"]), p["jcs"])
            self.expect(f"patch {name} hash", sha_text(p["jcs"]), p["patch_hash"])
        for name, lay in self.v["layouts"].items():
            if "layout_hash" in lay:
                self.expect(f"layout {name} jcs", canon(lay["value"]), lay["jcs"])
                self.expect(f"layout {name} hash", sha_text(lay["jcs"]), lay["layout_hash"])
        base = self.image_hash(self.original)
        self.expect("original image_hash", base, self.v["original"]["image_hash"])

        results: dict[str, Memories] = {}
        for case in self.v["cases"]:
            want = case["expect"]
            if "error" in want:
                continue
            cid = case["id"]
            names = case.get("patches", [])
            overlaps = case.get("overlaps", [])
            ordered = self.order(names, overlaps, self.patches)
            op = case.get("operation")

            if "checksum_patches" in case:
                img = self.apply(results[case["base_case"]], case["checksum_patches"], self.patches)
                for q in case["checksum_patches"]:
                    self.expect(f"{cid} {q} in checksum region", self.contained(self.patches[q], "base", "checksum"), True)
                self.expect(f"{cid} image_hash", self.image_hash(img), want["image_hash"])
                continue

            if "new_layout" in case:
                kept: list[str] = []
                conflicts: list[dict] = []
                img = self.copy(self.original)
                for n in ordered:
                    p = self.patches[n]
                    if not self.contained(p, case["new_layout"], "calibration"):
                        conflicts.append({"patch_hash": self.hash_of[n], "reason": "out_of_region"})
                        continue
                    try:
                        img = self.apply(img, [n], self.patches)
                    except ValueError:
                        conflicts.append({"patch_hash": self.hash_of[n], "reason": "before_mismatch"})
                        continue
                    kept.append(n)
                self.expect(f"{cid} version_hash", self.version_hash(base, case["new_layout"], kept, [], self.patches), want["version_hash"])
                self.expect(f"{cid} conflicts", conflicts, want["conflicts"])
                continue

            if op == "diff(o, x)":
                x = self.copy(self.original)
                for mid in ("pflash", "dflash"):
                    hexed = case.get(f"x_{mid}_hex")
                    if hexed is not None:
                        x[mid] = (x[mid][0], bytearray.fromhex(hexed))
                got_p, got_f = self.diff(self.original, x, "base")
                self.expect(f"{cid} patch_hashes", got_p, want["patch_hashes"])
                self.expect(f"{cid} foreign", got_f, want["foreign"])
                continue

            img = self.apply(self.original, ordered, self.patches)
            results[cid] = img

            if op == "diff(o, apply(o, v))":
                got_p, got_f = self.diff(self.original, img, "base")
                self.expect(f"{cid} patch_hashes", got_p, want["patch_hashes"])
                self.expect(f"{cid} foreign", got_f, want["foreign"])
                continue

            if op == "apply(apply(o, v), invert(o, v))":
                inv = {f"{n}'": {**self.patches[n], "before": self.patches[n]["after"], "after": self.patches[n]["before"]} for n in names}
                inv_overlaps = [[f"{b}'", f"{a}'"] for a, b in overlaps]
                self.expect(f"{cid} invert_base_image_hash", self.image_hash(img), want["invert_base_image_hash"])
                self.expect(
                    f"{cid} invert_overlaps",
                    sorted([sha_obj(inv[a]), sha_obj(inv[b])] for a, b in inv_overlaps),
                    want["invert_overlaps"],
                )
                back = self.apply(img, self.order(list(inv), inv_overlaps, inv), inv)
                self.expect(f"{cid} round-trip image_hash", self.image_hash(back), want["image_hash"])
                continue

            if "canonical_order" in want:
                self.expect(f"{cid} canonical_order", ordered, want["canonical_order"])
            self.expect(f"{cid} image_hash", self.image_hash(img), want["image_hash"])
            self.expect(f"{cid} version_hash", self.version_hash(base, "base", ordered, overlaps, self.patches), want["version_hash"])


def main(path: str) -> int:
    with open(path, encoding="utf-8") as f:
        checker = Checker(json.load(f))
    checker.run()
    for failure in checker.failures:
        print(f"DISAGREE: {failure}")
    print(f"checked {checker.checked} expected values, {len(checker.failures)} disagreements")
    return 1 if checker.failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
