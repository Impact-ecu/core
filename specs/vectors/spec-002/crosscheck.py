"""Second, independent implementation that recomputes every expected value in vectors.json.

Stdlib only and independent of the core and of generate.py:
- CRC: the bitwise, MSB-first canonical loop of SPEC-002 R62 (generate.py uses zlib and a reflected table engine);
- sums and XOR: struct.unpack (generate.py uses int.from_bytes);
- a generic descriptor interpreter (static validation, table resolution, dependency order by Kahn min-heap on
  name with table bytes counted as inputs, patch derivation), where generate.py hand-codes each descriptor with
  literal offsets in a different, hand-chosen topological order;
- canonical JSON: for these objects (ASCII strings, integers, booleans, null, no floats), RFC 8785 output equals
  json.dumps with sorted keys and no whitespace.
Run: python -I crosscheck.py vectors.json   (exit status 1 on any disagreement)
"""
from __future__ import annotations

import hashlib
import heapq
import json
import struct
import sys

MASK = 0xFFFFFFFF
ERRORS: list[str] = []


def canon(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def expect(label: str, got: object, want: object) -> None:
    if got != want:
        ERRORS.append(f"{label}: got {got!r}, want {want!r}")


def bitrev(value: int, width: int) -> int:
    s = format(value, f"0{width}b")
    return int(s[::-1], 2)


def crc32_canonical(message: bytes, a: dict) -> int:
    reg = a["init"]
    for byte in message:
        if a["reflect_in"]:
            byte = bitrev(byte, 8)
        reg ^= byte << 24
        for _ in range(8):
            if reg & 0x80000000:
                reg = ((reg << 1) ^ a["poly"]) & MASK
            else:
                reg = (reg << 1) & MASK
    if a["reflect_out"]:
        reg = bitrev(reg, 32)
    return reg ^ a["xor_out"]


def width_of(a: dict) -> int:
    return {"crc32": 32, "sum16": 16, "sum32": 32}.get(a["name"], 8 * a.get("word_size", 0))


def unpack_words(chunk: bytes, size: int, endian: str) -> tuple[int, ...]:
    code = {1: "B", 2: "H", 4: "I"}[size]
    order = "<" if endian == "little" else ">"
    return struct.unpack(f"{order}{len(chunk) // size}{code}", chunk)


def accumulate(a: dict, chunks: list[bytes]) -> int:
    """Raw accumulator (before xor_out) for sum/xor; final value for crc."""
    if a["name"] == "crc32":
        return crc32_canonical(b"".join(chunks), a)
    acc = a["init"]
    modulus = 1 << width_of(a)
    for chunk in chunks:
        for w in unpack_words(chunk, a["word_size"], a["endianness"]):
            acc = (acc + w) % modulus if a["name"] != "xor" else acc ^ w
    return acc


def final_value(a: dict, chunks: list[bytes]) -> int:
    v = accumulate(a, chunks)
    return v if a["name"] == "crc32" else v ^ a["xor_out"]


# ---------------------------------------------------------------------------------------------------------
# Descriptor model

CKS_KEYS = {"descriptor_version", "name", "memory_id", "algorithm", "ranges", "ranges_from_table", "chain",
            "skip_self", "store", "target", "strategy", "compensate"}
MIRROR_KEYS = {"descriptor_version", "name", "memory_id", "mirror_block"}
ALG_KEYS = {"crc32": {"name", "poly", "init", "xor_out", "reflect_in", "reflect_out"},
            "sum16": {"name", "word_size", "endianness", "init", "xor_out"},
            "sum32": {"name", "word_size", "endianness", "init", "xor_out"},
            "xor": {"name", "word_size", "endianness", "init", "xor_out"}}


def is_mirror(d: dict) -> bool:
    return "mirror_block" in d


def outputs(d: dict) -> list[tuple[int, int]]:
    if is_mirror(d):
        mb = d["mirror_block"]
        n = mb["source"]["end"] - mb["source"]["start"]
        return [(mb["dest_offset"], mb["dest_offset"] + n)]
    if d["strategy"] == "compensate":
        if d["algorithm"]["name"] == "crc32":
            raise Failure("compensate_not_supported")
        size = d["algorithm"]["word_size"]
        return [(d["compensate"]["offset"], d["compensate"]["offset"] + size)]
    st = d["store"]
    return [(st["offset"], st["offset"] + st["size"])]


def store_span(d: dict) -> tuple[int, int] | None:
    st = d.get("store")
    return None if st is None else (st["offset"], st["offset"] + st["size"])


def overlaps(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def inside(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return b[0] <= a[0] and a[1] <= b[1]


class Failure(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def raw_ranges(d: dict, mem: bytes, base: int | None) -> list[tuple[int, int]]:
    if d["ranges"] is not None:
        return [(r["start"], r["end"]) for r in d["ranges"]]
    t = d["ranges_from_table"]
    out = []
    for i in range(t["count"]):
        entry = t["offset"] + i * t["entry_size"]

        def read(f: dict) -> int:
            pos = entry + f["at"]
            return int.from_bytes(mem[pos : pos + f["size"]], "little" if f["endianness"] == "little" else "big")

        s, e = read(t["start"]), read(t["end"])
        if t["addressing"] == "absolute":
            if base is None:
                raise Failure("unknown_base_address")
            s -= base
            if t["end_is"] != "length":
                e -= base
        if t["end_is"] == "inclusive":
            e += 1
        elif t["end_is"] == "length":
            e = s + e
        if s < 0 or e > len(mem) or s > e:
            raise Failure("table_out_of_bounds")
        if s == e:
            raise Failure("empty_range")
        out.append((s, e))
    return out


def pieces(d: dict, mem: bytes, base: int | None, by_name: dict) -> list[tuple[int, int]]:
    """Resolved message pieces, in message order, after skip_self excision. Raises Failure."""
    if d["chain"] is not None:
        ps = [store_span(by_name[n]) for n in d["chain"]]
    else:
        rs = raw_ranges(d, mem, base)
        for i, a in enumerate(rs):
            for b in rs[i + 1 :]:
                if overlaps(a, b):
                    raise Failure("overlapping_ranges")
        st = store_span(d)
        hit = [r for r in rs if st is not None and overlaps(r, st)]
        if d["skip_self"]:
            if not hit:
                raise Failure("skip_self_without_self")
            if not inside(st, hit[0]):
                raise Failure("partial_self")
            ps = []
            for r in rs:
                if r is hit[0]:
                    ps += [p for p in ((r[0], st[0]), (st[1], r[1])) if p[0] < p[1]]
                else:
                    ps.append(r)
        else:
            if hit and d["strategy"] == "recalculate":
                raise Failure("self_reference")
            ps = rs
    ws = d["algorithm"].get("word_size", 1)
    for p in ps:
        if (p[1] - p[0]) % ws:
            raise Failure("misaligned_piece")
    if d["strategy"] == "compensate":
        c = outputs(d)[0]
        host = [p for p in ps if inside(c, p)]
        if not host or (c[0] - host[0][0]) % ws:
            raise Failure("compensate_outside_message")
    return ps


def inputs(d: dict, mem: bytes, base: int | None, by_name: dict) -> list[tuple[int, int]]:
    if is_mirror(d):
        s = d["mirror_block"]["source"]
        return [(s["start"], s["end"])]
    ins = pieces(d, mem, base, by_name)
    t = d["ranges_from_table"]
    if t is not None:
        ins = ins + [(t["offset"], t["offset"] + t["count"] * t["entry_size"])]
    if d["strategy"] == "compensate" and d["store"] is not None:
        ins = ins + [store_span(d)]
    return ins


def static_reasons(ds: list[dict], lay: dict) -> list[str]:
    found: list[str] = []
    mem_l = lay["memories"][0]
    size = mem_l["size"]
    regions = mem_l["regions"]
    by_name: dict[str, dict] = {}
    for d in ds:
        if d["name"] in by_name:
            found.append("duplicate_name")
        by_name[d["name"]] = d
    for d in ds:
        keys = set(d)
        if keys not in (CKS_KEYS, MIRROR_KEYS) or d["descriptor_version"] != 1:
            found.append("schema")
            continue
        if d["memory_id"] != mem_l["memory_id"]:
            found.append("unknown_memory")
        if is_mirror(d):
            src, dst = d["mirror_block"]["source"], d["mirror_block"]["dest_offset"]
            n = src["end"] - src["start"]
            if not (0 <= src["start"] < src["end"] <= size and dst + n <= size):
                found.append("bad_range")
            elif overlaps((src["start"], src["end"]), (dst, dst + n)):
                found.append("self_reference")
            continue
        a = d["algorithm"]
        if set(a) != ALG_KEYS.get(a.get("name"), set()):
            found.append("schema")
            continue
        if a["name"] != "crc32":
            ws, w = a["word_size"], width_of(a)
            if ws not in (1, 2, 4):
                found.append("schema")
                continue
            if 8 * ws > w:
                found.append("bad_width")
        sources = [d["ranges"] is not None, d["ranges_from_table"] is not None, d["chain"] is not None]
        if sum(sources) != 1:
            found.append("message_source")
        if d["chain"] is not None and d["skip_self"]:
            found.append("schema")
        if d["strategy"] == "recalculate":
            if d["store"] is None or d["target"] is not None or d["compensate"] is not None:
                found.append("strategy_fields")
                continue
        else:
            if d["compensate"] is None or (d["store"] is None) == (d["target"] is None):
                found.append("strategy_fields")
                continue
            if a["name"] == "crc32" or 8 * a["word_size"] != width_of(a):
                found.append("compensate_not_supported")
                continue
        if d["store"] is not None and d["store"]["size"] != width_of(a) // 8:
            found.append("bad_width")
        if d["chain"] is not None:
            for n in d["chain"]:
                t = by_name.get(n)
                if t is None or t is d or is_mirror(t) or t["store"] is None or t["memory_id"] != d["memory_id"]:
                    found.append("unknown_chain_target")
                    break
            else:
                pass
        if d["ranges"] is not None:
            for r in d["ranges"]:
                if not 0 <= r["start"] < r["end"] <= size:
                    found.append("bad_range")
        if d["ranges_from_table"] is not None:
            t = d["ranges_from_table"]
            span = (t["offset"], t["offset"] + t["count"] * t["entry_size"])
            if span[1] > size:
                found.append("bad_range")
            if not any(r["kind"] == "protected" and inside(span, (r["start"], r["end"])) for r in regions):
                found.append("table_not_protected")
        if d["ranges"] is not None or (d["chain"] is not None and "unknown_chain_target" not in found):
            try:
                pieces(d, b"\x00" * size, None, by_name)
            except Failure as f:
                found.append(f.reason)
    if found:
        return found
    cks_regions = [(r["start"], r["end"]) for r in regions if r["kind"] == "checksum"]
    fields = [(d["name"], o) for d in ds for o in outputs(d)]
    for _, f in fields:
        if not any(inside(f, c) for c in cks_regions):
            found.append("field_out_of_checksum_region")
    for i, (_, a) in enumerate(fields):
        for _, b in fields[i + 1 :]:
            if overlaps(a, b):
                found.append("field_overlap")
    covered = set()
    for _, f in fields:
        covered.update(range(*f))
    need = set()
    for c in cks_regions:
        need.update(range(*c))
    if covered != need and "field_out_of_checksum_region" not in found:
        found.append("unaccounted_checksum_bytes")
    static = [d for d in ds if is_mirror(d) or d["ranges_from_table"] is None]
    try:
        order(static, {d["name"]: inputs(d, b"\x00" * size, None, by_name) for d in static})
    except Failure as f:
        found.append(f.reason)
    return found


def order(ds: list[dict], ins: dict[str, list[tuple[int, int]]]) -> list[dict]:
    by_name = {d["name"]: d for d in ds}
    preds: dict[str, set[str]] = {d["name"]: set() for d in ds}
    for d in ds:
        for e in ds:
            if d is not e and any(overlaps(i, o) for i in ins[d["name"]] for o in outputs(e)):
                preds[d["name"]].add(e["name"])
    succ: dict[str, set[str]] = {n: set() for n in preds}
    for n, ps in preds.items():
        for p in ps:
            succ[p].add(n)
    remaining = {n: len(ps) for n, ps in preds.items()}
    heap = [n for n, k in remaining.items() if k == 0]
    heapq.heapify(heap)
    out = []
    while heap:
        n = heapq.heappop(heap)
        out.append(by_name[n])
        for s in succ[n]:
            remaining[s] -= 1
            if remaining[s] == 0:
                heapq.heappush(heap, s)
    if len(out) != len(ds):
        raise Failure("dependency_cycle")
    return out


def region_result(d: dict, mem: bytes, base: int | None, by_name: dict) -> dict:
    res = {"name": d["name"], "memory_id": d["memory_id"], "kind": "recalculable", "reason": None, "bypass": None}
    if is_mirror(d):
        (s, e), (ds_, de) = inputs(d, mem, base, by_name)[0], outputs(d)[0]
        res.update(stored=sha(mem[ds_:de]), computed=sha(mem[s:e]))
        res["status"] = "ok" if mem[ds_:de] == mem[s:e] else "fail"
        return res
    a = d["algorithm"]
    nbytes = width_of(a) // 8
    st = d["store"]
    if st is not None:
        stored = mem[st["offset"] : st["offset"] + st["size"]]
        endian = st["endianness"]
    else:
        stored = d["target"].to_bytes(nbytes, "big")
        endian = "big"
    try:
        ps = pieces(d, mem, base, by_name)
    except Failure as f:
        res.update(stored=stored.hex(), computed=None, reason=f.reason, status="fail")
        return res
    computed = final_value(a, [mem[p[0] : p[1]] for p in ps]).to_bytes(nbytes, endian)
    res.update(stored=stored.hex(), computed=computed.hex(), status="ok" if stored == computed else "fail")
    return res


def aggregate(statuses: list[str]) -> str:
    if not statuses:
        return "not_applicable"
    for s in ("fail", "bypassed", "signature_unverifiable"):
        if s in statuses:
            return s
    return "ok"


def verify(ds: list[dict], mem: bytes, base: int | None) -> dict:
    by_name = {d["name"]: d for d in ds}
    regions = sorted((region_result(d, mem, base, by_name) for d in ds), key=lambda r: (r["memory_id"], r["name"]))
    return {"status": aggregate([r["status"] for r in regions]), "reason": None, "regions": regions}


def checksum_patches(ds: list[dict], mem: bytes, base: int | None, memory_id: str) -> tuple[list[dict], bytes]:
    by_name = {d["name"]: d for d in ds}
    work = bytearray(mem)
    for d in order(ds, {d["name"]: inputs(d, mem, base, by_name) for d in ds}):
        if is_mirror(d):
            (s, e), (o, _) = inputs(d, work, base, by_name)[0], outputs(d)[0]
            work[o : o + (e - s)] = work[s:e]
            continue
        a = d["algorithm"]
        ps = pieces(d, bytes(work), base, by_name)
        chunks = [bytes(work[p[0] : p[1]]) for p in ps]
        if d["strategy"] == "recalculate":
            st = d["store"]
            work[st["offset"] : st["offset"] + st["size"]] = final_value(a, chunks).to_bytes(st["size"], st["endianness"])
            continue
        ws, wbits = a["word_size"], width_of(a)
        if d["store"] is not None:
            st = d["store"]
            t = int.from_bytes(work[st["offset"] : st["offset"] + st["size"]], st["endianness"])
        else:
            t = d["target"]
        goal = t ^ a["xor_out"]
        c = d["compensate"]["offset"]
        old = unpack_words(bytes(work[c : c + ws]), ws, a["endianness"])[0]
        acc = accumulate(a, chunks)
        new = (goal - acc + old) % (1 << wbits) if a["name"] != "xor" else goal ^ acc ^ old
        work[c : c + ws] = struct.pack(("<" if a["endianness"] == "little" else ">") + {1: "B", 2: "H", 4: "I"}[ws], new)
    patches = []
    for d in ds:
        for o in outputs(d):
            if work[o[0] : o[1]] != mem[o[0] : o[1]]:
                p = {"memory_id": memory_id, "offset": o[0], "length": o[1] - o[0],
                     "before": mem[o[0] : o[1]].hex(), "after": work[o[0] : o[1]].hex()}
                patches.append({"value": p, "patch_hash": sha(canon(p))})
    patches.sort(key=lambda p: (p["value"]["memory_id"], p["value"]["offset"]))
    return patches, bytes(work)


def image_hash(dump_kind: str, memory_id: str, base: int | None, data: bytes) -> str:
    return sha(canon({"dump_kind": dump_kind, "memories": [
        {"memory_id": memory_id, "base_address": base, "size": len(data), "sha256": sha(data)}]}))


def main(path: str) -> int:
    v = json.load(open(path, encoding="utf-8"))
    for av in v["algorithms"]:
        msg = bytes.fromhex(av["message_hex"])
        got = final_value(av["algorithm"], [msg])
        expect(f"algorithm {av['id']}", got, av["expected"])
        if "catalogue_check" in av:
            expect(f"algorithm {av['id']} catalogue", got, av["catalogue_check"])

    fx = v["fixture"]
    m = fx["memory"]
    mid, base, kind = m["memory_id"], m["base_address"], fx["dump_kind"]
    ds = [e["value"] for e in fx["descriptors"]]
    for e in fx["descriptors"]:
        expect(f"descriptor_hash {e['value']['name']}", sha(canon(e["value"])), e["descriptor_hash"])
    expect("layout_hash", sha(canon(fx["layout"])), fx["layout_hash"])
    expect("fixture static validation", static_reasons(ds, fx["layout"]), [])

    orig = bytes.fromhex(fx["original"]["bytes_hex"])
    expect("original image_hash", image_hash(kind, mid, base, orig), fx["original"]["image_hash"])
    expect("original verify", verify(ds, orig, base), fx["original"]["verify"])
    q0, _ = checksum_patches(ds, orig, base, mid)
    expect("original checksum_patches (fixed point)", q0, fx["original"]["checksum_patches"])

    for c in v["cases"]:
        work = bytearray(orig)
        for ep in c["edits"]:
            p = ep["value"]
            expect(f"{c['id']} edit patch_hash", sha(canon(p)), ep["patch_hash"])
            expect(f"{c['id']} edit before", work[p["offset"] : p["offset"] + p["length"]].hex(), p["before"])
            work[p["offset"] : p["offset"] + p["length"]] = bytes.fromhex(p["after"])
        u = bytes(work)
        expect(f"{c['id']} unverified bytes", u.hex(), c["unverified"]["bytes_hex"])
        expect(f"{c['id']} unverified image_hash", image_hash(kind, mid, base, u), c["unverified"]["image_hash"])
        expect(f"{c['id']} verify_before_fix", verify(ds, u, base), c["verify_before_fix"])
        q, released = checksum_patches(ds, u, base, mid)
        expect(f"{c['id']} checksum_patches", q, c["checksum_patches"])
        cks = [(r["start"], r["end"]) for r in fx["layout"]["memories"][0]["regions"] if r["kind"] == "checksum"]
        for p in q:
            span = (p["value"]["offset"], p["value"]["offset"] + p["value"]["length"])
            expect(f"{c['id']} patch in checksum region", any(inside(span, r) for r in cks), True)
        expect(f"{c['id']} released image_hash", image_hash(kind, mid, base, released), c["released"]["image_hash"])
        expect(f"{c['id']} verify_after_fix", verify(ds, released, base), c["verify_after_fix"])
        expect(f"{c['id']} fixed point", checksum_patches(ds, released, base, mid)[0], [])

    for rf in v["resolution_failures"]:
        data = bytes.fromhex(rf["bytes_hex"])
        expect(f"{rf['id']} image_hash", image_hash(kind, mid, base, data), rf["image_hash"])
        expect(f"{rf['id']} verify", verify(ds, data, base), rf["verify"])

    for inv in v["invalid_descriptor_sets"]:
        expect(f"invalid {inv['id']}", static_reasons(inv["descriptors"], inv["layout"]), [inv["reason"]])

    for ag in v["aggregation"]:
        expect(f"aggregation {ag['id']}", aggregate(ag["regions"]), ag["expected"])

    for e in ERRORS:
        print("MISMATCH", e)
    n = len(v["algorithms"]) + len(v["cases"]) + len(v["invalid_descriptor_sets"]) + len(v["aggregation"])
    print(f"crosscheck: {len(ERRORS)} mismatches over {n} vector groups + fixture")
    return 1 if ERRORS else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
