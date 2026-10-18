"""Generate SPEC-002 test vectors (checksum descriptor interpreter and verify aggregation).

Independent of the core. All data is synthetic: no byte comes from an ECU dump, and no algorithm parameter is a
claim about any ECU family (ADR-001). CRC parameters are generic catalogue models.
- CRC with the 0x04C11DB7 polynomial: Python zlib.crc32, adapted to arbitrary init/xor_out/reflection by bit
  reversal identities. Other polynomials: a table-driven, LSB-first (reflected-register) implementation that is
  first checked against zlib. crosscheck.py uses the bitwise MSB-first loop written in SPEC-002 §4.3 instead.
- Sums and XOR: int.from_bytes loops. crosscheck.py uses struct.unpack.
- Fixture images: built by explicit per-descriptor code with literal offsets, in a hand-written order; never by
  a generic interpreter. crosscheck.py has the generic interpreter.
- JCS: the third-party rfc8785 package (requirements.txt). SHA-256: hashlib.
Run: python -I generate.py > vectors.json   then   python -I crosscheck.py vectors.json
"""
from __future__ import annotations

import copy
import hashlib
import importlib.metadata
import json
import sys
import zlib

import rfc8785

M32 = 0xFFFFFFFF


def h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def jh(obj: object) -> str:
    return h(rfc8785.dumps(obj))


def refl(v: int, bits: int) -> int:
    out = 0
    for _ in range(bits):
        out = (out << 1) | (v & 1)
        v >>= 1
    return out


def rev_bytes(data: bytes) -> bytes:
    return bytes(refl(b, 8) for b in data)


def crc_ieee_poly(data: bytes, init: int, xor_out: int, reflect_in: bool, reflect_out: bool) -> int:
    """Rocksoft-model CRC-32 for poly 0x04C11DB7 using zlib's reflected engine."""
    feed = data if reflect_in else rev_bytes(data)
    r_final = zlib.crc32(feed, refl(init, 32) ^ M32) ^ M32
    reg = refl(r_final, 32)
    out = refl(reg, 32) if reflect_out else reg
    return out ^ xor_out


def crc_table(data: bytes, poly: int, init: int, xor_out: int, reflect_in: bool, reflect_out: bool) -> int:
    rpoly = refl(poly, 32)
    table = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ rpoly if c & 1 else c >> 1
        table.append(c)
    feed = data if reflect_in else rev_bytes(data)
    r = refl(init, 32)
    for b in feed:
        r = (r >> 8) ^ table[(r ^ b) & 0xFF]
    reg = refl(r, 32)
    out = refl(reg, 32) if reflect_out else reg
    return out ^ xor_out


def crc(data: bytes, a: dict) -> int:
    if a["poly"] == 0x04C11DB7:
        return crc_ieee_poly(data, a["init"], a["xor_out"], a["reflect_in"], a["reflect_out"])
    return crc_table(data, a["poly"], a["init"], a["xor_out"], a["reflect_in"], a["reflect_out"])


def words(data: bytes, size: int, endian: str) -> list[int]:
    assert len(data) % size == 0
    return [int.from_bytes(data[i : i + size], endian) for i in range(0, len(data), size)]


def sum_acc(pieces: list[bytes], width: int, size: int, endian: str, init: int) -> int:
    acc = init
    for p in pieces:
        for w in words(p, size, endian):
            acc = (acc + w) % (1 << width)
    return acc


def xor_acc(pieces: list[bytes], size: int, endian: str, init: int) -> int:
    acc = init
    for p in pieces:
        for w in words(p, size, endian):
            acc ^= w
    return acc


# Self-check of the table engine against zlib before it is trusted for other polynomials.
_probe = bytes(range(256)) * 3
for _ri, _ro, _init, _xo in [(True, True, M32, M32), (False, False, M32, M32), (True, False, 0x1234ABCD, 0), (False, True, 0, 0x55AA55AA)]:
    assert crc_table(_probe, 0x04C11DB7, _init, _xo, _ri, _ro) == crc_ieee_poly(_probe, _init, _xo, _ri, _ro)


def alg_crc(poly: int, init: int, xor_out: int, ri: bool, ro: bool) -> dict:
    return {"name": "crc32", "poly": poly, "init": init, "xor_out": xor_out, "reflect_in": ri, "reflect_out": ro}


def alg_word(name: str, word_size: int, endianness: str, init: int, xor_out: int) -> dict:
    return {"name": name, "word_size": word_size, "endianness": endianness, "init": init, "xor_out": xor_out}


CHECK = b"123456789"
ALGORITHM_VECTORS: list[dict] = []


def add_alg(vid: str, algorithm: dict, message: bytes, expected: int, catalogue_check: int | None) -> None:
    entry = {"id": vid, "rules": ["R62"], "algorithm": algorithm, "message_hex": message.hex(), "expected": expected}
    if catalogue_check is not None:
        entry["catalogue_check"] = catalogue_check
    ALGORITHM_VECTORS.append(entry)


# CRC catalogue models (check value of "123456789" as listed in the reveng CRC catalogue; see SPEC-002 §10).
for vid, a, check in [
    ("crc32_iso_hdlc", alg_crc(0x04C11DB7, M32, M32, True, True), 0xCBF43926),
    ("crc32_bzip2", alg_crc(0x04C11DB7, M32, M32, False, False), 0xFC891918),
    ("crc32_mpeg2", alg_crc(0x04C11DB7, M32, 0, False, False), 0x0376E6E7),
    ("crc32_cksum", alg_crc(0x04C11DB7, 0, M32, False, False), 0x765E7680),
    ("crc32_iscsi", alg_crc(0x1EDC6F41, M32, M32, True, True), 0xE3069283),
]:
    got = crc(CHECK, a)
    assert got == check, (vid, hex(got))
    add_alg(vid, a, CHECK, got, check)
assert zlib.crc32(CHECK) == 0xCBF43926

synthetic = bytes((i * 151 + 7) & 0xFF for i in range(64))
for vid, a in [
    ("crc32_custom_init_reflected", alg_crc(0x04C11DB7, 0x12345678, 0, True, True)),
    ("crc32_custom_init_mixed", alg_crc(0x04C11DB7, 0x89ABCDEF, 0x0F0F0F0F, True, False)),
    ("crc32_iscsi_unreflected_custom", alg_crc(0x1EDC6F41, 0xDEADBEEF, 0x00000001, False, True)),
]:
    add_alg(vid, a, synthetic, crc(synthetic, a), None)

for vid, a in [
    ("sum16_w1", alg_word("sum16", 1, "big", 0, 0)),
    ("sum16_w2_be", alg_word("sum16", 2, "big", 0x00FF, 0xFFFF)),
    ("sum16_w2_le", alg_word("sum16", 2, "little", 0, 0)),
    ("sum32_w1", alg_word("sum32", 1, "little", 0, 0)),
    ("sum32_w2_le", alg_word("sum32", 2, "little", 0x10000000, 0)),
    ("sum32_w4_be", alg_word("sum32", 4, "big", 0, M32)),
    ("sum32_w4_le", alg_word("sum32", 4, "little", 0xCAFEBABE, 0x01020304)),
]:
    width = 16 if a["name"] == "sum16" else 32
    v = sum_acc([synthetic], width, a["word_size"], a["endianness"], a["init"]) ^ a["xor_out"]
    add_alg(vid, a, synthetic, v, None)

for vid, a in [
    ("xor_w1", alg_word("xor", 1, "big", 0, 0)),
    ("xor_w2_le", alg_word("xor", 2, "little", 0xFFFF, 0)),
    ("xor_w4_be", alg_word("xor", 4, "big", 0, 0xA5A5A5A5)),
]:
    v = xor_acc([synthetic], a["word_size"], a["endianness"], a["init"]) ^ a["xor_out"]
    add_alg(vid, a, synthetic, v, None)

# ---------------------------------------------------------------------------------------------------------
# Fixture: one synthetic memory, a layout, and six descriptors that exercise every descriptor feature.
MEM = "pflash"
BASE = 0x80000000
SIZE = 512
DUMP_KIND = "bench_full"


def base_pattern() -> bytearray:
    return bytearray((i * 37 + 11) & 0xFF for i in range(SIZE))


def region(kind: str, start: int, end: int, name: str) -> dict:
    return {"kind": kind, "start": start, "end": end, "name": name}


BASE_REGIONS = [
    region("protected", 0, 32, "boot"),
    region("calibration", 32, 256, "maps"),
    region("checksum", 256, 288, "checksums"),
    region("protected", 288, 400, "code"),
    region("protected", 400, 416, "block_table"),
    region("protected", 416, 480, "emissions_egr"),
    region("protected", 480, 512, "vin"),
]


def layout(regions: list[dict]) -> dict:
    return {"memories": [{"memory_id": MEM, "base_address": BASE, "size": SIZE, "regions": regions}]}


def cks(name: str, algorithm: dict, *, ranges=None, table=None, chain=None, skip_self=False, store=None,
        target=None, strategy="recalculate", compensate=None) -> dict:
    return {
        "descriptor_version": 1, "name": name, "memory_id": MEM, "algorithm": algorithm,
        "ranges": ranges, "ranges_from_table": table, "chain": chain, "skip_self": skip_self,
        "store": store, "target": target, "strategy": strategy, "compensate": compensate,
    }


def field(offset: int, size: int, endianness: str) -> dict:
    return {"offset": offset, "size": size, "endianness": endianness}


TABLE = {
    "offset": 400, "count": 2, "entry_size": 8,
    "start": {"at": 0, "size": 4, "endianness": "big"},
    "end": {"at": 4, "size": 4, "endianness": "big"},
    "end_is": "exclusive", "addressing": "absolute",
}

D1 = cks("e_crc", alg_crc(0x04C11DB7, M32, M32, True, True), ranges=[{"start": 32, "end": 256}],
         store=field(256, 4, "big"))
D2 = cks("c_sum16", alg_word("sum16", 2, "big", 0, 0xFFFF), ranges=[{"start": 0, "end": 262}], skip_self=True,
         store=field(260, 2, "big"))
D3 = cks("f_table", alg_word("sum32", 4, "little", 0x12345678, 0), table=TABLE, store=field(262, 4, "little"))
D4 = cks("b_chain", alg_word("xor", 2, "big", 0, 0), chain=["e_crc", "f_table"], store=field(266, 2, "big"))
D5 = cks("a_comp", alg_word("sum32", 4, "big", 0, 0), ranges=[{"start": 32, "end": 272}], target=0,
         strategy="compensate", compensate={"offset": 268})
D6 = {"descriptor_version": 1, "name": "d_mirror", "memory_id": MEM,
      "mirror_block": {"source": {"start": 32, "end": 48}, "dest_offset": 272}}
# Names are chosen so that neither name order nor list order is a topological order of the R75 dependencies
# (a_comp reads every other store; b_chain reads e_crc and f_table; c_sum16 reads e_crc): an interpreter that
# ignores dependency order fails the edit cases. The R75 min-heap order is d_mirror, e_crc, c_sum16, f_table,
# b_chain, a_comp.
DESCRIPTORS = [D5, D4, D2, D6, D1, D3]


def write_table(m: bytearray, entries: list[tuple[int, int]]) -> None:
    for i, (s, e) in enumerate(entries):
        m[400 + 8 * i : 404 + 8 * i] = s.to_bytes(4, "big")
        m[404 + 8 * i : 408 + 8 * i] = e.to_bytes(4, "big")


def fix_by_hand(m: bytearray) -> None:
    """Recompute every field with literal offsets, in the hand-chosen order e_crc, c_sum16, f_table, b_chain, a_comp,
    d_mirror (a valid topological order that differs from the R75 min-heap order)."""
    m[256:260] = crc(bytes(m[32:256]), D1["algorithm"]).to_bytes(4, "big")
    m[260:262] = (sum_acc([bytes(m[0:260])], 16, 2, "big", 0) ^ 0xFFFF).to_bytes(2, "big")
    m[262:266] = sum_acc([bytes(m[32:128]), bytes(m[160:256])], 32, 4, "little", 0x12345678).to_bytes(4, "little")
    m[266:268] = xor_acc([bytes(m[256:260]), bytes(m[262:266])], 2, "big", 0).to_bytes(2, "big")
    acc = sum_acc([bytes(m[32:272])], 32, 4, "big", 0)
    w = int.from_bytes(m[268:272], "big")
    m[268:272] = ((0 - (acc - w)) % (1 << 32)).to_bytes(4, "big")
    m[272:288] = m[32:48]


def verify_by_hand(m: bytearray, table_reason: str | None = None) -> dict:
    def res(name: str, stored: bytes | None, computed: bytes | None, reason: str | None = None) -> dict:
        ok = reason is None and stored == computed
        return {"name": name, "memory_id": MEM, "kind": "recalculable", "status": "ok" if ok else "fail",
                "stored": None if stored is None else stored.hex(), "computed": None if computed is None else computed.hex(),
                "reason": reason, "bypass": None}

    regions = [
        res("e_crc", bytes(m[256:260]), crc(bytes(m[32:256]), D1["algorithm"]).to_bytes(4, "big")),
        res("c_sum16", bytes(m[260:262]), (sum_acc([bytes(m[0:260])], 16, 2, "big", 0) ^ 0xFFFF).to_bytes(2, "big")),
        res("f_table", bytes(m[262:266]), None, table_reason) if table_reason else res(
            "f_table", bytes(m[262:266]),
            sum_acc([bytes(m[32:128]), bytes(m[160:256])], 32, 4, "little", 0x12345678).to_bytes(4, "little")),
        res("b_chain", bytes(m[266:268]), xor_acc([bytes(m[256:260]), bytes(m[262:266])], 2, "big", 0).to_bytes(2, "big")),
        res("a_comp", (0).to_bytes(4, "big"), sum_acc([bytes(m[32:272])], 32, 4, "big", 0).to_bytes(4, "big")),
    ]
    mirror_ok = m[272:288] == m[32:48]
    regions.append({"name": "d_mirror", "memory_id": MEM, "kind": "recalculable",
                    "status": "ok" if mirror_ok else "fail", "stored": h(bytes(m[272:288])),
                    "computed": h(bytes(m[32:48])), "reason": None, "bypass": None})
    regions.sort(key=lambda r: (r["memory_id"], r["name"]))
    statuses = [r["status"] for r in regions]
    status = "fail" if "fail" in statuses else "ok"
    return {"status": status, "reason": None, "regions": regions}


def image_hash(m: bytes, base: int | None = BASE) -> str:
    return jh({"dump_kind": DUMP_KIND, "memories": [{"memory_id": MEM, "base_address": base, "size": len(m), "sha256": h(m)}]})


def patch_obj(offset: int, before: bytes, after: bytes) -> dict:
    return {"memory_id": MEM, "offset": offset, "length": len(before), "before": before.hex(), "after": after.hex()}


OUTPUT_FIELDS = [(256, 4), (260, 2), (262, 4), (266, 2), (268, 4), (272, 16)]


def patches_between(old: bytearray, new: bytearray) -> list[dict]:
    out = []
    for off, ln in OUTPUT_FIELDS:
        if old[off : off + ln] != new[off : off + ln]:
            p = patch_obj(off, bytes(old[off : off + ln]), bytes(new[off : off + ln]))
            out.append({"value": p, "patch_hash": jh(p)})
    return out


original = base_pattern()
write_table(original, [(BASE + 32, BASE + 128), (BASE + 160, BASE + 256)])
fix_by_hand(original)
assert verify_by_hand(original)["status"] == "ok"


def edit_case(cid: str, edits: list[tuple[int, bytes]], expect_unchanged: list[int]) -> dict:
    u = bytearray(original)
    edit_patches = []
    for off, after in edits:
        p = patch_obj(off, bytes(u[off : off + len(after)]), after)
        edit_patches.append({"value": p, "patch_hash": jh(p)})
        u[off : off + len(after)] = after
    released = bytearray(u)
    fix_by_hand(released)
    q = patches_between(u, released)
    changed = {p["value"]["offset"] for p in q}
    for off in expect_unchanged:
        assert off not in changed, (cid, off)
    vr = verify_by_hand(released)
    assert vr["status"] == "ok"
    return {
        "id": cid,
        "rules": ["R43", "R51", "R52", "R53", "R54", "R63", "R70", "R71", "R72", "R75", "R76", "R77"],
        "edits": edit_patches,
        "unverified": {"bytes_hex": u.hex(), "image_hash": image_hash(bytes(u))},
        "verify_before_fix": verify_by_hand(u),
        "checksum_patches": q,
        "released": {"image_hash": image_hash(bytes(released))},
        "verify_after_fix": vr,
    }


# edit_a touches only [128,160): outside f_table's table ranges and d_mirror's source, so f_table and d_mirror stay correct.
edit_a = edit_case("edit_a", [(140, bytes([0x00, 0x11, 0x22, 0x33]))], expect_unchanged=[262, 272])
# edit_b touches the mirror source and f_table's first table range.
edit_b = edit_case("edit_b", [(36, bytes([0xAB, 0xCD]))], expect_unchanged=[])

bad_table = bytearray(original)
write_table(bad_table, [(BASE + 32, BASE + 128), (BASE + 160, BASE + 0x300)])
resolution_failure = {
    "id": "table_out_of_bounds",
    "rules": ["R65", "R66", "R43"],
    "bytes_hex": bad_table.hex(),
    "image_hash": image_hash(bytes(bad_table)),
    "verify": verify_by_hand(bad_table, table_reason="table_out_of_bounds"),
}
assert resolution_failure["verify"]["status"] == "fail"

# ---------------------------------------------------------------------------------------------------------
# Invalid descriptor sets: each has exactly one violation (SPEC-002 R79).


def invalid(cid: str, reason: str, rule: str, mutate, regions: list[dict] | None = None) -> dict:
    ds = copy.deepcopy(DESCRIPTORS)
    mutate({d["name"]: d for d in ds})
    return {"id": cid, "rules": [rule, "R79"], "reason": reason, "descriptors": ds,
            "layout": layout(regions if regions is not None else BASE_REGIONS)}


def set_(path: list, value):
    def f(by_name: dict) -> None:
        obj = by_name[path[0]]
        for k in path[1:-1]:
            obj = obj[k]
        obj[path[-1]] = value
    return f


def split_checksum(parts: list[tuple[str, int, int]]) -> list[dict]:
    out = [r for r in BASE_REGIONS if r["end"] <= 256] + [region(k, s, e, "") for k, s, e in parts]
    return out + [r for r in BASE_REGIONS if r["start"] >= 288]


INVALID = [
    invalid("schema_extra_key", "schema", "R60", set_(["e_crc", "note"], "x")),
    invalid("bad_width", "bad_width", "R61", set_(["e_crc", "store", "size"], 2),
            split_checksum([("checksum", 256, 258), ("protected", 258, 260), ("checksum", 260, 288)])),
    invalid("self_reference", "self_reference", "R68", set_(["e_crc", "ranges"], [{"start": 32, "end": 260}])),
    invalid("partial_self", "partial_self", "R68",
            lambda d: (set_(["e_crc", "skip_self"], True)(d), set_(["e_crc", "ranges"], [{"start": 32, "end": 258}])(d))),
    invalid("misaligned_piece", "misaligned_piece", "R67", set_(["c_sum16", "ranges"], [{"start": 1, "end": 262}])),
    invalid("table_in_calibration", "table_not_protected", "R65", set_(["f_table", "ranges_from_table", "offset"], 200)),
    invalid("table_in_checksum_region", "table_not_protected", "R65", set_(["f_table", "ranges_from_table", "offset"], 272)),
    invalid("unknown_chain_target", "unknown_chain_target", "R69", set_(["b_chain", "chain"], ["e_crc", "z_missing"])),
    invalid("compensate_not_supported", "compensate_not_supported", "R71",
            set_(["a_comp", "algorithm"], alg_crc(0x04C11DB7, M32, M32, True, True))),
    invalid("field_out_of_checksum_region", "field_out_of_checksum_region", "R73", lambda d: None,
            split_checksum([("checksum", 256, 258), ("checksum", 258, 288)])),
    invalid("field_overlap", "field_overlap", "R73", set_(["c_sum16", "store", "offset"], 258),
            split_checksum([("checksum", 256, 260), ("protected", 260, 262), ("checksum", 262, 288)])),
    invalid("unaccounted_checksum_bytes", "unaccounted_checksum_bytes", "R74", lambda d: None,
            [r for r in BASE_REGIONS if r["end"] <= 256] + [region("checksum", 256, 290, "checksums"),
             region("protected", 290, 400, "code")] + [r for r in BASE_REGIONS if r["start"] >= 400]),
    invalid("dependency_cycle", "dependency_cycle", "R75",
            set_(["e_crc", "ranges"], [{"start": 32, "end": 256}, {"start": 266, "end": 268}])),
]

AGGREGATION = [
    {"id": "all_ok", "regions": ["ok", "ok"], "expected": "ok"},
    {"id": "fail_dominates", "regions": ["ok", "bypassed", "fail", "signature_unverifiable"], "expected": "fail"},
    {"id": "bypassed_over_signed", "regions": ["signature_unverifiable", "bypassed", "ok"], "expected": "bypassed"},
    {"id": "signed_only", "regions": ["signature_unverifiable", "ok"], "expected": "signature_unverifiable"},
    {"id": "no_regions", "regions": [], "expected": "not_applicable"},
]
for a in AGGREGATION:
    a["rules"] = ["R43"]

vectors = {
    "spec": "SPEC-002",
    "generator": {
        "jcs": f"rfc8785 {importlib.metadata.version('rfc8785')}",
        "sha256": "python hashlib",
        "crc": "python zlib.crc32 (poly 0x04C11DB7) and a table-driven reflected engine checked against it",
        "python": sys.version.split()[0],
    },
    "algorithms": ALGORITHM_VECTORS,
    "fixture": {
        "rules": ["R60", "R63", "R64", "R65", "R69", "R70", "R71", "R72", "R73", "R74", "R77", "R78"],
        "dump_kind": DUMP_KIND,
        "memory": {"memory_id": MEM, "base_address": BASE, "size": SIZE},
        "layout": layout(BASE_REGIONS),
        "layout_hash": jh(layout(BASE_REGIONS)),
        "descriptors": [{"value": d, "descriptor_hash": jh(d)} for d in DESCRIPTORS],
        "original": {"bytes_hex": original.hex(), "image_hash": image_hash(bytes(original)),
                     "verify": verify_by_hand(original), "checksum_patches": []},
    },
    "cases": [edit_a, edit_b],
    "resolution_failures": [resolution_failure],
    "invalid_descriptor_sets": INVALID,
    "aggregation": AGGREGATION,
}

json.dump(vectors, sys.stdout, indent=1, sort_keys=False)
sys.stdout.write("\n")
