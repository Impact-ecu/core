"""Second, independent implementation that recomputes every expected value in SPEC-008 vectors.json.

Stdlib only and independent of the core and of generate.py:
- canonical JSON: for these objects (ASCII keys, integers, strings, null, no floats), RFC 8785 output equals
  json.dumps with sorted keys, no whitespace and ensure_ascii=False (SPEC-005 R72);
- Ed25519: transcribed from the RFC 8032 section 6 reference code, checked against RFC 8032 section 7.1 TEST 1
  (see the notice above the Ed25519 section);
- the fingerprint (R11), registry checks (R10, R12, R13, R21) and the lookup (R22-R25), written from SPEC-008.
Run: python -I crosscheck.py vectors.json   (exit status 1 on any disagreement)
"""
from __future__ import annotations

import calendar
import copy
import hashlib
import json
import pathlib
import re
import sys
import time


def canon(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha_obj(obj: object) -> str:
    return sha_hex(canon(obj).encode("utf-8"))



# ---- Ed25519, RFC 8032 section 6 ----
# The functions below are transcribed from the Python reference code in RFC 8032, section 6
# (S. Josefsson, I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)", January 2017).
# Code Components extracted from IETF documents carry this notice:
#   Copyright (c) 2017 IETF Trust and the persons identified as authors of the code. All rights reserved.
#   Redistribution and use in source and binary forms, with or without modification, is permitted pursuant
#   to, and subject to the license terms contained in, the Simplified BSD License set forth in Section 4.c
#   of the IETF Trust's Legal Provisions Relating to IETF Documents (https://trustee.ietf.org/license-info).
P = 2**255 - 19
Q = 2**252 + 27742317777372353535851937790883648493


def inv(x: int) -> int:
    return pow(x, P - 2, P)


D = -121665 * inv(121666) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
Point = tuple[int, int, int, int]


def sha512_modq(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), "little") % Q


def point_add(a: Point, b: Point) -> Point:
    pa = (a[1] - a[0]) * (b[1] - b[0]) % P
    pb = (a[1] + a[0]) * (b[1] + b[0]) % P
    pc = 2 * a[3] * b[3] * D % P
    pd = 2 * a[2] * b[2] % P
    e, f, g, h = pb - pa, pd - pc, pd + pc, pb + pa
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def point_mul(s: int, pt: Point) -> Point:
    acc: Point = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            acc = point_add(acc, pt)
        pt = point_add(pt, pt)
        s >>= 1
    return acc


def point_equal(a: Point, b: Point) -> bool:
    return (a[0] * b[2] - b[0] * a[2]) % P == 0 and (a[1] * b[2] - b[1] * a[2]) % P == 0


def recover_x(y: int, sign: int) -> int | None:
    if y >= P:
        return None
    x2 = (y * y - 1) * inv(D * y * y + 1) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


G_Y = 4 * inv(5) % P
G_X = recover_x(G_Y, 0)
assert G_X is not None
G: Point = (G_X, G_Y, 1, G_X * G_Y % P)


def compress(pt: Point) -> bytes:
    zi = inv(pt[2])
    x, y = pt[0] * zi % P, pt[1] * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def decompress(s: bytes) -> Point | None:
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % P)


def expand(secret: bytes) -> tuple[int, bytes]:
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(secret: bytes) -> bytes:
    return compress(point_mul(expand(secret)[0], G))


def sign(secret: bytes, msg: bytes) -> bytes:
    a, prefix = expand(secret)
    pub = compress(point_mul(a, G))
    r = sha512_modq(prefix + msg)
    rs = compress(point_mul(r, G))
    s = (r + sha512_modq(rs + pub + msg) * a) % Q
    return rs + s.to_bytes(32, "little")


def verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    if len(pub) != 32 or len(sig) != 64:
        return False
    a = decompress(pub)
    r = decompress(sig[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= Q:
        return False
    h = sha512_modq(sig[:32] + pub + msg)
    return point_equal(point_mul(s, G), point_add(r, point_mul(h, a)))



def signing_input(h: str) -> bytes:
    return canon({"domain": "impact.stock-registry-signature.v1", "hash": h}).encode("utf-8")


def unhex(s: object) -> bytes:
    try:
        return bytes.fromhex(s) if isinstance(s, str) else b""
    except ValueError:
        return b""


# ---- Fingerprint (R11) ----
def kept_sha256(data: bytes, excluded: list[tuple[int, int]]) -> str:
    keep = bytearray()
    for i, b in enumerate(data):
        if not any(s <= i < e for s, e in excluded):
            keep.append(b)
    return sha_hex(bytes(keep))


# ---- Registry shape (R10, R12) ----
HEX32 = re.compile(r"^[0-9a-f]{64}$")
SW = re.compile(r"^[\x20-\x7e]{1,64}$")


def entry_ok(e: dict) -> bool:
    if set(e) != {"family", "sw_id", "memory_id", "size", "excluded", "kept_sha256"}:
        return False
    if not (isinstance(e["size"], int) and e["size"] >= 1 and SW.match(e["sw_id"]) and HEX32.match(e["kept_sha256"])):
        return False
    previous = -1
    for r in e["excluded"]:
        if set(r) != {"start", "end"} or not (previous < r["start"] < r["end"] <= e["size"]):
            return False
        previous = r["end"]
    return True


def registry_ok(reg: dict) -> bool:
    keys = [(e["family"], e["sw_id"], e["memory_id"], e["size"], e["kept_sha256"]) for e in reg["entries"]]
    return (
        reg["schema"] == "impact.stock-registry.v1"
        and all(entry_ok(e) for e in reg["entries"])
        and all(a < b for a, b in zip(keys, keys[1:]))
    )


def instant(ts: str) -> int:
    return calendar.timegm(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))


# ---- Lookup (R21-R25) ----
def lookup(memories: list[dict], ident: dict | None, sr: dict, trust: dict, policy: dict, as_of: str) -> dict:
    family = None if ident is None else ident["family"]
    sw_id = None if ident is None else ident["sw_id"]

    def result(status: str, reasons: list[str], used: bool, mems: list[dict]) -> dict:
        return {
            "schema": "impact.stock-check.v1",
            "status": status,
            "reasons": sorted(set(reasons)),
            "registry_hash": sr["registry_hash"] if used else None,
            "registry_version": sr["registry"]["version"] if used else None,
            "family": family,
            "sw_id": sw_id,
            "memories": mems,
        }

    reg = sr["registry"]
    if (
        sr["key_id"] != trust["key_id"]
        or sha_obj(reg) != sr["registry_hash"]
        or not verify(unhex(trust["public_key"]), signing_input(sr["registry_hash"]), unhex(sr["signature"]))
    ):
        return result("unknown", ["untrusted_registry"], False, [])
    t, i, x = instant(as_of), instant(reg["issued_at"]), instant(reg["expires_at"])
    stale = []
    if t < i:
        stale.append("registry_not_yet_valid")
    if t >= x:
        stale.append("registry_expired")
    if x - i > policy["max_validity_s"]:
        stale.append("registry_validity_too_long")
    if stale:
        return result("unknown", stale, False, [])
    if ident is None:
        return result("unknown", ["not_identified"], True, [])
    if sw_id is None:
        return result("unknown", ["no_sw_id"], True, [])
    mems = []
    for m in sorted(memories, key=lambda m: m["memory_id"]):
        data = bytes.fromhex(m["data_hex"])
        candidates = [
            e for e in reg["entries"]
            if (e["family"], e["sw_id"], e["memory_id"], e["size"]) == (family, sw_id, m["memory_id"], len(data))
        ]
        pii = [(p["start"], p["end"]) for p in ident["pii_locations"] if p["memory_id"] == m["memory_id"]]

        def covers(e: dict) -> bool:
            masked = {b for r in e["excluded"] for b in range(r["start"], r["end"])}
            return all(b in masked for s, f in pii for b in range(s, f))

        usable = [e for e in candidates if covers(e)]
        if not candidates:
            mems.append({"memory_id": m["memory_id"], "status": "unknown", "reason": "not_registered"})
        elif not usable:
            mems.append({"memory_id": m["memory_id"], "status": "unknown", "reason": "pii_not_excluded"})
        elif any(kept_sha256(data, [(r["start"], r["end"]) for r in e["excluded"]]) == e["kept_sha256"] for e in usable):
            mems.append({"memory_id": m["memory_id"], "status": "stock", "reason": None})
        else:
            mems.append({"memory_id": m["memory_id"], "status": "modified", "reason": None})
    statuses = [m["status"] for m in mems]
    if "modified" in statuses:
        return result("modified", [], True, mems)
    if all(s == "stock" for s in statuses):
        return result("stock", [], True, mems)
    return result("unknown", [m["reason"] for m in mems if m["status"] == "unknown"], True, mems)


class Checker:
    def __init__(self, v: dict) -> None:
        self.v = v
        self.failures: list[str] = []
        self.checked = 0

    def expect(self, label: str, got: object, want: object) -> None:
        self.checked += 1
        if got != want:
            self.failures.append(f"{label}: got {got!r}, want {want!r}")

    def run(self) -> None:
        v = self.v
        t1 = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        self.expect("rfc8032.test1.public", public_key(t1).hex(), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        t1sig = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        self.expect("rfc8032.test1.signature", sign(t1, b"").hex(), t1sig)

        k = v["key"]
        seed = hashlib.sha256(k["seed_text"].encode("utf-8")).digest()
        self.expect("key.seed", seed.hex(), k["seed_hex"])
        pub = public_key(seed)
        self.expect("key.public_key", pub.hex(), k["public_key"])
        self.expect("key.key_id", sha_hex(pub), k["key_id"])
        other_seed = hashlib.sha256(k["other_seed_text"].encode("utf-8")).digest()
        self.expect("trusts.main", v["trusts"]["main"], {"key_id": sha_hex(pub), "public_key": pub.hex()})
        other = public_key(other_seed)
        self.expect("trusts.other", v["trusts"]["other"], {"key_id": sha_hex(other), "public_key": other.hex()})

        for f in v["fingerprints"]["values"]:
            got = kept_sha256(bytes.fromhex(f["data_hex"]), [tuple(r) for r in f["excluded"]])
            self.expect(f"fingerprint.{f['id']}", got, f["kept_sha256"])

        main = v["registries"]["main"]
        self.expect("registry.jcs", canon(main["registry"]), v["registry"]["jcs"])
        self.expect("registry.hash", sha_obj(main["registry"]), v["registry"]["registry_hash"])
        self.expect("registry.signing_input", signing_input(main["registry_hash"]).decode("utf-8"), v["registry"]["signing_input"])
        for name in ("main", "too_long"):
            sr = v["registries"][name]
            self.expect(f"registries.{name}.shape", registry_ok(sr["registry"]), True)
            self.expect(f"registries.{name}.hash", sha_obj(sr["registry"]), sr["registry_hash"])
            self.expect(f"registries.{name}.resign", sign(seed, signing_input(sr["registry_hash"])).hex(), sr["signature"])
        bad = v["registries"]["bad_signature"]
        self.expect("registries.bad_signature.verifies", verify(pub, signing_input(bad["registry_hash"]), unhex(bad["signature"])), False)

        for c in v["cases"]:
            got = lookup(c["dump"]["memories"], c["identification"], v["registries"][c["registry"]], v["trusts"][c["trust"]], v["policy"], c["as_of"])
            self.expect(f"case.{c['id']}", got, c["expect"])
            again = lookup(list(reversed(c["dump"]["memories"])), c["identification"], v["registries"][c["registry"]], v["trusts"][c["trust"]], v["policy"], c["as_of"])
            self.expect(f"case.{c['id']}.order", again, got)


def main() -> int:
    path = pathlib.Path(sys.argv[1]).resolve()
    v = json.loads(path.read_text(encoding="utf-8"))
    c = Checker(copy.deepcopy(v))
    c.run()
    for f in c.failures:
        print("FAIL", f)
    print(f"checked {c.checked} values, {len(c.failures)} disagreements")
    return 1 if c.failures else 0


if __name__ == "__main__":
    sys.exit(main())
