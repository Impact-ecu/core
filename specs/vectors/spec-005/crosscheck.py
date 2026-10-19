"""Second, independent implementation that recomputes every expected value in SPEC-005 vectors.json.

Stdlib only and independent of the core and of generate.py:
- canonical JSON: for these objects (ASCII keys, integers, strings, no floats), RFC 8785 output equals
  json.dumps with sorted keys, no whitespace and ensure_ascii=False (SPEC-005 R72);
- Ed25519: transcribed from the RFC 8032 section 6 reference code, checked against RFC 8032 section 7.1 TEST 1
  (see the notice above the Ed25519 section);
- SPEC-001 images: P1, P2 and Q1 applied by hand to the original bytes of specs/vectors/spec-001/vectors.json;
- chain verification (SPEC-005 R40) and report binding (R61) written from the spec, used to derive tamper findings.
Run: python -I crosscheck.py vectors.json   (exit status 1 on any disagreement)
"""
from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import re
import sys


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


def signing_input(domain: str, h: str) -> bytes:
    return canon({"domain": domain, "hash": h}).encode("utf-8")


def unhex(s: str) -> bytes:
    try:
        return bytes.fromhex(s)
    except ValueError:
        return b""


# ---- SPEC-005 R36 payload shapes and R40 chain verification ----

HEX32 = re.compile(r"^[0-9a-f]{64}$")
HEX64B = re.compile(r"^[0-9a-f]{128}$")
VERIFY_STATUS = {"ok", "fail", "bypassed", "signature_unverifiable", "not_applicable"}


def is_hex32(x: object) -> bool:
    return isinstance(x, str) and bool(HEX32.match(x))


def is_str(x: object) -> bool:
    return isinstance(x, str) and x != ""


def is_opt_str(x: object) -> bool:
    return x is None or is_str(x)


def is_int(x: object) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) and 0 <= x <= 2**53 - 1


def one_of(*vals: str):
    return lambda x: x in vals


def obj_list(fields: dict, sort_key: str | None = None, exactly: int | None = None):
    def check(x: object) -> bool:
        if not isinstance(x, list) or (exactly is not None and len(x) != exactly):
            return False
        for it in x:
            if not isinstance(it, dict) or set(it) != set(fields) or not all(fn(it[k]) for k, fn in fields.items()):
                return False
        if sort_key is not None:
            ks = [it[sort_key] for it in x]
            if ks != sorted(ks) or len(set(ks)) != len(ks):
                return False
        return True

    return check


KEY = {"key_id": is_hex32, "public_key": is_hex32}
PAYLOAD = {
    "genesis": {"role": one_of("server", "cli"), "signing_keys": obj_list(KEY, "key_id")},
    "key_enrolled": {**KEY, "signer_key_id": is_hex32, "signature": lambda x: isinstance(x, str) and bool(HEX64B.match(x))},
    "key_revoked": {
        "key_id": is_hex32,
        "reason": one_of("compromised", "retired"),
        "signer_key_id": is_hex32,
        "signature": lambda x: isinstance(x, str) and bool(HEX64B.match(x)),
    },
    "import": {
        "artifact_sha256": is_hex32,
        "image_hash": is_hex32,
        "dump_kind": one_of("bench_full", "boot_full", "obd_full", "obd_partial", "virtual"),
        "origin": one_of("obd_read", "bench_read", "boot_read", "virtual_read", "file_service"),
    },
    "identification_confirmed": {
        "artifact_sha256": is_hex32,
        "image_hash": is_hex32,
        "family": is_str,
        "plugin_version": is_str,
        "hw_id": is_opt_str,
        "sw_id": is_opt_str,
        "checksum_variant_id": is_opt_str,
    },
    "suspect_ack": {
        "artifact_sha256": is_hex32,
        "image_hash": is_hex32,
        "input_report_hash": is_hex32,
        "verify_status": lambda x: x in VERIFY_STATUS,
    },
    "alert_ack": {
        "image_hash_release": is_hex32,
        "gate_report_hash": is_hex32,
        "warnings": obj_list({"finding_id": is_hex32, "rule_id": is_str, "text": is_str}),
        "presented_ms": is_int,
        "confirmed_ms": is_int,
    },
    "rule_silence": {"rule_id": is_str, "justification_commitment": lambda x: x is None or is_hex32(x)},
    "chain_ref": {
        "chain_signer_key_id": is_hex32,
        "genesis_hash": is_hex32,
        "seq": is_int,
        "head_hash": is_hex32,
        "signer_key_id": is_hex32,
        "signature": lambda x: isinstance(x, str) and bool(HEX64B.match(x)),
    },
    "export": {
        "provenance_hash": is_hex32,
        "report_hash": is_hex32,
        "key_id": is_hex32,
        "signature": lambda x: isinstance(x, str) and bool(HEX64B.match(x)),
    },
    "audit": {
        "audit_hash": is_hex32,
        "report_hash": is_hex32,
        "key_id": is_hex32,
        "signature": lambda x: isinstance(x, str) and bool(HEX64B.match(x)),
    },
    "consent_granted": {
        "artifact_sha256": is_hex32,
        "purpose": one_of("corpus"),
        "legal_basis": one_of("consent", "legitimate_interest"),
        "record_commitment": is_hex32,
    },
    "consent_revoked": {"artifact_sha256": is_hex32, "purpose": one_of("corpus"), "record_commitment": is_hex32},
    "erasure": {
        "subject": one_of("artifact", "record"),
        "ref": is_hex32,
        "reason": one_of("data_subject_request", "consent_revoked", "retention_expired"),
    },
    "attester_enrolled": {
        "attester_key_id": is_hex32,
        "public_key": is_hex32,
        "roles": lambda x: isinstance(x, list) and x != [] and x == sorted(set(x)) and set(x) <= {"attester", "reviewer"},
        "rotates": lambda x: x is None or is_hex32(x),
        "rotation_signature": lambda x: x is None or (isinstance(x, str) and bool(HEX64B.match(x))),
        "reason_commitment": is_hex32,
        "signer_key_id": is_hex32,
        "signature": lambda x: isinstance(x, str) and bool(HEX64B.match(x)),
    },
    "attester_revoked": {
        "attester_key_id": is_hex32,
        "reason": one_of("compromised", "misconduct", "retired", "error"),
        "reason_commitment": is_hex32,
        "signer_key_id": is_hex32,
        "signature": lambda x: isinstance(x, str) and bool(HEX64B.match(x)),
    },
    "attestation_included": {
        "attestation_hash": is_hex32,
        "attester_key_id": is_hex32,
        "signer_key_id": is_hex32,
        "signature": lambda x: isinstance(x, str) and bool(HEX64B.match(x)),
    },
    "review": {
        "subject_kind": one_of("export", "golden_record"),
        "export_ref": lambda x: x is None
        or (
            isinstance(x, dict)
            and set(x) == {"event_id", "seq", "hash"}
            and isinstance(x["event_id"], str)
            and bool(re.match(r"^[0-9a-f]{32}$", x["event_id"]))
            and is_int(x["seq"])
            and is_hex32(x["hash"])
        ),
        "subject_hash": is_hex32,
        "decision": one_of("approved", "rejected"),
        "reviewer_key_id": is_hex32,
        "signature": lambda x: isinstance(x, str) and bool(HEX64B.match(x)),
    },
}
EVENT_KEYS = {"schema", "tenant_id", "seq", "event_id", "project_id", "type", "payload", "actor", "ts", "prev_hash", "hash"}
TEST_SEED_TEXT = "impact spec-005 synthetic test key; never use outside test vectors"


def payload_ok(typ: str, pl: object) -> bool:
    shape = PAYLOAD[typ]
    if not isinstance(pl, dict) or set(pl) != set(shape) or not all(fn(pl[k]) for k, fn in shape.items()):
        return False
    if typ == "alert_ack" and pl["presented_ms"] > pl["confirmed_ms"]:
        return False
    if typ == "attester_enrolled" and (pl["rotates"] is None) != (pl["rotation_signature"] is None):
        return False
    if typ == "review" and (pl["subject_kind"] == "export") != (pl["export_ref"] is not None):
        return False
    return True


def event_hash(ev: dict) -> str:
    return sha_obj({k: v for k, v in ev.items() if k != "hash"})


def finding(seq: int, reason: str, informational: bool = False, missing: dict | None = None) -> dict:
    return {"seq": seq, "reason": reason, "informational": informational, "missing": missing}


def verify_chain(events: list[dict], anchors: list[dict], test_mode: bool) -> tuple[str, list[dict]]:
    test_key_id = sha_hex(public_key(hashlib.sha256(TEST_SEED_TEXT.encode("utf-8")).digest()))
    findings: list[dict] = []
    evs = sorted(events, key=lambda e: e["seq"])
    if not evs:
        return "broken", [finding(0, "not_genesis")]
    g = evs[0]

    def genesis_ok(ev: dict) -> bool:
        pl = ev.get("payload")
        return (
            ev["seq"] == 0
            and ev["type"] == "genesis"
            and ev["prev_hash"] == "0" * 64
            and ev["project_id"] is None
            and ev["actor"].get("kind") == "system"
            and isinstance(pl, dict)
            and isinstance(pl.get("signing_keys"), list)
            and len(pl["signing_keys"]) == 1
        )

    first_ok = genesis_ok(g)
    if not first_ok:
        findings.append(finding(g["seq"], "not_genesis"))
    keys: dict[str, tuple[bytes, int, int | None]] = {}  # key_id -> (public key, enrolled seq, revoked seq)
    seen_ids: set[str] = set()
    prev: dict | None = None
    for ev in evs:
        seq = ev["seq"]
        if set(ev) != EVENT_KEYS:
            findings.append(finding(seq, "bad_shape"))
            prev = ev
            continue
        if event_hash(ev) != ev["hash"]:
            findings.append(finding(seq, "hash_mismatch"))
        if prev is not None:
            if seq == prev["seq"]:
                findings.append(finding(seq, "seq_duplicate"))
            elif seq != prev["seq"] + 1:
                findings.append(finding(seq, "seq_gap", missing={"first": prev["seq"] + 1, "last": seq - 1}))
            if ev["prev_hash"] != prev["hash"]:
                findings.append(finding(seq, "prev_mismatch"))
            if ev["ts"] < prev["ts"]:
                findings.append(finding(seq, "ts_regression", informational=True))
        if ev["tenant_id"] != g["tenant_id"]:
            findings.append(finding(seq, "tenant_mismatch"))
        if ev["event_id"] in seen_ids:
            findings.append(finding(seq, "duplicate_event_id"))
        seen_ids.add(ev["event_id"])
        typ = ev["type"]
        if typ == "genesis" and ev is not g:
            findings.append(finding(seq, "not_genesis"))
            prev = ev
            continue
        if typ not in PAYLOAD:
            findings.append(finding(seq, "unknown_type"))
        elif not payload_ok(typ, ev["payload"]):
            findings.append(finding(seq, "bad_payload"))
        else:
            pl = ev["payload"]
            if typ in ("export", "audit"):
                k = keys.get(pl["key_id"])
                if k is None or k[1] >= seq:
                    findings.append(finding(seq, "unknown_key"))
                elif k[2] is not None and k[2] < seq:
                    findings.append(finding(seq, "revoked_key"))
                elif not verify(k[0], signing_input("impact.report-signature.v1", pl["report_hash"]), unhex(pl["signature"])):
                    findings.append(finding(seq, "bad_signature"))
            key_event_ok = True
            if typ in ("key_enrolled", "key_revoked", "attester_enrolled", "attester_revoked", "attestation_included", "chain_ref"):
                body = {kk: vv for kk, vv in pl.items() if kk != "signature"}
                kh = sha_obj({"schema": "impact.key-event.v1", "tenant_id": ev["tenant_id"], "genesis_hash": g["hash"], "seq": seq, "type": typ, "payload": body})
                k = keys.get(pl["signer_key_id"])
                if k is None or k[1] >= seq:
                    findings.append(finding(seq, "unknown_key"))
                    key_event_ok = False
                elif k[2] is not None and k[2] < seq:
                    findings.append(finding(seq, "revoked_key"))
                    key_event_ok = False
                elif not verify(k[0], signing_input("impact.key-event-signature.v1", kh), unhex(pl["signature"])):
                    findings.append(finding(seq, "bad_signature"))
                    key_event_ok = False
            if typ == "genesis":
                new_keys = pl["signing_keys"] if first_ok else []
            elif typ == "key_enrolled" and key_event_ok:
                new_keys = [{"key_id": pl["key_id"], "public_key": pl["public_key"]}]
            else:
                new_keys = []
            for nk in new_keys:
                pub = unhex(nk["public_key"])
                if sha_hex(pub) != nk["key_id"]:
                    findings.append(finding(seq, "bad_payload"))
                if nk["key_id"] == test_key_id and not test_mode:
                    findings.append(finding(seq, "test_key"))
                keys[nk["key_id"]] = (pub, seq, None)
            if typ == "key_revoked" and pl["key_id"] in keys:
                pub, enrolled, _ = keys[pl["key_id"]]
                keys[pl["key_id"]] = (pub, enrolled, seq)
        prev = ev
    by_seq = {e["seq"]: e for e in evs}
    last = evs[-1]["seq"]
    for af in anchors:
        st = af["statement"]
        aseq = st["seq"]
        if sha_obj(st) != af["statement_hash"]:
            findings.append(finding(aseq, "bad_anchor"))
        k = keys.get(af["key_id"])
        if k is None or k[1] > aseq:
            findings.append(finding(aseq, "unknown_key"))
        elif k[2] is not None and k[2] <= aseq:
            findings.append(finding(aseq, "revoked_key"))
        elif not verify(k[0], signing_input("impact.anchor-signature.v1", af["statement_hash"]), unhex(af["signature"])):
            findings.append(finding(aseq, "bad_signature"))
        if st["tenant_id"] != g["tenant_id"] or st["genesis_hash"] != g["hash"]:
            findings.append(finding(aseq, "anchor_mismatch"))
        elif aseq > last:
            findings.append(finding(aseq, "truncated"))
        elif aseq not in by_seq or by_seq[aseq]["hash"] != st["head_hash"]:
            findings.append(finding(aseq, "anchor_mismatch"))
    findings.sort(key=lambda f: (f["seq"], f["reason"]))
    status = "broken" if any(not f["informational"] for f in findings) else "intact"
    return status, findings


# ---- SPEC-005 R61: report binding ----
def verify_report_file(rf: dict) -> list[str]:
    out: list[str] = []
    rep, ev = rf["report"], rf["event"]
    if sha_obj(rep) != rf["report_hash"]:
        out.append("report_hash_mismatch")
    if sha_obj(rep["record"]) != rep["record_hash"]:
        out.append("record_hash_mismatch")
    pub = unhex(rep["signer"]["public_key"])
    if sha_hex(pub) != rep["signer"]["key_id"]:
        out.append("key_id_mismatch")
    pl = ev["payload"]
    record_field = "provenance_hash" if rep["kind"] == "export" else "audit_hash"
    if (
        event_hash(ev) != ev["hash"]
        or ev["type"] != rep["kind"]
        or ev["tenant_id"] != rep["tenant_id"]
        or pl.get("report_hash") != rf["report_hash"]
        or pl.get(record_field) != rep["record_hash"]
        or pl.get("key_id") != rep["signer"]["key_id"]
    ):
        out.append("event_mismatch")
    if not verify(pub, signing_input("impact.report-signature.v1", rf["report_hash"]), unhex(pl.get("signature", ""))):
        out.append("bad_signature")
    return sorted(out)


def rehash_from(events: list[dict], start: int) -> None:
    for i in range(start, len(events)):
        if i > 0:
            events[i]["prev_hash"] = events[i - 1]["hash"]
        events[i]["hash"] = event_hash(events[i])


def mutate_chain(events: list[dict], m: dict | None) -> list[dict]:
    evs = copy.deepcopy(events)
    if m is None:
        return evs
    idx = next(i for i, e in enumerate(evs) if e["seq"] == m["seq"])
    if m["op"] == "delete":
        del evs[idx]
    elif m["op"] == "set":
        tgt = evs[idx]
        for key in m["path"][:-1]:
            tgt = tgt[key]
        tgt[m["path"][-1]] = m["value"]
        if m["rehash"]:
            rehash_from(evs, idx)
    elif m["op"] == "insert":
        new = {"schema": "impact.event.v1", "tenant_id": evs[0]["tenant_id"], "seq": m["seq"], **m["event"]}
        new["prev_hash"] = ""
        new["hash"] = ""
        evs.insert(idx, {k: new[k] for k in sorted(EVENT_KEYS)})
        for i in range(idx + 1, len(evs)):
            evs[i]["seq"] += 1
        rehash_from(evs, idx)
    else:
        raise ValueError(m["op"])
    return evs


def nat(x: object) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) and x >= 0


class Checker:
    def __init__(self, v: dict, spec001: dict, spec001_sha: str) -> None:
        self.v = v
        self.s1 = spec001
        self.s1_sha = spec001_sha
        self.failures: list[str] = []
        self.checked = 0

    def expect(self, label: str, got: object, want: object) -> None:
        self.checked += 1
        if got != want:
            self.failures.append(f"{label}: got {got!r}, want {want!r}")

    def image_hash(self, dump_kind: str, mem: dict[str, tuple[int, bytes]]) -> str:
        return sha_obj(
            {
                "dump_kind": dump_kind,
                "memories": [
                    {"memory_id": m, "base_address": b, "size": len(d), "sha256": sha_hex(d)} for m, (b, d) in sorted(mem.items())
                ],
            }
        )

    def generic(self, v: dict, o: dict, dk: str) -> None:
        """R110-R115: every differing position, grouped, then each position looked up in the map spans."""
        gi = v["generic_audit_inputs"]
        orig = {m: (x["base_address"], bytes.fromhex(x["bytes_hex"])) for m, x in o["memories"].items()}
        cand = {m: (orig[m][0], bytes.fromhex(h)) for m, h in gi["candidate"].items()}
        self.expect("generic.candidate.shape", sorted((m, b, len(d)) for m, (b, d) in cand.items()), sorted((m, b, len(d)) for m, (b, d) in orig.items()))
        self.expect("generic.candidate_image_jcs", canon({"dump_kind": dk, "memories": [{"memory_id": m, "base_address": b, "size": len(d), "sha256": sha_hex(d)} for m, (b, d) in sorted(cand.items())]}), gi["candidate_image_jcs"])
        positions = {m: [i for i in range(len(d)) if d[i] != cand[m][1][i]] for m, (_, d) in orig.items()}

        def groups(memory_id: str, pos: list[int]) -> list[tuple[str, int, int]]:
            out: list[tuple[str, int, int]] = []
            for i in pos:
                if out and out[-1][1] + out[-1][2] == i:
                    out[-1] = (memory_id, out[-1][1], out[-1][2] + 1)
                else:
                    out.append((memory_id, i, 1))
            return out

        changes = [g for m in sorted(positions) for g in groups(m, positions[m])]
        cover: dict[tuple[str, int], set[str]] = {}
        for map_id, ranges in gi["spans"].items():
            for r in ranges:
                for i in range(r["start"], r["end"]):
                    cover.setdefault((r["memory_id"], i), set()).add(map_id)
        for name, with_definition, reason in (
            ("generic_audit", True, "no_admitted_plugin"),
            ("generic_audit_no_definition", False, "no_admitted_plugin"),
            ("generic_audit_no_rule_table", True, "no_rule_table"),
        ):
            vec = v[name]
            rec = vec["value"]
            want_changes = []
            for m, off, n in changes:
                maps: set[str] = set()
                if with_definition:
                    for i in range(off, off + n):
                        maps |= cover.get((m, i), set())
                before, after = orig[m][1][off : off + n], cand[m][1][off : off + n]
                ph = sha_obj({"memory_id": m, "offset": off, "length": n, "before": before.hex(), "after": after.hex()})
                want_changes.append({"memory_id": m, "offset": off, "length": n, "patch_hash": ph, "map_ids": sorted(maps)})
            outside = [
                {"memory_id": m, "offset": off, "length": n}
                for mem in sorted(positions)
                for m, off, n in groups(mem, [i for i in positions[mem] if not (with_definition and cover.get((mem, i)))])
            ]
            not_evaluated = sorted(
                [
                    {"check": "identification", "reason": reason},
                    {"check": "layout", "reason": reason},
                    {"check": "verify", "reason": reason},
                    {"check": "map_rules", "reason": "no_rule_table" if with_definition else "no_definition"},
                ],
                key=lambda e: e["check"],
            )
            self.expect(f"{name}.keys", sorted(rec), sorted(["schema", "dump_kind", "image_hash_original", "image_hash_candidate", "candidate_origin", "definition_hash", "changes", "outside_known_maps", "unbound_maps", "not_evaluated", "checksum_status", "versions", "python", "build", "reproducibility"]))
            self.expect(f"{name}.schema", rec["schema"], "impact.generic-audit-record.v1")
            self.expect(f"{name}.image_hash_original", rec["image_hash_original"], self.image_hash(dk, orig))
            self.expect(f"{name}.image_hash_candidate", rec["image_hash_candidate"], self.image_hash(dk, cand))
            self.expect(f"{name}.definition_hash", rec["definition_hash"], gi["definition_hash"] if with_definition else None)
            self.expect(f"{name}.R111_R112.changes", rec["changes"], want_changes)
            self.expect(f"{name}.R112.outside_known_maps", rec["outside_known_maps"], outside)
            self.expect(f"{name}.R112.unbound_maps", rec["unbound_maps"], sorted(gi["unbound"]) if with_definition else [])
            self.expect(f"{name}.R113.not_evaluated", rec["not_evaluated"], not_evaluated)
            self.expect(f"{name}.R113.checksum_status", rec["checksum_status"], "not_verified")
            self.expect(f"{name}.R113.never_ok", "\"ok\"" in json.dumps(rec), False)
            self.expect(f"{name}.versions", sorted(rec["versions"]), ["core"])
            self.expect(f"{name}.R17", rec["reproducibility"], "full" if rec["build"]["kind"] == "image" else "best_effort")
            self.expect(f"{name}.jcs", canon(rec), vec["jcs"])
            self.expect(f"{name}.generic_audit_hash", sha_obj(rec), vec["generic_audit_hash"])

    @staticmethod
    def generic_record_ok(rec: object) -> bool:
        """R3, R112, R113, R17 for a GenericAuditRecord, written from SPEC-005 §4.2."""
        keys = {"schema", "dump_kind", "image_hash_original", "image_hash_candidate", "candidate_origin", "definition_hash", "changes", "outside_known_maps", "unbound_maps", "not_evaluated", "checksum_status", "versions", "python", "build", "reproducibility"}
        if not isinstance(rec, dict) or set(rec) != keys:
            return False
        run_keys = {"memory_id", "offset", "length"}
        ne = rec["not_evaluated"]
        if not (
            rec["schema"] == "impact.generic-audit-record.v1"
            and rec["checksum_status"] == "not_verified"
            and is_hex32(rec["image_hash_original"]) and is_hex32(rec["image_hash_candidate"])
            and (rec["definition_hash"] is None or is_hex32(rec["definition_hash"]))
            and isinstance(rec["changes"], list) and isinstance(rec["outside_known_maps"], list)
            and isinstance(ne, list) and len(ne) == 4 and all(isinstance(e, dict) and set(e) == {"check", "reason"} for e in ne)
            and isinstance(rec["versions"], dict) and set(rec["versions"]) == {"core"}
            and isinstance(rec["build"], dict)
        ):
            return False
        for c in rec["changes"]:
            if not (isinstance(c, dict) and set(c) == run_keys | {"patch_hash", "map_ids"} and nat(c["offset"]) and nat(c["length"]) and is_hex32(c["patch_hash"])):
                return False
            if not (isinstance(c["map_ids"], list) and c["map_ids"] == sorted(set(c["map_ids"]))):
                return False
        if not all(isinstance(r, dict) and set(r) == run_keys for r in rec["outside_known_maps"]):
            return False
        if [e["check"] for e in ne] != ["identification", "layout", "map_rules", "verify"]:
            return False
        plugin = {ne[0]["reason"], ne[1]["reason"], ne[3]["reason"]}
        if len(plugin) != 1 or not plugin <= {"no_admitted_plugin", "no_rule_table"}:
            return False
        no_def = rec["definition_hash"] is None
        if ne[2]["reason"] != ("no_definition" if no_def else "no_rule_table"):
            return False
        if no_def and (rec["unbound_maps"] or any(c["map_ids"] for c in rec["changes"])):
            return False
        return rec["reproducibility"] == ("best_effort" if rec["build"].get("kind") == "lockfile" else "full")

    def generic_report_findings(self, rep: object, trust: list[str], test_mode: bool) -> list[str]:
        """R117, written from the spec: findings, never an exception."""
        if not (
            isinstance(rep, dict)
            and set(rep) == {"schema", "record", "record_hash", "key_id", "signature"}
            and rep["schema"] == "impact.generic-audit-report.v1"
            and isinstance(rep["record"], dict)
            and is_hex32(rep["record_hash"]) and is_hex32(rep["key_id"])
            and isinstance(rep["signature"], str) and re.fullmatch(r"[0-9a-f]{128}", rep["signature"]) is not None
        ):
            return ["bad_shape"]
        out: set[str] = set()
        if not self.generic_record_ok(rep["record"]):
            out.add("bad_record")
        elif sha_obj(rep["record"]) != rep["record_hash"]:
            out.add("record_hash_mismatch")
        if rep["key_id"] == self.v["key"]["key_id"] and not test_mode:
            out.add("test_key")
        keys = {sha_hex(bytes.fromhex(k)): k for k in trust}
        if rep["key_id"] not in keys:
            out.add("unknown_key")
        elif not verify(bytes.fromhex(keys[rep["key_id"]]), signing_input("impact.generic-audit-signature.v1", rep["record_hash"]), bytes.fromhex(rep["signature"])):
            out.add("bad_signature")
        return sorted(out)

    def generic_report(self, v: dict) -> None:
        gr = v["generic_audit_report"]
        rep = gr["value"]
        seed = hashlib.sha256(v["key"]["seed_text"].encode("utf-8")).digest()
        self.expect("generic_report.record", rep["record"], v["generic_audit"]["value"])
        self.expect("generic_report.record_hash", sha_obj(rep["record"]), rep["record_hash"])
        self.expect("generic_report.key_id", rep["key_id"], v["key"]["key_id"])
        msg = signing_input("impact.generic-audit-signature.v1", rep["record_hash"])
        self.expect("generic_report.signing_input", msg.decode("utf-8"), gr["signing_input"])
        self.expect("generic_report.signature(resign)", sign(seed, msg).hex(), rep["signature"])
        self.expect("generic_report.verify", self.generic_report_findings(rep, gr["trust"], gr["test_mode"]), [])
        self.expect("generic_report.record_valid", self.generic_record_ok(rep["record"]), True)
        for t in gr["tampers"]:
            mutated = copy.deepcopy(rep)
            if t["mutation"] is not None:
                tgt = mutated
                for key in t["mutation"]["path"][:-1]:
                    tgt = tgt[key]
                tgt[t["mutation"]["path"][-1]] = t["mutation"]["value"]
            self.expect(f"generic_report.tamper.{t['id']}", self.generic_report_findings(mutated, gr["trust"], t["test_mode"]), sorted(t["expect"]))

    def run(self) -> None:
        v, s1 = self.v, self.s1
        self.expect("generator.spec001_vectors_sha256", v["generator"]["spec001_vectors_sha256"], self.s1_sha)

        # RFC 8032 section 7.1 TEST 1 (external constants) validates this Ed25519 transcription.
        t1 = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        self.expect("rfc8032.test1.public", public_key(t1).hex(), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        t1sig = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        self.expect("rfc8032.test1.signature", sign(t1, b"").hex(), t1sig)
        self.expect("rfc8032.test1.verify", verify(public_key(t1), b"", bytes.fromhex(t1sig)), True)

        # SPEC-001 inputs: recomputed from the original bytes and the patch objects, then compared with spec-001.
        o = s1["original"]
        mem = {m: (x["base_address"], bytes.fromhex(x["bytes_hex"])) for m, x in o["memories"].items()}
        pat = {n: p["value"] for n, p in s1["patches"].items()}

        def applied(names: list[str], base: dict[str, tuple[int, bytes]]) -> dict[str, tuple[int, bytes]]:
            out = {m: (b, bytearray(d)) for m, (b, d) in base.items()}
            for n in names:
                p = pat[n]
                b, d = out[p["memory_id"]]
                assert d[p["offset"] : p["offset"] + p["length"]] == bytes.fromhex(p["before"])
                d[p["offset"] : p["offset"] + p["length"]] = bytes.fromhex(p["after"])
            return {m: (b, bytes(d)) for m, (b, d) in out.items()}

        dk = o["dump_kind"]
        apply_mem = applied(["P1", "P2"], mem)
        release_mem = applied(["Q1"], apply_mem)
        inp = v["spec001_inputs"]
        self.expect("spec001.original", self.image_hash(dk, mem), inp["image_hash_original"])
        self.expect("spec001.original(spec-001 file)", o["image_hash"], inp["image_hash_original"])
        self.expect("spec001.apply", self.image_hash(dk, apply_mem), inp["image_hash_apply"])
        self.expect("spec001.release", self.image_hash(dk, release_mem), inp["image_hash_release"])
        self.expect("spec001.layout", sha_obj(s1["layouts"]["base"]["value"]), inp["layout_hash"])
        ph = {n: sha_obj(pat[n]) for n in ("P1", "P2", "Q1")}
        self.expect("spec001.patch_hashes", ph, inp["patch_hashes"])
        version = {
            "base_image_hash": inp["image_hash_original"],
            "layout_hash": inp["layout_hash"],
            "patches": [ph["P1"], ph["P2"]],
            "overlaps": [],
        }
        self.expect("spec001.version_hash", sha_obj(version), inp["version_hash"])

        # Key
        k = v["key"]
        seed = hashlib.sha256(k["seed_text"].encode("utf-8")).digest()
        self.expect("key.seed", seed.hex(), k["seed_hex"])
        pub = public_key(seed)
        self.expect("key.public_key", pub.hex(), k["public_key"])
        self.expect("key.key_id", sha_hex(pub), k["key_id"])
        pub2 = public_key(hashlib.sha256(k["second_seed_text"].encode("utf-8")).digest())
        self.expect("key.second_public_key", pub2.hex(), k["second_public_key"])
        self.expect("key.second_key_id", sha_hex(pub2), k["second_key_id"])

        gr = v["gate_report"]
        self.expect("gate_report_hash", sha_obj(gr["value"]), gr["gate_report_hash"])
        self.expect("gate_report.finding_ids", [sha_obj(f) for f in gr["value"]["findings"]], gr["finding_ids"])
        gnf = v["gate_report_no_findings"]
        self.expect("gate_report_no_findings.hash", sha_obj(gnf["value"]), gnf["gate_report_hash"])
        ir = v["input_report"]
        self.expect("input_report.hash", sha_obj(ir["value"]), ir["input_report_hash"])

        # Chain: per-event JCS and hash, then full verification with the anchor.
        events = [e["event"] for e in v["chain"]["events"]]
        for i, e in enumerate(v["chain"]["events"]):
            body = {kk: vv for kk, vv in e["event"].items() if kk != "hash"}
            self.expect(f"chain[{i}].jcs", canon(body), e["jcs_without_hash"])
            self.expect(f"chain[{i}].hash", sha_obj(body), e["hash"])
        anchor = v["anchor"]["value"]
        self.expect("chain.test_mode", v["chain"]["test_mode"], True)
        self.expect("chain.verify", verify_chain(events, [anchor], True), ("intact", []))
        self.expect("chain.genesis.role", events[0]["payload"]["role"], "server")

        # Provenance: hash, R11 consistency, R13 alert_ack binding, R17.
        pv = v["provenance"]
        rec = pv["value"]
        self.expect("provenance.jcs", canon(rec), pv["jcs"])
        self.expect("provenance.hash", sha_obj(rec), pv["provenance_hash"])
        self.expect("provenance.image_hash_original", rec["image_hash_original"], inp["image_hash_original"])
        self.expect("provenance.image_hash_apply", rec["image_hash_apply"], inp["image_hash_apply"])
        self.expect("provenance.image_hash_release", rec["image_hash_release"], inp["image_hash_release"])
        self.expect(
            "provenance.R11.version_hash",
            sha_obj({"base_image_hash": rec["image_hash_original"], "layout_hash": rec["layout_hash"], "patches": rec["patch_hashes"], "overlaps": rec["overlaps"]}),
            rec["version_hash"],
        )
        self.expect("provenance.checksum_patch_hashes", rec["checksum_patch_hashes"], [ph["Q1"]])
        self.expect("provenance.definition_hash.is_hex32", is_hex32(rec["definition_hash"]), True)
        refs = rec["versions"]["references"]
        self.expect(
            "provenance.versions.references",
            obj_list({"id": is_str, "version": is_str}, "id")(refs),
            True,
        )
        self.expect("provenance.gate_report_hash", rec["gate_report_hash"], gr["gate_report_hash"])
        ack_ref = rec["alert_ack"]
        ack = next(e for e in events if e["event_id"] == ack_ref["event_id"])
        self.expect("provenance.R13.ack_ref", (ack["type"], ack["seq"], ack["hash"]), ("alert_ack", ack_ref["seq"], ack_ref["hash"]))
        self.expect(
            "provenance.R13.ack_payload",
            (ack["payload"]["image_hash_release"], ack["payload"]["gate_report_hash"]),
            (rec["image_hash_release"], rec["gate_report_hash"]),
        )
        self.expect(
            "provenance.R13.ack_warnings",
            ack["payload"]["warnings"],
            [
                {"finding_id": sha_obj(f), "rule_id": f["rule_id"], "text": f["text"]}
                for f in gr["value"]["findings"]
                if f["severity"] == "warn"
            ],
        )
        self.expect("provenance.R17", rec["reproducibility"], "full" if rec["build"]["kind"] == "image" else "best_effort")
        # R14: suspect original, acknowledged.
        iv = rec["input_verify"]
        sref = iv["suspect_ack"]
        sack = next(e for e in events if e["event_id"] == sref["event_id"])
        self.expect("provenance.R14.suspect_ref", (sack["type"], sack["seq"], sack["hash"]), ("suspect_ack", sref["seq"], sref["hash"]))
        self.expect(
            "provenance.R14.suspect_payload",
            (sack["payload"]["image_hash"], sack["payload"]["input_report_hash"], sack["payload"]["verify_status"]),
            (rec["image_hash_original"], ir["input_report_hash"], iv["status"]),
        )
        self.expect("provenance.R14.result", (iv["status"] != "ok", iv["result"]), (True, "failed_acknowledged"))
        self.expect("provenance.R14.input_verdict_block", ir["value"]["verdict"], "block")
        # No findings record: R13 null ack, R14 accepted original.
        nf = v["provenance_no_findings"]
        nrec = nf["value"]
        self.expect("provenance_no_findings.jcs", canon(nrec), nf["jcs"])
        self.expect("provenance_no_findings.hash", sha_obj(nrec), nf["provenance_hash"])
        self.expect("provenance_no_findings.R13", (nrec["verdict"], nrec["alert_ack"], nrec["gate_report_hash"]), ("no findings", None, gnf["gate_report_hash"]))
        self.expect("provenance_no_findings.R14", nrec["input_verify"], {"status": "ok", "result": "ok", "suspect_ack": None})
        self.expect(
            "provenance_no_findings.R11",
            sha_obj({"base_image_hash": nrec["image_hash_original"], "layout_hash": nrec["layout_hash"], "patches": nrec["patch_hashes"], "overlaps": nrec["overlaps"]}),
            nrec["version_hash"],
        )
        self.expect("provenance.versions.plugins.sorted", [p["family"] for p in rec["versions"]["plugins"]], sorted(p["family"] for p in rec["versions"]["plugins"]))
        pl = v["provenance_lockfile"]
        self.expect("provenance_lockfile.hash", sha_obj(pl["value"]), pl["provenance_hash"])
        self.expect("provenance_lockfile.R17", (pl["value"]["build"]["kind"], pl["value"]["reproducibility"]), ("lockfile", "best_effort"))

        # Report file: R61 binding, signature recomputed and compared byte for byte.
        rf = v["report_file"]
        self.expect("report.jcs", canon(rf["value"]["report"]), rf["report_jcs"])
        self.expect("report.R61", verify_report_file(rf["value"]), [])
        msg = signing_input("impact.report-signature.v1", rf["value"]["report_hash"])
        self.expect("report.signing_input", msg.decode("utf-8"), rf["signing_input"])
        self.expect("report.signature(resign)", sign(seed, msg).hex(), rf["signature"])
        self.expect("report.signature(event)", rf["value"]["event"]["payload"]["signature"], rf["signature"])
        self.expect("report.event_is_chain_head", rf["value"]["event"], events[-1])
        self.expect("report.record_is_provenance", rf["value"]["report"]["record"], rec)
        rep = rf["value"]["report"]
        integ = rep["sections"]["integrity"]
        self.expect("report.R62.integrity", (integ["input_verify"], integ["input_result"], integ["verdict"]), (rec["input_verify"]["status"], rec["input_verify"]["result"], rec["verdict"]))
        want_notices = sorted({"emissions_and_regulation"} | ({"input_verify_failed_acknowledged"} if rec["input_verify"]["result"] == "failed_acknowledged" else set()))
        self.expect("report.R63.notices", rep["notices"], want_notices)
        self.expect("report.R63.not_verified.base", {"map_interaction", "firmware_behavior", "real_engine"} <= set(rep["sections"]["not_verified"]), True)
        self.expect(
            "report.R63.signature_unverifiable",
            "signature_unverifiable" in rep["sections"]["not_verified"],
            bool(v["gate_report"]["value"]["subject"]["signed_regions"]),
        )

        # Anchor
        av = v["anchor"]
        self.expect("anchor.jcs", canon(anchor["statement"]), av["statement_jcs"])
        self.expect("anchor.statement_hash", sha_obj(anchor["statement"]), anchor["statement_hash"])
        amsg = signing_input("impact.anchor-signature.v1", anchor["statement_hash"])
        self.expect("anchor.signing_input", amsg.decode("utf-8"), av["signing_input"])
        self.expect("anchor.signature(resign)", sign(seed, amsg).hex(), anchor["signature"])
        self.expect("anchor.head", (anchor["statement"]["seq"], anchor["statement"]["head_hash"]), (events[-1]["seq"], events[-1]["hash"]))

        # Audit: candidate image hash from the V8 bytes; diff and foreign taken from SPEC-001 V8.
        au = v["audit"]
        v8 = next(c for c in s1["cases"] if c["id"] == "V8-diff-reports-foreign-changes")
        cand = {
            "pflash": (o["memories"]["pflash"]["base_address"], bytes.fromhex(au["candidate"]["pflash_hex"])),
            "dflash": (o["memories"]["dflash"]["base_address"], bytes.fromhex(au["candidate"]["dflash_hex"])),
        }
        self.expect("audit.candidate_bytes", (au["candidate"]["pflash_hex"], au["candidate"]["dflash_hex"]), (v8["x_pflash_hex"], v8["x_dflash_hex"]))
        self.expect("audit.image_hash_candidate", self.image_hash(dk, cand), au["value"]["image_hash_candidate"])
        self.expect("audit.diff", (au["value"]["diff_patch_hashes"], au["value"]["foreign"]), (v8["expect"]["patch_hashes"], v8["expect"]["foreign"]))
        self.expect("audit.hash", sha_obj(au["value"]), au["audit_hash"])

        cm = v["commitment"]
        self.expect("commitment", sha_obj(cm["value"]), cm["commitment"])

        self.generic(v, o, dk)
        self.generic_report(v)

        # Tampers: every mutation MUST be detected exactly as expected (T4b documents the unanchored limit).
        for t in v["tampers"]:
            if t["target"] == "chain":
                got = verify_chain(mutate_chain(events, t["mutation"]), [anchor] if t["use_anchor"] else [], t["test_mode"])
                want = (t["status"], t["expect"])
            else:
                mutated = copy.deepcopy(rf["value"])
                tgt = mutated
                for key in t["mutation"]["path"][:-1]:
                    tgt = tgt[key]
                tgt[t["mutation"]["path"][-1]] = t["mutation"]["value"]
                got = verify_report_file(mutated)
                want = sorted(f["reason"] for f in t["expect"])
            self.expect(f"tamper.{t['id']}", got, want)


def main() -> int:
    path = pathlib.Path(sys.argv[1]).resolve()
    v = json.loads(path.read_text(encoding="utf-8"))
    s1_path = path.parent.parent / "spec-001" / "vectors.json"
    s1_bytes = s1_path.read_bytes()
    c = Checker(v, json.loads(s1_bytes), sha_hex(s1_bytes))
    c.run()
    for f in c.failures:
        print("FAIL", f)
    print(f"checked {c.checked} values, {len(c.failures)} disagreements")
    return 1 if c.failures else 0


if __name__ == "__main__":
    sys.exit(main())
