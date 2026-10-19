"""Second, independent implementation that recomputes every expected value in SPEC-006 vectors.json.

Stdlib only and independent of the core and of generate.py:
- canonical JSON: for these objects (ASCII keys, integers, booleans, strings, no floats), RFC 8785 output equals
  json.dumps with sorted keys, no whitespace and ensure_ascii=False (SPEC-005 R72);
- Ed25519: transcribed from the RFC 8032 section 6 reference code, checked against RFC 8032 section 7.1 TEST 1
  (see the notice above the Ed25519 section);
- raw importer (R20, R27-R29), canonicalizers (R43, R45), commitment lookup keys by stdlib hmac (R46), registry
  builder (R60-R68 with SPEC-005 R31, R33, R57), attestation verifier (R50, R77), golden evaluation (R73-R78),
  signed registry heads and variant admission (R81-R83), all written from SPEC-006.
Run: python -I crosscheck.py vectors.json   (exit status 1 on any disagreement)
"""
from __future__ import annotations

import copy
import datetime
import hashlib
import hmac
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


def unhex(s: object) -> bytes:
    try:
        return bytes.fromhex(s) if isinstance(s, str) else b""
    except ValueError:
        return b""


# ---- Formats (R3) ----
HEX32 = re.compile(r"^[0-9a-f]{64}$")
SIG = re.compile(r"^[0-9a-f]{128}$")
TOOL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,63}$")
MEMORY_ID = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
FAMILY_RE = re.compile(r"^[a-z][a-z0-9]*(\.[a-z0-9][a-z0-9_]*)+$")
VARIANT_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
DTC_RE = re.compile(r"^[PCBU][0-3][0-9A-F]{3}(-[0-9A-F]{2})?$")
UNIT_RE = re.compile(r"^[A-Z0-9]{4,40}$")
TS_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
DUMP_KINDS = {"bench_full", "boot_full", "obd_full", "obd_partial", "virtual"}
MAX_INPUT_BYTES = 64 * 1024 * 1024


def is_hex32(x: object) -> bool:
    return isinstance(x, str) and bool(HEX32.match(x))


def matches(rx: re.Pattern[str], x: object) -> bool:
    return isinstance(x, str) and bool(rx.match(x))


# ---- Raw importer (R20, R27-R29) ----
def input_bytes(spec: dict) -> bytes:
    if "hex" in spec:
        return bytes.fromhex(spec["hex"])
    return bytes([spec["fill"]["byte"]]) * spec["fill"]["size"]


def run_raw_import(data: bytes, params: object, importer_version: str) -> dict:
    def rej(reason: str, ck: str | None) -> dict:
        return {"outcome": "rejected", "rejection": {"reason": reason, "container_kind": ck}}

    if (
        not isinstance(params, dict)
        or set(params) != {"dump_kind", "source_tool", "options"}
        or params["dump_kind"] not in DUMP_KINDS
        or not (params["source_tool"] is None or matches(TOOL, params["source_tool"]))
        or not isinstance(params["options"], dict)
    ):
        return rej("bad_params", None)
    if len(data) > MAX_INPUT_BYTES:
        return rej("too_large", None)
    opts = params["options"]
    if set(opts) != {"memory_id"} or not matches(MEMORY_ID, opts["memory_id"]):
        return rej("bad_params", "raw")
    if not data:
        return rej("empty_input", "raw")
    mid = opts["memory_id"]
    image = {"dump_kind": params["dump_kind"], "memories": [{"memory_id": mid, "base_address": None, "size": len(data), "sha256": sha_hex(data)}]}
    record = {
        "schema": "impact.import-record.v1",
        "importer_id": "impact.raw",
        "importer_version": importer_version,
        "source_tool": params["source_tool"],
        "container_kind": "raw",
        "input_sha256": sha_hex(data),
        "dump_kind": params["dump_kind"],
        "options": {"memory_id": mid},
        "image_hash": sha_obj(image),
    }
    return {"outcome": "imported", "data": data, "memory_id": mid, "dump_kind": params["dump_kind"], "image_jcs": canon(image), "record": record}


# ---- Canonicalizers (R43, R46) ----
class Reject(Exception):
    pass


def canonical_dtcs(raw: list[str]) -> list[str]:
    out = set()
    for r in raw:
        c = r.strip(" \t\n\r\f\v")
        c = "".join(ch.upper() if "a" <= ch <= "z" else ch for ch in c)
        if not DTC_RE.match(c):
            raise Reject("bad_dtc")
        out.add(c)
    return sorted(out)


def canonical_unit_id(raw: str) -> str:
    c = "".join(ch.upper() if "a" <= ch <= "z" else ch for ch in raw if ch not in " -./:_")
    if not UNIT_RE.match(c):
        raise Reject("bad_unit_id")
    return c


# ---- Registry (R60-R68) from the chain ----
TEST_KEY_NAMES = ["registry", "attester-a", "attester-a2", "attester-b", "attester-c", "attester-d", "attester-e", "reviewer-f", "attester-r"]
RETROACTIVE = {"compromised", "misconduct", "error"}


def test_key_ids() -> set[str]:
    out = set()
    for n in TEST_KEY_NAMES:
        seed = hashlib.sha256(f"impact spec-006 synthetic {n} key; never use outside test vectors".encode("utf-8")).digest()
        out.add(sha_hex(public_key(seed)))
    return out


TEST_KEYS = test_key_ids()
EVENT_KEYS = {"schema", "tenant_id", "seq", "event_id", "project_id", "type", "payload", "actor", "ts", "prev_hash", "hash"}
R57_TYPES = ("attester_enrolled", "attester_revoked", "attestation_included")


def review_hash(tenant: str, genesis: str, pl: dict) -> str:
    return sha_obj(
        {
            "schema": "impact.review.v1",
            "tenant_id": tenant,
            "genesis_hash": genesis,
            "subject_kind": pl["subject_kind"],
            "export_ref": pl["export_ref"],
            "subject_hash": pl["subject_hash"],
            "decision": pl["decision"],
        }
    )


def build_registry(events: list[dict], head: int, test_mode: bool) -> dict:
    """Raises Reject('registry_broken') when the chain does not verify (R65)."""
    evs = sorted([e for e in events if e["seq"] <= head], key=lambda e: e["seq"])
    g = evs[0]
    gp = g["payload"]
    if not (g["seq"] == 0 and g["type"] == "genesis" and g["prev_hash"] == "0" * 64 and g["actor"]["kind"] == "system" and len(gp["signing_keys"]) == 1):
        raise Reject("registry_broken")
    chain_keys = {k["key_id"]: unhex(k["public_key"]) for k in gp["signing_keys"]}
    for k_id, pub in chain_keys.items():
        if sha_hex(pub) != k_id or (k_id in TEST_KEYS and not test_mode):
            raise Reject("registry_broken")
    att: dict[str, dict] = {}
    successors: set[str] = set()
    inclusions: dict[str, dict] = {}
    reviews: list[dict] = []
    findings: list[dict] = []

    def usable(k_id: str, role: str, seq: int) -> str | None:
        e = att.get(k_id)
        if e is None:
            return "unknown"
        if e["revoked"] is not None and e["revoked"]["seq"] < seq:
            return "revoked"
        if role not in e["roles"]:
            return "role"
        return None

    prev = None
    for ev in evs:
        if set(ev) != EVENT_KEYS or sha_obj({k: v for k, v in ev.items() if k != "hash"}) != ev["hash"]:
            raise Reject("registry_broken")
        if prev is not None and (ev["seq"] != prev["seq"] + 1 or ev["prev_hash"] != prev["hash"] or ev["tenant_id"] != g["tenant_id"]):
            raise Reject("registry_broken")
        prev = ev
        typ, pl, seq = ev["type"], ev["payload"], ev["seq"]
        if typ in R57_TYPES:
            body = {k: v for k, v in pl.items() if k != "signature"}
            kh = sha_obj({"schema": "impact.key-event.v1", "tenant_id": ev["tenant_id"], "genesis_hash": g["hash"], "seq": seq, "type": typ, "payload": body})
            signer = chain_keys.get(pl["signer_key_id"])
            if signer is None or not verify(signer, signing_input("impact.key-event-signature.v1", kh), unhex(pl["signature"])):
                raise Reject("registry_broken")
        if typ == "attester_enrolled":
            k_id = pl["attester_key_id"]
            if ev["actor"]["kind"] != "user" or not is_hex32(pl["reason_commitment"]) or sha_hex(unhex(pl["public_key"])) != k_id:
                raise Reject("registry_broken")
            if k_id in TEST_KEYS and not test_mode:
                findings.append({"seq": seq, "reason": "test_key"})
                continue
            if k_id in att:
                findings.append({"seq": seq, "reason": "already_enrolled"})
                continue
            rot = pl["rotates"]
            if rot is not None:
                old = att.get(rot)
                ok = old is not None and rot not in successors and not (old["revoked"] is not None and old["revoked"]["reason"] in RETROACTIVE)
                if ok:
                    rh = sha_obj(
                        {
                            "schema": "impact.attester-rotation.v1",
                            "tenant_id": ev["tenant_id"],
                            "genesis_hash": g["hash"],
                            "old_key_id": rot,
                            "new_key_id": k_id,
                            "new_public_key": pl["public_key"],
                        }
                    )
                    ok = verify(unhex(old["public_key"]), signing_input("impact.attester-rotation-signature.v1", rh), unhex(pl["rotation_signature"]))
                if not ok:
                    findings.append({"seq": seq, "reason": "bad_rotation"})
                    continue
                successors.add(rot)
            elif pl["rotation_signature"] is not None:
                raise Reject("registry_broken")
            att[k_id] = {
                "attester_key_id": k_id,
                "public_key": pl["public_key"],
                "roles": pl["roles"],
                "identity": k_id if rot is None else att[rot]["identity"],
                "enrolled_seq": seq,
                "revoked": None,
            }
        elif typ == "attester_revoked":
            k_id = pl["attester_key_id"]
            if k_id not in att:
                findings.append({"seq": seq, "reason": "unknown_attester"})
            elif att[k_id]["revoked"] is not None:
                findings.append({"seq": seq, "reason": "already_revoked"})
            else:
                att[k_id]["revoked"] = {"seq": seq, "reason": pl["reason"]}
        elif typ == "attestation_included":
            u = usable(pl["attester_key_id"], "attester", seq + 1)
            if u is not None:
                findings.append({"seq": seq, "reason": {"unknown": "unknown_attester", "revoked": "revoked_attester", "role": "not_attester"}[u]})
            elif pl["attestation_hash"] in inclusions:
                findings.append({"seq": seq, "reason": "already_included"})
            else:
                inclusions[pl["attestation_hash"]] = {"attestation_hash": pl["attestation_hash"], "attester_key_id": pl["attester_key_id"], "seq": seq}
        elif typ == "review" and pl["subject_kind"] == "golden_record":
            u = usable(pl["reviewer_key_id"], "reviewer", seq + 1)
            if u is not None:
                findings.append({"seq": seq, "reason": {"unknown": "unknown_reviewer", "revoked": "revoked_reviewer", "role": "not_reviewer"}[u]})
            elif not verify(unhex(att[pl["reviewer_key_id"]]["public_key"]), signing_input("impact.review-signature.v1", review_hash(ev["tenant_id"], g["hash"], pl)), unhex(pl["signature"])):
                findings.append({"seq": seq, "reason": "bad_signature"})
            else:
                reviews.append({"golden_record_hash": pl["subject_hash"], "decision": pl["decision"], "reviewer_key_id": pl["reviewer_key_id"], "seq": seq})
    last = evs[-1]
    return {
        "schema": "impact.attester-registry.v1",
        "tenant_id": g["tenant_id"],
        "genesis_hash": g["hash"],
        "head": {"seq": last["seq"], "hash": last["hash"]},
        "attesters": [att[k] for k in sorted(att)],
        "inclusions": [inclusions[h] for h in sorted(inclusions)],
        "record_reviews": sorted(reviews, key=lambda r: (r["golden_record_hash"], r["seq"])),
        "findings": sorted(findings, key=lambda f: (f["seq"], f["reason"])),
    }


# ---- Attestations (R40-R52) ----
ATT_KEYS = {
    "schema", "subject_image_hash", "identification", "write_tool", "readback_image_hash", "communicates",
    "dtcs_after_clear_and_reread", "tool_checksum_status", "ecu_commitment", "ecu_commitment_epoch", "attester_key_id", "created_at",
}


def att_shape_ok(a: object) -> bool:
    if not isinstance(a, dict) or set(a) != ATT_KEYS or a["schema"] != "impact.field-attestation.v1":
        return False
    idn, wt, dtcs = a["identification"], a["write_tool"], a["dtcs_after_clear_and_reread"]
    com, ep = a["ecu_commitment"], a["ecu_commitment_epoch"]
    return (
        is_hex32(a["subject_image_hash"])
        and isinstance(idn, dict)
        and set(idn) == {"family", "hw_id", "sw_id", "checksum_variant_id"}
        and matches(FAMILY_RE, idn["family"])
        and matches(VARIANT_RE, idn["checksum_variant_id"])
        and all(v is None or isinstance(v, str) for v in (idn["hw_id"], idn["sw_id"]))
        and isinstance(wt, dict)
        and set(wt) == {"name", "version"}
        and matches(TOOL, wt["name"])
        and isinstance(wt["version"], str)
        and 0 < len(wt["version"]) <= 64
        and (a["readback_image_hash"] is None or is_hex32(a["readback_image_hash"]))
        and isinstance(a["communicates"], bool)
        and isinstance(dtcs, list)
        and all(matches(DTC_RE, x) for x in dtcs)
        and dtcs == sorted(set(dtcs))
        and a["tool_checksum_status"] in ("ok", "mismatch", "not_reported")
        and ((com is None and ep is None) or (is_hex32(com) and is_hex32(ep)))
        and is_hex32(a["attester_key_id"])
        and matches(TS_RE, a["created_at"])
    )


def verify_attestation(sa: dict, registry: dict) -> list[str]:
    if not isinstance(sa, dict) or set(sa) != {"attestation", "attestation_hash", "signature"} or not att_shape_ok(sa["attestation"]):
        return ["bad_shape"]
    if not is_hex32(sa["attestation_hash"]) or not matches(SIG, sa["signature"]):
        return ["bad_shape"]
    a = sa["attestation"]
    if sha_obj(a) != sa["attestation_hash"]:
        return ["attestation_hash_mismatch"]
    entry = next((x for x in registry["attesters"] if x["attester_key_id"] == a["attester_key_id"]), None)
    if entry is None:
        return ["unknown_attester"]
    rv = entry["revoked"]
    if rv is not None:
        inc = next((i for i in registry["inclusions"] if i["attestation_hash"] == sa["attestation_hash"] and i["attester_key_id"] == a["attester_key_id"]), None)
        if not (rv["reason"] == "retired" and inc is not None and inc["seq"] < rv["seq"]):
            return ["revoked_attester"]
    if "attester" not in entry["roles"]:
        return ["not_attester"]
    if not verify(unhex(entry["public_key"]), signing_input("impact.field-attestation-signature.v1", sa["attestation_hash"]), unhex(sa["signature"])):
        return ["bad_signature"]
    return []


# ---- Evaluation (R73-R78) ----
def evaluate(record: dict, supplied: list[dict], registry: dict, dtc_set: dict, epoch: str) -> dict:
    exp = record["expected_image_hash"]
    rows = []
    q_hashes, identities, units = set(), set(), set()
    negative_any = False
    ident_of = {x["attester_key_id"]: x["identity"] for x in registry["attesters"]}
    for h in record["oracle"]["attestations"]:
        cands = [s for s in supplied if s.get("attestation_hash") == h]
        good = [s for s in cands if isinstance(s.get("attestation"), dict) and sha_obj(s["attestation"]) == h]
        pool = good or sorted(cands, key=canon)
        chosen = pool[0] if pool else None
        negative = False
        if chosen is None:
            reasons = ["missing"]
        else:
            reasons = verify_attestation(chosen, registry)
            if not reasons:
                a = chosen["attestation"]
                rel = []
                if a["identification"]["family"] != record["family"] or a["identification"]["checksum_variant_id"] != record["checksum_variant_id"]:
                    rel.append("wrong_variant")
                if a["subject_image_hash"] != exp:
                    rel.append("wrong_subject")
                if a["ecu_commitment_epoch"] is not None and a["ecu_commitment_epoch"] != epoch:
                    rel.append("foreign_epoch")
                if a["write_tool"]["name"].lower().startswith("impact"):
                    rel.append("impact_write_tool")
                reasons = rel
                if not rel:
                    out = []
                    if not a["communicates"]:
                        out.append("no_communication")
                    if any(d[:5] in dtc_set["codes"] for d in a["dtcs_after_clear_and_reread"]):
                        out.append("disqualifying_dtc")
                    if a["tool_checksum_status"] == "mismatch":
                        out.append("tool_checksum_mismatch")
                    if a["readback_image_hash"] is not None and a["readback_image_hash"] != a["subject_image_hash"]:
                        out.append("readback_mismatch")
                    reasons = out
                    negative = bool(out)
                    if not out:
                        if a["ecu_commitment"] is None:
                            reasons = ["no_unit_commitment"]
                        else:
                            q_hashes.add(h)
                            identities.add(ident_of[a["attester_key_id"]])
                            units.add(a["ecu_commitment"])
        negative_any = negative_any or negative
        rows.append({"attestation_hash": h, "qualifying": not reasons, "negative": negative, "reasons": sorted(reasons)})
    rec_reasons = set()
    if len(q_hashes) < 2:
        rec_reasons.add("below_attestations")
    if len(identities) < 2:
        rec_reasons.add("below_attesters")
    if len(units) < 2:
        rec_reasons.add("below_units")
    if negative_any:
        rec_reasons.add("negative_field_evidence")
    tools = record["oracle"]["tools"]
    match = [t for t in tools if t["image_hash"] == exp]
    if any(t["image_hash"] != exp for t in tools):
        rec_reasons.add("tool_disagreement")
    if not rec_reasons & {"below_attestations", "below_attesters", "below_units", "negative_field_evidence"}:
        level = "golden_field"
    elif len({t["name"] for t in match}) >= 2 and "tool_disagreement" not in rec_reasons:
        level = "golden_concordant"
    elif match:
        level = "candidate"
    else:
        level = "none"
    return {
        "schema": "impact.golden-evaluation.v1",
        "golden_record_hash": sha_obj(record),
        "registry_hash": sha_obj(registry),
        "dtc_set_hash": sha_obj(dtc_set),
        "commitment_epoch": epoch,
        "thresholds": {"attestations": 2, "attesters": 2, "units": 2},
        "counts": {"attestations": len(q_hashes), "attesters": len(identities), "units": len(units)},
        "attestations": sorted(rows, key=lambda r: r["attestation_hash"]),
        "reasons": sorted(rec_reasons),
        "level": level,
    }


# ---- Signed registry head and admission (R81-R84) ----
def instant(ts: str) -> int:
    return int(datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc).timestamp())


def admit(sh: dict, registry: dict, records: list[dict], supplied: list[dict], trust: dict, policy: dict, as_of: str, dtc_set: dict, epoch: str, test_mode: bool) -> dict:
    def unavailable(reasons: list[str]) -> dict:
        return {"schema": "impact.evidence-admission.v1", "status": "unavailable", "reasons": sorted(reasons), "head_digest": None, "variants": []}

    h = sh["head"]
    if (
        h["tenant_id"] != trust["tenant_id"]
        or h["genesis_hash"] != trust["genesis_hash"]
        or sh["key_id"] != trust["key_id"]
        or (sh["key_id"] in TEST_KEYS and not test_mode)
        or sha_obj(h) != sh["head_digest"]
        or not verify(unhex(trust["public_key"]), signing_input("impact.registry-head-signature.v1", sh["head_digest"]), unhex(sh["signature"]))
    ):
        return unavailable(["untrusted_head"])
    reasons = []
    t, i, x = instant(as_of), instant(h["issued_at"]), instant(h["expires_at"])
    if not i <= t:
        reasons.append("head_not_yet_valid")
    if not t < x:
        reasons.append("head_expired")
    if x - i > policy["max_validity_s"]:
        reasons.append("head_validity_too_long")
    if sha_obj(registry) != h["registry_hash"] or registry["head"] != {"seq": h["seq"], "hash": h["head_hash"]}:
        reasons.append("registry_mismatch")
    if reasons:
        return unavailable(reasons)
    groups: dict[tuple[str, str], list[dict]] = {}
    for r in records:
        groups.setdefault((r["family"], r["checksum_variant_id"]), []).append(r)
    ident_of = {x["attester_key_id"]: x["identity"] for x in registry["attesters"]}
    variants = []
    for (fam, var), recs in sorted(groups.items()):
        evs = [evaluate(r, supplied, registry, dtc_set, epoch) for r in recs]
        vreasons = set()
        if not any(e["level"] == "golden_field" for e in evs):
            vreasons.add("no_golden_field")
        for r, e in zip(recs, evs):
            if "negative_field_evidence" not in e["reasons"]:
                continue
            rh = sha_obj(r)
            att_idents = set()
            for s in supplied:
                if s["attestation_hash"] in r["oracle"]["attestations"] and s["attestation"]["attester_key_id"] in ident_of:
                    att_idents.add(ident_of[s["attestation"]["attester_key_id"]])
            valid = []
            for rv in registry["record_reviews"]:
                if rv["golden_record_hash"] != rh:
                    continue
                rk = next(a for a in registry["attesters"] if a["attester_key_id"] == rv["reviewer_key_id"])
                if rk["revoked"] is not None and not (rk["revoked"]["reason"] == "retired" and rv["seq"] < rk["revoked"]["seq"]):
                    continue
                if rk["identity"] in att_idents:
                    continue
                valid.append(rv["decision"])
            if "rejected" in valid:
                vreasons.add("rejected_negative")
            elif "approved" not in valid:
                vreasons.add("unreviewed_negative")
        variants.append(
            {
                "family": fam,
                "checksum_variant_id": var,
                "golden_field": not vreasons,
                "reasons": sorted(vreasons),
                "evaluations": sorted(sha_obj(e) for e in evs),
            }
        )
    return {"schema": "impact.evidence-admission.v1", "status": "current", "reasons": [], "head_digest": sh["head_digest"], "variants": variants}


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

    def run(self) -> None:
        v, s1 = self.v, self.s1
        self.expect("generator.spec001_vectors_sha256", v["generator"]["spec001_vectors_sha256"], self.s1_sha)

        t1 = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        self.expect("rfc8032.test1.public", public_key(t1).hex(), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        t1sig = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        self.expect("rfc8032.test1.signature", sign(t1, b"").hex(), t1sig)

        cases1 = {c["id"]: c for c in s1["cases"]}
        inp = v["spec001_inputs"]
        self.expect("spec001.base", inp["base_image_hash"], s1["original"]["image_hash"])
        self.expect("spec001.version", inp["version_hash"], cases1["V4-apply-disjoint"]["expect"]["version_hash"])
        self.expect("spec001.golden", inp["golden_image_hash"], cases1["V9-checksum-patch"]["expect"]["image_hash"])
        self.expect("spec001.other", inp["other_image_hash"], cases1["V4-apply-disjoint"]["expect"]["image_hash"])

        # Keys
        seeds: dict[str, bytes] = {}
        for name, k in v["keys"]["keys"].items():
            self.expect(f"keys.{name}.seed_text", k["seed_text"], f"impact spec-006 synthetic {name} key; never use outside test vectors")
            seed = hashlib.sha256(k["seed_text"].encode("utf-8")).digest()
            seeds[k["key_id"]] = seed
            pub = public_key(seed)
            self.expect(f"keys.{name}.public_key", pub.hex(), k["public_key"])
            self.expect(f"keys.{name}.key_id", sha_hex(pub), k["key_id"])
        self.expect("keys.test_keys", {k["key_id"] for k in v["keys"]["keys"].values()}, TEST_KEYS)

        # Raw importer
        ri = v["raw_import"]
        self.expect("raw.max_input_bytes", ri["max_input_bytes"], MAX_INPUT_BYTES)
        for c in ri["cases"]:
            data = input_bytes(c["input"])
            got = run_raw_import(data, c["params"], ri["importer_version"])
            want = c["expect"]
            if want["outcome"] == "rejected":
                self.expect(f"raw.{c['id']}", got, want)
                continue
            self.expect(f"raw.{c['id']}.outcome", got["outcome"], "imported")
            if got["outcome"] != "imported":
                continue
            mem = want["dump"]["memories"]
            self.expect(f"raw.{c['id']}.dump", (want["dump"]["dump_kind"], len(mem), mem[0]["memory_id"], mem[0]["base_address"]), (got["dump_kind"], 1, got["memory_id"], None))
            self.expect(f"raw.{c['id']}.data", input_bytes(mem[0]["data"]), got["data"])
            self.expect(f"raw.{c['id']}.image_jcs", got["image_jcs"], want["image_jcs"])
            self.expect(f"raw.{c['id']}.record", got["record"], want["record"])
            self.expect(f"raw.{c['id']}.record_jcs", canon(got["record"]), want["record_jcs"])
            self.expect(f"raw.{c['id']}.import_record_hash", sha_obj(got["record"]), want["import_record_hash"])

        # DTCs
        for i, c in enumerate(v["dtcs"]["canonical"]):
            self.expect(f"dtcs.canonical[{i}]", canonical_dtcs(c["raw"]), c["expect"])
        for i, c in enumerate(v["dtcs"]["invalid"]):
            try:
                canonical_dtcs(c["raw"])
                got_r = None
            except Reject as e:
                got_r = str(e)
            self.expect(f"dtcs.invalid[{i}]", got_r, c["reason"])

        # Unit ids and the commitment service (lookup keys by HMAC; the table values are the service's data)
        for i, c in enumerate(v["unit_ids"]["canonical"]):
            self.expect(f"unit_ids.canonical[{i}]", canonical_unit_id(c["raw"]), c["expect"])
        for i, c in enumerate(v["unit_ids"]["invalid"]):
            try:
                canonical_unit_id(c["raw"])
                got_r = None
            except Reject as e:
                got_r = str(e)
            self.expect(f"unit_ids.invalid[{i}]", got_r, c["reason"])
        cs = v["commitment_service"]
        secret = hashlib.sha256(cs["secret_text"].encode("utf-8")).digest()
        self.expect("commitment.secret", secret.hex(), cs["secret_hex"])

        def lk(sec: bytes, unit_id: str) -> tuple[str, str]:
            msg = canon({"schema": "impact.ecu-unit.v1", "family": cs["family"], "unit_id": unit_id})
            return msg, hmac.new(sec, msg.encode("utf-8"), hashlib.sha256).hexdigest()

        table: dict[str, str] = {}
        for u in cs["units"]:
            msg, key = lk(secret, u["unit_id"])
            self.expect(f"commitment.{u['unit']}.input", msg, u["lookup_input"])
            self.expect(f"commitment.{u['unit']}.lookup_key", key, u["lookup_key"])
            self.expect(f"commitment.{u['unit']}.is_hex32", is_hex32(u["ecu_commitment"]), True)
            table[u["unit"]] = u["ecu_commitment"]
        self.expect("commitment.table_distinct", len(set(table.values())), len(table))
        se = cs["second_epoch"]
        for u in se["units"]:
            self.expect(f"commitment.epoch2.{u['unit']}.lookup_key", lk(bytes.fromhex(se["secret_hex"]), u["unit_id"])[1], u["lookup_key"])
            self.expect(f"commitment.epoch2.{u['unit']}.differs", u["ecu_commitment"] != table[u["unit"]], True)
        self.expect("commitment.epochs_differ", cs["epoch"] != se["epoch"], True)

        # DTC set and head policy
        ds = v["dtc_set"]
        self.expect(
            "dtc_set.value",
            ds["value"],
            {"schema": "impact.disqualifying-dtcs.v1", "version": 1, "codes": ["P0601", "P0602", "P0603", "P0604", "P0605", "P0606", "P0607", "P060A", "P062F"]},
        )
        self.expect("dtc_set.sorted", ds["value"]["codes"], sorted(set(ds["value"]["codes"])))
        self.expect("dtc_set.jcs", canon(ds["value"]), ds["jcs"])
        self.expect("dtc_set.hash", sha_obj(ds["value"]), ds["dtc_set_hash"])
        hp = v["head_policy"]
        self.expect("head_policy.value", hp["value"], {"schema": "impact.head-policy.v1", "version": 1, "max_validity_s": 86400})
        self.expect("head_policy.hash", sha_obj(hp["value"]), hp["head_policy_hash"])

        # Registry chain and registries
        events = [e["event"] for e in v["registry_chain"]["events"]]
        for i, e in enumerate(v["registry_chain"]["events"]):
            self.expect(f"registry_chain[{i}].hash", sha_obj({k: x for k, x in e["event"].items() if k != "hash"}), e["hash"])
        heads = {"pre": 9, "post": 12, "reviewed": 13}
        built = {name: build_registry(events, seq, True) for name, seq in heads.items()}
        for name, rg in v["registries"].items():
            self.expect(f"registries.{name}", built[name], rg["value"])
            self.expect(f"registries.{name}.hash", sha_obj(built[name]), rg["registry_hash"])
        # Re-sign every signed registry event with the seeds and compare bytes.
        g = events[0]
        s_seed = seeds[g["payload"]["signing_keys"][0]["key_id"]]
        for ev in events[1:]:
            pl = ev["payload"]
            if ev["type"] in R57_TYPES:
                body = {k: x for k, x in pl.items() if k != "signature"}
                kh = sha_obj({"schema": "impact.key-event.v1", "tenant_id": ev["tenant_id"], "genesis_hash": g["hash"], "seq": ev["seq"], "type": ev["type"], "payload": body})
                self.expect(f"registry_chain[{ev['seq']}].resign", sign(s_seed, signing_input("impact.key-event-signature.v1", kh)).hex(), pl["signature"])
            if ev["type"] == "attester_enrolled" and pl["rotates"] is not None:
                rh = sha_obj({"schema": "impact.attester-rotation.v1", "tenant_id": ev["tenant_id"], "genesis_hash": g["hash"], "old_key_id": pl["rotates"], "new_key_id": pl["attester_key_id"], "new_public_key": pl["public_key"]})
                self.expect(f"registry_chain[{ev['seq']}].rotation_resign", sign(seeds[pl["rotates"]], signing_input("impact.attester-rotation-signature.v1", rh)).hex(), pl["rotation_signature"])
            if ev["type"] == "review":
                self.expect(f"registry_chain[{ev['seq']}].review_resign", sign(seeds[pl["reviewer_key_id"]], signing_input("impact.review-signature.v1", review_hash(ev["tenant_id"], g["hash"], pl))).hex(), pl["signature"])

        # Attestations
        pool = v["attestations"]
        av = v["attestation_verify"]
        ex = av["example"]
        axs = pool[ex["label"]]
        self.expect("attestation.example.jcs", canon(axs["attestation"]), ex["attestation_jcs"])
        self.expect("attestation.example.hash", sha_obj(axs["attestation"]), ex["attestation_hash"])
        msg = signing_input("impact.field-attestation-signature.v1", ex["attestation_hash"])
        self.expect("attestation.example.signing_input", msg.decode("utf-8"), ex["signing_input"])
        self.expect("attestation.example.resign", sign(seeds[axs["attestation"]["attester_key_id"]], msg).hex(), ex["signature"])
        self.expect("attestation.example.stored_signature", axs["signature"], ex["signature"])
        epoch = cs["epoch"]
        for label, sa in pool.items():
            com = sa["attestation"]["ecu_commitment"]
            self.expect(f"attestation.{label}.commitment_from_service", com is None or com in table.values() or com in [u["ecu_commitment"] for u in se["units"]], True)
        for c in av["cases"]:
            self.expect(f"attestation_verify.{c['label']}.{c['registry']}", verify_attestation(pool[c["label"]], built[c["registry"]]), c["expect"])

        # Evaluations
        for c in v["evaluations"]:
            supplied = [pool[x] for x in c["supplied"]]
            self.expect(f"eval.{c['id']}.record_hash", sha_obj(c["record"]), c["golden_record_hash"])
            try:
                reg = build_registry(events, heads[c["registry"]] if c["registry"] else 9, c["test_mode"])
                got = {"evaluation": evaluate(c["record"], supplied, reg, ds["value"], epoch)}
                got["evaluation_hash"] = sha_obj(got["evaluation"])
            except Reject as e:
                got = {"error": str(e)}
            self.expect(f"eval.{c['id']}", got, c["expect"])
            if "evaluation" in got:
                rev = evaluate(c["record"], list(reversed(supplied)), reg, ds["value"], epoch)
                self.expect(f"eval.{c['id']}.order", rev, got["evaluation"])

        # Heads and admissions
        hv = v["heads"]
        trust = v["trust"]
        self.expect("trust.key", (trust["key_id"], trust["public_key"]), (g["payload"]["signing_keys"][0]["key_id"], g["payload"]["signing_keys"][0]["public_key"]))
        self.expect("trust.genesis", (trust["tenant_id"], trust["genesis_hash"]), (g["tenant_id"], g["hash"]))
        post = hv["values"]["post"]
        self.expect("heads.example.jcs", canon(post["head"]), hv["example"]["head_jcs"])
        self.expect("heads.example.digest", sha_obj(post["head"]), hv["example"]["head_digest"])
        hmsg = signing_input("impact.registry-head-signature.v1", post["head_digest"])
        self.expect("heads.example.signing_input", hmsg.decode("utf-8"), hv["example"]["signing_input"])
        for name in ("post", "reviewed", "too_long"):
            sh = hv["values"][name]
            self.expect(f"heads.{name}.resign", sign(s_seed, signing_input("impact.registry-head-signature.v1", sh["head_digest"])).hex(), sh["signature"])
        all_att = list(pool.values())
        for c in v["admissions"]:
            got = admit(hv["values"][c["head"]], built[c["registry"]], c["records"], all_att, trust, hp["value"], c["as_of"], ds["value"], epoch, c["test_mode"])
            self.expect(f"admission.{c['id']}", got, c["expect"])


def main() -> int:
    path = pathlib.Path(sys.argv[1]).resolve()
    v = json.loads(path.read_text(encoding="utf-8"))
    s1_path = path.parent.parent / "spec-001" / "vectors.json"
    s1_bytes = s1_path.read_bytes()
    c = Checker(copy.deepcopy(v), json.loads(s1_bytes), sha_hex(s1_bytes))
    c.run()
    for f in c.failures:
        print("FAIL", f)
    print(f"checked {c.checked} values, {len(c.failures)} disagreements")
    return 1 if c.failures else 0


if __name__ == "__main__":
    sys.exit(main())
