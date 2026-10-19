"""Generate SPEC-005 test vectors.

Independent of the core. JCS comes from the third-party `rfc8785` package, Ed25519 from the third-party
`cryptography` package (both pinned in requirements.txt), SHA-256 from hashlib. Every SPEC-001 hash is read from
specs/vectors/spec-001/vectors.json, never recomputed here. All data is synthetic.
Expected tamper findings are written by hand below; crosscheck.py derives them with its own verifier.
Run: python -I generate.py > vectors.json   then   python -I crosscheck.py vectors.json
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import pathlib
import sys

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = pathlib.Path(__file__).resolve().parent
SPEC001_PATH = HERE.parent / "spec-001" / "vectors.json"
SPEC001_BYTES = SPEC001_PATH.read_bytes()
S1 = json.loads(SPEC001_BYTES)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def jcs(obj: object) -> str:
    return rfc8785.dumps(obj).decode("utf-8")


def ohash(obj: object) -> str:
    return sha(rfc8785.dumps(obj))


# RFC 8032 section 7.1, TEST 1: the library must reproduce the published vector before it is trusted.
_t1 = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
assert _t1.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex() == (
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)
assert _t1.sign(b"").hex() == (
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)

SEED_TEXT = "impact spec-005 synthetic test key; never use outside test vectors"
SEED = hashlib.sha256(SEED_TEXT.encode("utf-8")).digest()
KEY = Ed25519PrivateKey.from_private_bytes(SEED)
PUBLIC_KEY = KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
KEY_ID = sha(bytes.fromhex(PUBLIC_KEY))
SEED2_TEXT = "impact spec-005 synthetic second key; never use outside test vectors"
KEY2 = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(SEED2_TEXT.encode("utf-8")).digest())
PUBLIC_KEY2 = KEY2.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
KEY2_ID = sha(bytes.fromhex(PUBLIC_KEY2))


def signature(domain: str, h: str, key: Ed25519PrivateKey = KEY) -> tuple[str, str]:
    message = jcs({"domain": domain, "hash": h})
    return message, key.sign(message.encode("utf-8")).hex()


# --- SPEC-001 inputs (read, not recomputed) ---
cases = {c["id"]: c for c in S1["cases"]}
ORIGINAL_HASH = S1["original"]["image_hash"]
LAYOUT_HASH = S1["layouts"]["base"]["layout_hash"]
PH = {n: p["patch_hash"] for n, p in S1["patches"].items()}
APPLY_HASH = cases["V4-apply-disjoint"]["expect"]["image_hash"]
VERSION_HASH = cases["V4-apply-disjoint"]["expect"]["version_hash"]
RELEASE_HASH = cases["V9-checksum-patch"]["expect"]["image_hash"]
V8 = cases["V8-diff-reports-foreign-changes"]

FINDING = {"rule_id": "synthetic.rule.1", "severity": "warn", "text": "synthetic warning text"}
FINDING_ID = ohash(FINDING)
GATE_REPORT = {
    "schema": "synthetic.gate-report.v0",
    "note": "synthetic placeholder; SPEC-004 defines the real gate report",
    "verdict": "warn",
    "findings": [FINDING],
    "subject": {"signed_regions": []},
}
GATE_REPORT_HASH = ohash(GATE_REPORT)
GATE_REPORT_NF = {
    "schema": "synthetic.gate-report.v0",
    "note": "synthetic placeholder; SPEC-004 defines the real gate report",
    "verdict": "no findings",
    "findings": [],
    "subject": {"signed_regions": []},
}
GATE_REPORT_NF_HASH = ohash(GATE_REPORT_NF)
INPUT_REPORT = {
    "schema": "synthetic.input-gate-report.v0",
    "note": "synthetic placeholder; SPEC-004 defines the real input gate report",
    "verdict": "block",
    "findings": [{"rule_id": "G-INPUT-VERIFY", "severity": "block", "text": "input verify returned fail"}],
}
INPUT_REPORT_HASH = ohash(INPUT_REPORT)

TENANT = "tenant-synthetic-1"
PROJECT = "project-synthetic-1"
USER = {"kind": "user", "id": "user-synthetic-1"}
SYSTEM = {"kind": "system", "id": "system"}
ZERO = "0" * 64

# Synthetic "file as received": pflash bytes followed by dflash bytes.
ARTIFACT_SHA256 = sha(
    bytes.fromhex(S1["original"]["memories"]["pflash"]["bytes_hex"])
    + bytes.fromhex(S1["original"]["memories"]["dflash"]["bytes_hex"])
)


def seal(event: dict[str, object]) -> dict[str, object]:
    body = {k: v for k, v in event.items() if k != "hash"}
    return {**body, "hash": ohash(body)}


def make_event(seq: int, prev: str, event_id: str, project: str | None, typ: str, payload: object, actor: object, ts: str) -> dict[str, object]:
    return seal(
        {
            "schema": "impact.event.v1",
            "tenant_id": TENANT,
            "seq": seq,
            "event_id": event_id,
            "project_id": project,
            "type": typ,
            "payload": payload,
            "actor": actor,
            "ts": ts,
            "prev_hash": prev,
        }
    )


e0 = make_event(
    0, ZERO, "00000000000000000000000000000000", None, "genesis",
    {"role": "server", "signing_keys": [{"key_id": KEY_ID, "public_key": PUBLIC_KEY}]}, SYSTEM, "2026-10-18T12:00:00Z",
)
e1 = make_event(
    1, e0["hash"], "00000000000000000000000000000001", PROJECT, "import",
    {"artifact_sha256": ARTIFACT_SHA256, "image_hash": ORIGINAL_HASH, "dump_kind": "bench_full", "origin": "bench_read"},
    USER, "2026-10-18T12:01:00Z",
)
e2 = make_event(
    2, e1["hash"], "00000000000000000000000000000002", PROJECT, "suspect_ack",
    {"artifact_sha256": ARTIFACT_SHA256, "image_hash": ORIGINAL_HASH, "input_report_hash": INPUT_REPORT_HASH, "verify_status": "fail"},
    USER, "2026-10-18T12:01:30Z",
)
e3 = make_event(
    3, e2["hash"], "00000000000000000000000000000003", PROJECT, "alert_ack",
    {
        "image_hash_release": RELEASE_HASH,
        "gate_report_hash": GATE_REPORT_HASH,
        "warnings": [{"finding_id": FINDING_ID, "rule_id": FINDING["rule_id"], "text": FINDING["text"]}],
        "presented_ms": 1792324915000,
        "confirmed_ms": 1792324920000,
    },
    USER, "2026-10-18T12:02:00Z",
)


CONFORMANCE_REPORT_HASH = sha(b"synthetic plugin conformance report")
DEFINITION_HASH = sha(b"synthetic definition")


def ref(ev: dict[str, object]) -> dict[str, object]:
    return {"event_id": ev["event_id"], "seq": ev["seq"], "hash": ev["hash"]}


def provenance(build: dict[str, object], reproducibility: str, *, suspect: bool = True, warn: bool = True) -> dict[str, object]:
    return {
        "schema": "impact.export-provenance.v1",
        "dump_kind": "bench_full",
        "image_hash_original": ORIGINAL_HASH,
        "image_hash_apply": APPLY_HASH,
        "image_hash_release": RELEASE_HASH,
        "layout_hash": LAYOUT_HASH,
        "version_hash": VERSION_HASH,
        "definition_hash": DEFINITION_HASH,
        "patch_hashes": [PH["P1"], PH["P2"]],
        "overlaps": [],
        "checksum_patch_hashes": [PH["Q1"]],
        "versions": {
            "core": "0.0.0-synthetic",
            "plugins": [
                {"family": "synthetic.family", "version": "0.0.0-synthetic", "conformance_report_hash": CONFORMANCE_REPORT_HASH}
            ],
            "gate_rules": "0.0.0-synthetic",
            "references": [{"id": "synthetic.reference", "version": "0.0.0-synthetic"}],
        },
        "gate_report_hash": GATE_REPORT_HASH if warn else GATE_REPORT_NF_HASH,
        "verdict": "warn" if warn else "no findings",
        "alert_ack": ref(e3) if warn else None,
        "input_verify": (
            {"status": "fail", "result": "failed_acknowledged", "suspect_ack": ref(e2)}
            if suspect
            else {"status": "ok", "result": "ok", "suspect_ack": None}
        ),
        "python": {"implementation": "cpython", "version": "3.12.3"},
        "build": build,
        "reproducibility": reproducibility,
    }


PROV = provenance(
    {"kind": "image", "value": "sha256:" + sha(b"synthetic image"), "platform": "linux/amd64", "attestation_id": None},
    "full",
)
PROV_HASH = ohash(PROV)
PROV_NF = provenance(
    {"kind": "image", "value": "sha256:" + sha(b"synthetic image"), "platform": "linux/amd64", "attestation_id": None},
    "full",
    suspect=False,
    warn=False,
)
PROV_LOCK = provenance(
    {"kind": "lockfile", "value": "sha256:" + sha(b"synthetic lockfile"), "platform": "linux/arm64", "attestation_id": None},
    "best_effort",
)

REPORT = {
    "schema": "impact.report.v1",
    "kind": "export",
    "tenant_id": TENANT,
    "genesis_hash": e0["hash"],
    "record": PROV,
    "record_hash": PROV_HASH,
    "signer": {"key_id": KEY_ID, "public_key": PUBLIC_KEY},
    "sections": {
        "what_changed": {
            "patches": [
                {"memory_id": "pflash", "offset": 16, "length": 4, "region_name": "maps_a", "map_id": "synthetic.map.a"},
                {"memory_id": "pflash", "offset": 32, "length": 2, "region_name": "maps_a", "map_id": None},
            ],
            "foreign": [],
        },
        "integrity": {
            "input_verify": "fail",
            "input_result": "failed_acknowledged",
            "candidate_verify": None,
            "verdict": "warn",
            "reproducibility": "full",
            "checksum_patch_count": 1,
        },
        "not_verified": ["firmware_behavior", "map_interaction", "real_engine"],
    },
    "notices": ["emissions_and_regulation", "input_verify_failed_acknowledged"],
    "disclaimer": (
        "This gate verifies file integrity and cell-by-cell plausibility. "
        "It does not verify the combination between maps, firmware behavior, or the real engine."
    ),
}
REPORT_HASH = ohash(REPORT)
REPORT_MSG, REPORT_SIG = signature("impact.report-signature.v1", REPORT_HASH)

e4 = make_event(
    4, e3["hash"], "00000000000000000000000000000004", PROJECT, "export",
    {"provenance_hash": PROV_HASH, "report_hash": REPORT_HASH, "key_id": KEY_ID, "signature": REPORT_SIG},
    USER, "2026-10-18T12:03:00Z",
)
CHAIN = [e0, e1, e2, e3, e4]

ANCHOR = {
    "schema": "impact.anchor.v1",
    "tenant_id": TENANT,
    "genesis_hash": e0["hash"],
    "seq": 4,
    "head_hash": e4["hash"],
    "day": "2026-10-18",
}
ANCHOR_HASH = ohash(ANCHOR)
ANCHOR_MSG, ANCHOR_SIG = signature("impact.anchor-signature.v1", ANCHOR_HASH)

x_pflash = bytes.fromhex(V8["x_pflash_hex"])
x_dflash = bytes.fromhex(V8["x_dflash_hex"])
o_mem = S1["original"]["memories"]
CANDIDATE_IMAGE = {
    "dump_kind": "bench_full",
    "memories": [
        {"memory_id": "dflash", "base_address": o_mem["dflash"]["base_address"], "size": len(x_dflash), "sha256": sha(x_dflash)},
        {"memory_id": "pflash", "base_address": o_mem["pflash"]["base_address"], "size": len(x_pflash), "sha256": sha(x_pflash)},
    ],
}
AUDIT = {
    "schema": "impact.audit-record.v1",
    "dump_kind": "bench_full",
    "image_hash_original": ORIGINAL_HASH,
    "image_hash_candidate": ohash(CANDIDATE_IMAGE),
    "candidate_origin": "file_service",
    "layout_hash": LAYOUT_HASH,
    "diff_patch_hashes": V8["expect"]["patch_hashes"],
    "foreign": V8["expect"]["foreign"],
    "verify": {"original": "ok", "candidate": "bypassed"},
    "versions": PROV["versions"],
    "gate_report_hash": GATE_REPORT_HASH,
    "python": PROV["python"],
    "build": PROV["build"],
    "reproducibility": "full",
}

# --- Generic audit (R110-R115, revision 6) ---
# The V8 candidate with two more synthetic edits: pflash 38..42 crosses the maps_a/maps_b boundary at 40, and
# pflash 47..50 crosses the calibration/protected boundary at 48. No layout is used: neither run is split.
G_EDITS = {"pflash": [(38, 4, 0xFF), (47, 3, 0x5A)]}
g_mem: dict[str, bytes] = {"dflash": x_dflash, "pflash": bytearray(x_pflash)}
for g_offset, g_length, g_mask in G_EDITS["pflash"]:
    for g_i in range(g_offset, g_offset + g_length):
        g_mem["pflash"][g_i] ^= g_mask
g_mem["pflash"] = bytes(g_mem["pflash"])
G_ORIGINAL = {m: bytes.fromhex(o_mem[m]["bytes_hex"]) for m in ("dflash", "pflash")}
G_IMAGE = {
    "dump_kind": "bench_full",
    "memories": [
        {"memory_id": m, "base_address": o_mem[m]["base_address"], "size": len(g_mem[m]), "sha256": sha(g_mem[m])}
        for m in ("dflash", "pflash")
    ],
}
# Synthetic definition spans as byte ranges [start, end) (SPEC-003 R30 resolves them; here they are given), and one
# map whose span failed (SPEC-003 R101 `unbound`). syn.c holds no changed byte.
G_SPANS = {
    "syn.a": [{"memory_id": "pflash", "start": 16, "end": 24}, {"memory_id": "pflash", "start": 36, "end": 40}],
    "syn.b": [{"memory_id": "pflash", "start": 40, "end": 48}],
    "syn.c": [{"memory_id": "dflash", "start": 8, "end": 16}],
}
G_UNBOUND = ["syn.z"]
# Expected by hand: the maximal differing runs (R111) and the maps holding each (R112).
G_CHANGES = [
    ("dflash", 0, 1, []),
    ("pflash", 5, 1, []),
    ("pflash", 20, 1, ["syn.a"]),
    ("pflash", 38, 4, ["syn.a", "syn.b"]),
    ("pflash", 47, 3, ["syn.b"]),
    ("pflash", 62, 1, []),
]
G_OUTSIDE = [("dflash", 0, 1), ("pflash", 5, 1), ("pflash", 48, 2), ("pflash", 62, 1)]


def g_patch_hash(memory_id: str, offset: int, length: int) -> str:
    before, after = G_ORIGINAL[memory_id][offset : offset + length], g_mem[memory_id][offset : offset + length]
    return ohash({"memory_id": memory_id, "offset": offset, "length": length, "before": before.hex(), "after": after.hex()})


def generic(*, definition: bool, reason: str) -> dict[str, object]:
    return {
        "schema": "impact.generic-audit-record.v1",
        "dump_kind": "bench_full",
        "image_hash_original": ORIGINAL_HASH,
        "image_hash_candidate": ohash(G_IMAGE),
        "candidate_origin": "file_service",
        "definition_hash": DEFINITION_HASH if definition else None,
        "changes": [
            {
                "memory_id": m,
                "offset": off,
                "length": n,
                "patch_hash": g_patch_hash(m, off, n),
                "map_ids": maps if definition else [],
            }
            for m, off, n, maps in G_CHANGES
        ],
        "outside_known_maps": [
            {"memory_id": m, "offset": off, "length": n}
            for m, off, n in (G_OUTSIDE if definition else [(c[0], c[1], c[2]) for c in G_CHANGES])
        ],
        "unbound_maps": G_UNBOUND if definition else [],
        "not_evaluated": [
            {"check": "identification", "reason": reason},
            {"check": "layout", "reason": reason},
            {"check": "map_rules", "reason": "no_rule_table" if definition else "no_definition"},
            {"check": "verify", "reason": reason},
        ],
        "checksum_status": "not_verified",
        "versions": {"core": "0.0.0-synthetic"},
        "python": PROV["python"],
        "build": PROV["build"],
        "reproducibility": "full",
    }


GENERIC = generic(definition=True, reason="no_admitted_plugin")
GENERIC_NO_DEFINITION = generic(definition=False, reason="no_admitted_plugin")
GENERIC_NO_RULE_TABLE = generic(definition=True, reason="no_rule_table")

COMMIT_CONTENT = {"text": "synthetic justification typed by a person"}
COMMIT_NONCE = sha(b"synthetic nonce 1")
COMMITMENT = {"schema": "impact.commitment.v1", "nonce": COMMIT_NONCE, "content": COMMIT_CONTENT}

def finding(seq: int, reason: str, *, informational: bool = False, missing: dict[str, int] | None = None) -> dict[str, object]:
    return {"seq": seq, "reason": reason, "informational": informational, "missing": missing}


def key_event(seq: int, typ: str, body: dict[str, object], key: Ed25519PrivateKey) -> dict[str, object]:
    """R57: sign the key event over its chain, position, type and payload without the signature."""
    h = ohash({"schema": "impact.key-event.v1", "tenant_id": TENANT, "genesis_hash": e0["hash"], "seq": seq, "type": typ, "payload": body})
    return {**body, "signature": signature("impact.key-event-signature.v1", h, key)[1]}


# Inserted at seq 4 (before the export): a self-signed revocation of the only key.
REVOKE = {
    "event_id": "000000000000000000000000000000ff",
    "project_id": None,
    "type": "key_revoked",
    "payload": key_event(4, "key_revoked", {"key_id": KEY_ID, "reason": "compromised", "signer_key_id": KEY_ID}, KEY),
    "actor": USER,
    "ts": "2026-10-18T12:02:30Z",
}
# Inserted at seq 4: enrollment of a second key, signed by that key, which is not enrolled (R57 -> unknown_key).
ENROLL_BY_UNKNOWN_KEY = {
    "event_id": "000000000000000000000000000000fe",
    "project_id": None,
    "type": "key_enrolled",
    "payload": key_event(4, "key_enrolled", {"key_id": KEY2_ID, "public_key": PUBLIC_KEY2, "signer_key_id": KEY2_ID}, KEY2),
    "actor": USER,
    "ts": "2026-10-18T12:02:30Z",
}
SECOND_GENESIS = {
    "event_id": "000000000000000000000000000000fd",
    "project_id": None,
    "type": "genesis",
    "payload": {"role": "server", "signing_keys": [{"key_id": KEY2_ID, "public_key": PUBLIC_KEY2}]},
    "actor": SYSTEM,
    "ts": "2026-10-18T12:02:30Z",
}
# Inserted at seq 4: a chain_ref naming a synthetic CLI chain (R45), signed per R57.
CLI_REF_BODY = {
    "chain_signer_key_id": KEY2_ID,
    "genesis_hash": sha(b"synthetic cli genesis"),
    "seq": 7,
    "head_hash": sha(b"synthetic cli head"),
}
CHAIN_REF_OK = {
    "event_id": "000000000000000000000000000000fc",
    "project_id": None,
    "type": "chain_ref",
    "payload": key_event(4, "chain_ref", {**CLI_REF_BODY, "signer_key_id": KEY_ID}, KEY),
    "actor": SYSTEM,
    "ts": "2026-10-18T12:02:30Z",
}
CHAIN_REF_BY_UNKNOWN_KEY = {
    "event_id": "000000000000000000000000000000fb",
    "project_id": None,
    "type": "chain_ref",
    "payload": key_event(4, "chain_ref", {**CLI_REF_BODY, "signer_key_id": KEY2_ID}, KEY2),
    "actor": USER,
    "ts": "2026-10-18T12:02:30Z",
}
TWO_KEYS = sorted(
    [{"key_id": KEY_ID, "public_key": PUBLIC_KEY}, {"key_id": KEY2_ID, "public_key": PUBLIC_KEY2}], key=lambda k: k["key_id"]
)

# Each chain tamper runs verify_chain(events, anchors, test_mode) with test_mode true unless stated (R56).
TAMPERS = [
    {
        "id": "T1-payload-edited-without-rehash",
        "rules": ["R40"],
        "target": "chain",
        "mutation": {"op": "set", "seq": 1, "path": ["payload", "dump_kind"], "value": "obd_full", "rehash": False},
        "use_anchor": True,
        "test_mode": True,
        "status": "broken",
        "expect": [finding(1, "hash_mismatch")],
    },
    {
        "id": "T2-middle-event-removed",
        "rules": ["R40", "R41"],
        "target": "chain",
        "mutation": {"op": "delete", "seq": 2},
        "use_anchor": True,
        "test_mode": True,
        "status": "broken",
        "expect": [finding(3, "prev_mismatch"), finding(3, "seq_gap", missing={"first": 2, "last": 2})],
    },
    {
        "id": "T3-tail-truncated",
        "rules": ["R41"],
        "target": "chain",
        "mutation": {"op": "delete", "seq": 4},
        "use_anchor": True,
        "test_mode": True,
        "status": "broken",
        "expect": [finding(4, "truncated")],
    },
    {
        "id": "T4-consistent-rewrite-caught-only-by-anchor",
        "rules": ["R41"],
        "target": "chain",
        "mutation": {"op": "set", "seq": 1, "path": ["payload", "dump_kind"], "value": "obd_full", "rehash": True},
        "use_anchor": True,
        "test_mode": True,
        "status": "broken",
        "expect": [finding(4, "anchor_mismatch")],
    },
    {
        "id": "T4b-consistent-rewrite-without-anchor-is-undetected",
        "rules": ["R41"],
        "target": "chain",
        "mutation": {"op": "set", "seq": 1, "path": ["payload", "dump_kind"], "value": "obd_full", "rehash": True},
        "use_anchor": False,
        "test_mode": True,
        "status": "intact",
        "expect": [],
    },
    {
        "id": "T5-export-signature-flipped",
        "rules": ["R40", "R51"],
        "target": "chain",
        "mutation": {
            "op": "set",
            "seq": 4,
            "path": ["payload", "signature"],
            "value": ("0" if REPORT_SIG[0] != "0" else "1") + REPORT_SIG[1:],
            "rehash": True,
        },
        "use_anchor": False,
        "test_mode": True,
        "status": "broken",
        "expect": [finding(4, "bad_signature")],
    },
    {
        "id": "T6-report-verdict-edited",
        "rules": ["R61"],
        "target": "report_file",
        "mutation": {"op": "set", "path": ["report", "record", "verdict"], "value": "no findings"},
        "expect": [{"reason": "record_hash_mismatch"}, {"reason": "report_hash_mismatch"}],
    },
    {
        "id": "T7-key-revoked-before-export",
        "rules": ["R40", "R52"],
        "target": "chain",
        "mutation": {"op": "insert", "seq": 4, "event": REVOKE},
        "use_anchor": False,
        "test_mode": True,
        "status": "broken",
        "expect": [finding(5, "revoked_key")],
    },
    {
        "id": "T8-anchor-signed-with-key-revoked-at-anchored-seq",
        "rules": ["R40", "R52"],
        "target": "chain",
        "mutation": {"op": "insert", "seq": 4, "event": REVOKE},
        "use_anchor": True,
        "test_mode": True,
        "status": "broken",
        "expect": [finding(4, "anchor_mismatch"), finding(4, "revoked_key"), finding(5, "revoked_key")],
    },
    {
        "id": "T9-ts-regression-is-informational",
        "rules": ["R38", "R40"],
        "target": "chain",
        "mutation": {"op": "set", "seq": 1, "path": ["ts"], "value": "2026-10-18T11:59:00Z", "rehash": True},
        "use_anchor": False,
        "test_mode": True,
        "status": "intact",
        "expect": [finding(1, "ts_regression", informational=True)],
    },
    {
        "id": "T10-test-key-outside-test-mode",
        "rules": ["R40", "R56"],
        "target": "chain",
        "mutation": None,
        "use_anchor": False,
        "test_mode": False,
        "status": "broken",
        "expect": [finding(0, "test_key")],
    },
    {
        "id": "T11-genesis-with-two-keys",
        "rules": ["R32", "R40"],
        "target": "chain",
        "mutation": {"op": "set", "seq": 0, "path": ["payload", "signing_keys"], "value": TWO_KEYS, "rehash": True},
        "use_anchor": False,
        "test_mode": True,
        "status": "broken",
        "expect": [finding(0, "not_genesis"), finding(4, "unknown_key")],
    },
    {
        "id": "T12-key-enrolled-by-a-key-not-in-the-chain",
        "rules": ["R40", "R57"],
        "target": "chain",
        "mutation": {"op": "insert", "seq": 4, "event": ENROLL_BY_UNKNOWN_KEY},
        "use_anchor": False,
        "test_mode": True,
        "status": "broken",
        "expect": [finding(4, "unknown_key")],
    },
    {
        "id": "T13-second-genesis",
        "rules": ["R40"],
        "target": "chain",
        "mutation": {"op": "insert", "seq": 4, "event": SECOND_GENESIS},
        "use_anchor": False,
        "test_mode": True,
        "status": "broken",
        "expect": [finding(4, "not_genesis")],
    },
    {
        "id": "T14-chain-ref-signed-by-chain-key",
        "rules": ["R40", "R45", "R57"],
        "target": "chain",
        "mutation": {"op": "insert", "seq": 4, "event": CHAIN_REF_OK},
        "use_anchor": False,
        "test_mode": True,
        "status": "intact",
        "expect": [],
    },
    {
        "id": "T15-chain-ref-signed-by-a-key-not-in-the-chain",
        "rules": ["R40", "R45", "R57"],
        "target": "chain",
        "mutation": {"op": "insert", "seq": 4, "event": CHAIN_REF_BY_UNKNOWN_KEY},
        "use_anchor": False,
        "test_mode": True,
        "status": "broken",
        "expect": [finding(4, "unknown_key")],
    },
]


def hashed(obj: dict[str, object], key: str, h: str) -> dict[str, object]:
    return {"value": obj, "jcs": jcs(obj), key: h}


vectors = {
    "generator": {
        "jcs": f"rfc8785 {importlib.metadata.version('rfc8785')}",
        "ed25519": f"cryptography {importlib.metadata.version('cryptography')}",
        "sha256": "python hashlib",
        "python": sys.version.split()[0],
        "spec001_vectors_sha256": sha(SPEC001_BYTES),
    },
    "spec001_inputs": {
        "image_hash_original": ORIGINAL_HASH,
        "image_hash_apply": APPLY_HASH,
        "image_hash_release": RELEASE_HASH,
        "layout_hash": LAYOUT_HASH,
        "version_hash": VERSION_HASH,
        "patch_hashes": {"P1": PH["P1"], "P2": PH["P2"], "Q1": PH["Q1"]},
        "from": ["original", "layouts.base", "patches", "V4-apply-disjoint", "V9-checksum-patch", "V8-diff-reports-foreign-changes"],
    },
    "key": {
        "rules": ["R50"],
        "seed_text": SEED_TEXT,
        "seed_hex": SEED.hex(),
        "public_key": PUBLIC_KEY,
        "key_id": KEY_ID,
        "second_seed_text": SEED2_TEXT,
        "second_public_key": PUBLIC_KEY2,
        "second_key_id": KEY2_ID,
    },
    "gate_report": {"value": GATE_REPORT, "gate_report_hash": GATE_REPORT_HASH, "finding_ids": [FINDING_ID]},
    "gate_report_no_findings": {"value": GATE_REPORT_NF, "gate_report_hash": GATE_REPORT_NF_HASH},
    "input_report": {"value": INPUT_REPORT, "input_report_hash": INPUT_REPORT_HASH},
    "chain": {
        "rules": ["R2", "R5", "R30", "R31", "R32", "R33", "R35", "R36"],
        "test_mode": True,
        "artifact_note": "artifact_sha256 is sha256(pflash || dflash) of the SPEC-001 original, a synthetic file",
        "events": [
            {"event": ev, "jcs_without_hash": jcs({k: v for k, v in ev.items() if k != "hash"}), "hash": ev["hash"]}
            for ev in CHAIN
        ],
    },
    "provenance": {
        "rules": ["R10", "R11", "R12", "R13", "R14", "R16", "R17", "R18"],
        "note": "warn export of a suspect original acknowledged by suspect_ack (seq 2) and alert_ack (seq 3)",
        **hashed(PROV, "provenance_hash", PROV_HASH),
    },
    "provenance_no_findings": {
        "rules": ["R11", "R13", "R14", "R18"],
        "note": "no findings export of an accepted original: alert_ack and suspect_ack are null",
        **hashed(PROV_NF, "provenance_hash", ohash(PROV_NF)),
    },
    "provenance_lockfile": {"rules": ["R16", "R17", "R18"], **hashed(PROV_LOCK, "provenance_hash", ohash(PROV_LOCK))},
    "report_file": {
        "rules": ["R51", "R60", "R61", "R62", "R63"],
        "value": {"report": REPORT, "report_hash": REPORT_HASH, "event": e4},
        "report_jcs": jcs(REPORT),
        "signing_input": REPORT_MSG,
        "signature": REPORT_SIG,
    },
    "anchor": {
        "rules": ["R42", "R51"],
        "value": {"statement": ANCHOR, "statement_hash": ANCHOR_HASH, "key_id": KEY_ID, "signature": ANCHOR_SIG},
        "statement_jcs": jcs(ANCHOR),
        "signing_input": ANCHOR_MSG,
    },
    "audit": {
        "rules": ["R20", "R21"],
        "candidate": {"pflash_hex": V8["x_pflash_hex"], "dflash_hex": V8["x_dflash_hex"]},
        "candidate_image_jcs": jcs(CANDIDATE_IMAGE),
        **hashed(AUDIT, "audit_hash", ohash(AUDIT)),
    },
    "commitment": {"rules": ["R82"], **hashed(COMMITMENT, "commitment", ohash(COMMITMENT))},
    "tampers": TAMPERS,
    "generic_audit_inputs": {
        "rules": ["R111", "R112"],
        "note": "the V8 candidate with pflash 38..42 xor 0xff and 47..50 xor 0x5a; map spans given as byte ranges",
        "candidate": {m: g_mem[m].hex() for m in ("dflash", "pflash")},
        "candidate_image_jcs": jcs(G_IMAGE),
        "definition_hash": DEFINITION_HASH,
        "spans": G_SPANS,
        "unbound": G_UNBOUND,
    },
    "generic_audit": {
        "rules": ["R110", "R111", "R112", "R113", "R114"],
        **hashed(GENERIC, "generic_audit_hash", ohash(GENERIC)),
    },
    "generic_audit_no_definition": {
        "rules": ["R111", "R112", "R113", "R114"],
        **hashed(GENERIC_NO_DEFINITION, "generic_audit_hash", ohash(GENERIC_NO_DEFINITION)),
    },
    "generic_audit_no_rule_table": {
        "rules": ["R113", "R115"],
        **hashed(GENERIC_NO_RULE_TABLE, "generic_audit_hash", ohash(GENERIC_NO_RULE_TABLE)),
    },
}

json.dump(vectors, sys.stdout, indent=2)
sys.stdout.write("\n")
