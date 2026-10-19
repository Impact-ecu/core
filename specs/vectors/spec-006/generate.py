"""Generate SPEC-006 test vectors.

Independent of the core. JCS comes from the third-party `rfc8785` package, Ed25519 from the third-party
`cryptography` package (both pinned in requirements.txt), SHA-256 from hashlib, HMAC-SHA-256 from hmac. The golden hash, base and version
are read from specs/vectors/spec-001/vectors.json, never recomputed here. All data is synthetic.
Every expected registry, classification, count, reason and level below is written by hand; only hashes and
signatures are computed. crosscheck.py derives all of them with its own code.
Run: python -I generate.py > vectors.json   then   python -I crosscheck.py vectors.json
"""
from __future__ import annotations

import hashlib
import hmac
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

# ---- Keys (R66: test keys) ----
KEY_NAMES = ["registry", "attester-a", "attester-a2", "attester-b", "attester-c", "attester-d", "attester-e", "reviewer-f", "attester-r"]
KEYS: dict[str, dict[str, object]] = {}
for _n in KEY_NAMES:
    _text = f"impact spec-006 synthetic {_n} key; never use outside test vectors"
    _priv = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(_text.encode("utf-8")).digest())
    _pub = _priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    KEYS[_n] = {"seed_text": _text, "priv": _priv, "public_key": _pub, "key_id": sha(bytes.fromhex(_pub))}
S, A, A2, B, C, D, E, F, R = (KEYS[n] for n in KEY_NAMES)


def kid(k: dict[str, object]) -> str:
    return str(k["key_id"])


def signature(domain: str, h: str, key: dict[str, object]) -> tuple[str, str]:
    message = jcs({"domain": domain, "hash": h})
    priv = key["priv"]
    assert isinstance(priv, Ed25519PrivateKey)
    return message, priv.sign(message.encode("utf-8")).hex()


# ---- SPEC-001 inputs (read, not recomputed) ----
_cases = {c["id"]: c for c in S1["cases"]}
BASE_HASH = S1["original"]["image_hash"]
VERSION_HASH = _cases["V4-apply-disjoint"]["expect"]["version_hash"]
APPLY_HASH = _cases["V4-apply-disjoint"]["expect"]["image_hash"]
GOLDEN_HASH = _cases["V9-checksum-patch"]["expect"]["image_hash"]

FAMILY = "synthetic.family"
VARIANT = "synthetic.variant.1"
OTHER_VARIANT = "synthetic.variant.2"

# ---- Raw importer (R10, R16, R17, R20, R21, R27-R29) ----
MAX_INPUT_BYTES = 67108864
CORE_VERSION = "0.0.0-synthetic"


def raw_ok(case_id: str, data_spec: dict[str, object], data: bytes, dump_kind: str, source_tool: str | None, memory_id: str) -> dict[str, object]:
    image = {
        "dump_kind": dump_kind,
        "memories": [{"memory_id": memory_id, "base_address": None, "size": len(data), "sha256": sha(data)}],
    }
    record = {
        "schema": "impact.import-record.v1",
        "importer_id": "impact.raw",
        "importer_version": CORE_VERSION,
        "source_tool": source_tool,
        "container_kind": "raw",
        "input_sha256": sha(data),
        "dump_kind": dump_kind,
        "options": {"memory_id": memory_id},
        "image_hash": ohash(image),
    }
    return {
        "id": case_id,
        "rules": ["R10", "R17", "R20", "R21", "R27", "R28", "R29"],
        "input": data_spec,
        "params": {"dump_kind": dump_kind, "source_tool": source_tool, "options": {"memory_id": memory_id}},
        "expect": {
            "outcome": "imported",
            "dump": {"dump_kind": dump_kind, "memories": [{"memory_id": memory_id, "base_address": None, "data": data_spec}]},
            "image_jcs": jcs(image),
            "record": record,
            "record_jcs": jcs(record),
            "import_record_hash": ohash(record),
        },
    }


def raw_rejected(case_id: str, rules: list[str], data_spec: dict[str, object], params: dict[str, object], reason: str, container_kind: str | None) -> dict[str, object]:
    return {
        "id": case_id,
        "rules": rules,
        "input": data_spec,
        "params": params,
        "expect": {"outcome": "rejected", "rejection": {"reason": reason, "container_kind": container_kind}},
    }


I1_DATA = bytes(range(0x40, 0x70))
I2_DATA = b"\xff" * 16
RAW_CASES = [
    raw_ok("I1-raw-single-memory", {"hex": I1_DATA.hex()}, I1_DATA, "bench_full", "Synthetic Reader 1.0", "pflash"),
    raw_ok("I2-raw-null-source-tool", {"hex": I2_DATA.hex()}, I2_DATA, "obd_partial", None, "eeprom"),
    raw_rejected("I3-empty-input", ["R29"], {"hex": ""}, {"dump_kind": "bench_full", "source_tool": None, "options": {"memory_id": "pflash"}}, "empty_input", "raw"),
    raw_rejected("I4-bad-memory-id", ["R28"], {"hex": I1_DATA.hex()}, {"dump_kind": "bench_full", "source_tool": None, "options": {"memory_id": "PFlash"}}, "bad_params", "raw"),
    raw_rejected(
        "I5-extra-option",
        ["R28"],
        {"hex": I1_DATA.hex()},
        {"dump_kind": "bench_full", "source_tool": None, "options": {"memory_id": "pflash", "base_address": 0}},
        "bad_params",
        "raw",
    ),
    raw_rejected("I6-bad-dump-kind", ["R11", "R20"], {"hex": I1_DATA.hex()}, {"dump_kind": "full", "source_tool": None, "options": {"memory_id": "pflash"}}, "bad_params", None),
    raw_rejected(
        "I7-too-large",
        ["R16", "R20"],
        {"fill": {"byte": 0, "size": MAX_INPUT_BYTES + 1}},
        {"dump_kind": "bench_full", "source_tool": None, "options": {"memory_id": "pflash"}},
        "too_large",
        None,
    ),
]
_big = bytes(MAX_INPUT_BYTES)
_i8 = raw_ok("I8-at-size-limit", {"fill": {"byte": 0, "size": MAX_INPUT_BYTES}}, _big, "boot_full", None, "pflash")
_i8["rules"] = ["R16", "R29"]
RAW_CASES.append(_i8)
del _big

# ---- DTCs (R43) ----
DTCS = {
    "rules": ["R43"],
    "canonical": [
        {"raw": [" p0120 ", "P0601-00", "u0100", "P0120"], "expect": ["P0120", "P0601-00", "U0100"]},
        {"raw": [], "expect": []},
        {"raw": ["c1234-af", "B3FFF"], "expect": ["B3FFF", "C1234-AF"]},
    ],
    "invalid": [
        {"raw": ["P4123"], "reason": "bad_dtc"},
        {"raw": ["X0123"], "reason": "bad_dtc"},
        {"raw": ["P012"], "reason": "bad_dtc"},
        {"raw": ["P0601-0"], "reason": "bad_dtc"},
        {"raw": ["P0601", "P06O1"], "reason": "bad_dtc"},
    ],
}

# ---- Unit ids and the commitment service (R45-R47) ----
UNITS = {"X": ("sn-0001.x", "SN0001X"), "Y": ("SN 0002 Y", "SN0002Y"), "Z": ("sn/0003:z_", "SN0003Z")}
SECRET_TEXT = "impact spec-006 synthetic commitment secret; never use outside test vectors"
SECRET = hashlib.sha256(SECRET_TEXT.encode("utf-8")).digest()
EPOCH = sha(b"impact spec-006 synthetic commitment epoch 1")
EPOCH2 = sha(b"impact spec-006 synthetic commitment epoch 2")


def lookup_input(unit_id: str) -> str:
    return jcs({"schema": "impact.ecu-unit.v1", "family": FAMILY, "unit_id": unit_id})


def lookup_key(secret: bytes, unit_id: str) -> str:
    return hmac.new(secret, lookup_input(unit_id).encode("utf-8"), hashlib.sha256).hexdigest()


# Hand-written table: the service's random pseudonyms, stood for by fixed synthetic values.
TABLE = {u: sha(f"impact spec-006 synthetic pseudonym {u}".encode()) for u in ("X", "Y", "Z")}
SECOND_EPOCH_SECRET = hashlib.sha256(b"impact spec-006 synthetic second commitment secret; never use outside test vectors").digest()
TABLE2 = {"Y": sha(b"impact spec-006 synthetic pseudonym Y epoch 2")}

UNIT_IDS = {
    "rules": ["R45"],
    "canonical": [{"raw": raw, "expect": canon} for raw, canon in UNITS.values()],
    "invalid": [
        {"raw": "ab1", "reason": "bad_unit_id"},
        {"raw": "SN#0001", "reason": "bad_unit_id"},
        {"raw": "SNÄ0001", "reason": "bad_unit_id"},
        {"raw": "A" * 41, "reason": "bad_unit_id"},
    ],
}
COMMITMENT_SERVICE = {
    "rules": ["R46", "R47"],
    "family": FAMILY,
    "secret_text": SECRET_TEXT,
    "secret_hex": SECRET.hex(),
    "epoch": EPOCH,
    "units": [
        {"unit": u, "unit_id": UNITS[u][1], "lookup_input": lookup_input(UNITS[u][1]), "lookup_key": lookup_key(SECRET, UNITS[u][1]), "ecu_commitment": TABLE[u]}
        for u in ("X", "Y", "Z")
    ],
    "second_epoch": {
        "epoch": EPOCH2,
        "secret_hex": SECOND_EPOCH_SECRET.hex(),
        "units": [{"unit": "Y", "unit_id": UNITS["Y"][1], "lookup_key": lookup_key(SECOND_EPOCH_SECRET, UNITS["Y"][1]), "ecu_commitment": TABLE2["Y"]}],
    },
}

# ---- Disqualifying DTC set (R55, R56) and head policy (R82) ----
DTC_SET = {
    "schema": "impact.disqualifying-dtcs.v1",
    "version": 1,
    "codes": ["P0601", "P0602", "P0603", "P0604", "P0605", "P0606", "P0607", "P060A", "P062F"],
}
DTC_SET_HASH = ohash(DTC_SET)
HEAD_POLICY = {"schema": "impact.head-policy.v1", "version": 1, "max_validity_s": 86400}

# ---- Attestations (R40-R52) ----


def make_att(
    key: dict[str, object],
    unit: str,
    *,
    variant: str = VARIANT,
    subject: str = GOLDEN_HASH,
    readback: str | None = None,
    communicates: bool = True,
    dtcs: list[str] | None = None,
    tcs: str = "ok",
    epoch: int = 1,
    created: str = "2026-10-18T14:00:00Z",
    tool_version: str = "1.0",
) -> dict[str, object]:
    if unit == "W":  # a unit without a readable serial (R45, R52)
        commitment, ep = None, None
    elif epoch == 1:
        commitment, ep = TABLE[unit], EPOCH
    else:
        commitment, ep = TABLE2[unit], EPOCH2
    return {
        "schema": "impact.field-attestation.v1",
        "subject_image_hash": subject,
        "identification": {"family": FAMILY, "hw_id": "synthetic-hw-1", "sw_id": "synthetic-sw-1", "checksum_variant_id": variant},
        "write_tool": {"name": "Synthetic Flasher", "version": tool_version},
        "readback_image_hash": readback,
        "communicates": communicates,
        "dtcs_after_clear_and_reread": dtcs or [],
        "tool_checksum_status": tcs,
        "ecu_commitment": commitment,
        "ecu_commitment_epoch": ep,
        "attester_key_id": kid(key),
        "created_at": created,
    }


def signed(att: dict[str, object], signer: dict[str, object]) -> dict[str, object]:
    h = ohash(att)
    return {"attestation": att, "attestation_hash": h, "signature": signature("impact.field-attestation-signature.v1", h, signer)[1]}


VERSION2_HASH = sha(b"impact spec-006 synthetic version 2")
IMAGE2_HASH = sha(b"impact spec-006 synthetic released image 2")

POOL: dict[str, dict[str, object]] = {
    "AX": signed(make_att(A, "X", readback=GOLDEN_HASH), A),
    "AY": signed(make_att(A, "Y"), A),
    "AX2": signed(make_att(A, "X", created="2026-10-18T15:00:00Z"), A),
    "BY": signed(make_att(B, "Y"), B),
    "BX": signed(make_att(B, "X"), B),
    "CY": signed(make_att(C, "Y"), C),
    "CY_BACKDATED": signed(make_att(C, "Y", created="2026-10-18T12:00:00Z"), C),
    "DY": signed(make_att(D, "Y"), D),
    "A2Y": signed(make_att(A2, "Y"), A2),
    "BY_V2": signed(make_att(B, "Y", variant=OTHER_VARIANT), B),
    "BY_WRONG_SUBJECT": signed(make_att(B, "Y", subject=APPLY_HASH), B),
    "EZ_NOCOMM": signed(make_att(E, "Z", communicates=False), E),
    "EZ_DTC": signed(make_att(E, "Z", dtcs=["P0601-00"]), E),
    "AX_OKDTC": signed(make_att(A, "X", dtcs=["P0120", "U0100"]), A),
    "BY_MISMATCH": signed(make_att(B, "Y", tcs="mismatch"), B),
    "AX_NOTREP": signed(make_att(A, "X", tcs="not_reported"), A),
    "BY_READBACK": signed(make_att(B, "Y", readback=APPLY_HASH), B),
    "BY_EPOCH2": signed(make_att(B, "Y", epoch=2), B),
    "CZ_NOCOMM": signed(make_att(C, "Z", communicates=False), C),
    "FY": signed(make_att(F, "Y"), F),
    "A_SIGNED_BY_B": signed(make_att(A, "Z"), B),
    "EW": signed(make_att(E, "W"), E),
    "BW": signed(make_att(B, "W"), B),
    "EW_NOCOMM": signed(make_att(E, "W", communicates=False), E),
    "RY": signed(make_att(R, "Y"), R),
    "RZ": signed(make_att(R, "Z"), R),
    "AX_IMG2": signed(make_att(A, "X", subject=IMAGE2_HASH), A),
    "BY_IMG2": signed(make_att(B, "Y", subject=IMAGE2_HASH), B),
}
# Edited after signing: write_tool version changed. With rehash the hash is consistent and the signature fails;
# without rehash the stored hash no longer matches.
_by = POOL["BY"]
_edited = {**make_att(B, "Y"), "write_tool": {"name": "Synthetic Flasher", "version": "1.1"}}
POOL["BY_EDITED_REHASH"] = {"attestation": _edited, "attestation_hash": ohash(_edited), "signature": _by["signature"]}
POOL["BY_EDITED_NOREHASH"] = {"attestation": _edited, "attestation_hash": _by["attestation_hash"], "signature": _by["signature"]}


def ah(label: str) -> str:
    return str(POOL[label]["attestation_hash"])


# ---- Golden records (R70) ----
T1 = {"name": "Synthetic Tool One", "version": "2.0", "image_hash": GOLDEN_HASH, "date": "2026-10-17"}
T2 = {"name": "Synthetic Tool Two", "version": "5.1", "image_hash": GOLDEN_HASH, "date": "2026-10-17"}
T3 = {"name": "Synthetic Tool Three", "version": "1.0", "image_hash": APPLY_HASH, "date": "2026-10-17"}


def golden_record(labels: list[str], tools: list[dict[str, object]], *, version_hash: str = VERSION_HASH, expected: str = GOLDEN_HASH) -> dict[str, object]:
    return {
        "schema": "impact.golden-record.v1",
        "family": FAMILY,
        "checksum_variant_id": VARIANT,
        "base_image_hash": BASE_HASH,
        "version_hash": version_hash,
        "expected_image_hash": expected,
        "oracle": {
            "tools": sorted(tools, key=lambda t: (t["name"], t["version"])),
            "attestations": sorted({ah(x) for x in labels}),
        },
    }


NEG_RECORD = golden_record(["AX", "BY", "EZ_NOCOMM"], [])
NEG_RECORD_HASH = ohash(NEG_RECORD)
NEW_RECORD = golden_record(["AX_IMG2", "BY_IMG2"], [], version_hash=VERSION2_HASH, expected=IMAGE2_HASH)
BASIC_RECORD = golden_record(["AX", "BY"], [])

# ---- Registry chain (R60-R68; payload shapes SPEC-005 R36, signatures SPEC-005 R57) ----
TENANT = "tenant-registry-synthetic"
OPERATOR = {"kind": "user", "id": "user-registry-operator"}
REVIEWER_ACTOR = {"kind": "user", "id": "user-reviewer-f"}
SYSTEM = {"kind": "system", "id": "system"}
ZERO = "0" * 64


def seal(event: dict[str, object]) -> dict[str, object]:
    body = {k: v for k, v in event.items() if k != "hash"}
    return {**body, "hash": ohash(body)}


def reason_commitment(n: int) -> str:
    return ohash({"schema": "impact.commitment.v1", "nonce": sha(f"spec-006 nonce {n}".encode()), "content": {"text": f"synthetic registry reason {n}"}})


GENESIS = seal(
    {
        "schema": "impact.event.v1",
        "tenant_id": TENANT,
        "seq": 0,
        "event_id": "00000000000000000000000000000000",
        "project_id": None,
        "type": "genesis",
        "payload": {"role": "server", "signing_keys": [{"key_id": kid(S), "public_key": S["public_key"]}]},
        "actor": SYSTEM,
        "ts": "2026-10-18T13:00:00Z",
        "prev_hash": ZERO,
    }
)
GENESIS_HASH = str(GENESIS["hash"])
CHAIN = [GENESIS]


def push(typ: str, payload: dict[str, object], actor: dict[str, object]) -> None:
    seq = len(CHAIN)
    CHAIN.append(
        seal(
            {
                "schema": "impact.event.v1",
                "tenant_id": TENANT,
                "seq": seq,
                "event_id": f"{seq:032x}",
                "project_id": None,
                "type": typ,
                "payload": payload,
                "actor": actor,
                "ts": f"2026-10-18T13:{seq:02d}:00Z",
                "prev_hash": CHAIN[-1]["hash"],
            }
        )
    )


def append_signed(typ: str, body: dict[str, object]) -> None:
    """SPEC-005 R57: signed by the chain key over chain, position, type and payload without the signature."""
    seq = len(CHAIN)
    body = {**body, "signer_key_id": kid(S)}
    h = ohash({"schema": "impact.key-event.v1", "tenant_id": TENANT, "genesis_hash": GENESIS_HASH, "seq": seq, "type": typ, "payload": body})
    push(typ, {**body, "signature": signature("impact.key-event-signature.v1", h, S)[1]}, OPERATOR)


def enroll(key: dict[str, object], roles: list[str], old: dict[str, object] | None, n: int) -> None:
    rotation_signature = None
    if old is not None:
        rh = ohash(
            {
                "schema": "impact.attester-rotation.v1",
                "tenant_id": TENANT,
                "genesis_hash": GENESIS_HASH,
                "old_key_id": kid(old),
                "new_key_id": kid(key),
                "new_public_key": key["public_key"],
            }
        )
        rotation_signature = signature("impact.attester-rotation-signature.v1", rh, old)[1]
    append_signed(
        "attester_enrolled",
        {
            "attester_key_id": kid(key),
            "public_key": key["public_key"],
            "roles": roles,
            "rotates": None if old is None else kid(old),
            "rotation_signature": rotation_signature,
            "reason_commitment": reason_commitment(n),
        },
    )


def include(label: str) -> None:
    append_signed("attestation_included", {"attestation_hash": ah(label), "attester_key_id": POOL[label]["attestation"]["attester_key_id"]})


def revoke(key: dict[str, object], reason: str, n: int) -> None:
    append_signed("attester_revoked", {"attester_key_id": kid(key), "reason": reason, "reason_commitment": reason_commitment(n)})


def review_record(reviewer: dict[str, object], record_hash: str, decision: str) -> None:
    h = ohash(
        {
            "schema": "impact.review.v1",
            "tenant_id": TENANT,
            "genesis_hash": GENESIS_HASH,
            "subject_kind": "golden_record",
            "export_ref": None,
            "subject_hash": record_hash,
            "decision": decision,
        }
    )
    push(
        "review",
        {
            "subject_kind": "golden_record",
            "export_ref": None,
            "subject_hash": record_hash,
            "decision": decision,
            "reviewer_key_id": kid(reviewer),
            "signature": signature("impact.review-signature.v1", h, reviewer)[1],
        },
        REVIEWER_ACTOR,
    )


enroll(A, ["attester"], None, 1)  # seq 1
enroll(B, ["attester"], None, 2)  # seq 2
enroll(C, ["attester"], None, 3)  # seq 3
enroll(E, ["attester"], None, 4)  # seq 4
enroll(A2, ["attester"], A, 5)  # seq 5, rotation of A signed by A
enroll(F, ["reviewer"], None, 6)  # seq 6
enroll(R, ["attester"], None, 7)  # seq 7
include("RY")  # seq 8
include("CY")  # seq 9
revoke(C, "compromised", 10)  # seq 10
revoke(R, "retired", 11)  # seq 11
include("RZ")  # seq 12: key already revoked, no effect (finding revoked_attester)
review_record(F, NEG_RECORD_HASH, "approved")  # seq 13


def entry(key: dict[str, object], roles: list[str], identity: dict[str, object], seq: int, revoked: dict[str, object] | None) -> dict[str, object]:
    return {"attester_key_id": kid(key), "public_key": key["public_key"], "roles": roles, "identity": kid(identity), "enrolled_seq": seq, "revoked": revoked}


def registry(head: int, revoked: bool, reviews: list[dict[str, object]]) -> dict[str, object]:
    entries = [
        entry(A, ["attester"], A, 1, None),
        entry(B, ["attester"], B, 2, None),
        entry(C, ["attester"], C, 3, {"seq": 10, "reason": "compromised"} if revoked else None),
        entry(E, ["attester"], E, 4, None),
        entry(A2, ["attester"], A, 5, None),
        entry(F, ["reviewer"], F, 6, None),
        entry(R, ["attester"], R, 7, {"seq": 11, "reason": "retired"} if revoked else None),
    ]
    inclusions = [
        {"attestation_hash": ah("RY"), "attester_key_id": kid(R), "seq": 8},
        {"attestation_hash": ah("CY"), "attester_key_id": kid(C), "seq": 9},
    ]
    return {
        "schema": "impact.attester-registry.v1",
        "tenant_id": TENANT,
        "genesis_hash": GENESIS_HASH,
        "head": {"seq": head, "hash": CHAIN[head]["hash"]},
        "attesters": sorted(entries, key=lambda x: x["attester_key_id"]),
        "inclusions": sorted(inclusions, key=lambda x: x["attestation_hash"]),
        "record_reviews": reviews,
        "findings": [{"seq": 12, "reason": "revoked_attester"}] if head >= 12 else [],
    }


REGISTRIES = {
    "pre": registry(9, False, []),
    "post": registry(12, True, []),
    "reviewed": registry(13, True, [{"golden_record_hash": NEG_RECORD_HASH, "decision": "approved", "reviewer_key_id": kid(F), "seq": 13}]),
}
REGISTRY_HASH = {k: ohash(v) for k, v in REGISTRIES.items()}

_ax_msg, _ax_sig = signature("impact.field-attestation-signature.v1", ah("AX"), A)
ATTESTATION_VERIFY = {
    "rules": ["R48", "R49", "R50", "R77"],
    "example": {
        "label": "AX",
        "attestation_jcs": jcs(POOL["AX"]["attestation"]),
        "attestation_hash": ah("AX"),
        "signing_input": _ax_msg,
        "signature": _ax_sig,
    },
    "cases": [
        {"label": "AX", "registry": "pre", "expect": []},
        {"label": "BY_EDITED_REHASH", "registry": "pre", "expect": ["bad_signature"]},
        {"label": "BY_EDITED_NOREHASH", "registry": "pre", "expect": ["attestation_hash_mismatch"]},
        {"label": "A_SIGNED_BY_B", "registry": "pre", "expect": ["bad_signature"]},
        {"label": "DY", "registry": "pre", "expect": ["unknown_attester"]},
        {"label": "CY", "registry": "pre", "expect": []},
        {"label": "CY", "registry": "post", "expect": ["revoked_attester"]},
        {"label": "RY", "registry": "post", "expect": []},
        {"label": "RZ", "registry": "post", "expect": ["revoked_attester"]},
        {"label": "FY", "registry": "pre", "expect": ["not_attester"]},
        {"label": "EW", "registry": "pre", "expect": []},
    ],
}

# ---- Evaluations (R70-R78) ----
BELOW = ["below_attestations", "below_attesters", "below_units"]
EVAL_RULES = ["R70", "R71", "R72", "R73", "R75", "R76", "R78"]


def evaluation(record: dict[str, object], labels: list[str], registry_name: str, per: dict[str, tuple[list[str], bool]], counts: tuple[int, int, int], reasons: list[str], level: str) -> dict[str, object]:
    by_hash = {ah(label): label for label in labels}
    rows = []
    for h in sorted(by_hash):
        rs, negative = per.get(by_hash[h], ([], False))
        rows.append({"attestation_hash": h, "qualifying": rs == [], "negative": negative, "reasons": rs})
    return {
        "schema": "impact.golden-evaluation.v1",
        "golden_record_hash": ohash(record),
        "registry_hash": REGISTRY_HASH[registry_name],
        "dtc_set_hash": DTC_SET_HASH,
        "commitment_epoch": EPOCH,
        "thresholds": {"attestations": 2, "attesters": 2, "units": 2},
        "counts": {"attestations": counts[0], "attesters": counts[1], "units": counts[2]},
        "attestations": sorted(rows, key=lambda r: r["attestation_hash"]),
        "reasons": reasons,
        "level": level,
    }


def case(
    case_id: str,
    rules: list[str],
    listed: list[str],
    tools: list[dict[str, object]],
    registry_name: str,
    per: dict[str, tuple[list[str], bool]],
    counts: tuple[int, int, int],
    reasons: list[str],
    level: str,
    supplied: list[str] | None = None,
) -> dict[str, object]:
    record = golden_record(listed, tools)
    ev = evaluation(record, listed, registry_name, per, counts, reasons, level)
    return {
        "id": case_id,
        "rules": rules,
        "registry": registry_name,
        "test_mode": True,
        "record": record,
        "golden_record_hash": ohash(record),
        "supplied": supplied if supplied is not None else listed,
        "expect": {"evaluation": ev, "evaluation_hash": ohash(ev)},
    }


CASES = [
    case("G01-two-attesters-two-ecus", EVAL_RULES, ["AX", "BY"], [], "pre", {}, (2, 2, 2), [], "golden_field"),
    case("G02-one-attester-two-ecus", EVAL_RULES, ["AX", "AY"], [T1, T2], "pre", {}, (2, 1, 2), ["below_attesters"], "golden_concordant"),
    case("G03-two-attesters-one-ecu", EVAL_RULES, ["AX", "BX"], [T1], "pre", {}, (2, 2, 1), ["below_units"], "candidate"),
    case("G04-single-attestation", EVAL_RULES, ["AX"], [], "pre", {}, (1, 1, 1), BELOW, "none"),
    case("G05-three-attestations", EVAL_RULES, ["AX", "AY", "BX"], [], "pre", {}, (3, 2, 2), [], "golden_field"),
    case(
        "G06-other-attester-has-zero-qualifying",
        EVAL_RULES,
        ["AX", "AY", "BY_WRONG_SUBJECT"],
        [],
        "pre",
        {"BY_WRONG_SUBJECT": (["wrong_subject"], False)},
        (2, 1, 2),
        ["below_attesters"],
        "none",
    ),
    case("G07-before-revocation", EVAL_RULES + ["R77"], ["AX", "CY"], [], "pre", {}, (2, 2, 2), [], "golden_field"),
    case(
        "G08-compromise-is-retroactive-even-if-included",
        EVAL_RULES + ["R63", "R67", "R77", "R79"],
        ["AX", "CY"],
        [],
        "post",
        {"CY": (["revoked_attester"], False)},
        (1, 1, 1),
        BELOW,
        "none",
    ),
    case(
        "G09-backdated-attestation-of-revoked-key",
        EVAL_RULES + ["R51", "R77"],
        ["AX", "CY_BACKDATED"],
        [],
        "post",
        {"CY_BACKDATED": (["revoked_attester"], False)},
        (1, 1, 1),
        BELOW,
        "none",
    ),
    case("G10-unenrolled-key", EVAL_RULES + ["R50"], ["AX", "DY"], [], "pre", {"DY": (["unknown_attester"], False)}, (1, 1, 1), BELOW, "none"),
    case("G11-duplicates-and-reflash", EVAL_RULES, ["AX", "AX2", "BY"], [], "pre", {}, (3, 2, 2), [], "golden_field", supplied=["BY", "AX", "AX2", "BY"]),
    case("G12-rotation-is-one-identity", EVAL_RULES + ["R64"], ["AX", "A2Y"], [], "pre", {}, (2, 1, 2), ["below_attesters"], "none"),
    case("G13-edited-and-rehashed", EVAL_RULES + ["R50"], ["AX", "BY_EDITED_REHASH"], [], "pre", {"BY_EDITED_REHASH": (["bad_signature"], False)}, (1, 1, 1), BELOW, "none"),
    case(
        "G14-edited-without-rehash",
        EVAL_RULES + ["R50"],
        ["AX", "BY"],
        [],
        "pre",
        {"BY": (["attestation_hash_mismatch"], False)},
        (1, 1, 1),
        BELOW,
        "none",
        supplied=["AX", "BY_EDITED_NOREHASH"],
    ),
    case("G15-wrong-variant", EVAL_RULES, ["AX", "BY_V2"], [], "pre", {"BY_V2": (["wrong_variant"], False)}, (1, 1, 1), BELOW, "none"),
    case(
        "G16-negative-no-communication",
        EVAL_RULES + ["R74"],
        ["AX", "BY", "EZ_NOCOMM"],
        [],
        "pre",
        {"EZ_NOCOMM": (["no_communication"], True)},
        (2, 2, 2),
        ["negative_field_evidence"],
        "none",
    ),
    case(
        "G17-negative-dtc-with-failure-type",
        EVAL_RULES + ["R55", "R56", "R74"],
        ["AX", "BY", "EZ_DTC"],
        [],
        "pre",
        {"EZ_DTC": (["disqualifying_dtc"], True)},
        (2, 2, 2),
        ["negative_field_evidence"],
        "none",
    ),
    case("G18-non-disqualifying-dtcs", EVAL_RULES + ["R55"], ["AX_OKDTC", "BY"], [], "pre", {}, (2, 2, 2), [], "golden_field"),
    case(
        "G19-tool-checksum-mismatch",
        EVAL_RULES + ["R42", "R74"],
        ["AX", "BY_MISMATCH"],
        [T1],
        "pre",
        {"BY_MISMATCH": (["tool_checksum_mismatch"], True)},
        (1, 1, 1),
        BELOW + ["negative_field_evidence"],
        "candidate",
    ),
    case("G20-checksum-not-reported", EVAL_RULES + ["R42"], ["AX_NOTREP", "BY"], [], "pre", {}, (2, 2, 2), [], "golden_field"),
    case(
        "G21-readback-mismatch",
        EVAL_RULES + ["R44", "R74"],
        ["AX", "BY_READBACK"],
        [],
        "pre",
        {"BY_READBACK": (["readback_mismatch"], True)},
        (1, 1, 1),
        BELOW + ["negative_field_evidence"],
        "none",
    ),
    case("G22-foreign-epoch", EVAL_RULES + ["R47"], ["AX", "BY_EPOCH2"], [], "pre", {"BY_EPOCH2": (["foreign_epoch"], False)}, (1, 1, 1), BELOW, "none"),
    case("G23-missing-attestation", EVAL_RULES, ["AX", "BY"], [], "pre", {"BY": (["missing"], False)}, (1, 1, 1), BELOW, "none", supplied=["AX"]),
    case(
        "G24-negative-by-revoked-key-ignored",
        EVAL_RULES + ["R74", "R77"],
        ["AX", "BY", "CZ_NOCOMM"],
        [],
        "post",
        {"CZ_NOCOMM": (["revoked_attester"], False)},
        (2, 2, 2),
        [],
        "golden_field",
    ),
    case("G25-reviewer-only-key", EVAL_RULES + ["R62"], ["AX", "FY"], [], "pre", {"FY": (["not_attester"], False)}, (1, 1, 1), BELOW, "none"),
    case("G26-tools-disagree", EVAL_RULES, [], [T1, T3], "pre", {}, (0, 0, 0), BELOW + ["tool_disagreement"], "candidate"),
    {
        "id": "G27-test-keys-outside-test-mode",
        "rules": ["R65", "R66", "R80"],
        "registry": None,
        "test_mode": False,
        "record": BASIC_RECORD,
        "golden_record_hash": ohash(BASIC_RECORD),
        "supplied": ["AX", "BY"],
        "expect": {"error": "registry_broken"},
    },
    case("G28-field-with-tool-disagreement", EVAL_RULES, ["AX", "BY"], [T1, T3], "pre", {}, (2, 2, 2), ["tool_disagreement"], "golden_field"),
    case("G29-unit-without-serial-not-counted", EVAL_RULES + ["R45", "R52"], ["AX", "BY", "EW"], [], "pre", {"EW": (["no_unit_commitment"], False)}, (2, 2, 2), [], "golden_field"),
    case("G30-unit-without-serial-counts-for-nothing", EVAL_RULES + ["R52"], ["AX", "BW"], [], "pre", {"BW": (["no_unit_commitment"], False)}, (1, 1, 1), BELOW, "none"),
    case(
        "G31-unit-without-serial-negative-blocks",
        EVAL_RULES + ["R52", "R74"],
        ["AX", "BY", "EW_NOCOMM"],
        [],
        "pre",
        {"EW_NOCOMM": (["no_communication"], True)},
        (2, 2, 2),
        ["negative_field_evidence"],
        "none",
    ),
    case("G32-retired-key-included-before", EVAL_RULES + ["R63", "R67", "R77"], ["AX", "RY"], [], "post", {}, (2, 2, 2), [], "golden_field"),
    case(
        "G33-retired-key-included-after",
        EVAL_RULES + ["R63", "R67", "R77"],
        ["AX", "RZ"],
        [],
        "post",
        {"RZ": (["revoked_attester"], False)},
        (1, 1, 1),
        BELOW,
        "none",
    ),
]

# ---- Signed registry heads and admission (R81-R84) ----
TRUST = {"tenant_id": TENANT, "genesis_hash": GENESIS_HASH, "key_id": kid(S), "public_key": S["public_key"]}


def head(registry_name: str, issued: str, expires: str) -> dict[str, object]:
    reg = REGISTRIES[registry_name]
    return {
        "schema": "impact.registry-head.v1",
        "tenant_id": TENANT,
        "genesis_hash": GENESIS_HASH,
        "seq": reg["head"]["seq"],
        "head_hash": reg["head"]["hash"],
        "registry_hash": REGISTRY_HASH[registry_name],
        "issued_at": issued,
        "expires_at": expires,
    }


def signed_head(h: dict[str, object]) -> dict[str, object]:
    d = ohash(h)
    return {"head": h, "head_digest": d, "key_id": kid(S), "signature": signature("impact.registry-head-signature.v1", d, S)[1]}


HEADS = {
    "post": signed_head(head("post", "2026-10-19T00:00:00Z", "2026-10-20T00:00:00Z")),
    "reviewed": signed_head(head("reviewed", "2026-10-19T00:00:00Z", "2026-10-20T00:00:00Z")),
    "too_long": signed_head(head("post", "2026-10-19T00:00:00Z", "2026-10-21T00:00:00Z")),
}
_sig = str(HEADS["post"]["signature"])
HEADS["bad_signature"] = {**HEADS["post"], "signature": ("0" if _sig[0] != "0" else "1") + _sig[1:]}
_ex = HEADS["post"]["head"]
_ex_msg = jcs({"domain": "impact.registry-head-signature.v1", "hash": HEADS["post"]["head_digest"]})

EV_BASIC_POST = evaluation(BASIC_RECORD, ["AX", "BY"], "post", {}, (2, 2, 2), [], "golden_field")
EV_NEG = {
    name: evaluation(NEG_RECORD, ["AX", "BY", "EZ_NOCOMM"], name, {"EZ_NOCOMM": (["no_communication"], True)}, (2, 2, 2), ["negative_field_evidence"], "none")
    for name in ("post", "reviewed")
}
EV_NEW = {name: evaluation(NEW_RECORD, ["AX_IMG2", "BY_IMG2"], name, {}, (2, 2, 2), [], "golden_field") for name in ("post", "reviewed")}


def admission(case_id: str, rules: list[str], head_name: str, registry_name: str, records: list[dict[str, object]], as_of: str, status: str, reasons: list[str], variants: list[dict[str, object]]) -> dict[str, object]:
    expect = {
        "schema": "impact.evidence-admission.v1",
        "status": status,
        "reasons": reasons,
        "head_digest": HEADS[head_name]["head_digest"] if status == "current" else None,
        "variants": variants,
    }
    return {
        "id": case_id,
        "rules": rules,
        "head": head_name,
        "registry": registry_name,
        "records": records,
        "as_of": as_of,
        "test_mode": True,
        "expect": expect,
    }


def variant(golden: bool, reasons: list[str], evals: list[dict[str, object]]) -> dict[str, object]:
    return {"family": FAMILY, "checksum_variant_id": VARIANT, "golden_field": golden, "reasons": reasons, "evaluations": sorted(ohash(e) for e in evals)}


NOON = "2026-10-19T12:00:00Z"
ADM_RULES = ["R81", "R82", "R83"]
ADMISSIONS = [
    admission("A1-current-head", ADM_RULES + ["R84"], "post", "post", [BASIC_RECORD], NOON, "current", [], [variant(True, [], [EV_BASIC_POST])]),
    admission("A2-head-not-yet-valid", ADM_RULES, "post", "post", [BASIC_RECORD], "2026-10-18T23:59:59Z", "unavailable", ["head_not_yet_valid"], []),
    admission("A3-head-expired", ADM_RULES, "post", "post", [BASIC_RECORD], "2026-10-20T00:00:00Z", "unavailable", ["head_expired"], []),
    admission("A4-head-validity-too-long", ADM_RULES, "too_long", "post", [BASIC_RECORD], NOON, "unavailable", ["head_validity_too_long"], []),
    admission("A5-head-bad-signature", ADM_RULES, "bad_signature", "post", [BASIC_RECORD], NOON, "unavailable", ["untrusted_head"], []),
    admission("A6-registry-does-not-match-head", ADM_RULES, "post", "reviewed", [BASIC_RECORD], NOON, "unavailable", ["registry_mismatch"], []),
    admission(
        "A7-negative-without-review",
        ADM_RULES + ["R74", "R89"],
        "post",
        "post",
        [NEG_RECORD, NEW_RECORD],
        NOON,
        "current",
        [],
        [variant(False, ["unreviewed_negative"], [EV_NEG["post"], EV_NEW["post"]])],
    ),
    admission(
        "A8-negative-with-approved-review",
        ADM_RULES + ["R68", "R74", "R89"],
        "reviewed",
        "reviewed",
        [NEG_RECORD, NEW_RECORD],
        NOON,
        "current",
        [],
        [variant(True, [], [EV_NEG["reviewed"], EV_NEW["reviewed"]])],
    ),
]

vectors = {
    "generator": {
        "jcs": f"rfc8785 {importlib.metadata.version('rfc8785')}",
        "ed25519": f"cryptography {importlib.metadata.version('cryptography')}",
        "sha256": "python hashlib",
        "hmac": "python hmac",
        "python": sys.version.split()[0],
        "spec001_vectors_sha256": sha(SPEC001_BYTES),
    },
    "spec001_inputs": {
        "base_image_hash": BASE_HASH,
        "version_hash": VERSION_HASH,
        "golden_image_hash": GOLDEN_HASH,
        "other_image_hash": APPLY_HASH,
        "from": ["original", "V4-apply-disjoint", "V9-checksum-patch"],
    },
    "synthetic_second_version": {"version_hash": VERSION2_HASH, "image_hash": IMAGE2_HASH},
    "keys": {
        "rules": ["R49", "R66"],
        "keys": {n: {"seed_text": k["seed_text"], "public_key": k["public_key"], "key_id": k["key_id"]} for n, k in KEYS.items()},
    },
    "raw_import": {"max_input_bytes": MAX_INPUT_BYTES, "importer_version": CORE_VERSION, "cases": RAW_CASES},
    "dtcs": DTCS,
    "unit_ids": UNIT_IDS,
    "commitment_service": COMMITMENT_SERVICE,
    "dtc_set": {"rules": ["R55", "R56"], "value": DTC_SET, "jcs": jcs(DTC_SET), "dtc_set_hash": DTC_SET_HASH},
    "head_policy": {"rules": ["R82"], "value": HEAD_POLICY, "head_policy_hash": ohash(HEAD_POLICY)},
    "registry_chain": {
        "rules": ["R60", "R61", "R62", "R63", "R64", "R67", "R68"],
        "test_mode": True,
        "events": [{"event": ev, "hash": ev["hash"]} for ev in CHAIN],
    },
    "registries": {
        name: {"rules": ["R61", "R62", "R63", "R64", "R65", "R67", "R68"], "value": reg, "registry_hash": REGISTRY_HASH[name]}
        for name, reg in REGISTRIES.items()
    },
    "attestations": POOL,
    "attestation_verify": ATTESTATION_VERIFY,
    "evaluations": CASES,
    "trust": TRUST,
    "heads": {
        "rules": ["R81"],
        "example": {"head_jcs": jcs(_ex), "head_digest": HEADS["post"]["head_digest"], "signing_input": _ex_msg},
        "values": HEADS,
    },
    "admissions": ADMISSIONS,
}

json.dump(vectors, sys.stdout, indent=2)
sys.stdout.write("\n")
