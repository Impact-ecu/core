"""Generate SPEC-006 test vectors.

Independent of the core. JCS comes from the third-party `rfc8785` package, Ed25519 from the third-party
`cryptography` package (both pinned in requirements.txt), SHA-256 from hashlib. The golden hash, base and version
are read from specs/vectors/spec-001/vectors.json, never recomputed here. All data is synthetic.
Every expected registry, classification, count, reason and level below is written by hand; only hashes and
signatures are computed. crosscheck.py derives all of them with its own code.
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

# ---- Keys (R66: test keys) ----
KEY_NAMES = ["registry", "attester-a", "attester-a2", "attester-b", "attester-c", "attester-d", "attester-e", "reviewer-f"]
KEYS: dict[str, dict[str, object]] = {}
for _n in KEY_NAMES:
    _text = f"impact spec-006 synthetic {_n} key; never use outside test vectors"
    _priv = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(_text.encode("utf-8")).digest())
    _pub = _priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    KEYS[_n] = {"seed_text": _text, "priv": _priv, "public_key": _pub, "key_id": sha(bytes.fromhex(_pub))}
S, A, A2, B, C, D, E, F = (KEYS[n] for n in KEY_NAMES)


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

# ---- Salt, unit ids, ECU commitments (R46, R47) ----
SALT = hashlib.sha256(b"impact spec-006 synthetic ecu salt; never use outside test vectors").hexdigest()
SALT2 = hashlib.sha256(b"impact spec-006 synthetic second ecu salt; never use outside test vectors").hexdigest()
SALT_ID = ohash({"schema": "impact.ecu-salt-id.v1", "salt": SALT})
SALT2_ID = ohash({"schema": "impact.ecu-salt-id.v1", "salt": SALT2})
UNITS = {"X": ("sn-0001.x", "SN0001X"), "Y": ("SN 0002 Y", "SN0002Y"), "Z": ("sn/0003:z_", "SN0003Z")}


def commitment(salt: str, unit_id: str) -> str:
    return ohash({"schema": "impact.ecu-commitment.v1", "salt": salt, "family": FAMILY, "unit_id": unit_id})


UNIT_IDS = {
    "rules": ["R46"],
    "canonical": [{"raw": raw, "expect": canon} for raw, canon in UNITS.values()],
    "invalid": [
        {"raw": "ab1", "reason": "bad_unit_id"},
        {"raw": "SN#0001", "reason": "bad_unit_id"},
        {"raw": "SNÄ0001", "reason": "bad_unit_id"},
        {"raw": "A" * 41, "reason": "bad_unit_id"},
    ],
}
ECU_COMMITMENTS = {
    "rules": ["R46"],
    "family": FAMILY,
    "cases": [
        {
            "unit": u,
            "salt": "primary",
            "unit_id": UNITS[u][1],
            "input_jcs": jcs({"schema": "impact.ecu-commitment.v1", "salt": SALT, "family": FAMILY, "unit_id": UNITS[u][1]}),
            "ecu_commitment": commitment(SALT, UNITS[u][1]),
        }
        for u in ("X", "Y", "Z")
    ]
    + [{"unit": "Y", "salt": "second", "unit_id": UNITS["Y"][1], "ecu_commitment": commitment(SALT2, UNITS["Y"][1])}],
}

# ---- Disqualifying DTC set (R55, R56) ----
DTC_SET = {"schema": "impact.disqualifying-dtcs.v1", "version": 1, "codes": ["P0601", "P0602", "P0603", "P0604", "P0605", "P0606", "P062F"]}
DTC_SET_HASH = ohash(DTC_SET)

# ---- Registry chain (R60-R66; payload shapes SPEC-005 R36, signatures SPEC-005 R57) ----
TENANT = "tenant-registry-synthetic"
OPERATOR = {"kind": "user", "id": "user-registry-operator"}
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


def append(typ: str, body: dict[str, object]) -> None:
    seq = len(CHAIN)
    body = {**body, "signer_key_id": kid(S)}
    h = ohash({"schema": "impact.key-event.v1", "tenant_id": TENANT, "genesis_hash": GENESIS_HASH, "seq": seq, "type": typ, "payload": body})
    payload = {**body, "signature": signature("impact.key-event-signature.v1", h, S)[1]}
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
                "actor": OPERATOR,
                "ts": f"2026-10-18T13:{seq:02d}:00Z",
                "prev_hash": CHAIN[-1]["hash"],
            }
        )
    )


def enroll(key: dict[str, object], roles: list[str], rotates: str | None, n: int) -> None:
    append(
        "attester_enrolled",
        {"attester_key_id": kid(key), "public_key": key["public_key"], "roles": roles, "rotates": rotates, "reason_commitment": reason_commitment(n)},
    )


enroll(A, ["attester"], None, 1)  # seq 1
enroll(B, ["attester"], None, 2)  # seq 2
enroll(C, ["attester"], None, 3)  # seq 3
enroll(E, ["attester"], None, 4)  # seq 4
enroll(A2, ["attester"], kid(A), 5)  # seq 5, rotation of A
enroll(F, ["reviewer"], None, 6)  # seq 6
append("attester_revoked", {"attester_key_id": kid(C), "reason": "compromised", "reason_commitment": reason_commitment(7)})  # seq 7
REVOCATION_TS = CHAIN[7]["ts"]


def entry(key: dict[str, object], roles: list[str], identity: dict[str, object], seq: int, revoked: dict[str, object] | None) -> dict[str, object]:
    return {"attester_key_id": kid(key), "public_key": key["public_key"], "roles": roles, "identity": kid(identity), "enrolled_seq": seq, "revoked": revoked}


def registry(head: int, c_revoked: dict[str, object] | None) -> dict[str, object]:
    entries = [
        entry(A, ["attester"], A, 1, None),
        entry(B, ["attester"], B, 2, None),
        entry(C, ["attester"], C, 3, c_revoked),
        entry(E, ["attester"], E, 4, None),
        entry(A2, ["attester"], A, 5, None),
        entry(F, ["reviewer"], F, 6, None),
    ]
    return {
        "schema": "impact.attester-registry.v1",
        "tenant_id": TENANT,
        "genesis_hash": GENESIS_HASH,
        "head": {"seq": head, "hash": CHAIN[head]["hash"]},
        "attesters": sorted(entries, key=lambda x: x["attester_key_id"]),
        "findings": [],
    }


REGISTRIES = {
    "head6": registry(6, None),
    "head7": registry(7, {"seq": 7, "reason": "compromised"}),
}
REGISTRY_HASH = {k: ohash(v) for k, v in REGISTRIES.items()}

# ---- Attestations (R40-R50) ----


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
    salt: str = SALT,
    created: str = "2026-10-18T14:00:00Z",
    tool_version: str = "1.0",
) -> dict[str, object]:
    return {
        "schema": "impact.field-attestation.v1",
        "subject_image_hash": subject,
        "identification": {"family": FAMILY, "hw_id": "synthetic-hw-1", "sw_id": "synthetic-sw-1", "checksum_variant_id": variant},
        "write_tool": {"name": "Synthetic Flasher", "version": tool_version},
        "readback_image_hash": readback,
        "communicates": communicates,
        "dtcs_after_clear_and_reread": dtcs or [],
        "tool_checksum_status": tcs,
        "ecu_commitment": commitment(salt, UNITS[unit][1]),
        "ecu_salt_id": ohash({"schema": "impact.ecu-salt-id.v1", "salt": salt}),
        "attester_key_id": kid(key),
        "created_at": created,
    }


def signed(att: dict[str, object], signer: dict[str, object]) -> dict[str, object]:
    h = ohash(att)
    return {"attestation": att, "attestation_hash": h, "signature": signature("impact.field-attestation-signature.v1", h, signer)[1]}


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
    "BY_SALT2": signed(make_att(B, "Y", salt=SALT2), B),
    "CZ_NOCOMM": signed(make_att(C, "Z", communicates=False), C),
    "FY": signed(make_att(F, "Y"), F),
    "A_SIGNED_BY_B": signed(make_att(A, "Z"), B),
}
# Edited after signing: write_tool version changed. With rehash the hash is consistent and the signature fails;
# without rehash the stored hash no longer matches.
_by = POOL["BY"]
_edited = {**make_att(B, "Y"), "write_tool": {"name": "Synthetic Flasher", "version": "1.1"}}
POOL["BY_EDITED_REHASH"] = {"attestation": _edited, "attestation_hash": ohash(_edited), "signature": _by["signature"]}
POOL["BY_EDITED_NOREHASH"] = {"attestation": _edited, "attestation_hash": _by["attestation_hash"], "signature": _by["signature"]}

_ax_msg, _ax_sig = signature("impact.field-attestation-signature.v1", str(POOL["AX"]["attestation_hash"]), A)
ATTESTATION_VERIFY = {
    "rules": ["R48", "R49", "R50"],
    "example": {
        "label": "AX",
        "attestation_jcs": jcs(POOL["AX"]["attestation"]),
        "attestation_hash": POOL["AX"]["attestation_hash"],
        "signing_input": _ax_msg,
        "signature": _ax_sig,
    },
    "cases": [
        {"label": "AX", "registry": "head6", "expect": []},
        {"label": "BY_EDITED_REHASH", "registry": "head6", "expect": ["bad_signature"]},
        {"label": "BY_EDITED_NOREHASH", "registry": "head6", "expect": ["attestation_hash_mismatch"]},
        {"label": "A_SIGNED_BY_B", "registry": "head6", "expect": ["bad_signature"]},
        {"label": "DY", "registry": "head6", "expect": ["unknown_attester"]},
        {"label": "CY", "registry": "head6", "expect": []},
        {"label": "CY", "registry": "head7", "expect": ["revoked_attester"]},
        {"label": "FY", "registry": "head6", "expect": ["not_attester"]},
    ],
}

# ---- Golden records and evaluations (R70-R78) ----
T1 = {"name": "Synthetic Tool One", "version": "2.0", "image_hash": GOLDEN_HASH, "date": "2026-10-17"}
T2 = {"name": "Synthetic Tool Two", "version": "5.1", "image_hash": GOLDEN_HASH, "date": "2026-10-17"}
T3 = {"name": "Synthetic Tool Three", "version": "1.0", "image_hash": APPLY_HASH, "date": "2026-10-17"}

BELOW = ["below_attestations", "below_attesters", "below_units"]
EVAL_RULES = ["R70", "R71", "R72", "R73", "R75", "R76", "R78"]


def golden_record(labels: list[str], tools: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema": "impact.golden-record.v1",
        "family": FAMILY,
        "checksum_variant_id": VARIANT,
        "base_image_hash": BASE_HASH,
        "version_hash": VERSION_HASH,
        "expected_image_hash": GOLDEN_HASH,
        "oracle": {
            "tools": sorted(tools, key=lambda t: (t["name"], t["version"])),
            "attestations": sorted({str(POOL[x]["attestation_hash"]) for x in labels}),
        },
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
    test_mode: bool = True,
) -> dict[str, object]:
    record = golden_record(listed, tools)
    rows = []
    for label in listed:
        rs, negative = per.get(label, ([], False))
        rows.append({"attestation_hash": POOL[label]["attestation_hash"], "qualifying": rs == [], "negative": negative, "reasons": rs})
    evaluation = {
        "schema": "impact.golden-evaluation.v1",
        "golden_record_hash": ohash(record),
        "registry_hash": REGISTRY_HASH[registry_name],
        "dtc_set_hash": DTC_SET_HASH,
        "salt_id": SALT_ID,
        "thresholds": {"attestations": 2, "attesters": 2, "units": 2},
        "counts": {"attestations": counts[0], "attesters": counts[1], "units": counts[2]},
        "attestations": sorted(rows, key=lambda r: r["attestation_hash"]),
        "reasons": reasons,
        "level": level,
    }
    return {
        "id": case_id,
        "rules": rules,
        "registry": registry_name,
        "test_mode": test_mode,
        "record": record,
        "golden_record_hash": ohash(record),
        "supplied": supplied if supplied is not None else listed,
        "expect": {"evaluation": evaluation, "evaluation_hash": ohash(evaluation)},
    }


Q: tuple[list[str], bool] = ([], False)
CASES = [
    case("G01-two-attesters-two-ecus", EVAL_RULES, ["AX", "BY"], [], "head6", {}, (2, 2, 2), [], "golden_field"),
    case("G02-one-attester-two-ecus", EVAL_RULES, ["AX", "AY"], [T1, T2], "head6", {}, (2, 1, 2), ["below_attesters"], "golden_concordant"),
    case("G03-two-attesters-one-ecu", EVAL_RULES, ["AX", "BX"], [T1], "head6", {}, (2, 2, 1), ["below_units"], "candidate"),
    case("G04-single-attestation", EVAL_RULES, ["AX"], [], "head6", {}, (1, 1, 1), BELOW, "none"),
    case("G05-three-attestations", EVAL_RULES, ["AX", "AY", "BX"], [], "head6", {}, (3, 2, 2), [], "golden_field"),
    case(
        "G06-other-attester-has-zero-qualifying",
        EVAL_RULES,
        ["AX", "AY", "BY_WRONG_SUBJECT"],
        [],
        "head6",
        {"BY_WRONG_SUBJECT": (["wrong_subject"], False)},
        (2, 1, 2),
        ["below_attesters"],
        "none",
    ),
    case("G07-before-revocation", EVAL_RULES + ["R77"], ["AX", "CY"], [], "head6", {}, (2, 2, 2), [], "golden_field"),
    case("G08-after-revocation", EVAL_RULES + ["R77", "R79"], ["AX", "CY"], [], "head7", {"CY": (["revoked_attester"], False)}, (1, 1, 1), BELOW, "none"),
    case(
        "G09-backdated-attestation-of-revoked-key",
        EVAL_RULES + ["R51", "R77"],
        ["AX", "CY_BACKDATED"],
        [],
        "head7",
        {"CY_BACKDATED": (["revoked_attester"], False)},
        (1, 1, 1),
        BELOW,
        "none",
    ),
    case("G10-unenrolled-key", EVAL_RULES + ["R50"], ["AX", "DY"], [], "head6", {"DY": (["unknown_attester"], False)}, (1, 1, 1), BELOW, "none"),
    case(
        "G11-duplicates-and-reflash",
        EVAL_RULES,
        ["AX", "AX2", "BY"],
        [],
        "head6",
        {},
        (3, 2, 2),
        [],
        "golden_field",
        supplied=["BY", "AX", "AX2", "BY"],
    ),
    case("G12-rotation-is-one-identity", EVAL_RULES + ["R64"], ["AX", "A2Y"], [], "head6", {}, (2, 1, 2), ["below_attesters"], "none"),
    case("G13-edited-and-rehashed", EVAL_RULES + ["R50"], ["AX", "BY_EDITED_REHASH"], [], "head6", {"BY_EDITED_REHASH": (["bad_signature"], False)}, (1, 1, 1), BELOW, "none"),
    case(
        "G14-edited-without-rehash",
        EVAL_RULES + ["R50"],
        ["AX", "BY"],
        [],
        "head6",
        {"BY": (["attestation_hash_mismatch"], False)},
        (1, 1, 1),
        BELOW,
        "none",
        supplied=["AX", "BY_EDITED_NOREHASH"],
    ),
    case("G15-wrong-variant", EVAL_RULES, ["AX", "BY_V2"], [], "head6", {"BY_V2": (["wrong_variant"], False)}, (1, 1, 1), BELOW, "none"),
    case(
        "G16-negative-no-communication",
        EVAL_RULES + ["R74"],
        ["AX", "BY", "EZ_NOCOMM"],
        [],
        "head6",
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
        "head6",
        {"EZ_DTC": (["disqualifying_dtc"], True)},
        (2, 2, 2),
        ["negative_field_evidence"],
        "none",
    ),
    case("G18-non-disqualifying-dtcs", EVAL_RULES + ["R55"], ["AX_OKDTC", "BY"], [], "head6", {}, (2, 2, 2), [], "golden_field"),
    case(
        "G19-tool-checksum-mismatch",
        EVAL_RULES + ["R42", "R74"],
        ["AX", "BY_MISMATCH"],
        [T1],
        "head6",
        {"BY_MISMATCH": (["tool_checksum_mismatch"], True)},
        (1, 1, 1),
        BELOW + ["negative_field_evidence"],
        "candidate",
    ),
    case("G20-checksum-not-reported", EVAL_RULES + ["R42"], ["AX_NOTREP", "BY"], [], "head6", {}, (2, 2, 2), [], "golden_field"),
    case(
        "G21-readback-mismatch",
        EVAL_RULES + ["R44", "R74"],
        ["AX", "BY_READBACK"],
        [],
        "head6",
        {"BY_READBACK": (["readback_mismatch"], True)},
        (1, 1, 1),
        BELOW + ["negative_field_evidence"],
        "none",
    ),
    case("G22-foreign-salt", EVAL_RULES + ["R47"], ["AX", "BY_SALT2"], [], "head6", {"BY_SALT2": (["foreign_salt"], False)}, (1, 1, 1), BELOW, "none"),
    case("G23-missing-attestation", EVAL_RULES, ["AX", "BY"], [], "head6", {"BY": (["missing"], False)}, (1, 1, 1), BELOW, "none", supplied=["AX"]),
    case(
        "G24-negative-by-revoked-key-ignored",
        EVAL_RULES + ["R74", "R77"],
        ["AX", "BY", "CZ_NOCOMM"],
        [],
        "head7",
        {"CZ_NOCOMM": (["revoked_attester"], False)},
        (2, 2, 2),
        [],
        "golden_field",
    ),
    case("G25-reviewer-only-key", EVAL_RULES + ["R62"], ["AX", "FY"], [], "head6", {"FY": (["not_attester"], False)}, (1, 1, 1), BELOW, "none"),
    case("G26-tools-disagree", EVAL_RULES, [], [T1, T3], "head6", {}, (0, 0, 0), BELOW + ["tool_disagreement"], "candidate"),
    case("G28-field-with-tool-disagreement", EVAL_RULES, ["AX", "BY"], [T1, T3], "head6", {}, (2, 2, 2), ["tool_disagreement"], "golden_field"),
]
_g27 = golden_record(["AX", "BY"], [])
CASES.insert(
    26,
    {
        "id": "G27-test-keys-outside-test-mode",
        "rules": ["R65", "R66", "R80"],
        "registry": None,
        "test_mode": False,
        "record": _g27,
        "golden_record_hash": ohash(_g27),
        "supplied": ["AX", "BY"],
        "expect": {"error": "registry_broken"},
    },
)

vectors = {
    "generator": {
        "jcs": f"rfc8785 {importlib.metadata.version('rfc8785')}",
        "ed25519": f"cryptography {importlib.metadata.version('cryptography')}",
        "sha256": "python hashlib",
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
    "keys": {
        "rules": ["R49", "R66"],
        "keys": {n: {"seed_text": k["seed_text"], "public_key": k["public_key"], "key_id": k["key_id"]} for n, k in KEYS.items()},
    },
    "raw_import": {"max_input_bytes": MAX_INPUT_BYTES, "importer_version": CORE_VERSION, "cases": RAW_CASES},
    "dtcs": DTCS,
    "salt": {"rules": ["R47"], "salt": SALT, "salt_id": SALT_ID, "second_salt": SALT2, "second_salt_id": SALT2_ID},
    "unit_ids": UNIT_IDS,
    "ecu_commitment": ECU_COMMITMENTS,
    "dtc_set": {"rules": ["R55", "R56"], "value": DTC_SET, "jcs": jcs(DTC_SET), "dtc_set_hash": DTC_SET_HASH},
    "registry_chain": {
        "rules": ["R60", "R61", "R62", "R63", "R64"],
        "test_mode": True,
        "events": [{"event": ev, "hash": ev["hash"]} for ev in CHAIN],
        "revocation_ts": REVOCATION_TS,
    },
    "registries": {
        name: {"rules": ["R61", "R62", "R63", "R64", "R65"], "value": reg, "registry_hash": REGISTRY_HASH[name]}
        for name, reg in REGISTRIES.items()
    },
    "attestations": POOL,
    "attestation_verify": ATTESTATION_VERIFY,
    "evaluations": CASES,
}

json.dump(vectors, sys.stdout, indent=2)
sys.stdout.write("\n")
