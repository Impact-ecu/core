"""Generate SPEC-008 test vectors.

Independent of the core. JCS comes from the third-party `rfc8785` package, Ed25519 from the third-party
`cryptography` package (both pinned in requirements.txt), SHA-256 from hashlib. All data is synthetic: no byte,
address or identifier describes a real ECU. Fingerprints, the registry hash and signatures are computed here;
every expected StockCheck is written by hand. crosscheck.py derives all of them with its own code.
Run: python -I generate.py > vectors.json   then   python -I crosscheck.py vectors.json
"""
from __future__ import annotations

import copy
import hashlib
import importlib.metadata
import json
import sys

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

DOMAIN = "impact.stock-registry-signature.v1"


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


def key(text: str) -> dict[str, object]:
    priv = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(text.encode("utf-8")).digest())
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return {"seed_text": text, "priv": priv, "public_key": pub, "key_id": sha(bytes.fromhex(pub))}


SIGNER = key("impact spec-008 synthetic stock registry key; never use outside test vectors")
OTHER = key("impact spec-008 synthetic other key; never use outside test vectors")


def sign(h: str, k: dict[str, object]) -> tuple[str, str]:
    message = jcs({"domain": DOMAIN, "hash": h})
    priv = k["priv"]
    assert isinstance(priv, Ed25519PrivateKey)
    return message, priv.sign(message.encode("utf-8")).hex()


# ---- Fixture (synthetic) ----
FAMILY = "synthetic.stock"
SW1, SW2, SW3 = "SYN-SW-1", "SYN-SW-2", "SYN-SW-3"
PFLASH = bytes((i * 7 + 3) & 0xFF for i in range(64))
PFLASH_SW2 = PFLASH[:10] + b"\x5a" + PFLASH[11:]
PFLASH_EDITED = PFLASH[:40] + bytes([PFLASH[40] ^ 0x01]) + PFLASH[41:]
UNIT = (16, 24)


def dflash(unit: bytes) -> bytes:
    assert len(unit) == UNIT[1] - UNIT[0]
    return b"\xff" * 16 + unit + b"\x00" * 8


DFLASH_A = dflash(b"SYNUNIT1")
DFLASH_B = dflash(b"SYNUNIT2")
EEPROM = bytes(range(8))
PII = [{"memory_id": "dflash", "start": UNIT[0], "end": UNIT[1], "kind": "serial"}]


def kept(data: bytes, excluded: list[list[int]]) -> str:
    parts, position = [], 0
    for start, end in excluded:
        parts.append(data[position:start])
        position = end
    parts.append(data[position:])
    return sha(b"".join(parts))


FINGERPRINTS = [
    {"id": "F1", "data_hex": DFLASH_A.hex(), "excluded": [[16, 24]], "kept_sha256": kept(DFLASH_A, [[16, 24]])},
    {"id": "F2", "data_hex": DFLASH_B.hex(), "excluded": [[16, 24]], "kept_sha256": kept(DFLASH_B, [[16, 24]])},
    {"id": "F3", "data_hex": PFLASH.hex(), "excluded": [], "kept_sha256": sha(PFLASH)},
    {"id": "F4", "data_hex": PFLASH.hex(), "excluded": [[0, 2], [10, 12], [63, 64]], "kept_sha256": kept(PFLASH, [[0, 2], [10, 12], [63, 64]])},
]
assert FINGERPRINTS[0]["kept_sha256"] == FINGERPRINTS[1]["kept_sha256"]


def entry(sw_id: str, memory_id: str, data: bytes, excluded: list[list[int]]) -> dict[str, object]:
    return {
        "family": FAMILY,
        "sw_id": sw_id,
        "memory_id": memory_id,
        "size": len(data),
        "excluded": [{"start": s, "end": e} for s, e in excluded],
        "kept_sha256": kept(data, excluded),
    }


ENTRIES = [
    entry(SW1, "dflash", DFLASH_A, [[16, 24]]),
    entry(SW1, "pflash", PFLASH, []),
    entry(SW2, "pflash", PFLASH_SW2, []),
    entry(SW3, "dflash", DFLASH_A, []),
]
ENTRIES.sort(key=lambda e: (e["family"], e["sw_id"], e["memory_id"], e["size"], e["kept_sha256"]))


def registry(issued_at: str, expires_at: str) -> dict[str, object]:
    return {
        "schema": "impact.stock-registry.v1",
        "version": 3,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "entries": ENTRIES,
    }


def signed(reg: dict[str, object], k: dict[str, object]) -> dict[str, object]:
    h = ohash(reg)
    _, sig = sign(h, k)
    return {"registry": reg, "registry_hash": h, "key_id": k["key_id"], "signature": sig}


MAIN = signed(registry("2026-10-19T00:00:00Z", "2026-10-20T00:00:00Z"), SIGNER)
BAD_SIGNATURE = copy.deepcopy(MAIN)
BAD_SIGNATURE["signature"] = ("00" if MAIN["signature"][:2] != "00" else "01") + MAIN["signature"][2:]
TOO_LONG = signed(registry("2026-10-19T00:00:00Z", "2026-10-20T00:00:01Z"), SIGNER)
REGISTRIES = {"main": MAIN, "bad_signature": BAD_SIGNATURE, "too_long": TOO_LONG}

TRUSTS = {
    "main": {"key_id": SIGNER["key_id"], "public_key": SIGNER["public_key"]},
    "other": {"key_id": OTHER["key_id"], "public_key": OTHER["public_key"]},
}
# A synthetic policy for the vectors only: SPEC-008 R15 leaves the published value to the author.
POLICY = {"schema": "impact.stock-policy.v1", "version": 0, "max_validity_s": 86400}

MAIN_HASH = MAIN["registry_hash"]
AS_OF = "2026-10-19T12:00:00Z"


def memories(*items: tuple[str, int | None, bytes]) -> list[dict[str, object]]:
    return [{"memory_id": m, "base_address": b, "data_hex": d.hex()} for m, b, d in items]


P = ("pflash", 0x80000000, PFLASH)
DA = ("dflash", 0xAF000000, DFLASH_A)
DB = ("dflash", 0xAF000000, DFLASH_B)


def ident(sw_id: str | None, pii: list[dict[str, object]] | None = None) -> dict[str, object]:
    return {"family": FAMILY, "sw_id": sw_id, "pii_locations": PII if pii is None else pii}


def used(status: str, reasons: list[str], sw_id: str | None, mems: list[dict[str, object]], family: str | None = FAMILY) -> dict[str, object]:
    return {
        "schema": "impact.stock-check.v1",
        "status": status,
        "reasons": reasons,
        "registry_hash": MAIN_HASH,
        "registry_version": 3,
        "family": family,
        "sw_id": sw_id,
        "memories": mems,
    }


def unusable(reasons: list[str], sw_id: str | None = SW1) -> dict[str, object]:
    return {
        "schema": "impact.stock-check.v1",
        "status": "unknown",
        "reasons": reasons,
        "registry_hash": None,
        "registry_version": None,
        "family": FAMILY,
        "sw_id": sw_id,
        "memories": [],
    }


def mem(memory_id: str, status: str, reason: str | None = None) -> dict[str, object]:
    return {"memory_id": memory_id, "status": status, "reason": reason}


def case(cid: str, rules: list[str], dump: list[dict[str, object]], identification: dict[str, object] | None,
         expect: dict[str, object], *, registry_name: str = "main", trust: str = "main", as_of: str = AS_OF) -> dict[str, object]:
    return {
        "id": cid,
        "rules": rules,
        "dump": {"dump_kind": "bench_full", "memories": dump},
        "identification": identification,
        "registry": registry_name,
        "trust": trust,
        "as_of": as_of,
        "expect": expect,
    }


CASES = [
    case("K01-stock", ["R11", "R23", "R24"], memories(P, DA), ident(SW1),
         used("stock", [], SW1, [mem("dflash", "stock"), mem("pflash", "stock")])),
    case("K02-stock-other-unit", ["R11", "R23"], memories(P, DB), ident(SW1),
         used("stock", [], SW1, [mem("dflash", "stock"), mem("pflash", "stock")])),
    case("K03-modified", ["R23", "R24"], memories(("pflash", 0x80000000, PFLASH_EDITED), DA), ident(SW1),
         used("modified", [], SW1, [mem("dflash", "stock"), mem("pflash", "modified")])),
    case("K04-not-registered", ["R23", "R24"], memories(P, DA), ident("SYN-SW-9"),
         used("unknown", ["not_registered"], "SYN-SW-9", [mem("dflash", "unknown", "not_registered"), mem("pflash", "unknown", "not_registered")])),
    case("K05-other-software-version", ["R20", "R23", "R24"], memories(P, DA), ident(SW2),
         used("modified", [], SW2, [mem("dflash", "unknown", "not_registered"), mem("pflash", "modified")])),
    case("K06-pii-not-excluded", ["R23"], memories(DA), ident(SW3),
         used("unknown", ["pii_not_excluded"], SW3, [mem("dflash", "unknown", "pii_not_excluded")])),
    case("K07-partial-dump", ["R10", "R24"], memories(P), ident(SW1, []),
         used("stock", [], SW1, [mem("pflash", "stock")])),
    case("K08-one-memory-unknown", ["R24"], memories(("eeprom", None, EEPROM), P), ident(SW1, []),
         used("unknown", ["not_registered"], SW1, [mem("eeprom", "unknown", "not_registered"), mem("pflash", "stock")])),
    case("K09-no-identification", ["R22"], memories(P, DA), None,
         used("unknown", ["not_identified"], None, [], family=None)),
    case("K10-no-sw-id", ["R22"], memories(P, DA), ident(None),
         used("unknown", ["no_sw_id"], None, [])),
    case("K11-bad-signature", ["R13", "R21"], memories(P, DA), ident(SW1), unusable(["untrusted_registry"]),
         registry_name="bad_signature"),
    case("K12-other-key", ["R14", "R21"], memories(P, DA), ident(SW1), unusable(["untrusted_registry"]), trust="other"),
    case("K13-not-yet-valid", ["R15", "R21"], memories(P, DA), ident(SW1), unusable(["registry_not_yet_valid"]),
         as_of="2026-10-18T23:59:59Z"),
    case("K14-expired", ["R15", "R21"], memories(P, DA), ident(SW1), unusable(["registry_expired"]),
         as_of="2026-10-20T00:00:00Z"),
    case("K15-validity-too-long", ["R15", "R21"], memories(P, DA), ident(SW1), unusable(["registry_validity_too_long"]),
         registry_name="too_long"),
]

_msg, _ = sign(MAIN_HASH, SIGNER)
vectors = {
    "spec": "SPEC-008",
    "generator": {
        "jcs": f"rfc8785 {importlib.metadata.version('rfc8785')}",
        "ed25519": f"cryptography {importlib.metadata.version('cryptography')}",
        "sha256": "python hashlib",
        "python": sys.version.split()[0],
    },
    "key": {
        "rules": ["R13", "R14"],
        "seed_text": SIGNER["seed_text"],
        "seed_hex": sha(str(SIGNER["seed_text"]).encode("utf-8")),
        "public_key": SIGNER["public_key"],
        "key_id": SIGNER["key_id"],
        "other_seed_text": OTHER["seed_text"],
    },
    "fingerprints": {"rules": ["R11"], "values": FINGERPRINTS},
    "registry": {
        "rules": ["R10", "R12", "R13"],
        "jcs": jcs(MAIN["registry"]),
        "registry_hash": MAIN_HASH,
        "signing_input": _msg,
    },
    "registries": REGISTRIES,
    "trusts": TRUSTS,
    "policy": POLICY,
    "cases": CASES,
}

json.dump(vectors, sys.stdout, indent=2)
sys.stdout.write("\n")
