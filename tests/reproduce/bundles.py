"""Synthetic reproduction bundles (SPEC-005 §9) built from the SPEC-001 and SPEC-005 vectors.

Re-signed report files use the third-party `rfc8785` and `cryptography` with the published SPEC-005 test seed,
never the core and never the script under test. Every byte is synthetic.
"""

import copy
import hashlib
import sys
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.unit.provenance_support import ROOT, SPEC005
from tests.vectors.test_spec_001 import VECTORS as SPEC001

SCRIPT = ROOT / "tools" / "reproduce" / "reproduce.py"
BUNDLE_SCHEMA = "impact.reproduction-bundle.v1"
REPORT_DOMAIN = "impact.report-signature.v1"
TEST_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SPEC005["key"]["seed_hex"]))


def sha(value: dict[str, Any] | list[Any]) -> str:
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def original() -> dict[str, Any]:
    vector = SPEC001["original"]
    return {
        "dump_kind": vector["dump_kind"],
        "memories": [
            {"memory_id": memory_id, "base_address": memory["base_address"], "data": memory["bytes_hex"]}
            for memory_id, memory in vector["memories"].items()
        ],
    }


def patch(name: str) -> dict[str, Any]:
    value: dict[str, Any] = copy.deepcopy(SPEC001["patches"][name]["value"])
    return value


def vector_bundle() -> dict[str, Any]:
    """The `report_file` vector: V4 (P1, P2) released by V9 (Q1) on layout `base` (SPEC-005 §12)."""
    return {
        "schema": BUNDLE_SCHEMA,
        "report_file": copy.deepcopy(SPEC005["report_file"]["value"]),
        "original": original(),
        "layout": copy.deepcopy(SPEC001["layouts"]["base"]["value"]),
        "patches": [patch("P2"), patch("P1")],
        "overlaps": [],
        "checksum_patches": [patch("Q1")],
        "gate_report": copy.deepcopy(SPEC005["gate_report"]["value"]),
    }


def rehash_event(event: dict[str, Any]) -> None:
    event["hash"] = sha({key: value for key, value in event.items() if key != "hash"})


def resign(report_file: dict[str, Any]) -> None:
    """Recompute `record_hash`, `report_hash`, the event payload, its signature and its hash."""
    report = report_file["report"]
    report["record_hash"] = sha(report["record"])
    report_file["report_hash"] = sha(report)
    payload = report_file["event"]["payload"]
    payload["provenance_hash"] = report["record_hash"]
    payload["report_hash"] = report_file["report_hash"]
    message = rfc8785.dumps({"domain": REPORT_DOMAIN, "hash": report_file["report_hash"]})
    payload["signature"] = TEST_KEY.sign(message).hex()
    rehash_event(report_file["event"])


def record_bundle(name: str) -> dict[str, Any]:
    """The bundle of a SPEC-005 record vector, its report re-signed with the test key."""
    bundle = vector_bundle()
    record = copy.deepcopy(SPEC005[name]["value"])
    reports = [SPEC005["gate_report"], SPEC005["gate_report_no_findings"]]
    bundle["gate_report"] = next(g["value"] for g in reports if g["gate_report_hash"] == record["gate_report_hash"])
    bundle["report_file"]["report"]["record"] = record
    resign(bundle["report_file"])
    return bundle


def write(path: Path, bundle: dict[str, Any]) -> Path:
    path.write_bytes(rfc8785.dumps(bundle))
    return path


TAMPERS = {t["id"]: t for t in SPEC005["tampers"]}


def t6_bundle() -> dict[str, Any]:
    """Tamper T6 (target `report_file`) on the vector bundle."""
    bundle = vector_bundle()
    mutation = TAMPERS["T6-report-verdict-edited"]["mutation"]
    target = bundle["report_file"]
    for key in mutation["path"][:-1]:
        target = target[key]
    target[mutation["path"][-1]] = mutation["value"]
    return bundle


def t5_bundle() -> dict[str, Any]:
    """Tamper T5 on the export event (`seq` 4), which is the report file's event; rehashed as T5 says."""
    bundle = vector_bundle()
    mutation = TAMPERS["T5-export-signature-flipped"]["mutation"]
    event = bundle["report_file"]["event"]
    assert (event["seq"], mutation["seq"], mutation["path"], mutation["rehash"]) == (
        4,
        4,
        ["payload", "signature"],
        True,
    )
    event["payload"]["signature"] = mutation["value"]
    rehash_event(event)
    return bundle


def audit_bundle() -> dict[str, Any]:
    bundle = vector_bundle()
    bundle["report_file"]["report"]["kind"] = "audit"
    return bundle


def vector_cases() -> dict[str, tuple[dict[str, Any], bool]]:
    """Every SPEC-005 vector the script applies to, with whether it reproduces (SPEC-005 R76)."""
    return {
        "report_file": (vector_bundle(), True),
        "provenance": (record_bundle("provenance"), True),
        "provenance_no_findings": (record_bundle("provenance_no_findings"), True),
        "provenance_lockfile": (record_bundle("provenance_lockfile"), True),
        "T5": (t5_bundle(), False),
        "T6": (t6_bundle(), False),
        "audit": (audit_bundle(), False),
    }


if __name__ == "__main__":
    # CI (SPEC-005 R76) writes the vector bundles, then runs the script on them with the runner's own python3 -I.
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    for name, (bundle, reproduces) in vector_cases().items():
        write(out / f"{'reproduced' if reproduces else 'not_reproduced'}.{name}.json", bundle)
