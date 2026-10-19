"""A synthetic export scenario over tests/unit/fixtures.py: version, checksum patches, gate reports and a signed chain.

Expected hashes use the third-party `rfc8785` JCS, never the core's own canonicalization.
"""

import hashlib
from dataclasses import dataclass
from typing import Any

import rfc8785

from core.kernel import Patch, Version, apply, apply_checksum_patches, image_hash, layout_hash
from core.provenance import Build, Event, ExportInputs, PluginVersion, Reference, Versions
from tests.unit.fixtures import DUMP, LAYOUT, patch
from tests.unit.provenance_support import add, import_payload, start

DEFINITION_HASH = hashlib.sha256(b"synthetic definition").hexdigest()
CHECKSUM: tuple[Patch, ...] = (patch(28, b"\x01"), patch(24, b"\xaa\xab"))
VERSION = Version(image_hash(DUMP), layout_hash(LAYOUT), (patch(16, b"\x90\x91"), patch(10, b"\x77")))
VERSIONS = Versions(
    "0.1.0",
    (PluginVersion("zeta.family", "1", "11" * 32), PluginVersion("alpha.family", "2", "22" * 32)),
    "rules-1",
    (Reference("ref.b", "1"), Reference("ref.a", "2")),
)
IMAGE_BUILD = Build("image", "sha256:" + "33" * 32, "linux/amd64", "build-1")
LOCK_BUILD = Build("lockfile", "sha256:" + "44" * 32, "linux/arm64", None)
WARN = {"rule_id": "T-RANGE", "severity": "warn", "text": "value near the limit"}
INFO = {"rule_id": "T-INFO", "severity": "info", "text": "informational"}


def sha(value: dict[str, Any] | list[Any]) -> str:
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def gate_report(verdict: str = "warn", **subject: object) -> dict[str, Any]:
    findings = [INFO, WARN] if verdict == "warn" else []
    return {
        "schema": "synthetic.gate-report.v0",
        "verdict": verdict,
        "findings": findings,
        "subject": {
            "definition_hash": DEFINITION_HASH,
            "layout_hash": layout_hash(LAYOUT),
            "references": [{"id": "ref.a", "version": "2"}, {"id": "ref.b", "version": "1"}],
            "signed_regions": [],
            **subject,
        },
    }


def input_report(verdict: str = "block", status: str = "fail") -> dict[str, Any]:
    return {"verdict": verdict, "subject": {"verify_status": status}}


RELEASE_HASH = apply_checksum_patches(apply(DUMP, VERSION, LAYOUT), CHECKSUM, LAYOUT).image_hash


@dataclass
class Scenario:
    inputs: ExportInputs
    chain: list[Event]
    alert_ack: Event | None
    suspect_ack: Event | None


def scenario(*, warn: bool = True, suspect: bool = True, build: Build = IMAGE_BUILD) -> Scenario:
    gate = gate_report("warn" if warn else "no findings")
    report_in = input_report("block", "fail") if suspect else input_report("no findings", "ok")
    chain = [start()]
    add(chain, "import", import_payload(image_hash(DUMP)))
    suspect_ack = None
    if suspect:
        payload = {"artifact_sha256": "bb" * 32, "image_hash": image_hash(DUMP), "input_report_hash": sha(report_in)}
        suspect_ack = add(chain, "suspect_ack", {**payload, "verify_status": "fail"})
    alert_ack = None
    if warn:
        alert_ack = add(
            chain,
            "alert_ack",
            {
                "image_hash_release": RELEASE_HASH,
                "gate_report_hash": sha(gate),
                "warnings": [{"finding_id": sha(WARN), "rule_id": WARN["rule_id"], "text": WARN["text"]}],
                "presented_ms": 1,
                "confirmed_ms": 2,
            },
        )
    inputs = ExportInputs(DUMP, VERSION, LAYOUT, CHECKSUM, DEFINITION_HASH, VERSIONS, gate, report_in, build)
    return Scenario(inputs, chain, alert_ack, suspect_ack)
