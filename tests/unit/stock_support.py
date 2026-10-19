"""Synthetic SPEC-008 data: the spec-008 vectors as core objects. Nothing here describes a real ECU."""

import json
from typing import Any

from core.kernel import Dump, Memory
from core.plugins import Identification, PiiLocation, PresentMemory
from core.stock._check import Published
from tests.unit.provenance_support import ROOT, VERIFIER

V: dict[str, Any] = json.loads((ROOT / "specs" / "vectors" / "spec-008" / "vectors.json").read_text("utf-8"))
MAIN: dict[str, Any] = V["registries"]["main"]
TRUST: dict[str, Any] = V["trusts"]["main"]
POLICY: dict[str, Any] = V["policy"]
TEST_PUBLISHED = Published(TRUST, POLICY)
AS_OF = "2026-10-19T12:00:00Z"
CASES: dict[str, dict[str, Any]] = {case["id"]: case for case in V["cases"]}
__all__ = ["AS_OF", "CASES", "MAIN", "POLICY", "TEST_PUBLISHED", "TRUST", "VERIFIER", "V", "dump_of", "ident_of"]


def dump_of(value: dict[str, Any]) -> Dump:
    memories = tuple(Memory(m["memory_id"], m["base_address"], bytes.fromhex(m["data_hex"])) for m in value["memories"])
    return Dump(value["dump_kind"], memories)


def ident_of(value: dict[str, Any] | None, dump: Dump) -> Identification | None:
    """A SPEC-002 identification of `dump` with the vector's family, sw_id and pii locations."""
    if value is None:
        return None
    present = tuple(
        PresentMemory(m.memory_id, m.base_address, len(m.data))
        for m in sorted(dump.memories, key=lambda m: m.memory_id)
    )
    pii = tuple(PiiLocation(p["memory_id"], p["start"], p["end"], p["kind"]) for p in value["pii_locations"])
    return Identification(value["family"], None, value["sw_id"], None, None, present, (), pii, (), 900)
