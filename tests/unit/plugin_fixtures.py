"""Synthetic SPEC-002 data for tests: the 512-byte vector fixture and a fake plugin built on it.

Nothing here describes a real ECU (ADR-001 decision 2): every value comes from specs/vectors/spec-002.
"""

import json
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from core.kernel import Dump, DumpKind, LayoutMemory, Memory, MemoryLayout, Patch, Region
from core.plugins import (
    ChecksumRegion,
    Descriptor,
    Identification,
    MapHint,
    PresentMemory,
    Range,
    Reference,
    VerifyReport,
    aggregate,
    descriptor_from_json,
)
from core.plugins.descriptor import interpret_patches, interpret_verify

VECTORS_PATH = Path(__file__).resolve().parents[2] / "specs" / "vectors" / "spec-002" / "vectors.json"
VECTORS: dict[str, Any] = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
FIXTURE: dict[str, Any] = VECTORS["fixture"]
MEMORY: dict[str, Any] = FIXTURE["memory"]
ORIGINAL = bytes.fromhex(FIXTURE["original"]["bytes_hex"])
INTERPRETER = Reference("interpreter", None, None)
NONE = Reference("none", None, None)
FAMILY = "synthetic.fixture"
VARIANT = "fixture-512"


def layout_from_json(value: dict[str, Any]) -> MemoryLayout:
    return MemoryLayout(
        tuple(
            LayoutMemory(
                m["memory_id"],
                m["base_address"],
                m["size"],
                tuple(Region(r["kind"], r["start"], r["end"], r["name"]) for r in m["regions"]),
            )
            for m in value["memories"]
        )
    )


LAYOUT = layout_from_json(FIXTURE["layout"])
DESCRIPTORS: tuple[Descriptor, ...] = tuple(descriptor_from_json(e["value"]) for e in FIXTURE["descriptors"])


def region_of(d: Descriptor) -> ChecksumRegion:
    return ChecksumRegion(d.name, d.memory_id, "recalculable", d, None, None, INTERPRETER)


def regions_of(descriptors: tuple[Descriptor, ...] | list[Descriptor]) -> tuple[ChecksumRegion, ...]:
    return tuple(region_of(d) for d in descriptors)


REGIONS = regions_of(DESCRIPTORS)


def dump_of(data: bytes, dump_kind: DumpKind = "bench_full", base_address: int | None = None) -> Dump:
    base = MEMORY["base_address"] if base_address is None else base_address
    return Dump(dump_kind, (Memory(MEMORY["memory_id"], base, data),))


DUMP = dump_of(ORIGINAL)

IDENT = Identification(
    family=FAMILY,
    hw_id="hw-1",
    sw_id="sw-1",
    mcu=None,
    checksum_variant_id=VARIANT,
    memories_present=(PresentMemory("pflash", MEMORY["base_address"], 512),),
    memories_absent=("dflash",),
    pii_locations=(),
    protection_flags=(),
    confidence=900,
)


def edited(data: bytes, offset: int, after: bytes) -> bytes:
    return data[:offset] + after + data[offset + len(after) :]


def report_of(results: dict[str, Any]) -> VerifyReport:
    ordered = tuple(sorted(results.values(), key=lambda r: (r.memory_id, r.name)))
    status, reason = aggregate([r.status for r in ordered])
    return VerifyReport(status, reason, ordered)


@dataclass
class FakePlugin:
    """A plugin that answers from the fixture through the core interpreter.

    Real plugins must not do this (R47); here it gives a known-good plugin whose outputs tests corrupt.
    """

    family: str = FAMILY
    version: str = "1.0.0"
    contract_version: int = 1
    pii_in_flash: bool = True
    regions: tuple[ChecksumRegion, ...] = REGIONS
    layout_value: MemoryLayout = LAYOUT
    hint_list: list[MapHint] = field(default_factory=lambda: [MapHint("pflash", 32, 64, "spark", "ignition")])

    def identify(self, dump: Dump) -> Identification | None:
        if len(dump.memories) != 1 or len(dump.memories[0].data) != 512:
            return None
        return replace(IDENT, memories_present=(PresentMemory("pflash", dump.memories[0].base_address, 512),))

    def layout(self, ident: Identification, dump_kind: DumpKind) -> MemoryLayout:
        del ident, dump_kind
        return self.layout_value

    def checksums(self, ident: Identification) -> list[ChecksumRegion]:
        return [] if ident.checksum_variant_id is None else list(self.regions)

    def verify(self, dump: Dump, ident: Identification) -> VerifyReport:
        del ident
        if dump.dump_kind == "virtual":
            return VerifyReport("not_applicable", "virtual_dump", ())
        return report_of(interpret_verify(self.regions, dump, self.layout_value))

    def checksum_patches(self, dump: Dump, ident: Identification) -> list[Patch]:
        del ident
        return list(interpret_patches(self.regions, dump, self.layout_value))

    def hints(self, ident: Identification) -> list[MapHint]:
        del ident
        return list(self.hint_list)


def python_region(
    name: str, covered: tuple[Range, ...], fields: tuple[Range, ...], reference: Reference
) -> ChecksumRegion:
    return ChecksumRegion(name, "pflash", "recalculable", None, covered, fields, reference)
