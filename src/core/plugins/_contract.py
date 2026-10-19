"""EcuPlugin contract: the protocol and the shapes it exchanges (SPEC-002 §2, §3).

Kernel shapes (`Dump`, `MemoryLayout`, `Patch`, ...) are reused unchanged (R1). Every contract object
validates its own shape on construction and raises `PluginContractError` with the reason named after
the rule it breaks; checks that need the dump, the layout or the region list are in `_checks`.
"""

import re
from dataclasses import dataclass, field
from typing import Literal, Protocol, TypeGuard, cast

from core.definitions import Category
from core.definitions._model import CATEGORIES
from core.kernel import Dump, DumpKind, MemoryLayout, Patch
from core.plugins._errors import PluginContractError
from core.plugins._jcs import MAX_SAFE_INTEGER, ContractJson, contract_hash
from core.plugins._schema import MEMORY_ID, NAME, Descriptor, Range, descriptor_hash, descriptor_json

PiiKind = Literal["vin", "serial"]
ProtectionFlag = Literal["tprot"]
RegionKindOfChecksum = Literal["recalculable", "signed"]
ReferenceKind = Literal["interpreter", "independent", "none"]
RegionStatus = Literal["ok", "fail", "bypassed", "signature_unverifiable"]
VerifyStatus = Literal["ok", "fail", "bypassed", "signature_unverifiable", "not_applicable"]
NotApplicableReason = Literal["virtual_dump", "unknown_variant", "no_checksum_regions"]

FAMILY = re.compile(r"[a-z][a-z0-9]*(\.[a-z0-9][a-z0-9_]*)+")
VARIANT_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_HEX = re.compile(r"(?:[0-9a-f]{2})+")

PROTECTION_FLAGS: frozenset[str] = frozenset({"tprot"})
REGION_STATUSES: frozenset[str] = frozenset({"ok", "fail", "bypassed", "signature_unverifiable"})
NOT_APPLICABLE_REASONS: frozenset[str] = frozenset({"virtual_dump", "unknown_variant", "no_checksum_regions"})


def require(holds: bool, reason: str, detail: str = "") -> None:
    if not holds:
        raise PluginContractError(reason, detail)


def is_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _offset(value: object) -> bool:
    return is_int(value) and 0 <= value <= MAX_SAFE_INTEGER


def _memory_id(value: object) -> bool:
    return isinstance(value, str) and MEMORY_ID.fullmatch(value) is not None


def _optional_str(value: object) -> bool:
    return value is None or isinstance(value, str)


def _tuple_of(value: object, kind: type) -> bool:
    # A list inside a frozen dataclass could still change after its hash was taken.
    return isinstance(value, tuple) and all(isinstance(item, kind) for item in cast("tuple[object, ...]", value))


def _strictly_sorted[T: (str, tuple[str, str])](keys: list[T]) -> bool:
    return all(keys[index] < keys[index + 1] for index in range(len(keys) - 1))


@dataclass(frozen=True, slots=True)
class PresentMemory:
    memory_id: str
    base_address: int | None
    size: int

    def __post_init__(self) -> None:
        require(_memory_id(self.memory_id), "r4", f"memory_id = {self.memory_id!r}")
        require(self.base_address is None or _offset(self.base_address), "r4", "base_address")
        require(_offset(self.size) and self.size > 0, "r4", f"size = {self.size!r}")


@dataclass(frozen=True, slots=True)
class PiiLocation:
    """A location only, never a value (R6)."""

    memory_id: str
    start: int
    end: int
    kind: PiiKind

    def __post_init__(self) -> None:
        require(_memory_id(self.memory_id), "r6", f"memory_id = {self.memory_id!r}")
        require(_offset(self.start) and _offset(self.end) and self.start < self.end, "r6", "[start, end)")
        require(self.kind in ("vin", "serial"), "r6", f"kind = {self.kind!r}")


@dataclass(frozen=True, slots=True)
class Identification:
    """SPEC-002 §2.1."""

    family: str
    hw_id: str | None
    sw_id: str | None
    mcu: str | None
    checksum_variant_id: str | None
    memories_present: tuple[PresentMemory, ...]
    memories_absent: tuple[str, ...]
    pii_locations: tuple[PiiLocation, ...]
    protection_flags: tuple[ProtectionFlag, ...]
    confidence: int

    def __post_init__(self) -> None:
        check_identification_shape(self)


def check_identification_shape(ident: Identification) -> None:
    require(isinstance(ident.family, str) and FAMILY.fullmatch(ident.family) is not None, "r2", "family")
    variant = ident.checksum_variant_id
    require(variant is None or (isinstance(variant, str) and VARIANT_ID.fullmatch(variant) is not None), "r2", "id")
    require(_optional_str(ident.hw_id) and _optional_str(ident.sw_id) and _optional_str(ident.mcu), "r2", "ids")
    require(is_int(ident.confidence) and 0 <= ident.confidence <= 1000, "r3", f"confidence = {ident.confidence!r}")
    require(_tuple_of(ident.memories_present, PresentMemory), "r4", "memories_present")
    present = [memory.memory_id for memory in ident.memories_present]
    require(bool(present) and _strictly_sorted(present), "r4", "memories_present sorted by memory_id, unique")
    require(_tuple_of(ident.memories_absent, str), "r5", "memories_absent")
    absent = list(ident.memories_absent)
    require(all(_memory_id(memory_id) for memory_id in absent), "r5", "memories_absent ids")
    require(_strictly_sorted(absent) and not set(absent) & set(present), "r5", "memories_absent sorted, absent")
    require(_tuple_of(ident.pii_locations, PiiLocation), "r6", "pii_locations")
    for kind in ("vin", "serial"):
        keys = [(loc.memory_id, loc.start) for loc in ident.pii_locations if loc.kind == kind]
        require(keys == sorted(keys), "r6", f"{kind} locations sorted by (memory_id, start)")
    flags = ident.protection_flags
    require(_tuple_of(flags, str) and set(flags) <= PROTECTION_FLAGS and len(set(flags)) == len(flags), "r14")


@dataclass(frozen=True, slots=True)
class Reference:
    """R33: the second implementation a region is compared with. No default."""

    kind: ReferenceKind
    id: str | None
    source: str | None


@dataclass(frozen=True, slots=True)
class ChecksumRegion:
    """SPEC-002 §2.2. `descriptor_hash` is derived (R78), never supplied."""

    name: str
    memory_id: str
    kind: RegionKindOfChecksum
    descriptor: Descriptor | None
    covered: tuple[Range, ...] | None
    fields: tuple[Range, ...] | None
    reference: Reference
    descriptor_hash: str | None = field(init=False)

    def __post_init__(self) -> None:
        check_region_shape(self)
        object.__setattr__(
            self, "descriptor_hash", None if self.descriptor is None else descriptor_hash(self.descriptor)
        )


def _ranges(value: object) -> bool:
    return _tuple_of(value, Range) and all(
        _offset(item.start) and _offset(item.end) and item.start < item.end for item in cast("tuple[Range, ...]", value)
    )


def check_region_shape(region: ChecksumRegion) -> None:
    require(isinstance(region.name, str) and NAME.fullmatch(region.name) is not None, "r7", f"name = {region.name!r}")
    require(_memory_id(region.memory_id), "r7", f"memory_id = {region.memory_id!r}")
    d = region.descriptor
    if region.kind == "signed":
        require(d is None and region.covered is None and region.fields is None, "r7", "signed region with coverage")
    else:
        require(region.kind == "recalculable", "r7", f"kind = {region.kind!r}")
        if d is None:
            require(_ranges(region.covered) and _ranges(region.fields), "r7", "static covered and fields required")
        else:
            # Descriptor validity itself is R60 (raised on construction) and R79 (static validation).
            descriptor_json(d)
            require(region.covered is None and region.fields is None, "r7", "the interpreter derives coverage")
            require(d.name == region.name and d.memory_id == region.memory_id, "r7", "descriptor name, memory_id")
    _check_reference(region)


def _check_reference(region: ChecksumRegion) -> None:
    # R33: the only pairings allowed; anything else is `bad_reference`.
    ref = region.reference
    if not isinstance(ref, Reference):
        raise PluginContractError("bad_reference", "reference must be a Reference")
    none = Reference("none", None, None)
    if region.descriptor is not None:
        allowed = ref == Reference("interpreter", None, None)
    elif region.kind == "signed":
        allowed = ref == none
    else:
        allowed = ref == none or (
            ref.kind == "independent"
            and isinstance(ref.id, str)
            and VARIANT_ID.fullmatch(ref.id) is not None
            and isinstance(ref.source, str)
            and ref.source != ""
        )
    require(allowed, "bad_reference", f"{region.name}: {ref!r}")


@dataclass(frozen=True, slots=True)
class Bypass:
    """R44: where the patched verification routine lies."""

    memory_id: str
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class RegionResult:
    """SPEC-002 §2.3."""

    name: str
    memory_id: str
    kind: RegionKindOfChecksum
    status: RegionStatus
    stored: str | None
    computed: str | None
    reason: str | None
    bypass: Bypass | None

    def __post_init__(self) -> None:
        check_result_shape(self)


def _hex(value: object) -> bool:
    return value is None or (isinstance(value, str) and _HEX.fullmatch(value) is not None)


def check_result_shape(result: RegionResult) -> None:
    # R40 requires R8; R44 and R46 constrain bypassed and signed results.
    require(isinstance(result.name, str) and _memory_id(result.memory_id), "r40", "name, memory_id")
    require(result.kind in ("recalculable", "signed"), "r40", f"kind = {result.kind!r}")
    require(result.status in REGION_STATUSES, "r40", f"status = {result.status!r}")
    require(_hex(result.stored) and _hex(result.computed), "r40", "stored and computed are lowercase hex or null")
    require(result.reason is None or isinstance(result.reason, str), "r40", "reason")
    require(result.reason is None or (result.status == "fail" and result.computed is None), "r40", "R66 reason")
    if result.kind == "signed":
        signed = result.status == "signature_unverifiable" and result.stored is None and result.computed is None
        require(signed and result.bypass is None, "r46", result.name)
    else:
        require(result.status != "signature_unverifiable", "r46", f"{result.name} is not signed")
    bypass = result.bypass
    if result.status == "bypassed":
        require(isinstance(bypass, Bypass), "r44", f"{result.name}: bypassed without a location")
        located = cast("Bypass", bypass)
        valid = _memory_id(located.memory_id) and _offset(located.start) and _offset(located.end)
        require(valid and located.start < located.end, "r44", f"{result.name}: empty bypass location")
    else:
        require(bypass is None, "r44", f"{result.name}: bypass location on status {result.status}")


@dataclass(frozen=True, slots=True)
class VerifyReport:
    """SPEC-002 §2.3. The aggregation (R43) is checked against the dump by `check_verify_report`."""

    status: VerifyStatus
    reason: str | None
    regions: tuple[RegionResult, ...]

    def __post_init__(self) -> None:
        check_report_shape(self)


def check_report_shape(report: VerifyReport) -> None:
    require(_tuple_of(report.regions, RegionResult), "r40", "regions")
    if report.status == "not_applicable":
        require(not report.regions and report.reason in NOT_APPLICABLE_REASONS, "r40", f"reason = {report.reason!r}")
        return
    require(report.status in REGION_STATUSES and report.reason is None, "r40", f"{report.status}, {report.reason}")
    keys = [(result.memory_id, result.name) for result in report.regions]
    require(_strictly_sorted(keys), "r40", "regions sorted by (memory_id, name), one each")


@dataclass(frozen=True, slots=True)
class MapHint:
    """SPEC-002 §2.4."""

    memory_id: str
    start: int
    end: int
    name: str
    category: Category | None

    def __post_init__(self) -> None:
        require(_memory_id(self.memory_id) and isinstance(self.name, str), "r58", "memory_id, name")
        require(_offset(self.start) and _offset(self.end) and self.start < self.end, "r58", "[start, end)")
        require(self.category is None or self.category in CATEGORIES, "r58", f"category = {self.category!r}")


class EcuPlugin(Protocol):
    """SPEC-002 §3, exactly (R10). No method receives a mutable buffer."""

    family: str
    version: str
    contract_version: int
    pii_in_flash: bool

    def identify(self, dump: Dump) -> Identification | None:
        """R12-R14: never raises; None when the dump is not of this family."""

    def layout(self, ident: Identification, dump_kind: DumpKind) -> MemoryLayout:
        """R20-R23."""

    def checksums(self, ident: Identification) -> list[ChecksumRegion]:
        """R30-R34."""

    def verify(self, dump: Dump, ident: Identification) -> VerifyReport:
        """R40-R47."""

    def checksum_patches(self, dump: Dump, ident: Identification) -> list[Patch]:
        """R50-R55."""

    def hints(self, ident: Identification) -> list[MapHint]:
        """R58, R59."""


class RegionReference(Protocol):
    """R34: an independent second implementation of one Python region, from another source."""

    id: str
    version: str

    def verify_region(self, dump: Dump, ident: Identification, region: ChecksumRegion) -> RegionResult:
        """Returns `ok` or `fail` only (R45)."""

    def patches_region(self, dump: Dump, ident: Identification, region: ChecksumRegion) -> list[Patch]:
        """Byte-identical to the plugin's patches for that region (R55)."""


# JSON forms (R9): byte strings are lowercase hex; no floats anywhere.


def _range_json(item: Range) -> dict[str, ContractJson]:
    return {"start": item.start, "end": item.end}


def identification_json(ident: Identification) -> dict[str, ContractJson]:
    return {
        "family": ident.family,
        "hw_id": ident.hw_id,
        "sw_id": ident.sw_id,
        "mcu": ident.mcu,
        "checksum_variant_id": ident.checksum_variant_id,
        "memories_present": [
            {"memory_id": m.memory_id, "base_address": m.base_address, "size": m.size} for m in ident.memories_present
        ],
        "memories_absent": list(ident.memories_absent),
        "pii_locations": [
            {"memory_id": p.memory_id, "start": p.start, "end": p.end, "kind": p.kind} for p in ident.pii_locations
        ],
        "protection_flags": list(ident.protection_flags),
        "confidence": ident.confidence,
    }


def identification_hash(ident: Identification) -> str:
    """sha256(JCS(identification)), as SPEC-004 R12 records it."""
    return contract_hash(identification_json(ident))


def checksum_region_json(region: ChecksumRegion) -> dict[str, ContractJson]:
    return {
        "name": region.name,
        "memory_id": region.memory_id,
        "kind": region.kind,
        "descriptor": None if region.descriptor is None else descriptor_json(region.descriptor),
        "descriptor_hash": region.descriptor_hash,
        "covered": None if region.covered is None else [_range_json(item) for item in region.covered],
        "fields": None if region.fields is None else [_range_json(item) for item in region.fields],
        "reference": {"kind": region.reference.kind, "id": region.reference.id, "source": region.reference.source},
    }


def region_result_json(result: RegionResult) -> dict[str, ContractJson]:
    bypass = result.bypass
    return {
        "name": result.name,
        "memory_id": result.memory_id,
        "kind": result.kind,
        "status": result.status,
        "stored": result.stored,
        "computed": result.computed,
        "reason": result.reason,
        "bypass": None if bypass is None else {"memory_id": bypass.memory_id, "start": bypass.start, "end": bypass.end},
    }


def verify_report_json(report: VerifyReport) -> dict[str, ContractJson]:
    return {
        "status": report.status,
        "reason": report.reason,
        "regions": [region_result_json(result) for result in report.regions],
    }


def map_hint_json(hint: MapHint) -> dict[str, ContractJson]:
    return {
        "memory_id": hint.memory_id,
        "start": hint.start,
        "end": hint.end,
        "name": hint.name,
        "category": hint.category,
    }
