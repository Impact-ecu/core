"""Core-side checks of plugin outputs that do not need the interpreter (SPEC-002 R11-R59, R90-R94, R132-R135).

Every function takes the plugin output as `object`, because the core does not trust the plugin (R11): a
wrong type is a contract violation, not a crash. A violation raises `PluginContractError`, never repairs.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, cast

from core.kernel import Dump, LayoutMemory, MemoryLayout, Patch
from core.plugins._contract import (
    FAMILY,
    ChecksumRegion,
    EcuPlugin,
    Identification,
    MapHint,
    NotApplicableReason,
    RegionStatus,
    VerifyReport,
    VerifyStatus,
    check_identification_shape,
    check_region_shape,
    check_report_shape,
    check_result_shape,
    is_int,
    require,
)
from core.plugins._jcs import ContractJson, contract_hash
from core.plugins._schema import output_fields

CONTRACT_VERSION = 1
# R22, R90: names that mark protected content (VIN, immobilizer, coding, flash counters, emissions).
PROTECTED_PREFIXES = ("vin", "immo", "coding", "counter", "emissions")

Method = Literal["identify", "layout", "checksums", "hints", "verify", "checksum_patches"]
# R103: provisional wall-time budgets, replaced by measured values (open question 2).
TIME_BUDGET_MS: Mapping[Method, int] = {
    "checksum_patches": 2000,
    "checksums": 1000,
    "hints": 1000,
    "identify": 1000,
    "layout": 1000,
    "verify": 2000,
}


def check_plugin(plugin: EcuPlugin) -> None:
    """R135 `contract_version`, R2 `family`, and the attributes of R10. A missing attribute raises."""
    contract_version: object = plugin.contract_version
    valid = is_int(contract_version) and contract_version == CONTRACT_VERSION
    require(valid, "contract_version", f"contract_version = {contract_version!r}, core implements {CONTRACT_VERSION}")
    family: object = plugin.family
    require(isinstance(family, str) and FAMILY.fullmatch(family) is not None, "r2", f"family = {family!r}")
    version: object = plugin.version
    pii_in_flash: object = plugin.pii_in_flash
    require(isinstance(version, str) and isinstance(pii_in_flash, bool), "r10", "version, pii_in_flash")


def check_identification(ident: object, dump: Dump, family: str) -> Identification | None:
    """R1-R6, R12-R14 on the result of `identify(dump)`."""
    if ident is None:
        return None
    require(isinstance(ident, Identification), "r12", f"identify returned {type(ident).__name__}")
    checked = cast("Identification", ident)
    check_identification_shape(checked)
    require(checked.family == family, "r2", f"family {checked.family!r}, plugin {family!r}")
    memories = {memory.memory_id: memory for memory in dump.memories}
    require([m.memory_id for m in checked.memories_present] == sorted(memories), "r4", "memories_present")
    for present in checked.memories_present:
        memory = memories[present.memory_id]
        require(present.size == len(memory.data), "r4", f"{present.memory_id}: size")
        known = memory.base_address is None or present.base_address == memory.base_address
        require(known, "r4", f"{present.memory_id}: base_address")
    sizes = {present.memory_id: present.size for present in checked.memories_present}
    for location in checked.pii_locations:
        inside = location.memory_id in sizes and location.end <= sizes[location.memory_id]
        require(inside, "r6", f"{location.kind} location outside {location.memory_id}")
    return checked


def check_layout(layout: object, ident: Identification) -> MemoryLayout:
    """R20 (`bad_layout`), R21, R22 and the emissions boundary of R90."""
    require(isinstance(layout, MemoryLayout), "bad_layout", f"layout returned {type(layout).__name__}")
    checked = cast("MemoryLayout", layout)
    described = sorted((m.memory_id, m.base_address, m.size) for m in checked.memories)
    present = [(m.memory_id, m.base_address, m.size) for m in ident.memories_present]
    require(described == present, "bad_layout", "memories differ from memories_present")
    for memory in checked.memories:
        for region in memory.regions:
            if region.name == "unrecognized":
                require(region.kind == "protected" and len(memory.regions) == 1, "r21", memory.memory_id)
            if region.name.startswith(PROTECTED_PREFIXES):
                require(region.kind == "protected", "r22", f"{memory.memory_id}: {region.name} is {region.kind}")
    return checked


def aggregate(statuses: Sequence[RegionStatus]) -> tuple[VerifyStatus, NotApplicableReason | None]:
    """R43: the report status from the region statuses."""
    if not statuses:
        return ("not_applicable", "no_checksum_regions")
    precedence: tuple[VerifyStatus, ...] = ("fail", "bypassed", "signature_unverifiable")
    for status in precedence:
        if status in statuses:
            return (status, None)
    return ("ok", None)


def not_applicable(reason: NotApplicableReason) -> VerifyReport:
    """R41, R42: the report the core produces without asking the plugin."""
    return VerifyReport("not_applicable", reason, ())


def _region_of(layout: MemoryLayout, memory_id: str, start: int, end: int) -> str | None:
    """The kind of the single layout region holding `[start, end)`, or None."""
    memories: dict[str, LayoutMemory] = {memory.memory_id: memory for memory in layout.memories}
    memory = memories.get(memory_id)
    regions = () if memory is None else memory.regions
    return next((r.kind for r in regions if r.start <= start and end <= r.end), None)


def check_verify_report(
    report: object, dump: Dump, regions: Sequence[ChecksumRegion], layout: MemoryLayout
) -> VerifyReport:
    """R8 via R40, R41, R43, R44, R46 on the result of `verify(dump, ident)`."""
    require(isinstance(report, VerifyReport), "r40", f"verify returned {type(report).__name__}")
    checked = cast("VerifyReport", report)
    check_report_shape(checked)
    for result in checked.regions:
        check_result_shape(result)
    if dump.dump_kind == "virtual":
        require(checked.status == "not_applicable" and checked.reason == "virtual_dump", "r41", checked.status)
        return checked
    expected = sorted((region.memory_id, region.name, region.kind) for region in regions)
    actual = [(result.memory_id, result.name, result.kind) for result in checked.regions]
    require(actual == expected, "r40", "one result per checksum region")
    for result in checked.regions:
        bypass = result.bypass
        if bypass is not None:
            kind = _region_of(layout, bypass.memory_id, bypass.start, bypass.end)
            require(kind == "protected", "r44", f"{result.name}: bypass not inside one protected region")
    status, reason = aggregate([result.status for result in checked.regions])
    require((checked.status, checked.reason) == (status, reason), "r43", f"{checked.status}, expected {status}")
    return checked


def recalculable_fields(regions: Sequence[ChecksumRegion]) -> dict[tuple[str, int, int], str]:
    """Every static output field (R73) of the recalculable regions, to its region name."""
    fields: dict[tuple[str, int, int], str] = {}
    for region in regions:
        spans = output_fields(region.descriptor) if region.descriptor is not None else tuple(region.fields or ())
        for span in spans:
            fields[(region.memory_id, span.start, span.end)] = region.name
    return fields


def check_checksum_patches(
    patches: object, dump: Dump, layout: MemoryLayout, regions: Sequence[ChecksumRegion]
) -> tuple[Patch, ...]:
    """R50, R51, R52 on the result of `checksum_patches(dump, ident)`."""
    items = cast("Sequence[object]", patches)
    valid = isinstance(patches, list | tuple) and all(isinstance(item, Patch) for item in items)
    require(valid, "r50", "checksum_patches must return a list of Patch")
    checked = tuple(cast("Sequence[Patch]", patches))
    require(dump.dump_kind != "virtual" or not checked, "r50", "a virtual dump has no checksum patches")
    keys = [(patch.memory_id, patch.offset) for patch in checked]
    require(keys == sorted(keys), "r50", "patches sorted by (memory_id, offset)")
    fields = recalculable_fields(regions)
    data = {memory.memory_id: memory.data for memory in dump.memories}
    previous: Patch | None = None
    for patch in checked:
        require((patch.memory_id, patch.offset, patch.end) in fields, "r51", f"{patch.patch_hash}: not one whole field")
        kind = _region_of(layout, patch.memory_id, patch.offset, patch.end)
        require(kind == "checksum", "r51", f"{patch.patch_hash}: not inside one checksum region")
        disjoint = previous is None or previous.memory_id != patch.memory_id or previous.end <= patch.offset
        require(disjoint, "r51", f"{patch.patch_hash}: overlaps another patch")
        current = data.get(patch.memory_id, b"")[patch.offset : patch.end]
        require(current == patch.before, "r52", f"{patch.patch_hash}: before differs from the dump")
        previous = patch
    return checked


def check_hints(hints: object, layout: MemoryLayout) -> tuple[MapHint, ...]:
    """R58, R59: all or nothing, reason `r58`. The caller records the error and uses [] (R58)."""
    items = cast("Sequence[object]", hints)
    valid = isinstance(hints, list | tuple) and all(isinstance(item, MapHint) for item in items)
    require(valid, "r58", "hints must return a list of MapHint")
    checked = tuple(cast("Sequence[MapHint]", hints))
    for hint in checked:
        MapHint.__post_init__(hint)
        kind = _region_of(layout, hint.memory_id, hint.start, hint.end)
        require(kind == "calibration", "r58", f"{hint.name}: not inside one calibration region (R59)")
    return checked


def check_regions(regions: object) -> tuple[ChecksumRegion, ...]:
    """The shape half of R30: a list of valid `ChecksumRegion`s."""
    items = cast("Sequence[object]", regions)
    valid = isinstance(regions, list | tuple) and all(isinstance(item, ChecksumRegion) for item in items)
    require(valid, "r30", "checksums must return a list of ChecksumRegion")
    checked = tuple(cast("Sequence[ChecksumRegion]", regions))
    for region in checked:
        check_region_shape(region)
    return checked


# Admission - R132.


def report_hash(report: ContractJson) -> str:
    """R127: sha256(JCS(report))."""
    return contract_hash(report)


@dataclass(frozen=True, slots=True)
class Admission:
    """What the gate takes from a plugin's published conformance report (R132; SPEC-004 R15)."""

    report_hash: str
    admitted: frozenset[str]


def _field(value: object, key: str) -> object:
    return cast("dict[str, object]", value).get(key) if isinstance(value, dict) else None


def admission(report: ContractJson, plugin: EcuPlugin) -> Admission | None:
    """The admitted variants, or None when the report does not match the plugin (unavailable, R132)."""
    meta = _field(report, "plugin")
    matches = (
        _field(meta, "family") == plugin.family
        and _field(meta, "version") == plugin.version
        and _field(report, "verdict") == "conformant"
    )
    variants = _field(report, "variants")
    if not matches or not isinstance(variants, list):
        return None
    admitted: set[str] = set()
    for entry in cast("list[object]", variants):
        variant = _field(entry, "checksum_variant_id")
        if not isinstance(variant, str) or not isinstance(_field(entry, "admitted"), bool):
            return None
        if _field(entry, "admitted") is True:
            admitted.add(variant)
    return Admission(report_hash(report), frozenset(admitted))


def variant_admitted(ident: Identification, admitted: Admission | None) -> bool:
    """R42, R132: otherwise the dump is `unknown_variant` and nothing is verified or recalculated."""
    variant = ident.checksum_variant_id
    return admitted is not None and variant is not None and variant in admitted.admitted


# Limits - R103-R105. Timing and aborting happen in the host; the core receives the outcome as data.


@dataclass(frozen=True, slots=True)
class CallOutcome:
    """One recorded plugin call (R105): its outcome, wall time and, when measured, peak memory (R104)."""

    method: Method
    outcome: Literal["result", "timeout", "exception"]
    elapsed_ms: int
    peak_bytes: int | None


def within_limits(outcome: CallOutcome) -> bool:
    """R103, R105: a result within its budget. Anything else makes the plugin unavailable (R11)."""
    return outcome.outcome == "result" and outcome.elapsed_ms <= TIME_BUDGET_MS[outcome.method]
