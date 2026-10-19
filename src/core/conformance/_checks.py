"""Core-side checks of the conformance suite (SPEC-002 §7), as pure functions over recorded cases.

The runner (outside `src/core`) reads the corpus, calls the plugin, times calls and records outputs; it
hands each case here. A check never raises on a plugin fault: every fault becomes a `Failure`.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from core.conformance._mutation import Mode
from core.conformance._report import Check, Failure, Fuzz, Limit, Mutation
from core.conformance._scan import scan_source
from core.kernel import (
    Dump,
    KernelError,
    Memory,
    MemoryLayout,
    Patch,
    UnverifiedImage,
    apply_checksum_patches,
    image_hash,
    layout_hash,
)
from core.plugins import (
    TIME_BUDGET_MS,
    CallOutcome,
    ChecksumRegion,
    ContractJson,
    DescriptorError,
    Identification,
    InterpreterDivergence,
    PluginContractError,
    RegionResult,
    RegionStatus,
    VerifyReport,
    check_checksum_patches,
    check_hints,
    check_identification,
    check_layout,
    check_verify_report,
    contract_hash,
    within_limits,
)
from core.plugins.descriptor import check_checksums, compare_patches, compare_verify

MIN_CONFIDENCE = 500  # R111, R113
MIN_FUZZ_INPUTS = 100_000  # R114


def rule(number: int) -> str:
    return f"SPEC-002 R{number}"


def _check(number: int, cases: int, failures: Sequence[tuple[str, str]]) -> Check:
    return Check(rule(number), cases, tuple(Failure(rule(number), image, reason) for image, reason in failures))


@dataclass(frozen=True, slots=True)
class Identity:
    """Corpus metadata of one dump (R111)."""

    family: str
    hw_id: str | None
    sw_id: str | None
    checksum_variant_id: str


@dataclass(frozen=True, slots=True)
class IdentifyCase:
    dump: Dump
    result: object
    expected: Identity


def check_identify_positive(cases: Sequence[IdentifyCase], family: str) -> Check:
    """R111: identified with the corpus metadata and `confidence >= 500`."""
    failures: list[tuple[str, str]] = []
    for case in cases:
        image = image_hash(case.dump)
        try:
            ident = check_identification(case.result, case.dump, family)
        except PluginContractError as fault:
            failures.append((image, fault.reason))
            continue
        expected = case.expected
        got = None if ident is None else (ident.family, ident.hw_id, ident.sw_id, ident.checksum_variant_id)
        if got != (expected.family, expected.hw_id, expected.sw_id, expected.checksum_variant_id):
            failures.append((image, "identity_mismatch"))
        elif ident is not None and ident.confidence < MIN_CONFIDENCE:
            failures.append((image, "low_confidence"))
    return _check(111, len(cases), failures)


def _variant(result: object) -> str | None:
    return result.checksum_variant_id if isinstance(result, Identification) else None


def check_identify_discrimination(cases: Sequence[IdentifyCase]) -> Check:
    """R112: same `sw_id`, different checksum variant, different `checksum_variant_id`s."""
    failures: list[tuple[str, str]] = []
    pairs = 0
    for index, a in enumerate(cases):
        for b in cases[index + 1 :]:
            same_sw = a.expected.sw_id is not None and a.expected.sw_id == b.expected.sw_id
            if not same_sw or a.expected.checksum_variant_id == b.expected.checksum_variant_id:
                continue
            pairs += 1
            if _variant(a.result) is None or _variant(a.result) == _variant(b.result):
                failures.extend((image_hash(dump), "not_discriminated") for dump in (a.dump, b.dump))
    return _check(112, pairs, failures)


def check_identify_negative(cases: Sequence[tuple[str, object]]) -> Check:
    """R113: other families and random dumps give None or `confidence < 500`."""
    failures = [
        (image, "identified_foreign_dump")
        for image, result in cases
        if result is not None and not (isinstance(result, Identification) and result.confidence < MIN_CONFIDENCE)
    ]
    return _check(113, len(cases), failures)


def check_fuzz(fuzz: Fuzz) -> Check:
    """R114: at least 100,000 inputs, no exception, no timeout."""
    failures = [
        ("", reason)
        for reason, failed in (
            ("below_minimum_inputs", fuzz.inputs < MIN_FUZZ_INPUTS),
            ("exceptions", fuzz.exceptions > 0),
            ("timeouts", fuzz.timeouts > 0),
        )
        if failed
    ]
    return _check(114, fuzz.inputs, failures)


def checksum_region_set(layout: MemoryLayout) -> str:
    """R115: sha256(JCS(sorted list of {memory_id, start, end, name})) of the `checksum` regions."""
    rows = sorted(
        (memory.memory_id, region.start, region.end, region.name)
        for memory in layout.memories
        for region in memory.regions
        if region.kind == "checksum"
    )
    return contract_hash([{"memory_id": m, "start": s, "end": e, "name": n} for m, s, e, n in rows])


@dataclass(frozen=True, slots=True)
class LayoutCase:
    image_hash: str
    ident: Identification
    layout: object
    reference_layout_hash: str | None
    reviewed_region_sets: frozenset[str]


def check_layouts(cases: Sequence[LayoutCase]) -> Check:
    """R115: R20-R22, the reviewed `layout_hash` when one exists, and a reviewed checksum region set."""
    failures: list[tuple[str, str]] = []
    for case in cases:
        try:
            layout = check_layout(case.layout, case.ident)
        except PluginContractError as fault:
            failures.append((case.image_hash, fault.reason))
            continue
        reference = case.reference_layout_hash
        if reference is not None and layout_hash(layout) != reference:
            failures.append((case.image_hash, "layout_hash_mismatch"))
        if checksum_region_set(layout) not in case.reviewed_region_sets:
            failures.append((case.image_hash, "checksum_region_set_not_reviewed"))
    return _check(115, len(cases), failures)


@dataclass(frozen=True, slots=True)
class VerifyCase:
    """A plugin `verify` output on a dump, with the regions and layout of that dump."""

    dump: Dump
    regions: tuple[ChecksumRegion, ...]
    layout: MemoryLayout
    report: object


def _checked(case: VerifyCase) -> VerifyReport | str:
    try:
        return check_verify_report(case.report, case.dump, case.regions, case.layout)
    except PluginContractError as fault:
        return fault.reason


def check_originals(cases: Sequence[VerifyCase]) -> Check:
    """R116: every recalculable region `ok`, every signed region `signature_unverifiable`."""
    failures: list[tuple[str, str]] = []
    for case in cases:
        report = _checked(case)
        if isinstance(report, str):
            failures.append((image_hash(case.dump), report))
        elif any(r.status not in ("ok", "signature_unverifiable") for r in report.regions):
            failures.append((image_hash(case.dump), "original_not_ok"))
    return _check(116, len(cases), failures)


def check_checksum_off(cases: Sequence[VerifyCase]) -> Check:
    """R119: a "checksum off" file verifies `bypassed` with R44 locations, never `fail`."""
    failures: list[tuple[str, str]] = []
    for case in cases:
        report = _checked(case)
        if isinstance(report, str):
            failures.append((image_hash(case.dump), report))
        elif report.status != "bypassed":
            failures.append((image_hash(case.dump), f"status_{report.status}"))
    return _check(119, len(cases), failures)


def check_virtual(cases: Sequence[VerifyCase]) -> Check:
    """R120: a `virtual` dump verifies `not_applicable` (R41)."""
    failures: list[tuple[str, str]] = []
    for case in cases:
        report = _checked(case)
        if isinstance(report, str):
            failures.append((image_hash(case.dump), report))
        elif case.dump.dump_kind != "virtual":
            failures.append((image_hash(case.dump), "not_virtual"))
    return _check(120, len(cases), failures)


@dataclass(frozen=True, slots=True)
class InsideCase:
    """R117: the status of `region` after one mutation inside its coverage or fields."""

    image_hash: str
    checksum_variant_id: str
    region: str
    mode: Mode
    status: RegionStatus


@dataclass(frozen=True, slots=True)
class OutsideCase:
    """R118: verify before and after one mutation outside every coverage, field and table."""

    image_hash: str
    checksum_variant_id: str
    mode: Mode
    before: VerifyReport
    after: VerifyReport
    layout: MemoryLayout


def check_inside(cases: Sequence[InsideCase]) -> Check:
    """R117: every mutation turns the region to `fail`."""
    failures = [(case.image_hash, f"undetected_{case.region}") for case in cases if case.status != "fail"]
    return _check(117, len(cases), failures)


def _protected(layout: MemoryLayout, result: RegionResult) -> bool:
    bypass = result.bypass
    return bypass is not None and any(
        r.kind == "protected" and r.start <= bypass.start and bypass.end <= r.end
        for memory in layout.memories
        if memory.memory_id == bypass.memory_id
        for r in memory.regions
    )


def _unchanged(before: RegionResult, after: RegionResult | None, layout: MemoryLayout) -> bool:
    if after is None or (before.stored, before.computed, before.reason) != (after.stored, after.computed, after.reason):
        return False
    return after.status == before.status or (after.status == "bypassed" and _protected(layout, after))


def _outside_unchanged(case: OutsideCase) -> list[str]:
    after = {result.name: result for result in case.after.regions}
    return [r.name for r in case.before.regions if _unchanged(r, after.get(r.name), case.layout)]


def check_outside(cases: Sequence[OutsideCase]) -> Check:
    """R118: `stored`, `computed`, `reason` unchanged; `status` unchanged or `bypassed` at an R44 location."""
    failures: list[tuple[str, str]] = []
    for case in cases:
        unchanged = set(_outside_unchanged(case))
        failures.extend((case.image_hash, f"changed_{r.name}") for r in case.before.regions if r.name not in unchanged)
    return _check(118, len(cases), failures)


def mutation_summary(inside: Sequence[InsideCase], outside: Sequence[OutsideCase]) -> tuple[Mutation, ...]:
    """R126 `mutation`: counts per (variant, region, mode)."""
    counts: dict[tuple[str, str, Mode], list[int]] = {}
    for case in inside:
        row = counts.setdefault((case.checksum_variant_id, case.region, case.mode), [0, 0, 0, 0])
        row[0] += 1
        row[1] += case.status == "fail"
    for outside_case in outside:
        unchanged = set(_outside_unchanged(outside_case))
        for result in outside_case.before.regions:
            key = (outside_case.checksum_variant_id, result.name, outside_case.mode)
            row = counts.setdefault(key, [0, 0, 0, 0])
            row[2] += 1
            row[3] += result.name in unchanged
    return tuple(Mutation(v, region, mode, *row) for (v, region, mode), row in sorted(counts.items()))


@dataclass(frozen=True, slots=True)
class GoldenCase:
    """R121: one golden record of the variant, applied to its original.

    `unverified` is `apply(original, version)` as bytes; `patches` the plugin's `checksum_patches` on it;
    `independent` the `patches_region` of each independent reference; `after` the plugin's `verify` and
    `fixed_point` its `checksum_patches`, both on the released image.
    """

    expected_image_hash: str
    unverified: Dump
    layout: MemoryLayout
    regions: tuple[ChecksumRegion, ...]
    patches: object
    independent: Mapping[str, Sequence[Patch]]
    after: object
    fixed_point: object


def _write(dump: Dump, patches: Sequence[Patch]) -> Dump:
    data = {memory.memory_id: bytearray(memory.data) for memory in dump.memories}
    for patch in patches:
        data[patch.memory_id][patch.offset : patch.end] = patch.after
    return Dump(
        dump.dump_kind, tuple(Memory(m.memory_id, m.base_address, bytes(data[m.memory_id])) for m in dump.memories)
    )


def _golden(case: GoldenCase) -> str | None:
    q = check_checksum_patches(case.patches, case.unverified, case.layout, case.regions)
    compare_patches(case.regions, q, case.unverified, case.layout, case.independent)
    released = apply_checksum_patches(UnverifiedImage(case.unverified), q, case.layout)
    released_dump = _write(case.unverified, q)
    if released.image_hash != case.expected_image_hash or image_hash(released_dump) != released.image_hash:
        return "image_hash_mismatch"
    after = check_verify_report(case.after, released_dump, case.regions, case.layout)
    if any(r.kind == "recalculable" and r.status not in ("ok", "bypassed") for r in after.regions):
        return "r53"
    if check_checksum_patches(case.fixed_point, released_dump, case.layout, case.regions):
        return "r54"
    return None


def check_golden(cases: Sequence[GoldenCase]) -> Check:
    """R121: the released `image_hash` equals the golden hash; R51-R55 and the fixed point hold."""
    failures: list[tuple[str, str]] = []
    for case in cases:
        try:
            reason = _golden(case)
        except (PluginContractError, DescriptorError, InterpreterDivergence, KernelError) as fault:
            reason = fault.reason
        if reason is not None:
            failures.append((image_hash(case.unverified), reason))
    return _check(121, len(cases), failures)


@dataclass(frozen=True, slots=True)
class HintsCase:
    image_hash: str
    hints: object
    layout: MemoryLayout


def check_hints_cases(cases: Sequence[HintsCase]) -> Check:
    """R123: R58 and R59 for every corpus dump."""
    failures: list[tuple[str, str]] = []
    for case in cases:
        try:
            check_hints(case.hints, case.layout)
        except PluginContractError as fault:
            failures.append((case.image_hash, fault.reason))
    return _check(123, len(cases), failures)


@dataclass(frozen=True, slots=True)
class DeterminismCase:
    """R124: one method's output on one dump, from two calls in two different dump orders, as JSON."""

    method: str
    image_hash: str
    first: ContractJson
    second: ContractJson


def check_purity(sources: Mapping[str, str], package: str, determinism: Sequence[DeterminismCase]) -> Check:
    """R124: the R100 scan of every module and R101 JCS-identical repeated outputs."""
    failures = [
        ("", f"{module} {finding}")
        for module, source in sorted(sources.items())
        for finding in scan_source(source, package)
    ]
    failures.extend(
        (case.image_hash, f"nondeterministic_{case.method}")
        for case in determinism
        if contract_hash(case.first) != contract_hash(case.second)
    )
    return _check(124, len(sources) + len(determinism), failures)


def check_limits(outcomes: Sequence[CallOutcome]) -> Check:
    """R103, R105: every call returned within its budget; a timeout or exception fails the suite."""
    failures = [("", f"{o.method}_{o.outcome}_{o.elapsed_ms}ms") for o in outcomes if not within_limits(o)]
    return _check(105, len(outcomes), failures)


def limits_summary(outcomes: Sequence[CallOutcome]) -> tuple[Limit, ...]:
    """R126 `limits`: budget, slowest call and peak memory per method (R103, R104)."""
    methods = sorted({o.method for o in outcomes})
    return tuple(
        Limit(
            method,
            TIME_BUDGET_MS[method],
            max(o.elapsed_ms for o in outcomes if o.method == method),
            max((o.peak_bytes or 0) for o in outcomes if o.method == method),
        )
        for method in methods
    )


@dataclass(frozen=True, slots=True)
class DualCase:
    """R125: one dump (original, mutated or golden) with everything the plugin and references returned."""

    dump: Dump
    ident: Identification
    layout: MemoryLayout
    regions: object
    report: object
    patches: object
    independent_results: Mapping[str, RegionResult]
    independent_patches: Mapping[str, Sequence[Patch]]


def _dual(case: DualCase) -> None:
    regions = check_checksums(case.regions, case.ident, case.layout)
    report = check_verify_report(case.report, case.dump, regions, case.layout)
    compare_verify(regions, report, case.dump, case.layout, case.independent_results)
    q = check_checksum_patches(case.patches, case.dump, case.layout, regions)
    compare_patches(regions, q, case.dump, case.layout, case.independent_patches)


def check_descriptors_and_references(cases: Sequence[DualCase]) -> Check:
    """R125: R33 and R79 against every layout; R45, R55 and R81 agreement on every case."""
    failures: list[tuple[str, str]] = []
    for case in cases:
        try:
            _dual(case)
        except (PluginContractError, DescriptorError, InterpreterDivergence) as fault:
            failures.append((image_hash(case.dump), fault.reason))
    return _check(125, len(cases), failures)
