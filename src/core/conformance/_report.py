"""The conformance report (SPEC-002 R126, R127) and per-variant admission (R131).

The report holds integers, strings, booleans and null only, every list in the order R126 fixes, no dump
bytes, no VIN and no file names: dumps appear by `image_hash` only.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from core.plugins import ChecksumDescriptor, ChecksumRegion, ContractJson, MirrorDescriptor, output_fields, report_hash
from core.plugins._contract import FAMILY, VARIANT_ID
from core.plugins._jcs import MAX_SAFE_INTEGER

RunKind = Literal["pr", "nightly", "release"]
ReviewKind = Literal["mirror_destination", "compensation"]

REPORT_VERSION = 1
MIN_ORIGINALS = 5  # R131
_SHA256 = re.compile(r"[0-9a-f]{64}")
_GIT_SHA = re.compile(r"[0-9a-f]{40}")


@dataclass(frozen=True, slots=True)
class Failure:
    """One failed case: the rule, the dump by `image_hash` (empty when no dump is involved), a reason."""

    rule: str
    image_hash: str
    reason: str


@dataclass(frozen=True, slots=True)
class Check:
    """One rule over its cases (R126 `checks`)."""

    rule: str
    cases: int
    failures: tuple[Failure, ...]

    @property
    def passed(self) -> bool:
        return not self.failures


@dataclass(frozen=True, slots=True)
class Mutation:
    """R126 `mutation`: counts per region and mode."""

    checksum_variant_id: str
    region: str
    mode: Literal["sample", "full"]
    inside_sampled: int
    inside_detected: int
    outside_sampled: int
    outside_unchanged: int


@dataclass(frozen=True, slots=True)
class Fuzz:
    inputs: int
    exceptions: int
    timeouts: int


@dataclass(frozen=True, slots=True)
class Limit:
    """R103, R104: the budget and what was measured for one method."""

    method: str
    budget_ms: int
    max_ms: int
    peak_bytes: int


@dataclass(frozen=True, slots=True)
class LayoutReview:
    reviewer: str
    date: str


@dataclass(frozen=True, slots=True)
class RegistryHead:
    """The attester registry head the golden levels were computed against (R122, R126; SPEC-006 R79)."""

    genesis_hash: str
    seq: int
    head_hash: str
    registry_hash: str


@dataclass(frozen=True, slots=True)
class Variant:
    """What the run established for one checksum variant (R126 `variants`)."""

    checksum_variant_id: str
    originals: int
    checksum_off: int
    virtual: int
    golden_records: tuple[ContractJson, ...]
    regions: tuple[ChecksumRegion, ...]
    checksum_region_sets: frozenset[str]
    reviewed_region_sets: frozenset[str]


@dataclass(frozen=True, slots=True)
class Header:
    """`core`, `plugin`, `corpus` and `run` of R126."""

    core_version: str
    core_git_sha: str
    family: str
    plugin_version: str
    contract_version: int
    wheel_sha256: str
    corpus_revision: str
    corpus_dumps: int
    run_kind: RunKind
    seed: int


def review_fields(regions: Sequence[ChecksumRegion]) -> list[dict[str, ContractJson]]:
    """R126 `review_fields`: every mirror destination and compensation field, for the layout review (R92)."""
    rows: list[tuple[str, int, int, str, ReviewKind]] = []
    for region in regions:
        d = region.descriptor
        fields = () if d is None else output_fields(d)
        kind: ReviewKind
        if isinstance(d, MirrorDescriptor):
            kind = "mirror_destination"
        elif isinstance(d, ChecksumDescriptor) and d.strategy == "compensate" and fields:
            kind = "compensation"
        else:
            continue
        rows.append((region.memory_id, fields[0].start, fields[0].end, region.name, kind))
    return [{"region": n, "kind": k, "memory_id": m, "start": s, "end": e} for m, s, e, n, k in sorted(rows)]


def golden_levels(records: Sequence[ContractJson]) -> tuple[int, int]:
    """(`golden_field`, `golden_concordant`) counts of a variant's SPEC-006 golden records (R122).

    Fail-closed seam: SPEC-006 `evaluate_golden` (`core.evidence`) is not implemented yet, so no record
    counts at any level and no variant can be admitted (R131). It is replaced by the SPEC-006 R72-R76
    evaluation against the registry head recorded in the report.
    """
    del records
    return (0, 0)


def admitted(variant: Variant, golden_field: int, conformant: bool, layout_review: LayoutReview | None) -> bool:
    """R131. `conformant`: every check of the run passed. The reviewer-is-not-requester condition is
    a property of the job, recorded outside the report."""
    references_ok = all(region.kind == "signed" or region.reference.kind != "none" for region in variant.regions)
    return (
        variant.originals >= MIN_ORIGINALS
        and golden_field >= 1
        and conformant
        and references_ok
        and bool(variant.checksum_region_sets)
        and variant.checksum_region_sets <= variant.reviewed_region_sets
        and layout_review is not None
    )


def _variant_json(variant: Variant, conformant: bool, layout_review: LayoutReview | None) -> dict[str, ContractJson]:
    regions = variant.regions
    golden_field, golden_concordant = golden_levels(variant.golden_records)
    return {
        "checksum_variant_id": variant.checksum_variant_id,
        "originals": variant.originals,
        "checksum_off": variant.checksum_off,
        "virtual": variant.virtual,
        "golden_field": golden_field,
        "golden_concordant": golden_concordant,
        "descriptor_hashes": sorted({r.descriptor_hash for r in regions if r.descriptor_hash is not None}),
        "signed_regions": sorted(r.name for r in regions if r.kind == "signed"),
        "references": [
            {"region": r.name, "kind": r.reference.kind, "id": r.reference.id, "source": r.reference.source}
            for r in sorted(regions, key=_region_name)
        ],
        "checksum_region_sets": sorted(variant.checksum_region_sets),
        "review_fields": review_fields(regions),
        "admitted": admitted(variant, golden_field, conformant, layout_review),
    }


def _region_name(region: ChecksumRegion) -> str:
    return region.name


def _variant_key(variant: Variant) -> str:
    return variant.checksum_variant_id


def _check_key(check: Check) -> str:
    return check.rule


def _mutation_key(mutation: Mutation) -> tuple[str, str, str]:
    return (mutation.checksum_variant_id, mutation.region, mutation.mode)


def _limit_key(limit: Limit) -> str:
    return limit.method


def _need(holds: bool, what: str) -> None:
    # The runner's own input, not a plugin output: a programming error of the caller.
    if not holds:
        raise ValueError(what)


def _check_header(header: Header) -> None:
    _need(_GIT_SHA.fullmatch(header.core_git_sha) is not None, "R110: core is pinned by a 40-hex git SHA")
    _need(FAMILY.fullmatch(header.family) is not None, f"R2: family {header.family!r}")
    _need(_SHA256.fullmatch(header.wheel_sha256) is not None, "R130: wheel_sha256 is a SHA-256")
    _need(0 <= header.seed <= MAX_SAFE_INTEGER, "R127: the seed is a JSON-exact integer")


@dataclass(frozen=True, slots=True)
class RunResult:
    """Everything a run established, as recorded by the runner (R126)."""

    header: Header
    variants: tuple[Variant, ...]
    checks: tuple[Check, ...]
    mutation: tuple[Mutation, ...]
    fuzz: Fuzz
    limits: tuple[Limit, ...]
    layout_review: LayoutReview | None
    registry: RegistryHead | None


def build_report(run: RunResult) -> dict[str, ContractJson]:
    """R126: the report object, every list sorted and every key unique in its list."""
    header, variants, checks, mutation = run.header, run.variants, run.checks, run.mutation
    fuzz, limits, layout_review, registry = run.fuzz, run.limits, run.layout_review, run.registry
    _check_header(header)
    for variant in variants:
        _need(VARIANT_ID.fullmatch(variant.checksum_variant_id) is not None, f"R2: {variant.checksum_variant_id!r}")
    for keys in (
        [v.checksum_variant_id for v in variants],
        [c.rule for c in checks],
        [(m.checksum_variant_id, m.region, m.mode) for m in mutation],
        [limit.method for limit in limits],
    ):
        _need(len(set(keys)) == len(keys), "R126: each key is unique in its list")
    conformant = all(check.passed for check in checks)
    failures = sorted({(f.rule, f.image_hash, f.reason) for check in checks for f in check.failures})
    return {
        "report_version": REPORT_VERSION,
        "core": {"version": header.core_version, "git_sha": header.core_git_sha},
        "plugin": {
            "family": header.family,
            "version": header.plugin_version,
            "contract_version": header.contract_version,
            "wheel_sha256": header.wheel_sha256,
        },
        "corpus": {"revision": header.corpus_revision, "dumps": header.corpus_dumps},
        "run": {"kind": header.run_kind, "seed": header.seed},
        "variants": [_variant_json(v, conformant, layout_review) for v in sorted(variants, key=_variant_key)],
        "checks": [
            {"rule": c.rule, "passed": c.passed, "cases": c.cases, "failures": len(c.failures)}
            for c in sorted(checks, key=_check_key)
        ],
        "mutation": [
            {
                "checksum_variant_id": m.checksum_variant_id,
                "region": m.region,
                "mode": m.mode,
                "inside_sampled": m.inside_sampled,
                "inside_detected": m.inside_detected,
                "outside_sampled": m.outside_sampled,
                "outside_unchanged": m.outside_unchanged,
            }
            for m in sorted(mutation, key=_mutation_key)
        ],
        "fuzz": {"inputs": fuzz.inputs, "exceptions": fuzz.exceptions, "timeouts": fuzz.timeouts},
        "limits": [
            {"method": x.method, "budget_ms": x.budget_ms, "max_ms": x.max_ms, "peak_bytes": x.peak_bytes}
            for x in sorted(limits, key=_limit_key)
        ],
        "layout_review": None
        if layout_review is None
        else {"reviewer": layout_review.reviewer, "date": layout_review.date},
        "attester_registry": None
        if registry is None
        else {
            "genesis_hash": registry.genesis_hash,
            "seq": registry.seq,
            "head_hash": registry.head_hash,
            "registry_hash": registry.registry_hash,
        },
        "failures": [{"rule": rule, "image_hash": image, "reason": reason} for rule, image, reason in failures],
        "verdict": "conformant" if conformant else "nonconformant",
    }


def conformance_report_hash(report: dict[str, ContractJson]) -> str:
    """R127."""
    return report_hash(report)
