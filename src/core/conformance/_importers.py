"""Core-side checks of the importer conformance suite (SPEC-006 §3.5), as pure functions.

The runner, the private samples, random generation, timing and fuzzing loops live outside `src/core`
(R30): it feeds inputs to these functions and assembles their failures into the R34 report.
"""

import hashlib
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from core.importers import (
    CONTRACT_VERSION,
    Imported,
    Importer,
    ImporterContractError,
    ImportParams,
    ImportRejected,
    JsonValue,
    jcs,
    jcs_hash,
    outcome_jcs,
    run_import,
)

PREFIX_SIZES = 64
REPORT_VERSION = 1
_MAJOR = re.compile(r"(0|[1-9][0-9]*)\.")

RunKind = Literal["pr", "nightly", "release"]


@dataclass(frozen=True, slots=True)
class OracleRecord:
    """SPEC-006 R31: the expected `image_hash` of a positive sample, obtained outside the importer."""

    input_sha256: str
    expected_image_hash: str
    tool: str
    version: str
    method: str
    date: str


@dataclass(frozen=True, slots=True)
class Failure:
    """One failed case: the rule, the input by hash only (never its bytes or name), and why (R34)."""

    rule: str
    input_sha256: str
    reason: str


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _outcome(importer: Importer, data: bytes, params: ImportParams) -> Imported | ImportRejected | str:
    """The outcome, or the reason of the contract error, which the suite records instead of raising."""
    try:
        return run_import(importer, data, params)
    except ImporterContractError as exc:
        return exc.reason


def _describe(outcome: Imported | ImportRejected | str) -> str:
    if isinstance(outcome, Imported):
        return "imported"
    if isinstance(outcome, ImportRejected):
        return outcome.reason
    return f"contract_error:{outcome}"


def check_positive(importer: Importer, sample: bytes, params: ImportParams, oracle: OracleRecord) -> list[Failure]:
    """SPEC-006 R31: a positive sample imports to the oracle's `image_hash`."""
    digest = _sha256(sample)
    if oracle.input_sha256 != digest:
        return [Failure("SPEC-006 R31", digest, "oracle_input_mismatch")]
    outcome = _outcome(importer, sample, params)
    if not isinstance(outcome, Imported):
        return [Failure("SPEC-006 R31", digest, _describe(outcome))]
    if outcome.record.image_hash != oracle.expected_image_hash:
        return [Failure("SPEC-006 R31", digest, "image_hash_mismatch")]
    return []


def check_negative(importer: Importer, sample: bytes, params: ImportParams) -> list[Failure]:
    """SPEC-006 R32: another container or a random file is `unsupported_container`."""
    outcome = _outcome(importer, sample, params)
    if isinstance(outcome, ImportRejected) and outcome.reason == "unsupported_container":
        return []
    return [Failure("SPEC-006 R32", _sha256(sample), _describe(outcome))]


def check_encrypted(importer: Importer, sample: bytes, params: ImportParams) -> list[Failure]:
    """SPEC-006 R32: an encrypted sample is `encrypted_container`."""
    outcome = _outcome(importer, sample, params)
    if isinstance(outcome, ImportRejected) and outcome.reason == "encrypted_container":
        return []
    return [Failure("SPEC-006 R32", _sha256(sample), _describe(outcome))]


def prefix_sizes(size: int, seed: int) -> tuple[int, ...]:
    """SPEC-006 R32: 64 distinct strict-prefix sizes of a `size`-byte sample, chosen by `seed`; all of them if fewer."""
    if size <= PREFIX_SIZES:
        return tuple(range(size))
    chosen: set[int] = set()
    counter = 0
    while len(chosen) < PREFIX_SIZES:
        digest = hashlib.sha256(jcs({"seed": seed, "size": size, "counter": counter})).digest()
        chosen.add(int.from_bytes(digest[:8], "big") % size)
        counter += 1
    return tuple(sorted(chosen))


def check_prefixes(importer: Importer, sample: bytes, params: ImportParams, seed: int) -> list[Failure]:
    """SPEC-006 R32: every chosen strict prefix of a positive sample is rejected, never a `Dump`."""
    failures: list[Failure] = []
    for size in prefix_sizes(len(sample), seed):
        prefix = sample[:size]
        outcome = _outcome(importer, prefix, params)
        if not isinstance(outcome, ImportRejected):
            failures.append(Failure("SPEC-006 R32", _sha256(prefix), _describe(outcome)))
    return failures


def check_fuzz_input(importer: Importer, data: bytes, params: ImportParams) -> list[Failure]:
    """SPEC-006 R33: a fuzz input never raises and never exceeds the R16 limits."""
    outcome = _outcome(importer, data, params)
    if isinstance(outcome, str) or (isinstance(outcome, ImportRejected) and outcome.reason == "limit_exceeded"):
        return [Failure("SPEC-006 R33", _sha256(data), _describe(outcome))]
    return []


def check_determinism(importer: Importer, cases: Sequence[tuple[bytes, ImportParams]]) -> list[Failure]:
    """SPEC-006 R14, R33: every case imported twice, in two orders, gives JCS-identical outcomes."""
    forward = [_outcome_bytes(importer, data, params) for data, params in cases]
    backward = [_outcome_bytes(importer, data, params) for data, params in reversed(cases)]
    backward.reverse()
    return [
        Failure("SPEC-006 R33", _sha256(data), "nondeterministic")
        for (data, _), first, second in zip(cases, forward, backward, strict=True)
        if first != second
    ]


def _outcome_bytes(importer: Importer, data: bytes, params: ImportParams) -> bytes:
    outcome = _outcome(importer, data, params)
    if isinstance(outcome, str):
        return f"contract_error:{outcome}".encode()
    return outcome_jcs(outcome)


def admit_importers(importers: Iterable[Importer]) -> dict[str, Importer]:
    """SPEC-006 R35: refuse an unimplemented `contract_version` and two importers with one `importer_id`."""
    admitted: dict[str, Importer] = {}
    for importer in importers:
        if isinstance(importer.contract_version, bool) or importer.contract_version != CONTRACT_VERSION:
            raise ImporterContractError("contract_version", repr(importer.contract_version))
        if importer.importer_id in admitted:
            raise ValueError(f"two importers share importer_id {importer.importer_id!r}")
        admitted[importer.importer_id] = importer
    return admitted


def outcomes_differ(published: Sequence[bytes], candidate: Sequence[bytes]) -> bool:
    """SPEC-006 R36: any difference in outcome JCS over the same inputs, in the same order."""
    if len(published) != len(candidate):
        raise ValueError("outcomes of the published and candidate versions cover different inputs")
    return published != candidate


def _major(version: str) -> int:
    match = _MAJOR.match(version)
    if match is None:
        raise ValueError(f"not a semver version: {version!r}")
    return int(match.group(1))


def version_bump_ok(published_version: str, candidate_version: str, *, differ: bool) -> bool:
    """SPEC-006 R36: a difference in outcomes requires a major bump; the release fails otherwise."""
    return not differ or _major(candidate_version) > _major(published_version)


@dataclass(frozen=True, slots=True)
class Check:
    """One entry of the report's `checks` (R34)."""

    rule: str
    passed: bool
    cases: int
    failures: int


@dataclass(frozen=True, slots=True)
class Limit:
    """One entry of the report's `limits` (R34), measured by the runner (R16, SPEC-002 R103-R105)."""

    method: str
    budget_ms: int
    max_ms: int
    peak_bytes: int


@dataclass(frozen=True, slots=True)
class ReportInputs:
    """Everything of the R34 report except `verdict`, which `importer_report` computes."""

    core_version: str
    core_git_sha: str
    importer: Importer
    wheel_sha256: str
    samples_revision: str
    positive: int
    encrypted: int
    negative: int
    run_kind: RunKind
    seed: int
    checks: Sequence[Check]
    fuzz_inputs: int
    fuzz_exceptions: int
    fuzz_timeouts: int
    limits: Sequence[Limit]
    failures: Sequence[Failure]


def _check_key(check: Check) -> str:
    return check.rule


def _limit_key(limit: Limit) -> str:
    return limit.method


def _failure_key(failure: Failure) -> tuple[str, str, str]:
    return (failure.rule, failure.input_sha256, failure.reason)


def importer_report(inputs: ReportInputs) -> Mapping[str, JsonValue]:
    """SPEC-006 R34: the suite report, lists sorted as SPEC-002 R126, failures deduplicated.

    `conformant` only if every check passed, no fuzz input raised or timed out, every limit stayed in
    budget and no failure is listed.
    """
    failures = sorted(set(inputs.failures), key=_failure_key)
    checks = sorted(inputs.checks, key=_check_key)
    limits = sorted(inputs.limits, key=_limit_key)
    if len({check.rule for check in checks}) != len(checks) or len({limit.method for limit in limits}) != len(limits):
        raise ValueError("each check rule and limit method is unique in the report (SPEC-002 R126)")
    conformant = (
        all(check.passed for check in checks)
        and inputs.fuzz_exceptions == 0
        and inputs.fuzz_timeouts == 0
        and all(limit.max_ms <= limit.budget_ms for limit in limits)
        and not failures
    )
    return {
        "report_version": REPORT_VERSION,
        "core": {"version": inputs.core_version, "git_sha": inputs.core_git_sha},
        "importer": {
            "importer_id": inputs.importer.importer_id,
            "version": inputs.importer.version,
            "contract_version": inputs.importer.contract_version,
            "wheel_sha256": inputs.wheel_sha256,
        },
        "samples": {
            "revision": inputs.samples_revision,
            "positive": inputs.positive,
            "encrypted": inputs.encrypted,
            "negative": inputs.negative,
        },
        "run": {"kind": inputs.run_kind, "seed": inputs.seed},
        "checks": [
            {"rule": check.rule, "passed": check.passed, "cases": check.cases, "failures": check.failures}
            for check in checks
        ],
        "fuzz": {
            "inputs": inputs.fuzz_inputs,
            "exceptions": inputs.fuzz_exceptions,
            "timeouts": inputs.fuzz_timeouts,
        },
        "limits": [
            {
                "method": limit.method,
                "budget_ms": limit.budget_ms,
                "max_ms": limit.max_ms,
                "peak_bytes": limit.peak_bytes,
            }
            for limit in limits
        ],
        "failures": [
            {"rule": failure.rule, "input_sha256": failure.input_sha256, "reason": failure.reason}
            for failure in failures
        ],
        "verdict": "conformant" if conformant else "nonconformant",
    }


def report_hash(report: Mapping[str, JsonValue]) -> str:
    """SPEC-006 R34: `sha256(JCS(report))`."""
    return jcs_hash(report)
