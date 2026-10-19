"""Publication (R130), catalog entry (R133) and the automated semver rule (R134)."""

import re
from collections.abc import Mapping
from typing import Literal

from core.plugins import ContractJson

Bump = Literal["none", "minor", "major"]

# R134: a difference in these outputs needs a major; in `identify` or `hints`, at least a minor.
MAJOR_METHODS = frozenset({"layout", "checksums", "verify", "checksum_patches"})
MINOR_METHODS = frozenset({"identify", "hints"})
MIN_CATALOG_DUMPS = 20  # R133
_SEMVER = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")


def _get(value: object, key: str) -> object:
    return value.get(key) if isinstance(value, dict) else None


def publishable(report: ContractJson, wheel_sha256: str, nightly_green: bool) -> bool:
    """R130: a `release` run, `conformant`, for this exact wheel, with the last nightly green."""
    return (
        _get(_get(report, "run"), "kind") == "release"
        and _get(report, "verdict") == "conformant"
        and _get(_get(report, "plugin"), "wheel_sha256") == wheel_sha256
        and nightly_green
    )


def catalog_ready(distinct_dumps: int, offered: frozenset[str], golden_verified: frozenset[str], tuner: bool) -> bool:
    """R133: >= 20 distinct dumps, verified golden files for every variant offered, a validating tuner."""
    return distinct_dumps >= MIN_CATALOG_DUMPS and bool(offered) and offered <= golden_verified and tuner


def required_bump(published: Mapping[tuple[str, str], str], candidate: Mapping[tuple[str, str], str]) -> Bump:
    """R134. Keys are `(method, input)` (a corpus dump, an R117 mutated input or an R121 unverified image,
    by `image_hash`); values are the JCS hash of that output. A key on one side only is a difference."""
    changed = {
        method
        for method, item in set(published) | set(candidate)
        if published.get((method, item)) != candidate.get((method, item))
    }
    if changed & MAJOR_METHODS:
        return "major"
    if changed & MINOR_METHODS:
        return "minor"
    return "none"


def parse_semver(version: str) -> tuple[int, int, int]:
    """`MAJOR.MINOR.PATCH`; anything else is a `ValueError`."""
    match = _SEMVER.fullmatch(version)
    if match is None:
        raise ValueError(f"not a semver version: {version!r}")
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def bump_satisfied(published: str, candidate: str, required: Bump) -> bool:
    """R134: the candidate is newer and its bump is at least the required one; the release fails otherwise."""
    old, new = parse_semver(published), parse_semver(candidate)
    if required == "major":
        return new[0] > old[0]
    if required == "minor":
        return new[0] > old[0] or (new[0] == old[0] and new[1] > old[1])
    return new > old
