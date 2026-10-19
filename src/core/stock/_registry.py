"""The stock registry object, its shape, hash and fingerprint (SPEC-008 R1-R3, R10-R13)."""

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from itertools import pairwise
from typing import TypeGuard

from core.kernel import canonical_json
from core.provenance import Json, Raw

REGISTRY_SCHEMA = "impact.stock-registry.v1"
POLICY_SCHEMA = "impact.stock-policy.v1"
DOMAIN = "impact.stock-registry-signature.v1"
MAX_SAFE_INTEGER = 2**53 - 1

# SPEC-005 R5, SPEC-006 R3, SPEC-002 R2, SPEC-001 §2.1, SPEC-003 R34; `fullmatch`, so no trailing newline passes.
HEX32 = re.compile(r"[0-9a-f]{64}")
SIG = re.compile(r"[0-9a-f]{128}")
TIMESTAMP = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z")
FAMILY = re.compile(r"[a-z][a-z0-9]*(\.[a-z0-9][a-z0-9_]*)+")
MEMORY_ID = re.compile(r"[a-z][a-z0-9_]{0,31}")
SW_ID = re.compile(r"[\x20-\x7e]{1,64}")

_SIGNED_KEYS = frozenset({"registry", "registry_hash", "key_id", "signature"})
_REGISTRY_KEYS = frozenset({"schema", "version", "issued_at", "expires_at", "entries"})
_ENTRY_KEYS = frozenset({"family", "sw_id", "memory_id", "size", "excluded", "kept_sha256"})
_RANGE_KEYS = frozenset({"start", "end"})

type Excluded = tuple[tuple[int, int], ...]


class StockError(Exception):
    """SPEC-008 R41: a precondition failure with a stable `reason` (`bad_shape`, `bad_identification`)."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


def _shape(holds: bool, what: str) -> None:
    if not holds:
        raise StockError("bad_shape", what)


def matches(value: Raw, pattern: re.Pattern[str]) -> TypeGuard[str]:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def exact(value: Raw, keys: frozenset[str]) -> TypeGuard[Mapping[str, Raw]]:
    return isinstance(value, Mapping) and set(value) == keys


def uint(value: Raw) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_SAFE_INTEGER


def listing(value: Raw) -> TypeGuard[Sequence[Raw]]:
    return isinstance(value, Sequence) and not isinstance(value, str)


# --- timestamps (SPEC-005 R5) as UTC instants, without a clock or `datetime` (SPEC-008 R40) ---


def instant(value: Raw) -> int | None:
    """Seconds since 1970-01-01T00:00:00Z of a `Timestamp` naming a real UTC second, else None."""
    match = TIMESTAMP.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        return None
    year, month, day, hour, minute, second = (int(group) for group in match.groups())
    if not (year >= 1 and 1 <= month <= 12 and 1 <= day <= _month_days(year, month)):
        return None
    if not (hour < 24 and minute < 60 and second < 60):
        return None
    return _days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second


def _month_days(year: int, month: int) -> int:
    if month == 2:
        leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
        return 29 if leap else 28
    return 30 if month in {4, 6, 9, 11} else 31


def _days_from_civil(year: int, month: int, day: int) -> int:
    # Proleptic Gregorian day count (H. Hinnant, "chrono-Compatible Low-Level Date Algorithms").
    year -= month <= 2
    era = year // 400
    year_of_era = year - era * 400
    day_of_year = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    day_of_era = year_of_era * 365 + year_of_era // 4 - year_of_era // 100 + day_of_year
    return era * 146097 + day_of_era - 719468


# --- registry (R10-R13) ---


@dataclass(frozen=True, slots=True)
class StockEntry:
    """R10: one memory of a stock image of one software version."""

    family: str
    sw_id: str
    memory_id: str
    size: int
    excluded: Excluded
    kept_sha256: str

    @property
    def key(self) -> tuple[str, str, str, int, str]:
        """R12: the sort key of `entries`."""
        return (self.family, self.sw_id, self.memory_id, self.size, self.kept_sha256)

    def to_json(self) -> Json:
        excluded: list[Json] = [{"start": start, "end": end} for start, end in self.excluded]
        return {
            "family": self.family,
            "sw_id": self.sw_id,
            "memory_id": self.memory_id,
            "size": self.size,
            "excluded": excluded,
            "kept_sha256": self.kept_sha256,
        }


@dataclass(frozen=True, slots=True)
class StockRegistry:
    """R12."""

    version: int
    issued_at: str
    expires_at: str
    entries: tuple[StockEntry, ...]

    def to_json(self) -> Json:
        return {
            "schema": REGISTRY_SCHEMA,
            "version": self.version,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "entries": [entry.to_json() for entry in self.entries],
        }


@dataclass(frozen=True, slots=True)
class SignedStockRegistry:
    """R13."""

    registry: StockRegistry
    registry_hash: str
    key_id: str
    signature: str


def _object(value: Raw, keys: frozenset[str], what: str) -> Mapping[str, Raw]:
    if not exact(value, keys):
        raise StockError("bad_shape", f"{what} has exactly the keys {sorted(keys)}")
    return value


def _int(value: Raw, low: int, what: str) -> int:
    if not (uint(value) and value >= low):
        raise StockError("bad_shape", f"{what} is an integer >= {low}")
    return value


def _str(value: Raw, pattern: re.Pattern[str], what: str) -> str:
    if not matches(value, pattern):
        raise StockError("bad_shape", what)
    return value


def _list(value: Raw, what: str) -> Sequence[Raw]:
    if not listing(value):
        raise StockError("bad_shape", f"{what} is a list")
    return value


def _timestamp(value: Raw, what: str) -> str:
    if instant(value) is None:
        raise StockError("bad_shape", f"{what} is a Timestamp")
    return str(value)


def excluded_ranges(value: Raw, size: int) -> Excluded:
    """R10: sorted, `start < end <= size`, at least one byte between consecutive ranges."""
    ranges: list[tuple[int, int]] = []
    previous = -1
    for item in _list(value, "excluded"):
        bounds = _object(item, _RANGE_KEYS, "an excluded range")
        start, end = _int(bounds["start"], 0, "start"), _int(bounds["end"], 0, "end")
        _shape(previous < start < end <= size, "excluded ranges are sorted, apart and inside the memory")
        ranges.append((start, end))
        previous = end
    return tuple(ranges)


def kept_sha256(data: bytes, excluded: Excluded) -> str:
    """R11: SHA-256 of the bytes outside `excluded`, concatenated in offset order."""
    excluded_ranges([{"start": start, "end": end} for start, end in excluded], len(data))
    digest = hashlib.sha256()
    position = 0
    for start, end in excluded:
        digest.update(data[position:start])
        position = end
    digest.update(data[position:])
    return digest.hexdigest()


def _entry(value: Raw) -> StockEntry:
    item = _object(value, _ENTRY_KEYS, "an entry")
    size = _int(item["size"], 1, "size")
    return StockEntry(
        family=_str(item["family"], FAMILY, "family"),
        sw_id=_str(item["sw_id"], SW_ID, "sw_id"),
        memory_id=_str(item["memory_id"], MEMORY_ID, "memory_id"),
        size=size,
        excluded=excluded_ranges(item["excluded"], size),
        kept_sha256=_str(item["kept_sha256"], HEX32, "kept_sha256"),
    )


def _registry(value: Raw) -> StockRegistry:
    item = _object(value, _REGISTRY_KEYS, "a registry")
    _shape(item["schema"] == REGISTRY_SCHEMA, "schema")
    entries = tuple(_entry(entry) for entry in _list(item["entries"], "entries"))
    _shape(all(a.key < b.key for a, b in pairwise(entries)), "entries sorted by the R12 key, unique")
    return StockRegistry(
        version=_int(item["version"], 1, "version"),
        issued_at=_timestamp(item["issued_at"], "issued_at"),
        expires_at=_timestamp(item["expires_at"], "expires_at"),
        entries=entries,
    )


def parse_signed_registry(value: Raw) -> SignedStockRegistry:
    """R2, R10, R12, R13: the shape only; the hash and the signature are checked by the lookup (R21)."""
    item = _object(value, _SIGNED_KEYS, "a signed registry")
    return SignedStockRegistry(
        registry=_registry(item["registry"]),
        registry_hash=_str(item["registry_hash"], HEX32, "registry_hash"),
        key_id=_str(item["key_id"], HEX32, "key_id"),
        signature=_str(item["signature"], SIG, "signature"),
    )


def registry_hash(registry: StockRegistry) -> str:
    """R12: `sha256(JCS(StockRegistry))`."""
    return hashlib.sha256(canonical_json(registry.to_json())).hexdigest()


def signing_input(hash_hex: str) -> bytes:
    """R13, SPEC-005 R51: the UTF-8 JCS of `{domain, hash}`."""
    return canonical_json({"domain": DOMAIN, "hash": hash_hex})
