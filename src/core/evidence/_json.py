"""Hashing, formats and shape checks for SPEC-006 objects (R1-R3).

`FieldAttestation.communicates`, `GoldenEvaluation.attestations[].qualifying` and `EvidenceAdmission` carry
booleans, so SPEC-006 objects are encoded by the kernel's `jcs`, never by its boolean-free `canonical_json`.
"""

import hashlib
import re
from collections.abc import Mapping, Sequence
from itertools import pairwise
from typing import TypeGuard, cast

from core.kernel import JcsValue, jcs
from core.provenance import Raw, Verifier

MAX_SAFE_INTEGER = 2**53 - 1

# SPEC-005 R5 and SPEC-006 R3; `fullmatch` everywhere, so a trailing newline never passes.
HEX32 = re.compile(r"[0-9a-f]{64}")
SIG = re.compile(r"[0-9a-f]{128}")
TENANT_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
TIMESTAMP = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z")
DAY = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
FAMILY = re.compile(r"[a-z][a-z0-9]*(\.[a-z0-9][a-z0-9_]*)+")
VARIANT = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
TOOL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._+-]{0,63}")
DTC = re.compile(r"[PCBU][0-3][0-9A-F]{3}(-[0-9A-F]{2})?")
UNIT_ID = re.compile(r"[A-Z0-9]{4,40}")


def encode(value: Raw) -> bytes:
    """RFC 8785 of `value`; `TypeError`/`ValueError` for floats, unsafe integers or lone surrogates."""
    # `Raw` admits floats only because parsers yield them; `jcs` rejects them at run time (R1).
    return jcs(cast("JcsValue", value))


def digest(value: Raw) -> str:
    """R1: `sha256(JCS(value))` in lowercase hex."""
    return hashlib.sha256(encode(value)).hexdigest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def try_jcs(value: Raw) -> bytes | None:
    try:
        return encode(value)
    except (TypeError, ValueError):
        return None


def signing_input(domain: str, hash_hex: str) -> bytes:
    """SPEC-005 R51: the UTF-8 JCS of `{domain, hash}`."""
    return jcs({"domain": domain, "hash": hash_hex})


def verified(verifier: Verifier, public_key_hex: str, domain: str, hash_hex: str, signature_hex: str) -> bool:
    """SPEC-005 R51, R55 through the injected verifier. Callers pass validated hex; only `True` is acceptance."""
    message = signing_input(domain, hash_hex)
    return verifier.verify(bytes.fromhex(public_key_hex), message, bytes.fromhex(signature_hex)) is True


# --- shape checks (R2): each holds only for exactly the stated form ---


def matches(value: Raw, pattern: re.Pattern[str]) -> TypeGuard[str]:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def exact(value: Raw, keys: frozenset[str]) -> TypeGuard[Mapping[str, Raw]]:
    """An object with exactly `keys`."""
    return isinstance(value, Mapping) and set(value) == keys


def listing(value: Raw) -> TypeGuard[Sequence[Raw]]:
    return isinstance(value, Sequence) and not isinstance(value, str)


def uint(value: Raw) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_SAFE_INTEGER


def text(value: Raw) -> TypeGuard[str]:
    """A string without lone surrogates (R2)."""
    if not isinstance(value, str):
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def increasing[T: (str, tuple[str, str])](keys: Sequence[T]) -> bool:
    """Sorted by code point with no duplicates."""
    return all(a < b for a, b in pairwise(keys))


def strings(value: Raw, pattern: re.Pattern[str]) -> TypeGuard[Sequence[str]]:
    """A sorted, duplicate-free list of strings matching `pattern`."""
    return listing(value) and all(matches(item, pattern) for item in value) and increasing([str(v) for v in value])


# --- timestamps (SPEC-005 R5): compared as UTC instants without a clock or `datetime` (R4) ---


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
