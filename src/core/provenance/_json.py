"""JSON domain, hashing and the shape checks every SPEC-005 object uses (R1-R5).

`Raw` is what a JSON parser yields, so stored events and reports can be checked without trusting them;
`Json` is the hashable subset (SPEC-001 R60): no booleans, no floats, integers in `[0, 2**53 - 1]`.
"""

import hashlib
import re
from collections.abc import Callable, Mapping, Sequence
from itertools import pairwise
from types import MappingProxyType

from core.kernel import MAX_JSON_DEPTH, canonical_json

type Json = int | str | Sequence[Json] | Mapping[str, Json] | None
type Raw = bool | int | float | str | Sequence[Raw] | Mapping[str, Raw] | None
type Check = Callable[[Raw], bool]

MAX_SAFE_INTEGER = 2**53 - 1
ZERO_HASH = "0" * 64

# SPEC-005 R5.
ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
EVENT_ID = re.compile(r"[0-9a-f]{32}")
HEX32 = re.compile(r"[0-9a-f]{64}")
SIGNATURE = re.compile(r"[0-9a-f]{128}")
TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
DAY = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")

DUMP_KINDS = ("bench_full", "boot_full", "obd_full", "obd_partial", "virtual")
ORIGINS = ("obd_read", "bench_read", "boot_read", "virtual_read", "file_service")
VERIFY_STATUSES = ("ok", "fail", "bypassed", "signature_unverifiable", "not_applicable")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_json(value: Json) -> str:
    """`sha256(JCS(value))` in lowercase hex (SPEC-005 R1)."""
    return sha256_hex(canonical_json(value))


def signing_input(domain: str, hash_hex: str) -> bytes:
    """The UTF-8 JCS of `{domain, hash}` (SPEC-005 R51)."""
    return canonical_json({"domain": domain, "hash": hash_hex})


def encodable(text: str) -> bool:
    """No lone surrogates (SPEC-005 R4)."""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def to_json(value: Raw, depth: int = 0) -> Json:
    """A frozen copy of `value` in the hashable domain, or `ValueError` (SPEC-005 R1, R4; SPEC-001 R66)."""
    if value is None:
        return None
    if isinstance(value, bool | float):
        raise ValueError("booleans and floats never occur in a hashed object")
    if isinstance(value, int):
        if not 0 <= value <= MAX_SAFE_INTEGER:
            raise ValueError(f"integer {value} is outside [0, 2**53 - 1]")
        return value
    if isinstance(value, str):
        if not encodable(value):
            raise ValueError("lone surrogate")
        return value
    if depth == MAX_JSON_DEPTH and isinstance(value, (Mapping, list, tuple)):
        raise ValueError(f"arrays and objects nest deeper than {MAX_JSON_DEPTH}")
    if isinstance(value, Mapping):
        members: dict[str, Json] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise ValueError(f"object key {key!r} is not an ASCII string")
            members[key] = to_json(item, depth + 1)
        return MappingProxyType(members)
    if isinstance(value, list | tuple):
        return tuple(to_json(item, depth + 1) for item in value)
    raise ValueError(f"{type(value).__name__} is not a JSON value")


def as_mapping(value: Json) -> Mapping[str, Json]:
    """`value` if it is an object, else an empty one; callers pass values already checked to be objects."""
    return value if isinstance(value, Mapping) else MappingProxyType({})


def items(value: Raw) -> Sequence[Raw]:
    """The entries of a list, or none."""
    return value if isinstance(value, Sequence) and not isinstance(value, str) else ()


def strings(value: Raw) -> list[str]:
    return [item for item in items(value) if isinstance(item, str)]


def member(value: Raw, key: str) -> Raw:
    """`value[key]` of an object, or None when `value` is not an object or lacks `key`."""
    return value.get(key) if isinstance(value, Mapping) else None


def child(value: Json, key: str) -> Json:
    """`member` for values already in the hashable domain."""
    return value.get(key) if isinstance(value, Mapping) else None


def as_str(value: Raw) -> str:
    """A value already checked to be a string; "" otherwise."""
    return value if isinstance(value, str) else ""


def as_int(value: Raw) -> int:
    """A value already checked to be an integer; 0 otherwise."""
    return value if isinstance(value, int) else 0


def anything(_value: Raw) -> bool:
    return True


def try_hash(value: Raw) -> str | None:
    """`hash_json` of a raw value, or None when it is outside the hashable domain."""
    try:
        return hash_json(to_json(value))
    except ValueError:
        return None


# --- shape checks (SPEC-005 R3): each returns True only for exactly the stated form ---


def matches(pattern: re.Pattern[str]) -> Check:
    def check(value: Raw) -> bool:
        return isinstance(value, str) and pattern.fullmatch(value) is not None

    return check


def text(value: Raw) -> bool:
    """A non-empty string without lone surrogates."""
    return isinstance(value, str) and value != "" and encodable(value)


def uint(value: Raw) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_SAFE_INTEGER


def one_of(*allowed: str) -> Check:
    def check(value: Raw) -> bool:
        return isinstance(value, str) and value in allowed

    return check


def nullable(inner: Check) -> Check:
    def check(value: Raw) -> bool:
        return value is None or inner(value)

    return check


def obj(fields: Mapping[str, Check]) -> Check:
    """An object with exactly `fields` as keys, each value passing its check."""

    def check(value: Raw) -> bool:
        if not isinstance(value, Mapping) or set(value) != set(fields):
            return False
        return all(fields[key](value[key]) for key in fields)

    return check


def array(item: Check, *, sort_key: str | None = None, sorted_unique: bool = False, nonempty: bool = False) -> Check:
    """A list of items; `sort_key` (a string field) or `sorted_unique` (string items) demands strict order."""

    def check(value: Raw) -> bool:
        if not isinstance(value, Sequence) or isinstance(value, str) or not all(item(entry) for entry in value):
            return False
        if nonempty and not value:
            return False
        keys = [as_str(member(entry, sort_key)) for entry in value] if sort_key is not None else list(value)
        return not (sort_key is not None or sorted_unique) or strictly_increasing(keys)

    return check


def strictly_increasing(keys: Sequence[object]) -> bool:
    return all(a < b for a, b in pairwise(map(str, keys)))


HEX32_CHECK = matches(HEX32)
SIGNATURE_CHECK = matches(SIGNATURE)
EVENT_ID_CHECK = matches(EVENT_ID)
ID_CHECK = matches(ID)
EVENT_REF_CHECK = obj({"event_id": EVENT_ID_CHECK, "seq": uint, "hash": HEX32_CHECK})
