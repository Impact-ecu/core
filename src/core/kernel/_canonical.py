"""Canonical JSON (RFC 8785, JCS) and SHA-256 for every hash in SPEC-001 §7.

Written for the value domain of the kernel: null, integers within ±(2**53 - 1), strings, arrays
and objects. Booleans and floats never occur in a hashed object (SPEC-001 R60) and are rejected.
"""

import hashlib
from collections.abc import Mapping, Sequence

type Json = int | str | Sequence[Json] | Mapping[str, Json] | None

MAX_SAFE_INTEGER = 2**53 - 1

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def canonical_json(value: Json) -> bytes:
    """RFC 8785 serialization of `value`, UTF-8 encoded (SPEC-001 R60)."""
    parts: list[str] = []
    _encode(value, parts)
    return "".join(parts).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_json(value: Json) -> str:
    """Lowercase hex SHA-256 of the canonical JSON of `value` (SPEC-001 R65)."""
    return sha256_hex(canonical_json(value))


def _utf16_key(key: str) -> bytes:
    # RFC 8785 §3.2.3 sorts object keys by UTF-16 code units, not by code points.
    return key.encode("utf-16-be", "surrogatepass")


def _string(text: str) -> str:
    out = ['"']
    for char in text:
        escaped = _ESCAPES.get(char)
        if escaped is not None:
            out.append(escaped)
        elif char < " ":
            out.append(f"\\u{ord(char):04x}")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _encode(value: Json, parts: list[str]) -> None:
    if value is None:
        parts.append("null")
    elif isinstance(value, bool):
        raise TypeError("booleans never occur in a hashed kernel object")
    elif isinstance(value, int):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise ValueError(f"integer {value} is outside the exact JSON range")
        parts.append(str(value))
    elif isinstance(value, str):
        parts.append(_string(value))
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("byte strings are hex-encoded before hashing (SPEC-001 R60)")
    elif isinstance(value, Sequence):
        _array(value, parts)
    elif isinstance(value, Mapping):
        _object(value, parts)
    else:
        raise TypeError(f"{type(value).__name__} is not a canonical JSON value")


def _array(items: Sequence[Json], parts: list[str]) -> None:
    parts.append("[")
    for index, item in enumerate(items):
        if index:
            parts.append(",")
        _encode(item, parts)
    parts.append("]")


def _object(members: Mapping[str, Json], parts: list[str]) -> None:
    parts.append("{")
    for index, key in enumerate(sorted(members, key=_utf16_key)):
        if index:
            parts.append(",")
        parts.append(_string(key))
        parts.append(":")
        _encode(members[key], parts)
    parts.append("}")
