"""Canonical JSON (RFC 8785, JCS) and SHA-256: the one JCS encoder of the core.

`jcs` covers every JSON value a spec hashes or emits: null, booleans, integers within ±(2**53 - 1),
strings, arrays and objects with string keys. `canonical_json` is the same encoder in strict mode for
the hashes of SPEC-001 §7, whose inputs never contain a boolean (R60). Floats are always rejected.
"""

import hashlib
from collections.abc import Mapping, Sequence

type Json = int | str | Sequence[Json] | Mapping[str, Json] | None
type JcsValue = bool | int | str | Sequence[JcsValue] | Mapping[str, JcsValue] | None

MAX_SAFE_INTEGER = 2**53 - 1
# SPEC-001 R66: deeper input is rejected before Python's recursion limit turns it into a RecursionError.
MAX_JSON_DEPTH = 64

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def jcs(value: JcsValue) -> bytes:
    """RFC 8785 serialization of `value`, UTF-8 encoded; `TypeError`/`ValueError` outside the JSON domain."""
    parts: list[str] = []
    _encode(value, parts, booleans=True, depth=0)
    return "".join(parts).encode("utf-8")


def canonical_json(value: Json) -> bytes:
    """`jcs` for kernel hash inputs (SPEC-001 R60): a boolean anywhere is a `TypeError`."""
    parts: list[str] = []
    _encode(value, parts, booleans=False, depth=0)
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


def _encode(value: JcsValue, parts: list[str], *, booleans: bool, depth: int) -> None:
    if value is None:
        parts.append("null")
    elif isinstance(value, bool):
        if not booleans:
            raise TypeError("booleans never occur in a hashed kernel object")
        parts.append("true" if value else "false")
    elif isinstance(value, int):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise ValueError(f"integer {value} is outside the exact JSON range")
        parts.append(str(value))
    elif isinstance(value, str):
        parts.append(_string(value))
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("byte strings are hex-encoded before hashing (SPEC-001 R60)")
    elif isinstance(value, Sequence | Mapping) and depth == MAX_JSON_DEPTH:
        raise ValueError(f"arrays and objects nest deeper than {MAX_JSON_DEPTH} (SPEC-001 R66)")
    elif isinstance(value, Sequence):
        _array(value, parts, booleans=booleans, depth=depth + 1)
    elif isinstance(value, Mapping):
        _object(value, parts, booleans=booleans, depth=depth + 1)
    else:
        raise TypeError(f"{type(value).__name__} is not a canonical JSON value")


def _array(items: Sequence[JcsValue], parts: list[str], *, booleans: bool, depth: int) -> None:
    parts.append("[")
    for index, item in enumerate(items):
        if index:
            parts.append(",")
        _encode(item, parts, booleans=booleans, depth=depth)
    parts.append("]")


def _object(members: Mapping[str, JcsValue], parts: list[str], *, booleans: bool, depth: int) -> None:
    parts.append("{")
    for index, key in enumerate(sorted(members, key=_utf16_key)):
        if index:
            parts.append(",")
        parts.append(_string(key))
        parts.append(":")
        _encode(members[key], parts, booleans=booleans, depth=depth)
    parts.append("}")
