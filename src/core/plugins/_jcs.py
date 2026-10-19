"""RFC 8785 (JCS) for contract objects (SPEC-002 R9, R78, R127).

The kernel's encoder rejects booleans because none occurs in a kernel hash (SPEC-001 R60). Descriptors
(`reflect_in`, `skip_self`) and the conformance report (`passed`, `admitted`) carry booleans, so the
contract has its own encoder for the same domain plus `true`/`false`. Floats are never accepted (R3).
"""

import hashlib
from collections.abc import Mapping, Sequence

type ContractJson = bool | int | str | Sequence[ContractJson] | Mapping[str, ContractJson] | None

MAX_SAFE_INTEGER = 2**53 - 1

_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def contract_json(value: ContractJson) -> bytes:
    """RFC 8785 serialization of `value`, UTF-8 encoded."""
    parts: list[str] = []
    _encode(value, parts)
    return "".join(parts).encode("utf-8")


def contract_hash(value: ContractJson) -> str:
    """Lowercase hex SHA-256 of `contract_json(value)` (SPEC-001 R65)."""
    return hashlib.sha256(contract_json(value)).hexdigest()


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


def _utf16_key(key: str) -> bytes:
    return key.encode("utf-16-be", "surrogatepass")


def _encode(value: ContractJson, parts: list[str]) -> None:
    if value is None:
        parts.append("null")
    elif value is True:
        parts.append("true")
    elif value is False:
        parts.append("false")
    elif isinstance(value, int):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise ValueError(f"integer {value} is outside the exact JSON range")
        parts.append(str(value))
    elif isinstance(value, str):
        parts.append(_string(value))
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("byte strings are hex-encoded before hashing (SPEC-001 R60)")
    else:
        _container(value, parts)


def _container(value: ContractJson, parts: list[str]) -> None:
    if isinstance(value, Sequence) and not isinstance(value, str):
        parts.append("[")
        for index, item in enumerate(value):
            if index:
                parts.append(",")
            _encode(item, parts)
        parts.append("]")
    elif isinstance(value, Mapping):
        parts.append("{")
        # RFC 8785 §3.2.3: keys sorted by UTF-16 code units.
        for index, key in enumerate(sorted(value, key=_utf16_key)):
            if index:
                parts.append(",")
            parts.append(_string(key))
            parts.append(":")
            _encode(value[key], parts)
        parts.append("}")
    else:
        raise TypeError(f"{type(value).__name__} is not a canonical JSON value")
