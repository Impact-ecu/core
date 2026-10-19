"""The four RFC 8785 encoders the core carried before they were unified, copied verbatim as test oracles.

Sources at 6fb9fb7: `core.kernel._canonical` (`kernel`), `core.plugins._jcs` (`contract`), `core.importers._json`
(`importers`) and `core.evidence._json` (`evidence`). They are frozen here so the unified encoder can be shown to
emit the same bytes, and to fail the same way, on each one's domain.
"""

from collections.abc import Mapping, Sequence

from core.provenance import Raw

type KernelJson = int | str | Sequence[KernelJson] | Mapping[str, KernelJson] | None
type FullJson = bool | int | str | Sequence[FullJson] | Mapping[str, FullJson] | None

MAX_SAFE_INTEGER = 2**53 - 1

_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


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


# --- core.kernel._canonical.canonical_json ---


def kernel(value: KernelJson) -> bytes:
    parts: list[str] = []
    _kernel_encode(value, parts)
    return "".join(parts).encode("utf-8")


def _kernel_encode(value: KernelJson, parts: list[str]) -> None:
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
        _kernel_array(value, parts)
    elif isinstance(value, Mapping):
        _kernel_object(value, parts)
    else:
        raise TypeError(f"{type(value).__name__} is not a canonical JSON value")


def _kernel_array(items: Sequence[KernelJson], parts: list[str]) -> None:
    parts.append("[")
    for index, item in enumerate(items):
        if index:
            parts.append(",")
        _kernel_encode(item, parts)
    parts.append("]")


def _kernel_object(members: Mapping[str, KernelJson], parts: list[str]) -> None:
    parts.append("{")
    for index, key in enumerate(sorted(members, key=_utf16_key)):
        if index:
            parts.append(",")
        parts.append(_string(key))
        parts.append(":")
        _kernel_encode(members[key], parts)
    parts.append("}")


# --- core.plugins._jcs.contract_json ---


def contract(value: FullJson) -> bytes:
    parts: list[str] = []
    _contract_encode(value, parts)
    return "".join(parts).encode("utf-8")


def _contract_encode(value: FullJson, parts: list[str]) -> None:
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
        _contract_container(value, parts)


def _contract_container(value: FullJson, parts: list[str]) -> None:
    if isinstance(value, Sequence) and not isinstance(value, str):
        parts.append("[")
        for index, item in enumerate(value):
            if index:
                parts.append(",")
            _contract_encode(item, parts)
        parts.append("]")
    elif isinstance(value, Mapping):
        parts.append("{")
        for index, key in enumerate(sorted(value, key=_utf16_key)):
            if index:
                parts.append(",")
            parts.append(_string(key))
            parts.append(":")
            _contract_encode(value[key], parts)
        parts.append("}")
    else:
        raise TypeError(f"{type(value).__name__} is not a canonical JSON value")


# --- core.importers._json.jcs (defined only on values `freeze_json` accepts) ---


def importers(value: FullJson) -> bytes:
    parts: list[str] = []
    _importers_encode(value, parts)
    return "".join(parts).encode("utf-8")


def _importers_encode(value: FullJson, parts: list[str]) -> None:
    if value is None:
        parts.append("null")
    elif value is True:
        parts.append("true")
    elif value is False:
        parts.append("false")
    elif isinstance(value, int):
        parts.append(str(value))
    elif isinstance(value, str):
        parts.append(_string(value))
    elif isinstance(value, Mapping):
        parts.append("{")
        for index, key in enumerate(sorted(value)):
            if index:
                parts.append(",")
            parts.append(_string(key))
            parts.append(":")
            _importers_encode(value[key], parts)
        parts.append("}")
    else:
        parts.append("[")
        for index, item in enumerate(value):
            if index:
                parts.append(",")
            _importers_encode(item, parts)
        parts.append("]")


# --- core.evidence._json.jcs (booleans and framing here, scalars through the kernel encoder) ---


def evidence(value: Raw) -> bytes:
    if isinstance(value, bool):
        return b"true" if value else b"false"
    if isinstance(value, Mapping):
        members = [kernel(key) + b":" + evidence(value[key]) for key in sorted(value, key=_utf16_key)]
        return b"{" + b",".join(members) + b"}"
    if isinstance(value, Sequence) and not isinstance(value, str):
        return b"[" + b",".join(evidence(item) for item in value) + b"]"
    if isinstance(value, float):
        raise TypeError("floats never occur in a hashed object (SPEC-006 R1)")
    return kernel(value)
