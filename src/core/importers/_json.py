"""JCS values of SPEC-006 R1, frozen, and their RFC 8785 serialization.

The kernel's canonical JSON rejects booleans (SPEC-001 R60), but importer `options` may hold any JCS value
(SPEC-006 R11), so importers carry their own encoder for the R1 domain: null, booleans, integers in
`[0, 2**53 - 1]`, strings without lone surrogates, arrays, and objects with ASCII keys (R2).
"""

import hashlib
from collections.abc import Iterator, Mapping, Sequence

type JsonValue = bool | int | str | Sequence[JsonValue] | Mapping[str, JsonValue] | None

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


class NotJsonError(ValueError):
    """A value outside the SPEC-006 R1 domain."""


class FrozenObject(Mapping[str, JsonValue]):
    """A read-only JSON object: a record's `options` cannot change after its hash was taken."""

    __slots__ = ("_members",)

    def __init__(self, members: dict[str, JsonValue]) -> None:
        self._members = members

    def __getitem__(self, key: str) -> JsonValue:
        return self._members[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._members)

    def __len__(self) -> int:
        return len(self._members)

    def __repr__(self) -> str:
        return f"FrozenObject({self._members!r})"


def _check_string(text: str) -> str:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise NotJsonError("lone surrogate") from exc
    return text


def freeze_json(value: object) -> JsonValue:
    """A deep, immutable copy of `value`, or `NotJsonError` if it is outside SPEC-006 R1 and R2."""
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if not 0 <= value <= MAX_SAFE_INTEGER:
            raise NotJsonError(f"integer {value} outside [0, 2**53 - 1]")
        return value
    if isinstance(value, str):
        return _check_string(value)
    if isinstance(value, Mapping):
        members: dict[str, JsonValue] = {}
        for key in value:
            if not isinstance(key, str) or not key.isascii():
                raise NotJsonError(f"object key {key!r} is not an ASCII string")
            members[key] = freeze_json(value[key])
        return FrozenObject(members)
    if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray):
        return tuple(freeze_json(item) for item in value)
    raise NotJsonError(f"{type(value).__name__} is not a JCS value")


def jcs(value: JsonValue) -> bytes:
    """RFC 8785 serialization of a value already checked by `freeze_json`, UTF-8 encoded."""
    parts: list[str] = []
    _encode(value, parts)
    return "".join(parts).encode("utf-8")


def jcs_hash(value: JsonValue) -> str:
    """SPEC-006 R1: lowercase hex `sha256(JCS(value))`."""
    return hashlib.sha256(jcs(value)).hexdigest()


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


def _encode(value: JsonValue, parts: list[str]) -> None:
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
        # Keys are ASCII (R2), so code-point order equals RFC 8785's UTF-16 order.
        for index, key in enumerate(sorted(value)):
            if index:
                parts.append(",")
            parts.append(_string(key))
            parts.append(":")
            _encode(value[key], parts)
        parts.append("}")
    else:
        parts.append("[")
        for index, item in enumerate(value):
            if index:
                parts.append(",")
            _encode(item, parts)
        parts.append("]")
