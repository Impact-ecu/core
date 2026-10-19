"""JCS values of SPEC-006 R1, frozen, and their hash.

Importer `options` may hold any JCS value (SPEC-006 R11), booleans included, so they are encoded by the kernel's
`jcs`. `freeze_json` admits the R1 domain only: null, booleans, integers in `[0, 2**53 - 1]`, strings without
lone surrogates, arrays, and objects with ASCII keys (R2).
"""

import hashlib
from collections.abc import Iterator, Mapping, Sequence

from core.kernel import JcsValue, jcs

type JsonValue = JcsValue

MAX_SAFE_INTEGER = 2**53 - 1


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


def jcs_hash(value: JsonValue) -> str:
    """SPEC-006 R1: lowercase hex `sha256(JCS(value))`."""
    return hashlib.sha256(jcs(value)).hexdigest()
