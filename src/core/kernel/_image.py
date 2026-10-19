"""`UnverifiedImage`: the result of `apply`, with no public byte access (SPEC-001 R7)."""

from dataclasses import dataclass
from typing import NoReturn, SupportsIndex, final

from core.kernel._errors import ShapeError
from core.kernel._model import Dump, DumpKind, dump_image_hash


@dataclass(frozen=True, slots=True)
class MemoryShape:
    """Metadata of one memory of an image, without its bytes."""

    memory_id: str
    base_address: int
    size: int


def require_known_base(dump: Dump) -> Dump:
    """`apply`, `diff` and `migrate` reject a memory whose `base_address` is unknown (SPEC-001 R2)."""
    unknown = sorted(memory.memory_id for memory in dump.memories if memory.base_address is None)
    if unknown:
        raise ShapeError("unknown_base_address", ",".join(unknown))
    return dump


@final
class UnverifiedImage:
    """Carries `dump_kind`, memory metadata and `image_hash`; never its bytes (SPEC-001 R7).

    The only read-only `Dump` view is `core.kernel._internal.view` (R8). Pickling, copying, JSON
    encoding, `bytes()`, `memoryview()` and the buffer protocol all fail.
    """

    __slots__ = ("_dump", "_image_hash", "_memories")

    _dump: Dump
    _image_hash: str
    _memories: tuple[MemoryShape, ...]

    def __init__(self, dump: Dump) -> None:
        require_known_base(dump)
        # `or 0` only narrows the type: require_known_base above already rejected every None.
        memories: tuple[MemoryShape, ...] = tuple(
            MemoryShape(m.memory_id, m.base_address or 0, len(m.data)) for m in dump.memories
        )
        object.__setattr__(self, "_dump", dump)
        object.__setattr__(self, "_image_hash", dump_image_hash(dump))
        object.__setattr__(self, "_memories", memories)

    @property
    def dump_kind(self) -> DumpKind:
        return self._dump.dump_kind

    @property
    def memories(self) -> tuple[MemoryShape, ...]:
        return self._memories

    @property
    def image_hash(self) -> str:
        return self._image_hash

    def __repr__(self) -> str:
        return f"UnverifiedImage(dump_kind={self.dump_kind!r}, image_hash={self._image_hash!r})"

    def __setattr__(self, name: str, value: object) -> NoReturn:
        raise AttributeError(f"UnverifiedImage is immutable: cannot set {name!r}")

    def __delattr__(self, name: str) -> NoReturn:
        raise AttributeError(f"UnverifiedImage is immutable: cannot delete {name!r}")

    def __getstate__(self) -> NoReturn:
        raise TypeError("UnverifiedImage is not serializable (SPEC-001 R7)")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("UnverifiedImage is not serializable (SPEC-001 R7)")


def as_dump(image: Dump | UnverifiedImage) -> Dump:
    """Kernel-side read of an input; reading an `UnverifiedImage` inside the kernel is allowed (§3)."""
    if isinstance(image, UnverifiedImage):
        return image._dump
    return image


def image_hash(image: Dump | UnverifiedImage) -> str:
    """SPEC-001 R62."""
    if isinstance(image, UnverifiedImage):
        return image.image_hash
    return dump_image_hash(image)
