"""Data shapes of SPEC-001 §2 and the hashes of §7 that depend only on them."""

import re
from dataclasses import dataclass, field
from typing import Literal

from core.kernel._canonical import MAX_SAFE_INTEGER, hash_json, sha256_hex
from core.kernel._errors import KernelError, LayoutError, ShapeError

DumpKind = Literal["bench_full", "boot_full", "obd_full", "obd_partial", "virtual"]
RegionKind = Literal["calibration", "checksum", "protected"]

DUMP_KINDS: frozenset[str] = frozenset({"bench_full", "boot_full", "obd_full", "obd_partial", "virtual"})
REGION_KINDS: frozenset[str] = frozenset({"calibration", "checksum", "protected"})

_MEMORY_ID = re.compile(r"[a-z][a-z0-9_]{0,31}")


def _check_int(value: int, error: type[KernelError], what: str) -> None:
    # SPEC-001 §2: every integer is non-negative and at most 2**53 - 1.
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_SAFE_INTEGER:
        raise error("bad_integer", f"{what} = {value!r}")


def _check_memory_id(memory_id: str, error: type[KernelError]) -> None:
    if not isinstance(memory_id, str) or _MEMORY_ID.fullmatch(memory_id) is None:
        raise error("bad_memory_id", repr(memory_id))


def _check_tuple(value: tuple[object, ...], error: type[KernelError], what: str) -> None:
    # A list inside a frozen dataclass could still be mutated after its hash was taken.
    if not isinstance(value, tuple):
        raise error("bad_type", f"{what} must be a tuple")


def _check_items(items: tuple[object, ...], kind: type, error: type[KernelError], what: str) -> None:
    # Duck-typed stand-ins would skip the validation done on construction (R10-R12 for patches).
    if not all(isinstance(item, kind) for item in items):
        raise error("bad_type", f"every item of {what} must be a {kind.__name__}")


def _check_bytes(value: bytes, what: str) -> None:
    if not isinstance(value, bytes):
        raise ShapeError("bad_type", f"{what} must be bytes")


@dataclass(frozen=True, slots=True)
class Memory:
    """One memory of a dump; offsets are relative to the start of `data` (SPEC-001 R2)."""

    memory_id: str
    base_address: int | None
    data: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _check_memory_id(self.memory_id, ShapeError)
        if self.base_address is not None:
            _check_int(self.base_address, ShapeError, "base_address")
        _check_bytes(self.data, "data")
        if not self.data:
            raise ShapeError("empty_memory", self.memory_id)


@dataclass(frozen=True, slots=True)
class Dump:
    """SPEC-001 §2.1. At least one memory, unique ids, non-empty data (R1)."""

    dump_kind: DumpKind
    memories: tuple[Memory, ...]

    def __post_init__(self) -> None:
        if self.dump_kind not in DUMP_KINDS:
            raise ShapeError("bad_dump_kind", repr(self.dump_kind))
        _check_tuple(self.memories, ShapeError, "memories")
        _check_items(self.memories, Memory, ShapeError, "memories")
        if not self.memories:
            raise ShapeError("empty_dump")
        ids = [memory.memory_id for memory in self.memories]
        if len(set(ids)) != len(ids):
            raise ShapeError("duplicate_memory", ",".join(sorted(ids)))


@dataclass(frozen=True, slots=True)
class Region:
    """`[start, end)` of one memory (SPEC-001 §2.2)."""

    kind: RegionKind
    start: int
    end: int
    name: str = ""

    def __post_init__(self) -> None:
        if self.kind not in REGION_KINDS:
            raise LayoutError("bad_region_kind", repr(self.kind))
        _check_int(self.start, LayoutError, "start")
        _check_int(self.end, LayoutError, "end")
        if self.start >= self.end:
            raise LayoutError("bad_cover", f"empty region [{self.start}, {self.end})")
        if not isinstance(self.name, str) or not _encodable(self.name):
            raise LayoutError("bad_region_name", repr(self.name))


def start_of(region: Region) -> int:
    return region.start


def _encodable(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


@dataclass(frozen=True, slots=True)
class LayoutMemory:
    """Regions of one memory: sorted, non-overlapping, covering `[0, size)` exactly (SPEC-001 R4)."""

    memory_id: str
    base_address: int | None
    size: int
    regions: tuple[Region, ...]

    def __post_init__(self) -> None:
        _check_memory_id(self.memory_id, LayoutError)
        if self.base_address is not None:
            _check_int(self.base_address, LayoutError, "base_address")
        _check_int(self.size, LayoutError, "size")
        _check_tuple(self.regions, LayoutError, "regions")
        _check_items(self.regions, Region, LayoutError, "regions")
        position = 0
        for region in self.regions:
            if region.start != position:
                raise LayoutError("bad_cover", f"{self.memory_id}: a region starts at {region.start}, not {position}")
            position = region.end
        if position != self.size or not self.regions:
            raise LayoutError("bad_cover", f"{self.memory_id}: regions end at {position}, size is {self.size}")


@dataclass(frozen=True, slots=True)
class MemoryLayout:
    """SPEC-001 §2.2. Anything not `calibration` or `checksum` is `protected` (R6)."""

    memories: tuple[LayoutMemory, ...]

    def __post_init__(self) -> None:
        _check_tuple(self.memories, LayoutError, "memories")
        _check_items(self.memories, LayoutMemory, LayoutError, "memories")
        ids = [memory.memory_id for memory in self.memories]
        if len(set(ids)) != len(ids):
            raise LayoutError("duplicate_memory", ",".join(sorted(ids)))


@dataclass(frozen=True, slots=True)
class Patch:
    """SPEC-001 §2.3. Immutable and identified by `patch_hash` (R11); validated on construction."""

    memory_id: str
    offset: int
    length: int
    before: bytes = field(repr=False)
    after: bytes = field(repr=False)
    patch_hash: str = field(init=False, compare=False)

    def __post_init__(self) -> None:
        _check_memory_id(self.memory_id, ShapeError)
        _check_int(self.offset, ShapeError, "offset")
        _check_int(self.length, ShapeError, "length")
        _check_bytes(self.before, "before")
        _check_bytes(self.after, "after")
        if self.length == 0 or len(self.before) != self.length or len(self.after) != self.length:
            raise ShapeError("bad_length", f"{self.length}, {len(self.before)}, {len(self.after)}")
        if self.before == self.after:
            raise ShapeError("noop_patch", f"{self.memory_id} offset {self.offset}")
        object.__setattr__(
            self,
            "patch_hash",
            hash_json(
                {
                    "memory_id": self.memory_id,
                    "offset": self.offset,
                    "length": self.length,
                    "before": self.before.hex(),
                    "after": self.after.hex(),
                }
            ),
        )

    @property
    def end(self) -> int:
        return self.offset + self.length


@dataclass(frozen=True, slots=True)
class Version:
    """SPEC-001 §2.4. `overlaps` are ordered pairs of patch hashes: the first applies first."""

    base_image_hash: str
    layout_hash: str
    patches: tuple[Patch, ...]
    overlaps: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        _check_tuple(self.patches, ShapeError, "patches")
        _check_items(self.patches, Patch, ShapeError, "patches")
        _check_tuple(self.overlaps, ShapeError, "overlaps")
        for pair in self.overlaps:
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise ShapeError("bad_type", "each overlap must be a (patch_hash, patch_hash) tuple")


def memory_id_of(memory: Memory | LayoutMemory) -> str:
    return memory.memory_id


def dump_image_hash(dump: Dump) -> str:
    """SPEC-001 R62."""
    return hash_json(
        {
            "dump_kind": dump.dump_kind,
            "memories": [
                {
                    "memory_id": memory.memory_id,
                    "base_address": memory.base_address,
                    "size": len(memory.data),
                    "sha256": sha256_hex(memory.data),
                }
                for memory in sorted(dump.memories, key=memory_id_of)
            ],
        }
    )


def layout_hash(layout: MemoryLayout) -> str:
    """SPEC-001 R63. Regions are already sorted by `start` (R4)."""
    return hash_json(
        {
            "memories": [
                {
                    "memory_id": memory.memory_id,
                    "base_address": memory.base_address,
                    "size": memory.size,
                    "regions": [
                        {"kind": region.kind, "start": region.start, "end": region.end, "name": region.name}
                        for region in memory.regions
                    ],
                }
                for memory in sorted(layout.memories, key=memory_id_of)
            ]
        }
    )
