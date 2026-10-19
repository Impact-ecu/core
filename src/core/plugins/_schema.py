"""Declarative checksum descriptor: shapes, JSON form and hash (SPEC-002 §4.1, R60, R61, R78).

Construction checks only the schema (R60, reason `schema`): types, key sets, integer bounds and widths
of `poly`/`init`/`xor_out`/`target`. Everything that needs the variant or the layout (R61, R63-R75) is
static validation in `core.plugins.descriptor` (R79), so a descriptor object can hold, for example, a
`bad_width` store until it is validated.
"""

import re
from dataclasses import dataclass
from typing import ClassVar, Literal, TypeGuard, cast

from core.plugins._errors import DescriptorError
from core.plugins._jcs import ContractJson, contract_hash

Endianness = Literal["little", "big"]
WordName = Literal["sum16", "sum32", "xor"]
EndIs = Literal["exclusive", "inclusive", "length"]
Addressing = Literal["offset", "absolute"]
Strategy = Literal["recalculate", "compensate"]

U32 = 2**32 - 1
NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")
MEMORY_ID = re.compile(r"[a-z][a-z0-9_]{0,31}")  # SPEC-001 §2.1

_ENDIANNESS = frozenset({"little", "big"})
_WORD_NAMES = frozenset({"sum16", "sum32", "xor"})
_END_IS = frozenset({"exclusive", "inclusive", "length"})
_ADDRESSING = frozenset({"offset", "absolute"})
_STRATEGIES = frozenset({"recalculate", "compensate"})


def _schema(holds: bool, detail: str) -> None:
    if not holds:
        raise DescriptorError("schema", detail)


def _is_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _u32(value: object, what: str, bound: int = U32) -> None:
    # R60: every integer in [0, 2**32 - 1]; poly, init, xor_out and target within the algorithm width.
    _schema(_is_int(value) and 0 <= value <= bound, f"{what} = {value!r}")


def _member(value: object, allowed: frozenset[str], what: str) -> None:
    _schema(isinstance(value, str) and value in allowed, f"{what} = {value!r}")


def _boolean(value: object, what: str) -> None:
    _schema(isinstance(value, bool), f"{what} must be a boolean")


@dataclass(frozen=True, slots=True)
class Range:
    """`[start, end)` (SPEC-002 §2.2). Bounds are checked by the object that holds it."""

    start: int
    end: int


def _check_range(value: object, what: str) -> None:
    _schema(isinstance(value, Range), f"{what} must be a Range")
    item = cast("Range", value)
    _u32(item.start, f"{what}.start")
    _u32(item.end, f"{what}.end")


@dataclass(frozen=True, slots=True)
class Crc32:
    """Rocksoft model, `init` = unreflected register before the first byte (R62)."""

    name: ClassVar[str] = "crc32"
    poly: int
    init: int
    xor_out: int
    reflect_in: bool
    reflect_out: bool

    def __post_init__(self) -> None:
        for what, value in (("poly", self.poly), ("init", self.init), ("xor_out", self.xor_out)):
            _u32(value, what)
        _boolean(self.reflect_in, "reflect_in")
        _boolean(self.reflect_out, "reflect_out")


@dataclass(frozen=True, slots=True)
class WordAlgorithm:
    """`sum16`, `sum32` or `xor` over words of `word_size` bytes (R62)."""

    name: WordName
    word_size: int
    endianness: Endianness
    init: int
    xor_out: int

    def __post_init__(self) -> None:
        _member(self.name, _WORD_NAMES, "algorithm.name")
        _schema(_is_int(self.word_size) and self.word_size in (1, 2, 4), f"word_size = {self.word_size!r}")
        _member(self.endianness, _ENDIANNESS, "algorithm.endianness")
        limit = (1 << width(self)) - 1
        _u32(self.init, "init", limit)
        _u32(self.xor_out, "xor_out", limit)


type Algorithm = Crc32 | WordAlgorithm


def width(algorithm: Algorithm) -> int:
    """R61: W = 32 for crc32 and sum32, 16 for sum16, 8 x word_size for xor."""
    if isinstance(algorithm, Crc32) or algorithm.name == "sum32":
        return 32
    if algorithm.name == "sum16":
        return 16
    return 8 * algorithm.word_size


@dataclass(frozen=True, slots=True)
class Field:
    """A stored value: `size` bytes at `offset` with `endianness` (§4.1)."""

    offset: int
    size: int
    endianness: Endianness

    def __post_init__(self) -> None:
        _u32(self.offset, "store.offset")
        _schema(_is_int(self.size) and self.size in (1, 2, 4), f"store.size = {self.size!r}")
        _member(self.endianness, _ENDIANNESS, "store.endianness")

    @property
    def span(self) -> Range:
        return Range(self.offset, self.offset + self.size)


@dataclass(frozen=True, slots=True)
class TableField:
    """An unsigned integer of `size` bytes at `entry + at` (R65)."""

    at: int
    size: int
    endianness: Endianness

    def __post_init__(self) -> None:
        _u32(self.at, "table field at")
        _schema(_is_int(self.size) and self.size in (1, 2, 4), f"table field size = {self.size!r}")
        _member(self.endianness, _ENDIANNESS, "table field endianness")


@dataclass(frozen=True, slots=True)
class Table:
    """Block pointers inside the memory (R65)."""

    offset: int
    count: int
    entry_size: int
    start: TableField
    end: TableField
    end_is: EndIs
    addressing: Addressing

    def __post_init__(self) -> None:
        for what, value in (("offset", self.offset), ("count", self.count), ("entry_size", self.entry_size)):
            _u32(value, f"table.{what}")
        _schema(isinstance(self.start, TableField) and isinstance(self.end, TableField), "table fields")
        _member(self.end_is, _END_IS, "end_is")
        _member(self.addressing, _ADDRESSING, "addressing")

    @property
    def span(self) -> Range:
        return Range(self.offset, self.offset + self.count * self.entry_size)


@dataclass(frozen=True, slots=True)
class Compensate:
    offset: int

    def __post_init__(self) -> None:
        _u32(self.offset, "compensate.offset")


@dataclass(frozen=True, slots=True)
class MirrorBlock:
    source: Range
    dest_offset: int

    def __post_init__(self) -> None:
        _check_range(self.source, "mirror_block.source")
        _u32(self.dest_offset, "dest_offset")

    @property
    def dest(self) -> Range:
        return Range(self.dest_offset, self.dest_offset + self.source.end - self.source.start)


def _check_header(descriptor_version: object, name: object, memory_id: object) -> None:
    _schema(_is_int(descriptor_version) and descriptor_version == 1, f"descriptor_version = {descriptor_version!r}")
    _schema(isinstance(name, str) and NAME.fullmatch(name) is not None, f"name = {name!r}")
    _schema(isinstance(memory_id, str) and MEMORY_ID.fullmatch(memory_id) is not None, f"memory_id = {memory_id!r}")


@dataclass(frozen=True, slots=True)
class ChecksumDescriptor:
    """§4.1. Every key is present; unused ones are None (R60)."""

    descriptor_version: int
    name: str
    memory_id: str
    algorithm: Algorithm
    ranges: tuple[Range, ...] | None
    ranges_from_table: Table | None
    chain: tuple[str, ...] | None
    skip_self: bool
    store: Field | None
    target: int | None
    strategy: Strategy
    compensate: Compensate | None

    def __post_init__(self) -> None:
        _check_header(self.descriptor_version, self.name, self.memory_id)
        _schema(isinstance(self.algorithm, Crc32 | WordAlgorithm), "algorithm")
        if self.ranges is not None:
            _schema(isinstance(self.ranges, tuple), "ranges must be a tuple")
            for index, item in enumerate(self.ranges):
                _check_range(item, f"ranges[{index}]")
        _schema(self.ranges_from_table is None or isinstance(self.ranges_from_table, Table), "ranges_from_table")
        if self.chain is not None:
            _schema(isinstance(self.chain, tuple), "chain must be a tuple")
            _schema(all(isinstance(item, str) for item in self.chain), "chain names must be strings")
            # R69: no self excision in a chain.
            _schema(self.skip_self is False, "skip_self must be false with chain")
        _boolean(self.skip_self, "skip_self")
        _schema(self.store is None or isinstance(self.store, Field), "store")
        if self.target is not None:
            _u32(self.target, "target", (1 << width(self.algorithm)) - 1)
        _member(self.strategy, _STRATEGIES, "strategy")
        _schema(self.compensate is None or isinstance(self.compensate, Compensate), "compensate")


@dataclass(frozen=True, slots=True)
class MirrorDescriptor:
    """§4.1, R72."""

    descriptor_version: int
    name: str
    memory_id: str
    mirror_block: MirrorBlock

    def __post_init__(self) -> None:
        _check_header(self.descriptor_version, self.name, self.memory_id)
        _schema(isinstance(self.mirror_block, MirrorBlock), "mirror_block")


type Descriptor = ChecksumDescriptor | MirrorDescriptor


def output_fields(descriptor: Descriptor) -> tuple[Range, ...]:
    """R73: the store (recalculate), the compensation word (compensate) or the mirror destination.

    Total on any schema-valid descriptor: a combination R70 or R71 rejects has no output field.
    """
    if isinstance(descriptor, MirrorDescriptor):
        return (descriptor.mirror_block.dest,)
    if descriptor.strategy == "recalculate":
        return () if descriptor.store is None else (descriptor.store.span,)
    algorithm = descriptor.algorithm
    if descriptor.compensate is None or not isinstance(algorithm, WordAlgorithm):
        return ()
    return (Range(descriptor.compensate.offset, descriptor.compensate.offset + algorithm.word_size),)


# JSON form - R60 (exact key sets, no defaults) and R78.


def _range_json(item: Range) -> dict[str, ContractJson]:
    return {"start": item.start, "end": item.end}


def _algorithm_json(algorithm: Algorithm) -> dict[str, ContractJson]:
    if isinstance(algorithm, Crc32):
        return {
            "name": "crc32",
            "poly": algorithm.poly,
            "init": algorithm.init,
            "xor_out": algorithm.xor_out,
            "reflect_in": algorithm.reflect_in,
            "reflect_out": algorithm.reflect_out,
        }
    return {
        "name": algorithm.name,
        "word_size": algorithm.word_size,
        "endianness": algorithm.endianness,
        "init": algorithm.init,
        "xor_out": algorithm.xor_out,
    }


def _table_field_json(item: TableField) -> dict[str, ContractJson]:
    return {"at": item.at, "size": item.size, "endianness": item.endianness}


def descriptor_json(descriptor: Descriptor) -> dict[str, ContractJson]:
    """The JSON object of §4.1, every key present."""
    header: dict[str, ContractJson] = {
        "descriptor_version": descriptor.descriptor_version,
        "name": descriptor.name,
        "memory_id": descriptor.memory_id,
    }
    if isinstance(descriptor, MirrorDescriptor):
        block = descriptor.mirror_block
        return header | {"mirror_block": {"source": _range_json(block.source), "dest_offset": block.dest_offset}}
    table = descriptor.ranges_from_table
    store = descriptor.store
    return header | {
        "algorithm": _algorithm_json(descriptor.algorithm),
        "ranges": None if descriptor.ranges is None else [_range_json(item) for item in descriptor.ranges],
        "ranges_from_table": None
        if table is None
        else {
            "offset": table.offset,
            "count": table.count,
            "entry_size": table.entry_size,
            "start": _table_field_json(table.start),
            "end": _table_field_json(table.end),
            "end_is": table.end_is,
            "addressing": table.addressing,
        },
        "chain": None if descriptor.chain is None else list(descriptor.chain),
        "skip_self": descriptor.skip_self,
        "store": None
        if store is None
        else {"offset": store.offset, "size": store.size, "endianness": store.endianness},
        "target": descriptor.target,
        "strategy": descriptor.strategy,
        "compensate": None if descriptor.compensate is None else {"offset": descriptor.compensate.offset},
    }


def descriptor_hash(descriptor: Descriptor) -> str:
    """R78: sha256(JCS(descriptor))."""
    return contract_hash(descriptor_json(descriptor))


_CHECKSUM_KEYS = frozenset(
    {
        "descriptor_version",
        "name",
        "memory_id",
        "algorithm",
        "ranges",
        "ranges_from_table",
        "chain",
        "skip_self",
        "store",
        "target",
        "strategy",
        "compensate",
    }
)
_MIRROR_KEYS = frozenset({"descriptor_version", "name", "memory_id", "mirror_block"})
_CRC_KEYS = frozenset({"name", "poly", "init", "xor_out", "reflect_in", "reflect_out"})
_WORD_KEYS = frozenset({"name", "word_size", "endianness", "init", "xor_out"})
_TABLE_KEYS = frozenset({"offset", "count", "entry_size", "start", "end", "end_is", "addressing"})


def _is_object(value: object) -> TypeGuard[dict[object, object]]:
    return isinstance(value, dict)


def _object(value: object, keys: frozenset[str], what: str) -> dict[object, object]:
    _schema(_is_object(value) and set(value) == keys, f"{what}: keys")
    return cast("dict[object, object]", value)


def _list(value: object, what: str) -> list[object]:
    _schema(isinstance(value, list), f"{what} must be an array")
    return cast("list[object]", value)


def _int(value: object, what: str) -> int:
    # Bounds are checked by the dataclass; here only the JSON type.
    _schema(_is_int(value), f"{what} must be an integer")
    return cast("int", value)


def _optional_int(value: object, what: str) -> int | None:
    return None if value is None else _int(value, what)


def _range_from(value: object, what: str) -> Range:
    obj = _object(value, frozenset({"start", "end"}), what)
    return Range(_int(obj["start"], f"{what}.start"), _int(obj["end"], f"{what}.end"))


def _table_field_from(value: object, what: str) -> TableField:
    obj = _object(value, frozenset({"at", "size", "endianness"}), what)
    return TableField(_int(obj["at"], "at"), _int(obj["size"], "size"), cast("Endianness", obj["endianness"]))


def _algorithm_from(value: object) -> Algorithm:
    name = value.get("name") if _is_object(value) else None
    if name == "crc32":
        obj = _object(value, _CRC_KEYS, "algorithm")
        return Crc32(
            _int(obj["poly"], "poly"),
            _int(obj["init"], "init"),
            _int(obj["xor_out"], "xor_out"),
            cast("bool", obj["reflect_in"]),
            cast("bool", obj["reflect_out"]),
        )
    obj = _object(value, _WORD_KEYS, "algorithm")
    return WordAlgorithm(
        cast("WordName", obj["name"]),
        _int(obj["word_size"], "word_size"),
        cast("Endianness", obj["endianness"]),
        _int(obj["init"], "init"),
        _int(obj["xor_out"], "xor_out"),
    )


def descriptor_from_json(value: object) -> Descriptor:
    """Parse a §4.1 JSON object; any departure from the schema is `DescriptorError` `schema` (R60)."""
    if _is_object(value) and "mirror_block" in value:
        obj = _object(value, _MIRROR_KEYS, "mirror descriptor")
        block = _object(obj["mirror_block"], frozenset({"source", "dest_offset"}), "mirror_block")
        return MirrorDescriptor(
            _int(obj["descriptor_version"], "descriptor_version"),
            cast("str", obj["name"]),
            cast("str", obj["memory_id"]),
            MirrorBlock(_range_from(block["source"], "source"), _int(block["dest_offset"], "dest_offset")),
        )
    obj = _object(value, _CHECKSUM_KEYS, "checksum descriptor")
    ranges = obj["ranges"]
    table = obj["ranges_from_table"]
    chain = obj["chain"]
    store = obj["store"]
    compensate = obj["compensate"]
    table_obj = None if table is None else _object(table, _TABLE_KEYS, "ranges_from_table")
    store_obj = None if store is None else _object(store, frozenset({"offset", "size", "endianness"}), "store")
    return ChecksumDescriptor(
        descriptor_version=_int(obj["descriptor_version"], "descriptor_version"),
        name=cast("str", obj["name"]),
        memory_id=cast("str", obj["memory_id"]),
        algorithm=_algorithm_from(obj["algorithm"]),
        ranges=None
        if ranges is None
        else tuple(_range_from(item, f"ranges[{i}]") for i, item in enumerate(_list(ranges, "ranges"))),
        ranges_from_table=None
        if table_obj is None
        else Table(
            _int(table_obj["offset"], "offset"),
            _int(table_obj["count"], "count"),
            _int(table_obj["entry_size"], "entry_size"),
            _table_field_from(table_obj["start"], "start"),
            _table_field_from(table_obj["end"], "end"),
            cast("EndIs", table_obj["end_is"]),
            cast("Addressing", table_obj["addressing"]),
        ),
        chain=None if chain is None else tuple(cast("list[str]", _list(chain, "chain"))),
        skip_self=cast("bool", obj["skip_self"]),
        store=None
        if store_obj is None
        else Field(
            _int(store_obj["offset"], "store.offset"),
            _int(store_obj["size"], "store.size"),
            cast("Endianness", store_obj["endianness"]),
        ),
        target=_optional_int(obj["target"], "target"),
        strategy=cast("Strategy", obj["strategy"]),
        compensate=None
        if compensate is None
        else Compensate(_int(_object(compensate, frozenset({"offset"}), "compensate")["offset"], "offset")),
    )
