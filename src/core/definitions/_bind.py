"""Binding a definition to a dump: span, decode and edits as patches (SPEC-003 R22, R30, R55-R58)."""

from collections.abc import Mapping
from dataclasses import dataclass
from fractions import Fraction

from core.definitions._cells import Value, decode_cell, encode_cell
from core.definitions._errors import DefinitionError, ensure
from core.definitions._model import (
    AxisRef,
    Definition,
    Dtype,
    FixedAxis,
    InlineAxis,
    MapDef,
    PointerAxis,
    Scaling,
    SharedAxis,
    StoredAxis,
    resolve_axis,
)
from core.kernel import Dump, Memory, Patch


@dataclass(frozen=True, slots=True)
class ByteRange:
    """`[start, end)` of one memory."""

    memory_id: str
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class Decoded:
    """R56: physical values, rows outer; `x` and `y` are None for an absent axis."""

    cells: tuple[tuple[Value, ...], ...]
    x: tuple[Value, ...] | None
    y: tuple[Value, ...] | None


def _memory(dump: Dump, memory_id: str) -> Memory:
    for memory in dump.memories:
        if memory.memory_id == memory_id:
            return memory
    raise DefinitionError("unknown_memory", memory_id)


def _read(dump: Dump, memory_id: str, start: int, length: int) -> bytes:
    """R55: the bytes of a span that must lie inside an existing memory."""
    data = _memory(dump, memory_id).data
    if start + length > len(data):
        raise DefinitionError("out_of_memory", f"{memory_id} [{start}, {start + length}) beyond {len(data)}")
    return data[start : start + length]


def _breakpoints(axis: InlineAxis | PointerAxis, dump: Dump) -> tuple[str, int]:
    """Memory and offset of the breakpoint cells, resolving a pointer per R22."""
    if isinstance(axis, InlineAxis):
        return axis.memory_id, axis.offset
    raw = _read(dump, axis.memory_id, axis.pointer_offset, axis.pointer_dtype.size)
    pointer = int.from_bytes(raw, "little" if axis.pointer_dtype.byte_order == "le" else "big")
    base = _memory(dump, axis.target_memory_id).base_address
    if base is None:
        raise DefinitionError("unknown_base_address", axis.target_memory_id)
    if pointer < base:
        raise DefinitionError("out_of_memory", f"pointer {pointer:#x} below {axis.target_memory_id}")
    return axis.target_memory_id, pointer - base


def _axis_ranges(axis: StoredAxis | None, dump: Dump) -> list[ByteRange]:
    if axis is None or isinstance(axis, FixedAxis):
        return []
    memory_id, offset = _breakpoints(axis, dump)
    length = axis.count * axis.dtype.size
    _read(dump, memory_id, offset, length)
    ranges = [ByteRange(memory_id, offset, offset + length)]
    if isinstance(axis, PointerAxis):
        ranges.append(ByteRange(axis.memory_id, axis.pointer_offset, axis.pointer_offset + axis.pointer_dtype.size))
    return ranges


def _range_key(byte_range: ByteRange) -> tuple[str, int]:
    return byte_range.memory_id, byte_range.start


def span(mapdef: MapDef, definition: Definition, dump: Dump) -> tuple[ByteRange, ...]:
    """R30: every byte the meaning of `mapdef` depends on, sorted by (memory_id, start), merged."""
    _read(dump, mapdef.memory_id, mapdef.offset, mapdef.cell_bytes)
    parts = [ByteRange(mapdef.memory_id, mapdef.offset, mapdef.offset + mapdef.cell_bytes)]
    for axis in (mapdef.x, mapdef.y):
        parts.extend(_axis_ranges(resolve_axis(axis, definition), dump))
    merged: list[ByteRange] = []
    for part in sorted(parts, key=_range_key):
        last = merged[-1] if merged else None
        if last is not None and last.memory_id == part.memory_id and part.start <= last.end:
            merged[-1] = ByteRange(last.memory_id, last.start, max(last.end, part.end))
        else:
            merged.append(part)
    return tuple(merged)


def _cells(data: bytes, offset: int, count: int, dtype: Dtype, scaling: Scaling) -> tuple[Value, ...]:
    size = dtype.size
    return tuple(decode_cell(dtype, scaling, data[offset + i * size : offset + (i + 1) * size]) for i in range(count))


def _axis_values(axis: StoredAxis | None, dump: Dump) -> tuple[Value, ...] | None:
    if axis is None:
        return None
    if isinstance(axis, FixedAxis):
        return axis.values
    memory_id, offset = _breakpoints(axis, dump)
    return _cells(_read(dump, memory_id, offset, axis.count * axis.dtype.size), 0, axis.count, axis.dtype, axis.scaling)


def cell_index(mapdef: MapDef, row: int, col: int) -> int:
    """R8: x_fastest puts (r, c) at r·cols + c; y_fastest at c·rows + r."""
    return row * mapdef.cols + col if mapdef.cell_order == "x_fastest" else col * mapdef.rows + row


def decode(mapdef: MapDef, definition: Definition, dump: Dump) -> Decoded:
    """R56. Binding is checked first (R55): every memory and span the map reaches must exist."""
    span(mapdef, definition, dump)
    flat = _cells(
        _read(dump, mapdef.memory_id, mapdef.offset, mapdef.cell_bytes),
        0,
        mapdef.rows * mapdef.cols,
        mapdef.dtype,
        mapdef.scaling,
    )
    cells = tuple(tuple(flat[cell_index(mapdef, r, c)] for c in range(mapdef.cols)) for r in range(mapdef.rows))
    return Decoded(
        cells,
        _axis_values(resolve_axis(mapdef.x, definition), dump),
        _axis_values(resolve_axis(mapdef.y, definition), dump),
    )


def _check_target(value: object, what: str) -> Fraction:
    if not isinstance(value, Fraction):
        raise DefinitionError("bad_shape", f"{what} must be a Fraction")
    return value


def _check_index(value: object, bound: int, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < bound:
        raise DefinitionError("bad_shape", f"{what} = {value!r} outside [0, {bound})")
    return value


def _encode_span(
    where: tuple[str, int], current: bytes, dtype: Dtype, scaling: Scaling, targets: Mapping[int, Fraction]
) -> tuple[Patch, ...]:
    memory_id, offset = where
    size = dtype.size
    updated = bytearray(current)
    for index in sorted(targets):
        cell = current[index * size : (index + 1) * size]
        encoded = encode_cell(dtype, scaling, targets[index], cell)
        updated[index * size : (index + 1) * size] = encoded
    patches: list[Patch] = []
    position = 0
    while position < len(current):
        if updated[position] == current[position]:
            position += 1
            continue
        start = position
        while position < len(current) and updated[position] != current[position]:
            position += 1
        patches.append(
            Patch(memory_id, offset + start, position - start, current[start:position], bytes(updated[start:position]))
        )
    # R15: cells without a target keep their bytes.
    untouched = set(range(len(current) // size)) - set(targets)
    ensure(
        all(updated[i * size : (i + 1) * size] == current[i * size : (i + 1) * size] for i in untouched), "SPEC-003 R15"
    )
    return tuple(patches)


def encode(mapdef: MapDef, dump: Dump, targets: Mapping[tuple[int, int], Fraction]) -> tuple[Patch, ...]:
    """R57: one patch per maximal run of differing bytes in the cell span, in offset order."""
    current = _read(dump, mapdef.memory_id, mapdef.offset, mapdef.cell_bytes)
    by_index: dict[int, Fraction] = {}
    for (row_value, col_value), value in targets.items():
        row = _check_index(row_value, mapdef.rows, "row")
        col = _check_index(col_value, mapdef.cols, "col")
        by_index[cell_index(mapdef, row, col)] = _check_target(value, f"target ({row}, {col})")
    return _encode_span((mapdef.memory_id, mapdef.offset), current, mapdef.dtype, mapdef.scaling, by_index)


def encode_axis(axis: AxisRef, dump: Dump, targets: Mapping[int, Fraction]) -> tuple[Patch, ...]:
    """R58: an axis edit on the breakpoint span. A shared axis is edited once, through its AxisDef;
    a fixed axis has no bytes, so changing it is a definition change, not a patch."""
    if isinstance(axis, SharedAxis | FixedAxis):
        raise DefinitionError("bad_shape", "only inline and pointer axes have breakpoint bytes")
    memory_id, offset = _breakpoints(axis, dump)
    current = _read(dump, memory_id, offset, axis.count * axis.dtype.size)
    checked = {
        _check_index(index, axis.count, "index"): _check_target(value, f"target {index}")
        for index, value in targets.items()
    }
    return _encode_span((memory_id, offset), current, axis.dtype, axis.scaling, checked)
