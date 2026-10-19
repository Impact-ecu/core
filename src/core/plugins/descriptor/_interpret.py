"""Static validation (R79), resolution (R63-R69, R66), verify (R77) and patch derivation (R75, R76)."""

import heapq
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import cast

from core.kernel import Dump, LayoutMemory, Memory, MemoryLayout, Patch
from core.plugins._contract import ChecksumRegion, RegionResult, RegionStatus, require
from core.plugins._errors import DescriptorError
from core.plugins._schema import (
    ChecksumDescriptor,
    Compensate,
    Crc32,
    Descriptor,
    Field,
    MirrorDescriptor,
    Range,
    Table,
    TableField,
    WordAlgorithm,
    output_fields,
    width,
)
from core.plugins.descriptor import _engines

type Span = tuple[int, int]


def _span(item: Range) -> Span:
    return (item.start, item.end)


def _overlaps(a: Span, b: Span) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def _inside(a: Span, b: Span) -> bool:
    return b[0] <= a[0] and a[1] <= b[1]


def _reject(holds: bool, reason: str, detail: str) -> None:
    if not holds:
        raise DescriptorError(reason, detail)


@dataclass(frozen=True, slots=True)
class _Plan:
    """A descriptor resolved on one memory: message pieces in message order, inputs and outputs (R75)."""

    descriptor: Descriptor
    pieces: tuple[Span, ...]
    inputs: tuple[Span, ...]
    outputs: tuple[Span, ...]


# Message resolution - R63-R69, R71.


def _read(data: bytes, entry: int, item: TableField) -> int:
    position = entry + item.at
    return int.from_bytes(data[position : position + item.size], item.endianness)


def _table_ranges(table: Table, data: bytes, base_address: int | None, name: str) -> list[Span]:
    """R65, on the dump's bytes. Every failure here is a resolution failure (R66)."""
    size = len(data)
    out: list[Span] = []
    for index in range(table.count):
        entry = table.offset + index * table.entry_size
        s, e = _read(data, entry, table.start), _read(data, entry, table.end)
        if table.addressing == "absolute":
            _reject(base_address is not None, "unknown_base_address", name)
            base = base_address or 0
            s -= base
            if table.end_is != "length":
                e -= base
        if table.end_is == "inclusive":
            e += 1
        elif table.end_is == "length":
            e += s
        _reject(s >= 0 and s <= e <= size, "table_out_of_bounds", f"{name} entry {index}: [{s}, {e})")
        _reject(s < e, "empty_range", f"{name} entry {index}")
        out.append((s, e))
    return out


def _excise(d: ChecksumDescriptor, ranges: list[Span]) -> list[Span]:
    """R64 overlap, then R68 self excision."""
    for index, a in enumerate(ranges):
        _reject(not any(_overlaps(a, b) for b in ranges[index + 1 :]), "overlapping_ranges", d.name)
    store_field = d.store
    if not d.skip_self:
        hit = store_field is not None and any(_overlaps(r, _span(store_field.span)) for r in ranges)
        _reject(not hit or d.strategy == "compensate", "self_reference", d.name)
        return ranges
    if store_field is None:
        raise DescriptorError("skip_self_without_self", f"{d.name}: no store")
    store = _span(store_field.span)
    hits = [r for r in ranges if _overlaps(r, store)]
    _reject(bool(hits), "skip_self_without_self", d.name)
    _reject(_inside(store, hits[0]), "partial_self", d.name)
    pieces: list[Span] = []
    for r in ranges:
        if r == hits[0]:
            pieces.extend(p for p in ((r[0], store[0]), (store[1], r[1])) if p[0] < p[1])
        else:
            pieces.append(r)
    return pieces


def _finish(d: ChecksumDescriptor, pieces: list[Span]) -> list[Span]:
    """R67 alignment and R71 compensation placement."""
    algorithm = d.algorithm
    if isinstance(algorithm, Crc32):
        return pieces
    size = algorithm.word_size
    _reject(all((e - s) % size == 0 for s, e in pieces), "misaligned_piece", d.name)
    if d.compensate is not None:
        field = (d.compensate.offset, d.compensate.offset + size)
        host = [p for p in pieces if _inside(field, p) and (field[0] - p[0]) % size == 0]
        _reject(bool(host), "compensate_outside_message", d.name)
    return pieces


def _resolve(d: Descriptor, data: bytes, base_address: int | None, stores: Mapping[str, Span]) -> _Plan:
    """Resolve `d` on one memory. `stores` maps each valid chain target (R69) to its store field.

    Static validation calls it only for descriptors whose inputs are static, with empty `data`.
    """
    if isinstance(d, MirrorDescriptor):
        source = _span(d.mirror_block.source)
        return _Plan(d, (source,), (source,), (_span(d.mirror_block.dest),))
    inputs: list[Span] = []
    if d.ranges is not None:
        pieces = _excise(d, [_span(item) for item in d.ranges])
    elif d.ranges_from_table is not None:
        table = d.ranges_from_table
        pieces = _excise(d, _table_ranges(table, data, base_address, d.name))
        inputs.append(_span(table.span))
    else:
        # R63 leaves only the chain; R69 guarantees every name is in `stores`.
        pieces = [stores[name] for name in d.chain or ()]
    pieces = _finish(d, pieces)
    if d.strategy == "compensate" and d.store is not None:
        inputs.append(_span(d.store.span))
    return _Plan(d, tuple(pieces), (*pieces, *inputs), tuple(_span(item) for item in output_fields(d)))


def chain_stores(descriptors: Sequence[Descriptor]) -> dict[tuple[str, str], Span]:
    """(memory_id, name) of every checksum descriptor with a store, to its store field (R69 targets)."""
    return {
        (d.memory_id, d.name): _span(d.store.span)
        for d in descriptors
        if isinstance(d, ChecksumDescriptor) and d.store is not None
    }


def _stores_for(d: Descriptor, stores: Mapping[tuple[str, str], Span]) -> dict[str, Span]:
    return {name: span for (memory_id, name), span in stores.items() if memory_id == d.memory_id and name != d.name}


# Dependency order - R75.


def order(plans: Mapping[str, tuple[str, _Plan]]) -> list[str]:
    """Kahn's algorithm with a min-heap on `name` (code-point order); a cycle is `dependency_cycle`."""
    preds: dict[str, set[str]] = {name: set() for name in plans}
    for name, (memory_id, plan) in plans.items():
        for other, (other_memory, other_plan) in plans.items():
            edge = any(_overlaps(i, o) for i in plan.inputs for o in other_plan.outputs)
            if other != name and other_memory == memory_id and edge:
                preds[name].add(other)
    succ: dict[str, list[str]] = {name: [] for name in plans}
    for name, before in preds.items():
        for other in before:
            succ[other].append(name)
    remaining = {name: len(before) for name, before in preds.items()}
    heap = [name for name, count in remaining.items() if count == 0]
    heapq.heapify(heap)
    out: list[str] = []
    while heap:
        name = heapq.heappop(heap)
        out.append(name)
        for after in succ[name]:
            remaining[after] -= 1
            if remaining[after] == 0:
                heapq.heappush(heap, after)
    _reject(len(out) == len(plans), "dependency_cycle", ",".join(sorted(set(plans) - set(out))))
    return out


# Static validation - R60-R75, R79.


def _check_mirror(d: MirrorDescriptor, size: int) -> None:
    source, dest = _span(d.mirror_block.source), _span(d.mirror_block.dest)
    _reject(source[0] < source[1] <= size and dest[1] <= size, "bad_range", d.name)
    _reject(not _overlaps(source, dest), "self_reference", d.name)


def _check_strategy(d: ChecksumDescriptor) -> None:
    if d.strategy == "recalculate":
        _reject(d.store is not None and d.target is None and d.compensate is None, "strategy_fields", d.name)
        return
    _reject(d.compensate is not None and (d.store is None) != (d.target is None), "strategy_fields", d.name)
    algorithm = d.algorithm
    supported = isinstance(algorithm, WordAlgorithm) and 8 * algorithm.word_size == width(algorithm)
    _reject(supported, "compensate_not_supported", d.name)


def _check_table(d: ChecksumDescriptor, table: Table, memory: LayoutMemory) -> None:
    span = _span(table.span)
    fits = all(item.at + item.size <= table.entry_size for item in (table.start, table.end))
    _reject(span[1] <= memory.size and fits, "bad_range", f"{d.name}: table bytes")
    protected = any(r.kind == "protected" and _inside(span, (r.start, r.end)) for r in memory.regions)
    _reject(protected, "table_not_protected", d.name)


def _check_checksum(d: ChecksumDescriptor, memory: LayoutMemory, by_name: Mapping[str, Descriptor]) -> None:
    algorithm = d.algorithm
    w = width(algorithm)
    if isinstance(algorithm, WordAlgorithm):
        _reject(8 * algorithm.word_size <= w, "bad_width", d.name)
    _reject(d.store is None or 8 * d.store.size == w, "bad_width", d.name)
    sources = [d.ranges is not None, d.ranges_from_table is not None, d.chain is not None]
    _reject(sources.count(True) == 1, "message_source", d.name)
    _check_strategy(d)
    _reject(d.store is None or d.store.span.end <= memory.size, "bad_range", f"{d.name}: store")
    for item in d.ranges or ():
        _reject(item.start < item.end <= memory.size, "bad_range", d.name)
    if d.ranges_from_table is not None:
        _check_table(d, d.ranges_from_table, memory)
    for name in d.chain or ():
        target = by_name.get(name)
        valid = (
            isinstance(target, ChecksumDescriptor)
            and target is not d
            and target.store is not None
            and target.memory_id == d.memory_id
        )
        _reject(valid, "unknown_chain_target", f"{d.name} -> {name}")


def _static_fields(region: ChecksumRegion) -> tuple[Span, ...]:
    if region.descriptor is not None:
        return tuple(_span(item) for item in output_fields(region.descriptor))
    return tuple(_span(item) for item in region.fields or ())


def _check_fields(regions: Sequence[ChecksumRegion], memories: Mapping[str, LayoutMemory]) -> None:
    """R73 and R74, over descriptor fields and the static fields of Python regions."""
    fields = [(region.memory_id, span, region.name) for region in regions for span in _static_fields(region)]
    for memory_id, span, name in fields:
        checksum = [(r.start, r.end) for r in memories[memory_id].regions if r.kind == "checksum"]
        _reject(any(_inside(span, c) for c in checksum), "field_out_of_checksum_region", f"{name} {span}")
    for index, (memory_id, span, name) in enumerate(fields):
        for other_memory, other, other_name in fields[index + 1 :]:
            clash = other_memory == memory_id and _overlaps(span, other)
            _reject(not clash, "field_overlap", f"{name}, {other_name}")
    for memory_id, memory in memories.items():
        checksum_bytes = {i for r in memory.regions if r.kind == "checksum" for i in range(r.start, r.end)}
        field_bytes = {i for m, span, _ in fields if m == memory_id for i in range(*span)}
        _reject(checksum_bytes == field_bytes, "unaccounted_checksum_bytes", memory_id)


def validate_variant(regions: Sequence[ChecksumRegion], layout: MemoryLayout) -> None:
    """R79: static validation of a variant against one layout; raises the first `DescriptorError` found."""
    memories = {memory.memory_id: memory for memory in layout.memories}
    names = [region.name for region in regions]
    _reject(len(set(names)) == len(names), "duplicate_name", ",".join(sorted(names)))
    by_name = {region.name: region.descriptor for region in regions if region.descriptor is not None}
    for region in regions:
        memory = memories.get(region.memory_id)
        if memory is None:
            raise DescriptorError("unknown_memory", f"{region.name}: {region.memory_id}")
        d = region.descriptor
        if isinstance(d, MirrorDescriptor):
            _check_mirror(d, memory.size)
        elif isinstance(d, ChecksumDescriptor):
            _check_checksum(d, memory, by_name)
        else:
            for item in (*(region.covered or ()), *(region.fields or ())):
                _reject(item.end <= memory.size, "bad_range", region.name)
    _check_fields(regions, memories)
    stores = chain_stores(list(by_name.values()))
    static = {
        name: (d.memory_id, _resolve(d, b"", None, _stores_for(d, stores)))
        for name, d in by_name.items()
        if isinstance(d, MirrorDescriptor) or d.ranges_from_table is None
    }
    order(static)


# Evaluation on a dump - R66, R76, R77.


def _memory(dump: Dump, layout: MemoryLayout, memory_id: str) -> Memory:
    # The layout validated against must describe this dump (R31); otherwise nothing is evaluated.
    described = {m.memory_id: (m.base_address, m.size) for m in layout.memories}
    actual = {m.memory_id: (m.base_address, len(m.data)) for m in dump.memories}
    require(described == actual, "bad_layout", "the layout does not describe the dump")
    return next(m for m in dump.memories if m.memory_id == memory_id)


def _encode(value: int, size: int, endianness: str) -> bytes:
    return value.to_bytes(size, "little" if endianness == "little" else "big")


def verify_descriptor(d: Descriptor, memory: Memory, stores: Mapping[tuple[str, str], Span]) -> RegionResult:
    """R77: one descriptor on the bytes as they are, with no recalculation."""
    data = memory.data
    if isinstance(d, MirrorDescriptor):
        (s, e), (ds, de) = _span(d.mirror_block.source), _span(d.mirror_block.dest)
        stored = _engines.digest(data[ds:de], f"{d.name} destination")
        computed = _engines.digest(data[s:e], f"{d.name} source")
        status: RegionStatus = "ok" if stored == computed else "fail"
        return RegionResult(d.name, d.memory_id, "recalculable", status, stored, computed, None, None)
    size = width(d.algorithm) // 8
    if d.store is not None:
        stored_bytes, endianness = data[d.store.offset : d.store.span.end], d.store.endianness
    else:
        stored_bytes, endianness = _encode(d.target or 0, size, "big"), "big"
    try:
        plan = _resolve(d, data, memory.base_address, _stores_for(d, stores))
    except DescriptorError as failure:
        # R66: a resolution failure is a `fail` with its reason, never an exception in verify.
        return RegionResult(d.name, d.memory_id, "recalculable", "fail", stored_bytes.hex(), None, failure.reason, None)
    value = _engines.value(d.algorithm, [data[s:e] for s, e in plan.pieces], d.name)
    computed_bytes = _encode(value, size, endianness)
    verdict: RegionStatus = "ok" if computed_bytes == stored_bytes else "fail"
    return RegionResult(
        d.name, d.memory_id, "recalculable", verdict, stored_bytes.hex(), computed_bytes.hex(), None, None
    )


def interpret_verify(regions: Sequence[ChecksumRegion], dump: Dump, layout: MemoryLayout) -> dict[str, RegionResult]:
    """The interpreter's `RegionResult` for every descriptor region, by name (R45, R77)."""
    validate_variant(regions, layout)
    descriptors = [region.descriptor for region in regions if region.descriptor is not None]
    stores = chain_stores(descriptors)
    return {d.name: verify_descriptor(d, _memory(dump, layout, d.memory_id), stores) for d in descriptors}


def _recalculate(d: ChecksumDescriptor, plan: _Plan, buffer: bytearray) -> None:
    algorithm = d.algorithm
    chunks = [bytes(buffer[s:e]) for s, e in plan.pieces]
    if d.strategy == "recalculate":
        store = cast("Field", d.store)
        value = _engines.value(algorithm, chunks, d.name)
        buffer[store.offset : store.span.end] = _encode(value, store.size, store.endianness)
        return
    # R70 and R71 were checked statically: recalculate has a store; compensate has a word algorithm with
    # 8 x word_size == W and a compensation offset.
    word = cast("WordAlgorithm", algorithm)
    compensate = cast("Compensate", d.compensate)
    if d.store is not None:
        goal = int.from_bytes(buffer[d.store.offset : d.store.span.end], d.store.endianness)
    else:
        goal = d.target or 0
    g = goal ^ word.xor_out
    c, size = compensate.offset, word.word_size
    current = int.from_bytes(buffer[c : c + size], word.endianness)
    modulus = 1 << width(word)

    def compensated(acc: int) -> int:
        return g ^ acc ^ current if word.name == "xor" else (g - acc + current) % modulus

    new = _engines.agree(
        compensated(_engines.words_a(word, chunks)), compensated(_engines.words_b(word, chunks)), f"{d.name} word"
    )
    buffer[c : c + size] = _encode(new, size, word.endianness)


def interpret_patches(regions: Sequence[ChecksumRegion], dump: Dump, layout: MemoryLayout) -> tuple[Patch, ...]:
    """R76: recalculate a copy in R75 order, then one patch per output field that changed."""
    validate_variant(regions, layout)
    if dump.dump_kind == "virtual":
        return ()
    descriptors = [region.descriptor for region in regions if region.descriptor is not None]
    stores = chain_stores(descriptors)
    memories = {d.memory_id: _memory(dump, layout, d.memory_id) for d in descriptors}
    # R65: tables are resolved once, on the dump; protected bytes never change on the copy.
    plans = {
        d.name: (
            d.memory_id,
            _resolve(d, memories[d.memory_id].data, memories[d.memory_id].base_address, _stores_for(d, stores)),
        )
        for d in descriptors
    }
    work = {memory_id: bytearray(memory.data) for memory_id, memory in memories.items()}
    for name in order(plans):
        memory_id, plan = plans[name]
        d = plan.descriptor
        buffer = work[memory_id]
        if isinstance(d, MirrorDescriptor):
            (s, e), (o, _) = plan.pieces[0], plan.outputs[0]
            buffer[o : o + e - s] = buffer[s:e]
        else:
            _recalculate(d, plan, buffer)
    patches: list[Patch] = []
    for memory_id, plan in plans.values():
        original = memories[memory_id].data
        for s, e in plan.outputs:
            if work[memory_id][s:e] != original[s:e]:
                patches.append(Patch(memory_id, s, e - s, original[s:e], bytes(work[memory_id][s:e])))
    return tuple(sorted(patches, key=patch_key))


def patch_key(patch: Patch) -> tuple[str, int]:
    return (patch.memory_id, patch.offset)
