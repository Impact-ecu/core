"""SPEC-003 R1, R30, R35, R52, R56, R57 as properties. Oracles: rfc8785 + hashlib for hashes, a per-byte
set for spans, and a test-side application of the returned patches for edits."""

import hashlib
import json
from dataclasses import dataclass, replace
from fractions import Fraction

import rfc8785
from hypothesis import given
from hypothesis import strategies as st

from core.definitions import (
    AxisDef,
    Definition,
    DefinitionError,
    InlineAxis,
    License,
    MapDef,
    Origin,
    SharedAxis,
    SoftwareVersion,
    decode,
    decode_cell,
    definition_from_json,
    definition_hash,
    definition_json,
    encode,
    span,
)
from core.definitions._bind import cell_index
from core.kernel import Dump, Memory
from tests.properties.definition_strategies import names, rationals, xdf_definitions, xdf_mapdefs

MEMORY_SIZE = 512


# SPEC-003 R1, R50, R52: the JSON form round-trips and the hash is sha256 of its JCS (third-party rfc8785).
@given(xdf_definitions())
def test_json_round_trip_and_hash(definition: Definition) -> None:
    value = definition_json(definition)
    assert definition_from_json(json.loads(rfc8785.dumps(value))) == definition
    assert definition_hash(definition) == hashlib.sha256(rfc8785.dumps(value)).hexdigest()


# SPEC-003 R35: input order never changes the definition or its hash.
@given(xdf_definitions(), st.data())
def test_order_independence(definition: Definition, data: st.DataObject) -> None:
    shuffled = data.draw(st.permutations(definition.mapdefs))
    again = replace(definition, mapdefs=tuple(shuffled))
    assert again == definition
    assert definition_hash(again) == definition_hash(definition)


@dataclass(frozen=True)
class Scenario:
    definition: Definition
    dump: Dump


@st.composite
def scenarios(draw: st.DrawFn) -> Scenario:
    """Maps over a random `cal` memory; when the first has an inline x axis, maps may share it."""
    first = draw(xdf_mapdefs(0, MEMORY_SIZE))
    mapdefs: list[MapDef] = [first]
    axes: tuple[AxisDef, ...] = ()
    if isinstance(first.x, InlineAxis) and draw(st.booleans()):
        axes = (AxisDef("syn.shared", draw(names), first.x),)
        mapdefs = [replace(first, x=SharedAxis("syn.shared"))]
        second = draw(xdf_mapdefs(1, MEMORY_SIZE))
        if second.cols == first.cols:
            mapdefs.append(replace(second, x=SharedAxis("syn.shared")))
    definition = Definition(
        "synthetic.test",
        SoftwareVersion("exact", ("SYN0001",)),
        axes,
        tuple(mapdefs),
        Origin("platform", ()),
        License("platform_created", None),
        0,
    )
    data = draw(st.binary(min_size=MEMORY_SIZE, max_size=MEMORY_SIZE))
    return Scenario(definition, Dump("virtual", (Memory("cal", 0x1000, data),)))


def naive_span(mapdef: MapDef, definition: Definition) -> list[tuple[str, int, int]]:
    """Every byte as a set, then maximal runs: an oracle that shares no code with `span`."""
    used = set(range(mapdef.offset, mapdef.offset + mapdef.rows * mapdef.cols * mapdef.dtype.size))
    for ref in (mapdef.x, mapdef.y):
        axis = (
            next((a.axis for a in definition.axes if a.axis_id == ref.axis_id), None)
            if isinstance(ref, SharedAxis)
            else ref
        )
        if isinstance(axis, InlineAxis):
            used |= set(range(axis.offset, axis.offset + axis.count * axis.dtype.size))
    runs: list[tuple[str, int, int]] = []
    for byte in sorted(used):
        if runs and runs[-1][2] == byte:
            runs[-1] = ("cal", runs[-1][1], byte + 1)
        else:
            runs.append(("cal", byte, byte + 1))
    return runs


# SPEC-003 R30: sorted, merged and exactly the bytes the map depends on, shared axes included.
@given(scenarios())
def test_span_is_every_byte_the_map_reads(s: Scenario) -> None:
    for mapdef in s.definition.mapdefs:
        got = [(r.memory_id, r.start, r.end) for r in span(mapdef, s.definition, s.dump)]
        assert got == naive_span(mapdef, s.definition)


# SPEC-003 R15, R57: encoding the decoded values changes nothing, so no patch is produced.
@given(scenarios())
def test_encoding_the_current_values_is_a_no_op(s: Scenario) -> None:
    for mapdef in s.definition.mapdefs:
        decoded = decode(mapdef, s.definition, s.dump)
        targets = {
            (r, c): value
            for r, row in enumerate(decoded.cells)
            for c, value in enumerate(row)
            if isinstance(value, Fraction)
        }
        assert encode(mapdef, s.dump, targets) == ()


# SPEC-003 R13, R14, R57: patches are maximal runs whose `before` is the current bytes; applied, they
# put each target within half a step and leave every other cell's bytes untouched.
@given(scenarios(), st.data())
def test_edits_become_minimal_patches(s: Scenario, data: st.DataObject) -> None:
    mapdef = s.definition.mapdefs[0]
    cells = [(r, c) for r in range(mapdef.rows) for c in range(mapdef.cols)]
    chosen = data.draw(st.lists(st.sampled_from(cells), unique=True, max_size=len(cells)))
    targets = {cell: data.draw(rationals(10**4, 16)) for cell in chosen}
    try:
        patches = encode(mapdef, s.dump, targets)
    except DefinitionError as error:
        reason: str | None = error.reason
    else:
        reason = None
    if reason is not None:
        assert reason == "out_of_range"
        return
    current = s.dump.memories[0].data
    updated = bytearray(current)
    previous_end = -1
    for patch in patches:
        assert patch.memory_id == "cal"
        assert patch.offset > previous_end
        assert current[patch.offset : patch.end] == patch.before
        updated[patch.offset : patch.end] = patch.after
        previous_end = patch.end
    size = mapdef.dtype.size
    for r, c in cells:
        start = mapdef.offset + cell_index(mapdef, r, c) * size
        cell = bytes(updated[start : start + size])
        if (r, c) not in targets:
            assert cell == current[start : start + size]
            continue
        value = decode_cell(mapdef.dtype, mapdef.scaling, cell)
        assert isinstance(value, Fraction)
        if mapdef.dtype.kind != "float":
            assert 2 * abs(value - targets[(r, c)]) <= abs(mapdef.scaling.factor)
    outside = [i for i in range(len(current)) if not mapdef.offset <= i < mapdef.offset + mapdef.cell_bytes]
    assert all(updated[i] == current[i] for i in outside)
