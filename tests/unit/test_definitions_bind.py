"""SPEC-003 R7, R13-R15, R22, R30, R55-R58: cells, span, decode and edits against a synthetic dump."""

from dataclasses import replace
from fractions import Fraction
from typing import Any, cast

import pytest

from core.definitions import (
    NON_FINITE,
    ByteRange,
    DefinitionError,
    DefinitionInvariantError,
    Dtype,
    MapDef,
    Scaling,
    SharedAxis,
    decode,
    encode,
    encode_axis,
    encode_cell,
    span,
)
from core.definitions._cells import decode_raw, physical_to_raw, round_half_even
from core.definitions._errors import ensure
from core.kernel import Dump, Memory, Patch
from tests.unit.definitions_fixtures import (
    AXIS_DEF,
    CAL,
    DUMP,
    F32BE,
    FIXED3,
    I8,
    IDENTITY,
    INLINE,
    POINTER,
    SCALAR,
    SHARED_MAP,
    TABLE,
    U8,
    U16BE,
    U16LE,
    U32LE,
    definition,
)

F = Fraction
DEFINITION = definition(
    SCALAR, TABLE, SHARED_MAP, replace(SCALAR, map_id="syn.ptr", offset=20, cols=4, x=POINTER), axes=(AXIS_DEF,)
)


def _map(map_id: str) -> MapDef:
    return next(m for m in DEFINITION.mapdefs if m.map_id == map_id)


# SPEC-003 R122: a failed runtime assertion is an invariant error, never a DefinitionError.
def test_ensure() -> None:
    ensure(True, "R0")
    with pytest.raises(DefinitionInvariantError) as caught:
        ensure(False, "SPEC-003 R7")
    assert caught.value.rule == "SPEC-003 R7"
    assert not isinstance(caught.value, DefinitionError)


# SPEC-003 R7: a cell of the wrong length is a caller bug.
def test_decode_raw_checks_the_length() -> None:
    with pytest.raises(DefinitionInvariantError):
        decode_raw(U16BE, b"\x00")


# SPEC-003 R13: half to even at both parities and for negative values.
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (F(1, 2), 0),
        (F(3, 2), 2),
        (F(5, 2), 2),
        (F(-1, 2), 0),
        (F(-3, 2), -2),
        (F(7, 3), 2),
        (F(-7, 3), -2),
        (F(8, 3), 3),
    ],
)
def test_round_half_even(value: Fraction, expected: int) -> None:
    assert round_half_even(value) == expected


# SPEC-003 R13: integer kinds are never clamped.
@pytest.mark.parametrize(
    ("dtype", "target"), [(U8, F(-1)), (U8, F(511, 2)), (I8, F(128)), (U16BE, F(65536)), (U32LE, F(2**32))]
)
def test_out_of_range(dtype: Dtype, target: Fraction) -> None:
    with pytest.raises(DefinitionError) as caught:
        physical_to_raw(dtype, IDENTITY, target)
    assert caught.value.reason == "out_of_range"


# SPEC-003 R13, R15: zero is +0; a non-finite current cell is re-encoded; equal bytes are kept.
def test_encode_cell_edges() -> None:
    assert encode_cell(F32BE, IDENTITY, F(0), None) == b"\x00\x00\x00\x00"
    assert encode_cell(F32BE, IDENTITY, F(1), bytes.fromhex("7fc00000")) == bytes.fromhex("3f800000")
    assert encode_cell(U16LE, IDENTITY, F(1), b"\x01\x00") == b"\x01\x00"
    assert encode_cell(U16LE, IDENTITY, F(2), b"\x01\x00") == b"\x02\x00"
    assert encode_cell(F32BE, Scaling(F(-1, 2), F(0)), F(3, 4), None) == bytes.fromhex("bfc00000")
    with pytest.raises(DefinitionError) as caught:
        encode_cell(F32BE, IDENTITY, F(-(2**128)), None)
    assert caught.value.reason == "out_of_range"


# SPEC-003 R30 (vector S1 style): cells, inline, shared and pointer axes, sorted and merged.
def test_span() -> None:
    assert span(SCALAR, DEFINITION, DUMP) == (ByteRange("cal", 0, 1),)
    assert span(TABLE, DEFINITION, DUMP) == (ByteRange("cal", 8, 20), ByteRange("cal", 32, 36))
    assert span(_map("syn.shared"), DEFINITION, DUMP) == (ByteRange("cal", 32, 36), ByteRange("cal", 40, 44))
    assert span(_map("syn.ptr"), DEFINITION, DUMP) == (ByteRange("cal", 16, 24), ByteRange("pflash", 0, 4))


def _dump(
    cal: bytes = CAL, pflash: bytes = bytes.fromhex("80001010") + bytes(12), base: int | None = 0x8000_1000
) -> Dump:
    return Dump("virtual", (Memory("cal", base, cal), Memory("pflash", 0x8000_0000, pflash)))


# SPEC-003 R22, R55: binding failures, with their reasons.
@pytest.mark.parametrize(
    ("label", "mapdef", "dump", "reason"),
    [
        ("map memory absent", replace(SCALAR, memory_id="eeprom"), DUMP, "unknown_memory"),
        ("cells past the end", replace(SCALAR, offset=64), DUMP, "out_of_memory"),
        ("inline axis memory absent", replace(TABLE, x=replace(INLINE, memory_id="eeprom")), DUMP, "unknown_memory"),
        ("inline axis past the end", replace(TABLE, x=replace(INLINE, offset=61)), DUMP, "out_of_memory"),
        (
            "pointer cell past the end",
            replace(SCALAR, cols=4, x=replace(POINTER, pointer_offset=13)),
            DUMP,
            "out_of_memory",
        ),
        (
            "pointer target absent",
            replace(SCALAR, cols=4, x=replace(POINTER, target_memory_id="dflash")),
            DUMP,
            "unknown_memory",
        ),
        ("no base address", replace(SCALAR, cols=4, x=POINTER), _dump(base=None), "unknown_base_address"),
        ("pointer below base", replace(SCALAR, cols=4, x=POINTER), _dump(pflash=bytes(16)), "out_of_memory"),
        (
            "pointer target past end",
            replace(SCALAR, cols=4, x=POINTER),
            _dump(pflash=bytes.fromhex("8000103e") + bytes(12)),
            "out_of_memory",
        ),
    ],
)
def test_binding_errors(label: str, mapdef: MapDef, dump: Dump, reason: str) -> None:
    value = definition(mapdef)
    for operation in (span, decode):
        with pytest.raises(DefinitionError) as caught:
            operation(mapdef, value, dump)
        assert caught.value.reason == reason, label


# SPEC-003 R22: a little-endian 16-bit pointer resolves the same way.
def test_little_endian_pointer() -> None:
    axis = replace(POINTER, pointer_dtype=U16LE, pointer_offset=4)
    pflash = bytes(4) + bytes.fromhex("1810") + bytes(10)
    mapdef = replace(SCALAR, cols=4, x=axis)
    dump = Dump("virtual", (Memory("cal", 0x1000, CAL), Memory("pflash", 0, pflash)))
    assert span(mapdef, definition(mapdef), dump) == (
        ByteRange("cal", 0, 4),
        ByteRange("cal", 24, 28),
        ByteRange("pflash", 4, 6),
    )


# SPEC-003 R8, R56: rows outer, x_fastest and y_fastest, every axis source, physical units.
def test_decode() -> None:
    table = decode(TABLE, DEFINITION, DUMP)
    assert table.cells[0] == (F(8), F(9), F(10), F(11))
    assert table.cells[2] == (F(16), F(17), F(18), F(19))
    assert table.x == (F(800), F(825), F(850), F(875))
    assert table.y == FIXED3.values
    transposed = decode(replace(TABLE, cell_order="y_fastest"), DEFINITION, DUMP)
    assert transposed.cells[0] == (F(8), F(11), F(14), F(17))
    assert transposed.cells[1] == (F(9), F(12), F(15), F(18))
    assert decode(_map("syn.shared"), DEFINITION, DUMP).x == table.x
    assert decode(_map("syn.ptr"), DEFINITION, DUMP).x == (F(16), F(17), F(18), F(19))
    scalar = decode(SCALAR, DEFINITION, DUMP)
    assert (scalar.cells, scalar.x, scalar.y) == (((F(0),),), None, None)


# SPEC-003 R7, R56: a binary32 infinity or NaN cell decodes to non_finite.
def test_decode_non_finite() -> None:
    mapdef = replace(SCALAR, dtype=F32BE, cols=2)
    dump = Dump("virtual", (Memory("cal", None, bytes.fromhex("7f800000ffc00001")),))
    assert decode(mapdef, definition(mapdef), dump).cells == ((NON_FINITE, NON_FINITE),)


# SPEC-003 R57: one patch per maximal run of differing bytes, in offset order; empty when nothing changes.
def test_encode_runs() -> None:
    patches = encode(TABLE, DUMP, {(0, 0): F(255), (0, 1): F(254), (2, 3): F(0)})
    assert patches == (Patch("cal", 8, 2, CAL[8:10], b"\xff\xfe"), Patch("cal", 19, 1, CAL[19:20], b"\x00"))
    assert encode(TABLE, DUMP, {(1, 1): F(13)}) == ()
    assert encode(TABLE, DUMP, {}) == ()
    transposed = replace(TABLE, cell_order="y_fastest")
    assert encode(transposed, DUMP, {(1, 0): F(0)}) == (Patch("cal", 9, 1, CAL[9:10], b"\x00"),)


# SPEC-003 R57: targets are (row, col) inside the map with a Fraction value.
@pytest.mark.parametrize(
    "targets",
    [{(3, 0): F(1)}, {(0, 4): F(1)}, {(-1, 0): F(1)}, {(True, 0): F(1)}, {(0, 0): 1}, {(0, 0): "1"}],
    ids=["row", "col", "negative", "boolean", "int value", "text value"],
)
def test_encode_bad_targets(targets: dict[tuple[int, int], Any]) -> None:
    with pytest.raises(DefinitionError) as caught:
        encode(TABLE, DUMP, cast(Any, targets))
    assert caught.value.reason == "bad_shape"


def test_encode_errors() -> None:
    with pytest.raises(DefinitionError) as caught:
        encode(TABLE, DUMP, {(0, 0): F(256)})
    assert caught.value.reason == "out_of_range"
    with pytest.raises(DefinitionError) as caught:
        encode(replace(TABLE, memory_id="eeprom"), DUMP, {})
    assert caught.value.reason == "unknown_memory"


# SPEC-003 R58: axis edits patch the breakpoint span; shared axes go through their AxisDef; fixed have no bytes.
def test_encode_axis() -> None:
    assert encode_axis(INLINE, DUMP, {1: F(0)}) == (Patch("cal", 33, 1, CAL[33:34], b"\x00"),)
    assert encode_axis(AXIS_DEF.axis, DUMP, {0: F(800)}) == ()
    assert encode_axis(POINTER, DUMP, {3: F(0)}) == (Patch("cal", 19, 1, CAL[19:20], b"\x00"),)
    for axis in (SharedAxis("syn.axis"), FIXED3):
        with pytest.raises(DefinitionError) as caught:
            encode_axis(axis, DUMP, {})
        assert caught.value.reason == "bad_shape"
    with pytest.raises(DefinitionError) as caught:
        encode_axis(INLINE, DUMP, {4: F(0)})
    assert caught.value.reason == "bad_shape"
