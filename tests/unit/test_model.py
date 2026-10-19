"""Construction-time validation of the data shapes (SPEC-001 §2): every rejection and its reason."""

import dataclasses
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import pytest

from core.kernel import (
    Dump,
    KernelError,
    LayoutError,
    LayoutMemory,
    Memory,
    MemoryLayout,
    Patch,
    Region,
    ShapeError,
    Version,
)
from core.kernel._model import DUMP_KINDS, REGION_KINDS
from tests.properties.strategies import DUMP_KIND_VALUES, REGION_KIND_VALUES
from tests.unit.fixtures import DUMP, PFLASH, patch

M1 = (Memory("pflash", 0, b"\x00"), Memory("pflash", 1, b"\x01"))
R01 = (Region("protected", 0, 1),)
LM = LayoutMemory("m", 0, 1, R01)
# A stand-in that would pass duck typing but never went through Patch validation (R10-R12).
FORGED = SimpleNamespace(memory_id="pflash", offset=8, length=0, before=b"", after=b"", patch_hash="forged")

CASES: list[tuple[str, type[KernelError], str, Callable[..., object], tuple[Any, ...]]] = [
    # SPEC-001 R1
    ("bad memory id", ShapeError, "bad_memory_id", Memory, ("PFlash", 0, b"\x00")),
    ("memory id too long", ShapeError, "bad_memory_id", Memory, ("m" * 33, 0, b"\x00")),
    ("memory id with newline", ShapeError, "bad_memory_id", Memory, ("pflash\n", 0, b"\x00")),
    ("memory id not a string", ShapeError, "bad_memory_id", Memory, (7, 0, b"\x00")),
    ("negative base address", ShapeError, "bad_integer", Memory, ("pflash", -1, b"\x00")),
    ("base address above 2**53 - 1", ShapeError, "bad_integer", Memory, ("pflash", 2**53, b"\x00")),
    ("boolean base address", ShapeError, "bad_integer", Memory, ("pflash", True, b"\x00")),
    ("mutable data", ShapeError, "bad_type", Memory, ("pflash", 0, bytearray(b"\x00"))),
    ("empty data", ShapeError, "empty_memory", Memory, ("pflash", 0, b"")),
    ("unknown dump kind", ShapeError, "bad_dump_kind", Dump, ("full", DUMP.memories)),
    ("memories as a list", ShapeError, "bad_type", Dump, ("bench_full", list(DUMP.memories))),
    ("no memory", ShapeError, "empty_dump", Dump, ("bench_full", ())),
    ("memory not a Memory", ShapeError, "bad_type", Dump, ("bench_full", (object(),))),
    ("duplicate memory id", ShapeError, "duplicate_memory", Dump, ("bench_full", M1)),
    # SPEC-001 R4, R6
    ("unknown region kind", LayoutError, "bad_region_kind", Region, ("emissions", 0, 1)),
    ("negative region start", LayoutError, "bad_integer", Region, ("protected", -1, 1)),
    ("region end not an int", LayoutError, "bad_integer", Region, ("protected", 0, "8")),
    ("empty region", LayoutError, "bad_cover", Region, ("protected", 4, 4)),
    ("inverted region", LayoutError, "bad_cover", Region, ("protected", 5, 4)),
    ("lone surrogate in name", LayoutError, "bad_region_name", Region, ("protected", 0, 1, "\ud800")),
    ("name not a string", LayoutError, "bad_region_name", Region, ("protected", 0, 1, None)),
    ("layout memory id", LayoutError, "bad_memory_id", LayoutMemory, ("9", 0, 1, R01)),
    ("layout base address", LayoutError, "bad_integer", LayoutMemory, ("m", -5, 1, R01)),
    ("layout size", LayoutError, "bad_integer", LayoutMemory, ("m", 0, -1, ())),
    ("regions as a list", LayoutError, "bad_type", LayoutMemory, ("m", 0, 1, list(R01))),
    ("region not a Region", LayoutError, "bad_type", LayoutMemory, ("m", 0, 1, (object(),))),
    ("layout memory not a LayoutMemory", LayoutError, "bad_type", MemoryLayout, ((object(),),)),
    ("no regions", LayoutError, "bad_cover", LayoutMemory, ("m", 0, 0, ())),
    ("gap at start", LayoutError, "bad_cover", LayoutMemory, ("m", 0, 2, (Region("protected", 1, 2),))),
    (
        "overlap",
        LayoutError,
        "bad_cover",
        LayoutMemory,
        ("m", 0, 4, (Region("protected", 0, 3), Region("calibration", 2, 4))),
    ),
    (
        "unsorted",
        LayoutError,
        "bad_cover",
        LayoutMemory,
        ("m", 0, 4, (Region("protected", 2, 4), Region("calibration", 0, 2))),
    ),
    ("short of size", LayoutError, "bad_cover", LayoutMemory, ("m", 0, 4, (Region("protected", 0, 3),))),
    ("past size", LayoutError, "bad_cover", LayoutMemory, ("m", 0, 2, (Region("protected", 0, 3),))),
    ("layout memories as a list", LayoutError, "bad_type", MemoryLayout, ([],)),
    ("duplicate layout memory", LayoutError, "duplicate_memory", MemoryLayout, ((LM, LM),)),
    # SPEC-001 R10, R12
    ("patch memory id", ShapeError, "bad_memory_id", Patch, ("", 0, 1, b"\x00", b"\x01")),
    ("negative offset", ShapeError, "bad_integer", Patch, ("m", -1, 1, b"\x00", b"\x01")),
    ("length not an int", ShapeError, "bad_integer", Patch, ("m", 0, 1.0, b"\x00", b"\x01")),
    ("before not bytes", ShapeError, "bad_type", Patch, ("m", 0, 1, "0", b"\x01")),
    ("after not bytes", ShapeError, "bad_type", Patch, ("m", 0, 1, b"\x00", bytearray(b"\x01"))),
    ("zero length", ShapeError, "bad_length", Patch, ("m", 0, 0, b"", b"")),
    ("before shorter", ShapeError, "bad_length", Patch, ("m", 0, 2, b"\x00", b"\x01\x02")),
    ("after shorter", ShapeError, "bad_length", Patch, ("m", 0, 2, b"\x00\x01", b"\x01")),
    ("no-op", ShapeError, "noop_patch", Patch, ("m", 0, 2, b"\x00\x01", b"\x00\x01")),
    # SPEC-001 §2.4
    ("patches as a list", ShapeError, "bad_type", Version, ("a", "b", [])),
    ("patch not a Patch", ShapeError, "bad_type", Version, ("a", "b", (FORGED,))),
    ("overlaps as a list", ShapeError, "bad_type", Version, ("a", "b", (), [])),
    ("overlap pair as a list", ShapeError, "bad_type", Version, ("a", "b", (), (["x", "y"],))),
    ("overlap triple", ShapeError, "bad_type", Version, ("a", "b", (), (("x", "y", "z"),))),
]


@pytest.mark.parametrize(("label", "error", "reason", "build", "args"), CASES, ids=[case[0] for case in CASES])
def test_invalid_shapes_are_rejected(
    label: str, error: type[KernelError], reason: str, build: Callable[..., object], args: tuple[Any, ...]
) -> None:
    with pytest.raises(error) as caught:
        build(*args)
    assert caught.value.reason == reason, label


# SPEC-001 R3, R6: the runtime sets are exactly the Literal types.
def test_kind_sets_match_the_spec() -> None:
    assert set(DUMP_KIND_VALUES) == DUMP_KINDS == {"bench_full", "boot_full", "obd_full", "obd_partial", "virtual"}
    assert set(REGION_KIND_VALUES) == REGION_KINDS == {"calibration", "checksum", "protected"}


# SPEC-001 R2: a dump or layout with an unknown base address is valid and hashable (null is hashed as null).
def test_unknown_base_address_is_valid_data() -> None:
    dump = Dump("obd_partial", (Memory("pflash", None, b"\x01"),))
    assert dump.memories[0].base_address is None
    layout = MemoryLayout((LayoutMemory("pflash", None, 1, (Region("calibration", 0, 1),)),))
    assert layout.memories[0].base_address is None


# SPEC-001 R11: a patch is immutable and identified by its hash.
def test_patch_is_immutable_and_identified_by_hash() -> None:
    a = patch(8, b"\xaa")
    b = patch(8, b"\xaa")
    assert a == b
    assert a.patch_hash == b.patch_hash
    assert hash(a) == hash(b)
    assert a.end == 9
    name = "offset"
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(a, name, 9)
    assert patch(8, b"\xab").patch_hash != a.patch_hash


# SPEC-001 R13: no operation inserts or deletes; a patch cannot change a length.
def test_patch_has_no_resizing_form() -> None:
    field_names = {f.name for f in dataclasses.fields(Patch)}
    assert field_names == {"memory_id", "offset", "length", "before", "after", "patch_hash"}
    with pytest.raises(ShapeError):
        Patch("pflash", 8, 1, PFLASH[8:9], b"\x00\x00")


def test_data_shapes_are_frozen() -> None:
    for value, name in ((DUMP, "dump_kind"), (DUMP.memories[0], "data")):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(value, name, None)
