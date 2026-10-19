"""SPEC-004 R24, R25, R31 integrity checks, independently of the release flow; R82 runtime assertions."""

import ast
from pathlib import Path

import pytest

import core.gate
from core.definitions import ByteRange
from core.gate import GateInvariantError
from core.gate._integrity import kernel_check, outside_checksum_unchanged, uncovered
from core.gate._model import Run, ensure, present
from core.kernel import Dump, LayoutMemory, Memory, MemoryLayout, Patch, Region
from tests.unit.fixtures import DUMP, LAYOUT, PFLASH, patch

TWO_CALIBRATIONS = MemoryLayout(
    (
        LayoutMemory(
            "pflash",
            0x8000_0000,
            32,
            (
                Region("protected", 0, 8, "boot"),
                Region("calibration", 8, 16, "a"),
                Region("calibration", 16, 24, "b"),
                Region("checksum", 24, 32, "crc"),
            ),
        ),
        LAYOUT.memories[1],
    )
)


def written(*patches: Patch, dump: Dump = DUMP) -> Dump:
    data = {m.memory_id: bytearray(m.data) for m in dump.memories}
    for p in patches:
        data[p.memory_id][p.offset : p.end] = p.after
    return Dump(
        dump.dump_kind, tuple(Memory(m.memory_id, m.base_address, bytes(data[m.memory_id])) for m in dump.memories)
    )


# SPEC-004 R24: a clean edit passes; protected and checksum regions are G-PROTECTED, with runs.
def test_kernel_check_containment() -> None:
    clean = patch(10, b"\x00\x00")
    assert kernel_check(DUMP, written(clean), LAYOUT, (clean,)).protected == ()
    assert kernel_check(DUMP, written(clean), LAYOUT, (clean,)).invariant is False
    boot, crc = patch(2, b"\xaa"), patch(23, b"\xbb\xbb")
    outcome = kernel_check(DUMP, written(boot, crc), LAYOUT, (crc, boot))
    assert outcome.protected == (Run("pflash", 2, 1), Run("pflash", 23, 2))
    assert outcome.invariant is False
    unknown = Patch("dflash", 0, 1, b"\x00", b"\x01")
    assert kernel_check(DUMP, DUMP, LAYOUT, (unknown,)).protected == (Run("dflash", 0, 1),)


# SPEC-004 R24: any other violation is a kernel bug (S1).
def test_kernel_check_invariants() -> None:
    across = patch(14, b"\x00\x00\x00\x00")
    assert kernel_check(DUMP, written(across), TWO_CALIBRATIONS, (across,)).invariant is True
    clean = patch(10, b"\x00")
    shorter = Dump("bench_full", (Memory("pflash", 0x8000_0000, PFLASH[:31]), DUMP.memories[1]))
    assert kernel_check(DUMP, shorter, LAYOUT, (clean,)).invariant is True
    before = written(clean, patch(9, b"\x77"))
    assert kernel_check(DUMP, before, LAYOUT, (clean,)).invariant is True
    after = written(clean, patch(20, b"\x77"))
    assert kernel_check(DUMP, after, LAYOUT, (clean,)).invariant is True
    other_memory = written(clean, Patch("eeprom", 6, 1, b"\xff", b"\x00"))
    assert kernel_check(DUMP, other_memory, LAYOUT, (clean,)).invariant is True


# SPEC-001 R41 re-asserted at R25.
def test_outside_checksum_unchanged() -> None:
    assert outside_checksum_unchanged(DUMP, written(patch(25, b"\x00")), LAYOUT) is True
    assert outside_checksum_unchanged(DUMP, written(patch(12, b"\x00")), LAYOUT) is False


# SPEC-004 R31: maximal runs of patch bytes in no resolved span, sorted by (memory_id, offset).
def test_uncovered() -> None:
    patches = (patch(8, b"\x00\x00\x00\x00"), patch(12, b"\x00\x00"), Patch("eeprom", 0, 2, b"\xff\xff", b"\x00\x00"))
    covered = (ByteRange("pflash", 9, 10), ByteRange("pflash", 10, 11), ByteRange("pflash", 20, 22))
    assert uncovered(patches, covered) == (
        Run("eeprom", 0, 2),
        Run("pflash", 8, 1),
        Run("pflash", 11, 3),
    )
    assert uncovered(patches[:1], (ByteRange("pflash", 0, 32),)) == ()


# SPEC-004 R82, SPEC-001 R73: runtime assertions raise, never return.
def test_runtime_assertions() -> None:
    ensure(True, "SPEC-004 R29")
    with pytest.raises(GateInvariantError) as error:
        ensure(False, "SPEC-004 R29")
    assert error.value.rule == "SPEC-004 R29"
    assert present(0, "R23") == 0
    with pytest.raises(GateInvariantError):
        present(None, "R23")


GATE = Path(core.gate.__file__).resolve().parent


def constructions(name: str) -> set[str]:
    found = set()
    for path in sorted(Path(GATE).parents[0].rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == name:
                found.add(str(path.relative_to(GATE.parent)))
    return found


# SPEC-004 R9, R29, SPEC-001 R9: one module constructs each sealed result, and both are in the gate.
def test_sealed_results_are_built_in_one_place() -> None:
    assert constructions("ReleasedImage") == {"gate/_release.py"}
    assert constructions("InputResult") == {"gate/_check.py"}
