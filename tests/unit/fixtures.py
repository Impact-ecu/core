"""A small synthetic dump and layout for unit tests: pflash = 32 bytes 00..1f, eeprom = 8 bytes ff."""

from core.kernel import Dump, LayoutMemory, Memory, MemoryLayout, Patch, Region, Version, image_hash, layout_hash

PFLASH = bytes(range(32))
EEPROM = b"\xff" * 8

DUMP = Dump(
    "bench_full",
    (Memory("pflash", 0x8000_0000, PFLASH), Memory("eeprom", 0x0, EEPROM)),
)
LAYOUT = MemoryLayout(
    (
        LayoutMemory(
            "pflash",
            0x8000_0000,
            32,
            (
                Region("protected", 0, 8, "boot"),
                Region("calibration", 8, 24, "maps"),
                Region("checksum", 24, 32, "crc"),
            ),
        ),
        LayoutMemory("eeprom", 0x0, 8, (Region("calibration", 0, 4, "adapt"), Region("protected", 4, 8, "immo"))),
    )
)


def patch(offset: int, after: bytes, memory_id: str = "pflash", current: bytes = PFLASH) -> Patch:
    return Patch(memory_id, offset, len(after), current[offset : offset + len(after)], after)


def version(*patches: Patch, overlaps: tuple[tuple[str, str], ...] = (), dump: Dump = DUMP) -> Version:
    return Version(image_hash(dump), layout_hash(LAYOUT), patches, overlaps)
