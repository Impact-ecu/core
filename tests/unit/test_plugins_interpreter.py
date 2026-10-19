"""SPEC-002 §4 interpreter: every static and resolution reason, the two engines, R30-R33, R45, R55.

Synthetic data only (ADR-001 decision 2). The small variant lives in one 64-byte memory:
calibration [0, 16), checksum [16, 18), protected code [18, 48), protected block table [48, 64).
"""

from dataclasses import replace

import pytest

from core.kernel import Dump, LayoutMemory, Memory, MemoryLayout, Patch, Region
from core.plugins import (
    Addressing,
    Algorithm,
    Bypass,
    ChecksumDescriptor,
    ChecksumRegion,
    Compensate,
    Crc32,
    Descriptor,
    DescriptorError,
    EndIs,
    Field,
    Identification,
    InterpreterDivergence,
    MirrorBlock,
    MirrorDescriptor,
    PluginContractError,
    PresentMemory,
    Range,
    Reference,
    RegionResult,
    Table,
    TableField,
    WordAlgorithm,
    not_applicable,
)
from core.plugins.descriptor import (
    _engines,
    check_checksums,
    compare_patches,
    compare_verify,
    interpret_patches,
    interpret_verify,
    reference_result_usable,
    validate_variant,
)
from tests.unit.plugin_fixtures import (
    DESCRIPTORS,
    DUMP,
    IDENT,
    LAYOUT,
    ORIGINAL,
    REGIONS,
    FakePlugin,
    dump_of,
    edited,
    python_region,
    region_of,
    regions_of,
    report_of,
)

SUM16 = WordAlgorithm("sum16", 2, "big", 0, 0)
CRC = Crc32(0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, True, True)
BASE = 0x1000


def small_layout(checksum_end: int = 18, base: int | None = BASE, extra: tuple[LayoutMemory, ...] = ()) -> MemoryLayout:
    return MemoryLayout(
        (
            LayoutMemory(
                "pflash",
                base,
                64,
                (
                    Region("calibration", 0, 16, "maps"),
                    Region("checksum", 16, checksum_end, "sums"),
                    Region("protected", checksum_end, 48, "code"),
                    Region("protected", 48, 64, "block_table"),
                ),
            ),
            *extra,
        )
    )


EEPROM = LayoutMemory(
    "eeprom", 0, 8, (Region("calibration", 0, 4), Region("checksum", 4, 6), Region("protected", 6, 8))
)
LAYOUT_S = small_layout()


S = ChecksumDescriptor(
    1, "s", "pflash", SUM16, (Range(0, 16),), None, None, False, Field(16, 2, "big"), None, "recalculate", None
)


def tbl(offset: int = 48, count: int = 1, end_is: EndIs = "exclusive", addressing: Addressing = "offset") -> Table:
    return Table(offset, count, 4, TableField(0, 2, "big"), TableField(2, 2, "big"), end_is, addressing)


def mirror(name: str, source: Range, dest: int) -> MirrorDescriptor:
    return MirrorDescriptor(1, name, "pflash", MirrorBlock(source, dest))


def reason_of(descriptors: list[Descriptor], layout: MemoryLayout = LAYOUT_S) -> str:
    with pytest.raises(DescriptorError) as caught:
        validate_variant(regions_of(descriptors), layout)
    return caught.value.reason


def small_dump(data: bytes, base: int | None = BASE) -> Dump:
    return Dump("bench_full", (Memory("pflash", base, data),))


def with_table(*words: int, base: int | None = BASE) -> Dump:
    data = bytearray(64)
    data[48 : 48 + 2 * len(words)] = b"".join(w.to_bytes(2, "big") for w in words)
    return small_dump(bytes(data), base)


def ident_for(layout: MemoryLayout, variant: str | None = "v1") -> Identification:
    return Identification(
        "synthetic.fixture",
        None,
        None,
        None,
        variant,
        tuple(
            PresentMemory(m.memory_id, m.base_address, m.size)
            for m in sorted(layout.memories, key=lambda m: m.memory_id)
        ),
        (),
        (),
        (),
        700,
    )


def test_small_variant_is_valid() -> None:
    validate_variant(regions_of([S]), LAYOUT_S)


# SPEC-002 R61: word size above the width and a store of the wrong size.
@pytest.mark.parametrize(
    "descriptor",
    [
        replace(S, algorithm=WordAlgorithm("sum16", 4, "big", 0, 0)),
        replace(S, algorithm=CRC),
    ],
    ids=["word_size_above_width", "store_size"],
)
def test_bad_width(descriptor: Descriptor) -> None:
    assert reason_of([descriptor]) == "bad_width"


# SPEC-002 R63: exactly one message source.
@pytest.mark.parametrize(
    "descriptor",
    [replace(S, ranges=None), replace(S, ranges_from_table=tbl()), replace(S, chain=("x",))],
    ids=["none", "ranges_and_table", "ranges_and_chain"],
)
def test_message_source(descriptor: Descriptor) -> None:
    assert reason_of([descriptor]) == "message_source"


# SPEC-002 R70, R71: the strategy fields.
@pytest.mark.parametrize(
    "descriptor",
    [
        replace(S, store=None),
        replace(S, target=1),
        replace(S, compensate=Compensate(0)),
        replace(S, strategy="compensate", store=None, target=0),
        replace(S, strategy="compensate", target=0, compensate=Compensate(0)),
        replace(S, strategy="compensate", store=None, compensate=Compensate(0)),
    ],
    ids=["recalc_no_store", "recalc_target", "recalc_compensate", "comp_no_field", "comp_both_goals", "comp_no_goal"],
)
def test_strategy_fields(descriptor: Descriptor) -> None:
    assert reason_of([descriptor]) == "strategy_fields"


# SPEC-002 R71: CRC and sums whose word is narrower than W cannot be compensated; checked first.
@pytest.mark.parametrize("algorithm", [CRC, WordAlgorithm("sum32", 2, "big", 0, 0)], ids=["crc32", "sum32_word_size_2"])
def test_compensate_not_supported(algorithm: Algorithm) -> None:
    descriptor = replace(S, algorithm=algorithm, strategy="compensate", store=None, target=0, compensate=Compensate(16))
    assert reason_of([descriptor]) == "compensate_not_supported"


# SPEC-002 R64, R65, R72, R79: ranges, table bytes, table fields, stores, mirrors, Python coverage.
@pytest.mark.parametrize(
    ("descriptor", "detail"),
    [
        (replace(S, store=Field(63, 2, "big")), "store"),
        (replace(S, ranges=(Range(0, 65),)), "range beyond memory"),
        (replace(S, ranges=(Range(5, 5),)), "empty range"),
        (replace(S, ranges=None, ranges_from_table=tbl(offset=60, count=2)), "table beyond memory"),
        (
            replace(
                S,
                ranges=None,
                ranges_from_table=Table(
                    48, 1, 3, TableField(0, 2, "big"), TableField(2, 2, "big"), "exclusive", "offset"
                ),
            ),
            "table field beyond entry",
        ),
        (mirror("m", Range(0, 70), 18), "mirror source"),
        (mirror("m", Range(4, 4), 18), "mirror empty"),
        (mirror("m", Range(0, 8), 60), "mirror destination"),
    ],
    ids=lambda value: value if isinstance(value, str) else "",
)
def test_bad_range(descriptor: Descriptor, detail: str) -> None:
    assert reason_of([descriptor]) == "bad_range", detail


def test_bad_range_python_region() -> None:
    region = python_region("p", (Range(0, 70),), (Range(16, 18),), Reference("none", None, None))
    with pytest.raises(DescriptorError) as caught:
        validate_variant([region], LAYOUT_S)
    assert caught.value.reason == "bad_range"


# SPEC-002 R64: static ranges never overlap.
def test_overlapping_ranges_static() -> None:
    assert reason_of([replace(S, ranges=(Range(0, 8), Range(4, 12)))]) == "overlapping_ranges"


# SPEC-002 R65: the table lies in one protected region.
def test_table_not_protected() -> None:
    assert reason_of([replace(S, ranges=None, ranges_from_table=tbl(offset=0))]) == "table_not_protected"
    assert reason_of([replace(S, ranges=None, ranges_from_table=tbl(offset=44, count=2))]) == "table_not_protected"


# SPEC-002 R69: a chain names other checksum descriptors of the same memory with a store.
@pytest.mark.parametrize(
    ("extra", "chain"),
    [
        ([], ("missing",)),
        ([mirror("m", Range(0, 2), 18)], ("m",)),
        ([replace(S, name="t", strategy="compensate", store=None, target=0, compensate=Compensate(16))], ("t",)),
        ([replace(S, name="e", memory_id="eeprom", ranges=(Range(0, 4),), store=Field(4, 2, "big"))], ("e",)),
        ([], ("s",)),
    ],
    ids=["missing", "mirror", "no_store", "other_memory", "self"],
)
def test_unknown_chain_target(extra: list[Descriptor], chain: tuple[str, ...]) -> None:
    layout = small_layout(extra=(EEPROM,))
    descriptors: list[Descriptor] = [replace(S, ranges=None, chain=chain), *extra]
    assert reason_of(descriptors, layout) == "unknown_chain_target"


# SPEC-002 R68: self excision.
def test_partial_self() -> None:
    assert reason_of([replace(S, ranges=(Range(0, 17),), skip_self=True)]) == "partial_self"


@pytest.mark.parametrize(
    "descriptor",
    [
        replace(S, skip_self=True),
        replace(
            S,
            skip_self=True,
            strategy="compensate",
            store=None,
            target=0,
            ranges=(Range(0, 18),),
            compensate=Compensate(16),
        ),
    ],
    ids=["no_hit", "no_store"],
)
def test_skip_self_without_self(descriptor: Descriptor) -> None:
    assert reason_of([descriptor]) == "skip_self_without_self"


def test_self_reference() -> None:
    assert reason_of([replace(S, ranges=(Range(0, 18),))]) == "self_reference"
    assert reason_of([mirror("m", Range(0, 8), 4)]) == "self_reference"


# SPEC-002 R67: words never straddle pieces.
def test_misaligned_piece_static() -> None:
    assert reason_of([replace(S, ranges=(Range(0, 15),))]) == "misaligned_piece"


# SPEC-002 R71: the compensation word is inside one piece, at a word boundary.
@pytest.mark.parametrize(
    ("ranges", "offset"), [((Range(0, 16),), 16), ((Range(1, 19),), 16)], ids=["outside", "misaligned"]
)
def test_compensate_outside_message(ranges: tuple[Range, ...], offset: int) -> None:
    descriptor = replace(S, ranges=ranges, strategy="compensate", store=None, target=0, compensate=Compensate(offset))
    assert reason_of([descriptor]) == "compensate_outside_message"


# SPEC-002 R73, R74: output fields.
def test_field_out_of_checksum_region() -> None:
    assert reason_of([replace(S, ranges=(Range(2, 16),), store=Field(0, 2, "big"))]) == "field_out_of_checksum_region"


def test_field_overlap() -> None:
    assert reason_of([replace(S, name="a"), replace(S, name="b")]) == "field_overlap"


def test_unaccounted_checksum_bytes() -> None:
    assert reason_of([S], small_layout(checksum_end=20)) == "unaccounted_checksum_bytes"


# SPEC-002 R75: a static cycle.
def test_dependency_cycle_static() -> None:
    a = replace(S, name="a", ranges=(Range(0, 16), Range(18, 20)))
    b = replace(S, name="b", ranges=(Range(0, 16), Range(16, 18)), store=Field(18, 2, "big"))
    assert reason_of([a, b], small_layout(checksum_end=20)) == "dependency_cycle"


# SPEC-002 R79: names unique in the variant, memories known.
def test_duplicate_name_and_unknown_memory() -> None:
    assert reason_of([S, S]) == "duplicate_name"
    assert reason_of([replace(S, memory_id="dflash")]) == "unknown_memory"


# Resolution failures - SPEC-002 R65, R66: `fail` with a reason in verify, `DescriptorError` in patches.


def table_descriptor(table: Table, *, skip_self: bool = False) -> ChecksumDescriptor:
    return replace(S, ranges=None, ranges_from_table=table, skip_self=skip_self)


@pytest.mark.parametrize(
    ("descriptor", "dump", "reason"),
    [
        (table_descriptor(tbl(addressing="absolute")), with_table(BASE, BASE + 4, base=None), "unknown_base_address"),
        (table_descriptor(tbl(addressing="absolute")), with_table(BASE - 1, BASE + 4), "table_out_of_bounds"),
        (table_descriptor(tbl()), with_table(10, 4), "table_out_of_bounds"),
        (table_descriptor(tbl()), with_table(0, 100), "table_out_of_bounds"),
        (table_descriptor(tbl()), with_table(4, 4), "empty_range"),
        (table_descriptor(tbl(count=2)), with_table(0, 8, 4, 12), "overlapping_ranges"),
        (table_descriptor(tbl()), with_table(0, 15), "misaligned_piece"),
        (table_descriptor(tbl(), skip_self=True), with_table(0, 16), "skip_self_without_self"),
        (table_descriptor(tbl(), skip_self=True), with_table(0, 17), "partial_self"),
        (table_descriptor(tbl()), with_table(0, 18), "self_reference"),
        (
            replace(
                S,
                ranges=None,
                ranges_from_table=tbl(),
                strategy="compensate",
                store=None,
                target=0,
                compensate=Compensate(16),
            ),
            with_table(0, 16),
            "compensate_outside_message",
        ),
    ],
    ids=lambda value: value if isinstance(value, str) else "",
)
def test_resolution_failure(descriptor: ChecksumDescriptor, dump: Dump, reason: str) -> None:
    layout = small_layout(base=dump.memories[0].base_address)
    regions = regions_of([descriptor])
    validate_variant(regions, layout)
    result = interpret_verify(regions, dump, layout)["s"]
    assert (result.status, result.reason, result.computed) == ("fail", reason, None)
    assert result.stored == dump.memories[0].data[16:18].hex()
    with pytest.raises(DescriptorError) as caught:
        interpret_patches(regions, dump, layout)
    assert caught.value.reason == reason


# SPEC-002 R65: inclusive and length ends, offset and absolute addressing, all resolve to [0, 16).
@pytest.mark.parametrize(
    ("table", "words"),
    [
        (tbl(), (0, 16)),
        (tbl(end_is="inclusive"), (0, 15)),
        (tbl(end_is="length"), (0, 16)),
        (tbl(addressing="absolute"), (BASE, BASE + 16)),
        (tbl(end_is="inclusive", addressing="absolute"), (BASE, BASE + 15)),
        (tbl(end_is="length", addressing="absolute"), (BASE, 16)),
    ],
    ids=["exclusive", "inclusive", "length", "absolute", "absolute_inclusive", "absolute_length"],
)
def test_table_forms(table: Table, words: tuple[int, int]) -> None:
    dump = with_table(*words)
    data = bytearray(dump.memories[0].data)
    data[0:16] = bytes(range(1, 17))
    dump = small_dump(bytes(data))
    by_table = interpret_verify(regions_of([table_descriptor(table)]), dump, LAYOUT_S)["s"]
    by_ranges = interpret_verify(regions_of([S]), dump, LAYOUT_S)["s"]
    assert by_table == by_ranges
    assert (
        by_table.computed
        == sum(int.from_bytes(bytes(range(1, 17))[i : i + 2], "big") for i in range(0, 16, 2)).to_bytes(2, "big").hex()
    )


# SPEC-002 R75: a cycle that only appears once the table is resolved.
def test_dependency_cycle_at_resolution() -> None:
    a = replace(S, name="a", ranges=(Range(0, 16), Range(18, 20)))
    t = replace(S, name="t", ranges=None, ranges_from_table=tbl(), store=Field(18, 2, "big"))
    layout = small_layout(checksum_end=20)
    validate_variant(regions_of([a, t]), layout)
    with pytest.raises(DescriptorError) as caught:
        interpret_patches(regions_of([a, t]), with_table(0, 18), layout)
    assert caught.value.reason == "dependency_cycle"


# SPEC-002 R68: excision of the store from the range that holds it, other ranges kept in order.
def test_skip_self_keeps_other_ranges() -> None:
    d = replace(S, ranges=(Range(0, 8), Range(8, 18)), skip_self=True)
    data = bytes(range(64))
    got = interpret_verify(regions_of([d]), small_dump(data), LAYOUT_S)["s"]
    expected = sum(int.from_bytes(data[i : i + 2], "big") for i in range(0, 16, 2)) % 65536
    assert got.computed == expected.to_bytes(2, "big").hex()


# SPEC-002 R71: compensation with a stored goal (an input) and with xor.
@pytest.mark.parametrize(
    ("algorithm", "store", "target"),
    [
        (WordAlgorithm("sum16", 2, "little", 7, 0x1234), Field(18, 2, "big"), None),
        (WordAlgorithm("xor", 2, "big", 0, 0xFFFF), None, 0xBEEF),
    ],
    ids=["sum_store_goal", "xor_target"],
)
def test_compensate(algorithm: WordAlgorithm, store: Field | None, target: int | None) -> None:
    d = replace(
        S,
        algorithm=algorithm,
        ranges=(Range(0, 18),),
        store=store,
        target=target,
        strategy="compensate",
        compensate=Compensate(16),
    )
    data = bytes(range(10, 74))
    dump = small_dump(data)
    regions = regions_of([d])
    patches = interpret_patches(regions, dump, LAYOUT_S)
    assert [(p.offset, p.length) for p in patches] == [(16, 2)]
    released = small_dump(edited(data, 16, patches[0].after))
    result = interpret_verify(regions, released, LAYOUT_S)["s"]
    assert result.status == "ok"
    assert interpret_patches(regions, released, LAYOUT_S) == ()


# SPEC-002 R50 (interpreter side): nothing is derived for a virtual dump.
def test_virtual_dump_has_no_patches() -> None:
    edited_dump = dump_of(edited(ORIGINAL, 40, b"\x01\x02"), "virtual")
    assert interpret_patches(REGIONS, edited_dump, LAYOUT) == ()


# SPEC-002 R31: the layout validated against must describe the dump.
def test_layout_must_describe_the_dump() -> None:
    with pytest.raises(PluginContractError) as caught:
        interpret_verify(REGIONS, dump_of(ORIGINAL, base_address=0), LAYOUT)
    assert caught.value.reason == "bad_layout"


# SPEC-002 R81: a difference between the engines is `engine_divergence`, never a `fail`.
@pytest.mark.parametrize("engine", ["crc32_b", "words_b", "digest_b"])
def test_engine_divergence(engine: str, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken_crc(message: bytes, algorithm: Crc32) -> int:
        return _engines.crc32_a(message, algorithm) ^ 1

    def broken_words(algorithm: WordAlgorithm, pieces: list[bytes]) -> int:
        return _engines.words_a(algorithm, pieces) ^ 1

    def broken_digest(data: bytes) -> str:
        return _engines.digest_a(data[1:])

    replacement = {"crc32_b": broken_crc, "words_b": broken_words, "digest_b": broken_digest}[engine]
    monkeypatch.setattr(_engines, engine, replacement)
    with pytest.raises(InterpreterDivergence) as caught:
        interpret_verify(REGIONS, DUMP, LAYOUT)
    assert caught.value.reason == "engine_divergence"


def test_engine_divergence_in_compensation(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    honest = _engines.words_b

    def late(algorithm: WordAlgorithm, pieces: list[bytes]) -> int:
        calls.append(1)
        # Agree with engine A in `value`, disagree in the compensation of `a_comp` (the last one to run).
        return honest(algorithm, pieces) ^ (1 if algorithm.name == "sum32" and algorithm.endianness == "big" else 0)

    monkeypatch.setattr(_engines, "words_b", late)
    with pytest.raises(InterpreterDivergence):
        interpret_patches(REGIONS, dump_of(edited(ORIGINAL, 40, b"\x55")), LAYOUT)
    assert calls


# SPEC-002 R30-R33: checksums validation, with a Python region and an independent reference.

WIDE = MemoryLayout(
    (
        LayoutMemory(
            "pflash",
            0x8000_0000,
            512,
            (
                Region("protected", 0, 32, "boot"),
                Region("calibration", 32, 256, "maps"),
                Region("checksum", 256, 290, "checksums"),
                Region("protected", 290, 400, "code"),
                Region("protected", 400, 416, "block_table"),
                Region("protected", 416, 480, "emissions_egr"),
                Region("protected", 480, 512, "vin"),
            ),
        ),
    )
)
INDEPENDENT = Reference("independent", "ref-1", "someone else, repo x, commit y")
PY = python_region("p_python", (Range(300, 310),), (Range(288, 290),), INDEPENDENT)
WIDE_REGIONS = tuple(sorted((*REGIONS, PY), key=lambda r: (r.memory_id, r.name)))


def test_check_checksums_happy_path() -> None:
    # SPEC-002 R31, R33: static validation against the layout of the dump, Python region with a reference.
    assert check_checksums(list(WIDE_REGIONS), IDENT, WIDE) == WIDE_REGIONS
    no_checksum = MemoryLayout((LayoutMemory("pflash", 0x8000_0000, 512, (Region("protected", 0, 512),)),))
    assert check_checksums([], replace(IDENT, checksum_variant_id=None), no_checksum) == ()


@pytest.mark.parametrize(
    ("regions", "ident"),
    [
        (list(REGIONS), replace(IDENT, checksum_variant_id=None)),
        (
            [region_of(replace(DESCRIPTORS[0], memory_id="dflash"))],
            IDENT,
        ),
        (list(reversed(REGIONS)), IDENT),
    ],
    ids=["unknown_variant_with_regions", "absent_memory", "unsorted"],
)
def test_check_checksums_r30(regions: list[ChecksumRegion], ident: Identification) -> None:
    with pytest.raises(PluginContractError) as caught:
        check_checksums(regions, ident, LAYOUT)
    assert caught.value.reason == "r30"


# SPEC-002 R32: no dependency edge between Python and descriptor regions, in either direction.
@pytest.mark.parametrize(
    ("covered", "descriptor_ranges"),
    [((Range(16, 18),), (Range(0, 16),)), ((Range(0, 4),), (Range(0, 16), Range(18, 20)))],
    ids=["python_covers_descriptor_field", "descriptor_reads_python_field"],
)
def test_r32(covered: tuple[Range, ...], descriptor_ranges: tuple[Range, ...]) -> None:
    layout = small_layout(checksum_end=20, extra=(EEPROM,))
    regions = [
        region_of(replace(S, name="e", memory_id="eeprom", ranges=(Range(0, 4),), store=Field(4, 2, "big"))),
        python_region("p", covered, (Range(18, 20),), INDEPENDENT),
        region_of(replace(S, name="s", ranges=descriptor_ranges)),
    ]
    with pytest.raises(PluginContractError) as caught:
        check_checksums(regions, ident_for(layout), layout)
    assert caught.value.reason == "r32"


def test_r32_static_inputs_of_every_descriptor_form() -> None:
    # Mirror source, table bytes, chain stores and compensate stores are inputs (R75): none touches the
    # Python field [18, 20), so the variant passes.
    layout = MemoryLayout(
        (
            LayoutMemory(
                "pflash",
                BASE,
                64,
                (
                    Region("calibration", 0, 16),
                    Region("checksum", 16, 26),
                    Region("protected", 26, 48),
                    Region("protected", 48, 64),
                ),
            ),
        )
    )
    regions = [
        region_of(replace(S, name="a", ranges=(Range(0, 16),), store=Field(16, 2, "big"))),
        region_of(replace(S, name="b", ranges=None, chain=("a",), store=Field(20, 2, "big"))),
        region_of(replace(S, name="c", ranges=None, ranges_from_table=tbl(), store=Field(22, 2, "big"))),
        region_of(
            replace(
                S,
                name="d",
                ranges=(Range(0, 16), Range(24, 26)),
                store=Field(30, 2, "big"),
                strategy="compensate",
                compensate=Compensate(24),
            )
        ),
        region_of(mirror("e", Range(0, 2), 26)),
        python_region("p", (Range(32, 34),), (Range(18, 20),), INDEPENDENT),
    ]
    with pytest.raises(DescriptorError) as caught:
        check_checksums(regions, ident_for(layout), layout)
    assert caught.value.reason == "field_out_of_checksum_region"
    layout_ok = MemoryLayout(
        (
            LayoutMemory(
                "pflash",
                BASE,
                64,
                (
                    Region("calibration", 0, 16),
                    Region("checksum", 16, 28),
                    Region("protected", 28, 48),
                    Region("protected", 48, 64),
                ),
            ),
        )
    )
    checked = check_checksums(regions, ident_for(layout_ok), layout_ok)
    assert [r.name for r in checked] == ["a", "b", "c", "d", "e", "p"]


# SPEC-002 R34, R45: compare the plugin's verify with the interpreter and the independent RegionReference result.


def wide_dump() -> Dump:
    return dump_of(ORIGINAL)


def wide_report(independent: RegionResult) -> tuple[list[RegionResult], dict[str, RegionResult]]:
    results = interpret_verify(WIDE_REGIONS, wide_dump(), WIDE)
    return [*results.values(), independent], {PY.name: independent}


PY_OK = RegionResult("p_python", "pflash", "recalculable", "ok", "abcd", "abcd", None, None)


def test_compare_verify_agreement_and_disagreement() -> None:
    results, independent = wide_report(PY_OK)
    report = report_of({r.name: r for r in results})
    compare_verify(WIDE_REGIONS, report, wide_dump(), WIDE, independent)
    # A plugin may report `bypassed` where the reference says ok or fail (R44).
    bypassed = replace(results[0], status="bypassed", bypass=Bypass("pflash", 300, 310))
    compare_verify(
        WIDE_REGIONS, report_of({r.name: r for r in [bypassed, *results[1:]]}), wide_dump(), WIDE, independent
    )
    for wrong in (
        replace(results[0], stored="00000001"),
        replace(results[0], computed="00000001"),
        replace(results[0], status="fail"),
        replace(PY_OK, stored="abce"),
    ):
        changed = report_of({r.name: r for r in results} | {wrong.name: wrong})
        with pytest.raises(PluginContractError) as caught:
            compare_verify(WIDE_REGIONS, changed, wide_dump(), WIDE, independent)
        assert caught.value.reason == "plugin_disagreement"
        assert wrong.name in caught.value.detail


def test_compare_verify_missing_result_and_reason() -> None:
    results, independent = wide_report(PY_OK)
    missing = report_of({r.name: r for r in results if r.name != "e_crc"})
    with pytest.raises(PluginContractError):
        compare_verify(WIDE_REGIONS, missing, wide_dump(), WIDE, independent)
    with_reason = replace(PY_OK, status="fail", computed=None, reason="table_out_of_bounds")
    with pytest.raises(PluginContractError):
        compare_verify(
            WIDE_REGIONS,
            report_of({r.name: r for r in results} | {"p_python": with_reason}),
            wide_dump(),
            WIDE,
            independent,
        )


def test_compare_verify_skips_not_applicable() -> None:
    compare_verify(WIDE_REGIONS, not_applicable("virtual_dump"), dump_of(ORIGINAL, "virtual"), WIDE, {})


# SPEC-002 R55: byte-identical patches.
def test_compare_patches() -> None:
    dump = dump_of(edited(ORIGINAL, 40, b"\x99\x98"))
    ours = list(interpret_patches(REGIONS, dump, LAYOUT))
    python_patch = Patch("pflash", 288, 2, dump.memories[0].data[288:290], b"\x12\x34")
    compare_patches(WIDE_REGIONS, [*ours, python_patch], dump, WIDE, {PY.name: [python_patch]})
    compare_patches(WIDE_REGIONS, ours, dump, WIDE, {PY.name: []})
    for plugin, independent in (
        (ours[1:], [python_patch]),
        ([*ours, python_patch], []),
        (ours, [python_patch]),
    ):
        with pytest.raises(PluginContractError) as caught:
            compare_patches(WIDE_REGIONS, plugin, dump, WIDE, {PY.name: independent})
        assert caught.value.reason == "plugin_disagreement"


def test_compare_patches_virtual_and_none_reference() -> None:
    virtual = dump_of(ORIGINAL, "virtual")
    compare_patches(WIDE_REGIONS, [], virtual, WIDE, {PY.name: []})
    unchecked = python_region("p_python", (Range(300, 310),), (Range(288, 290),), Reference("none", None, None))
    regions = tuple(sorted((*REGIONS, unchecked), key=lambda r: r.name))
    stray = Patch("pflash", 288, 2, ORIGINAL[288:290], b"\x00\x01")
    compare_patches(regions, [stray], DUMP, WIDE, {})


# SPEC-002 R45: an independent reference returns ok or fail for this region only.
@pytest.mark.parametrize(
    ("result", "usable"),
    [
        (PY_OK, True),
        (replace(PY_OK, status="fail"), True),
        (replace(PY_OK, status="bypassed", bypass=Bypass("pflash", 300, 301)), False),
        (replace(PY_OK, name="other"), False),
        (replace(PY_OK, kind="signed", status="signature_unverifiable", stored=None, computed=None), False),
        ("ok", False),
    ],
    ids=["ok", "fail", "bypassed", "wrong_name", "wrong_kind", "not_a_result"],
)
def test_reference_result_usable(result: object, usable: bool) -> None:
    assert reference_result_usable(PY, result) is usable


# SPEC-002 R47, R80: the fake plugin uses the interpreter only because it is a test double.
def test_fake_plugin_agrees_with_the_interpreter() -> None:
    plugin = FakePlugin()
    report = plugin.verify(DUMP, IDENT)
    compare_verify(REGIONS, report, DUMP, LAYOUT, {})
    compare_patches(REGIONS, plugin.checksum_patches(DUMP, IDENT), DUMP, LAYOUT, {})
