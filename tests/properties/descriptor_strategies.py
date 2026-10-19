"""Hypothesis strategies for SPEC-002 descriptors, algorithms and messages. Synthetic values only."""

from hypothesis import strategies as st

from core.plugins import (
    Algorithm,
    ChecksumDescriptor,
    Compensate,
    Crc32,
    Descriptor,
    Endianness,
    Field,
    MirrorBlock,
    MirrorDescriptor,
    Range,
    Table,
    TableField,
    WordAlgorithm,
    WordName,
    width,
)

U32 = st.integers(0, 2**32 - 1)
ENDS: tuple[Endianness, ...] = ("little", "big")
WORD_NAMES: tuple[WordName, ...] = ("sum16", "sum32", "xor")
ENDIANNESS = st.sampled_from(ENDS)
NAMES = st.sampled_from(["a", "b", "c", "d", "e", "f", "z_x"])
SMALL = st.integers(0, 600)

crc32s = st.builds(Crc32, U32, U32, U32, st.booleans(), st.booleans())


@st.composite
def word_algorithms(draw: st.DrawFn) -> WordAlgorithm:
    name = draw(st.sampled_from(WORD_NAMES))
    word_size = draw(st.sampled_from([1, 2] if name == "sum16" else [1, 2, 4]))
    bits = 16 if name == "sum16" else 32 if name == "sum32" else 8 * word_size
    limit = (1 << bits) - 1
    return WordAlgorithm(name, word_size, draw(ENDIANNESS), draw(st.integers(0, limit)), draw(st.integers(0, limit)))


algorithms: st.SearchStrategy[Algorithm] = st.one_of(crc32s, word_algorithms())


@st.composite
def aligned_pieces(draw: st.DrawFn, algorithm: Algorithm) -> list[bytes]:
    """Message pieces whose lengths are multiples of the word size (R67)."""
    size = algorithm.word_size if isinstance(algorithm, WordAlgorithm) else 1
    count = draw(st.integers(0, 4))
    return [draw(st.binary(max_size=40).map(lambda b: b[: len(b) - len(b) % size])) for _ in range(count)]


ranges = st.builds(Range, SMALL, SMALL)
fields = st.builds(Field, SMALL, st.sampled_from([1, 2, 4]), ENDIANNESS)
table_fields = st.builds(TableField, st.integers(0, 8), st.sampled_from([1, 2, 4]), ENDIANNESS)
tables = st.builds(
    Table,
    SMALL,
    st.integers(0, 4),
    st.integers(0, 16),
    table_fields,
    table_fields,
    st.sampled_from(["exclusive", "inclusive", "length"]),
    st.sampled_from(["offset", "absolute"]),
)


@st.composite
def checksum_descriptors(draw: st.DrawFn) -> ChecksumDescriptor:
    algorithm = draw(algorithms)
    source = draw(st.sampled_from(["ranges", "table", "chain", "none"]))
    chain = tuple(draw(st.lists(NAMES, max_size=3))) if source == "chain" else None
    target = draw(st.none() | st.integers(0, (1 << width(algorithm)) - 1))
    return ChecksumDescriptor(
        1,
        draw(NAMES),
        draw(st.sampled_from(["pflash", "pflash", "eeprom"])),
        algorithm,
        tuple(draw(st.lists(ranges, max_size=3))) if source == "ranges" else None,
        draw(tables) if source == "table" else None,
        chain,
        False if chain is not None else draw(st.booleans()),
        draw(st.none() | fields),
        target,
        draw(st.sampled_from(["recalculate", "compensate"])),
        draw(st.none() | st.builds(Compensate, SMALL)),
    )


mirror_descriptors = st.builds(
    MirrorDescriptor, st.just(1), NAMES, st.just("pflash"), st.builds(MirrorBlock, ranges, SMALL)
)
descriptors: st.SearchStrategy[Descriptor] = st.one_of(checksum_descriptors(), mirror_descriptors)
