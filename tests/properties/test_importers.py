"""SPEC-006 properties: R14 determinism, R29 raw output, R32 random negatives and prefixes, R33 fuzz.

Under the `ci` profile the counts are the spec's: 10,000 random byte strings (R32) and 100,000 fuzz
inputs (R33); other properties take the profile's floor. Every byte is synthetic.
"""

import hashlib

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from core.conformance import check_determinism, check_fuzz_input, check_negative, check_prefixes
from core.importers import RAW_IMPORTER, Imported, ImportParams, ImportRejected, dispatch, outcome_jcs, run_import
from core.kernel import DumpKind
from tests.properties.strategies import DUMP_KIND_VALUES
from tests.unit.importer_fakes import MAGIC, SynthImporter, encode_synth

SYNTH = SynthImporter()


def spec_count(count: int) -> settings:
    """The spec's count under the PR profile (>= 2,000 examples); the profile's own count otherwise."""
    floor = settings.default.max_examples if settings.default is not None else 100
    return settings(max_examples=count if floor >= 2000 else floor)


memory_ids = st.from_regex(r"[a-z][a-z0-9_]{0,31}", fullmatch=True)
tools = st.none() | st.from_regex(r"[A-Za-z0-9][A-Za-z0-9 ._+-]{0,63}", fullmatch=True)
raw_params = st.builds(
    ImportParams, st.sampled_from(DUMP_KIND_VALUES), tools, st.builds(lambda m: {"memory_id": m}, memory_ids)
)
json_leaf = st.none() | st.booleans() | st.integers(-5, 2**53 + 5) | st.text(max_size=8) | st.floats(width=16)
json_values = st.recursive(
    json_leaf,
    lambda inner: st.lists(inner, max_size=3) | st.dictionaries(st.text(max_size=4), inner, max_size=3),
    max_leaves=8,
)
any_params = st.builds(
    ImportParams,
    st.sampled_from((*DUMP_KIND_VALUES, "full", "")),
    tools | st.text(max_size=70),
    st.dictionaries(st.text(max_size=10), json_values, max_size=3) | st.just({"memory_id": "pflash"}),
)
memories = st.lists(
    st.tuples(memory_ids, st.none() | st.integers(0, 2**32 - 1), st.binary(min_size=1, max_size=64)),
    min_size=1,
    max_size=4,
    unique_by=lambda memory: memory[0],
)


@st.composite
def containers(draw: st.DrawFn) -> tuple[bytes, ImportParams]:
    kind = draw(st.sampled_from(DUMP_KIND_VALUES))
    read_mode = draw(st.sampled_from((0, DUMP_KIND_VALUES.index(kind) + 1)))
    return encode_synth(draw(memories), read_mode=read_mode), ImportParams(kind, draw(tools), {})


@st.composite
def mutated(draw: st.DrawFn) -> bytes:
    data = bytearray(draw(containers())[0])
    for _ in range(draw(st.integers(1, 4))):
        operation = draw(st.sampled_from(("flip", "cut", "insert", "trailer")))
        position = draw(st.integers(0, len(data)))
        if operation == "flip" and position < len(data):
            data[position] ^= draw(st.integers(1, 255))
        elif operation == "cut":
            del data[position:]
        elif operation == "insert":
            data[position:position] = draw(st.binary(min_size=1, max_size=8))
        else:
            body = bytes(data[:-32])
            data[-32:] = hashlib.sha256(body).digest()
    return bytes(data)


# SPEC-006 R14, R110: same importer, data and params give a JCS-identical outcome, however often called.
@given(st.binary(max_size=256), any_params)
def test_raw_determinism(data: bytes, params: ImportParams) -> None:
    assert outcome_jcs(_outcome(data, params)) == outcome_jcs(_outcome(bytes(data), params))


def _outcome(data: bytes, params: ImportParams) -> Imported | ImportRejected:
    return run_import(RAW_IMPORTER, data, params)


# SPEC-006 R14, R33: two orders, identical outcomes, for valid and broken containers alike.
@given(st.lists(containers(), min_size=1, max_size=4), st.lists(mutated(), max_size=3))
def test_synth_determinism_two_orders(valid: list[tuple[bytes, ImportParams]], broken: list[bytes]) -> None:
    cases = valid + [(data, ImportParams("bench_full", None, {})) for data in broken]
    assert check_determinism(SYNTH, cases) == []


# SPEC-006 R29: the raw importer returns one memory, the bytes unchanged, base_address null; nothing else.
@given(st.binary(min_size=1, max_size=512), raw_params)
def test_raw_output(data: bytes, params: ImportParams) -> None:
    outcome = run_import(RAW_IMPORTER, data, params)
    assert isinstance(outcome, Imported)
    (memory,) = outcome.dump.memories
    assert (outcome.dump.dump_kind, memory.memory_id, memory.base_address, memory.data) == (
        params.dump_kind,
        params.options["memory_id"],
        None,
        data,
    )
    assert outcome.record.input_sha256 == hashlib.sha256(data).hexdigest()


# SPEC-006 R15, R11: a valid container imports every memory as stored, with the caller's dump_kind.
@given(memories, st.sampled_from(DUMP_KIND_VALUES))
def test_synth_roundtrip(stored: list[tuple[str, int | None, bytes]], kind: DumpKind) -> None:
    outcome = run_import(SYNTH, encode_synth(stored), ImportParams(kind, None, {}))
    assert isinstance(outcome, Imported)
    assert [(m.memory_id, m.base_address, m.data) for m in outcome.dump.memories] == stored
    assert outcome.dump.dump_kind == kind


# SPEC-006 R32: random byte strings are unsupported_container (10,000 per PR run).
@spec_count(10_000)
@given(st.binary(max_size=512))
def test_random_bytes_are_unsupported(data: bytes) -> None:
    assume(not data.startswith(MAGIC))
    assert check_negative(SYNTH, data, ImportParams("bench_full", None, {})) == []
    assert dispatch([SYNTH, RAW_IMPORTER], data, ImportParams("bench_full", None, {})) == ImportRejected(
        "unsupported_container", None
    )


# SPEC-006 R32: every strict prefix of a positive sample gives a rejection, never a Dump.
@given(containers(), st.integers(0, 2**32))
def test_prefixes_rejected(sample: tuple[bytes, ImportParams], seed: int) -> None:
    data, params = sample
    assert check_prefixes(SYNTH, data, params, seed) == []


FUZZ_SHARDS = 10


# SPEC-006 R12, R33: random and mutated inputs never raise and never exceed R16 (100,000 per PR run,
# in FUZZ_SHARDS independent shards so a parallel run is not bound by one test).
@pytest.mark.parametrize("shard", range(FUZZ_SHARDS))
@spec_count(100_000 // FUZZ_SHARDS)
@given(st.binary(max_size=128) | mutated() | st.builds(lambda c: c[0], containers()), any_params)
def test_fuzz_never_raises(shard: int, data: bytes, params: ImportParams) -> None:
    assert 0 <= shard < FUZZ_SHARDS
    assert check_fuzz_input(SYNTH, data, params) == []
    assert check_fuzz_input(RAW_IMPORTER, data, params) == []
