"""SPEC-006 §3: importer contract, run_import, dispatch, raw importer and every rejection and error reason."""

import hashlib
from collections.abc import Callable, Mapping
from typing import Any, cast

import pytest
import rfc8785

from core.importers import (
    MAX_INPUT_BYTES,
    MAX_MEMORIES,
    RAW_IMPORTER,
    Imported,
    Importer,
    ImporterContractError,
    ImportParams,
    ImportRejected,
    dispatch,
    jcs,
    outcome_jcs,
    run_import,
)
from core.importers._json import FrozenObject, NotJsonError, freeze_json
from core.importers._raw import ensure
from core.kernel import Dump, KernelError, KernelInvariantError, Memory
from tests.unit.importer_fakes import ScriptedImporter, SynthImporter, encode_synth

RAW = ImportParams("bench_full", None, {"memory_id": "pflash"})
SYNTH = ImportParams("bench_full", "Synthetic Reader 1.0", {})
CONTAINER = encode_synth([("pflash", 0x8000_0000, b"\x01\x02\x03"), ("eeprom", None, b"\xff\xff")])


def thaw(value: object) -> object:
    """Plain dicts and lists, for the third-party rfc8785 encoder."""
    if isinstance(value, Mapping):
        return {key: thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw(item) for item in value]
    return value


def scripted(result: object, **identity: object) -> ScriptedImporter:
    fields = cast(dict[str, Any], identity)
    return ScriptedImporter(lambda _data, _params: cast(Dump | ImportRejected, result), **fields)


def raising(error: Exception) -> ScriptedImporter:
    def behavior(_data: bytes, _params: ImportParams) -> Dump:
        raise error

    return ScriptedImporter(behavior)


def contract_error(importer: Importer, data: bytes = b"\x00", params: ImportParams = RAW) -> str:
    with pytest.raises(ImporterContractError) as info:
        run_import(importer, data, params)
    assert not isinstance(info.value, KernelError)  # SPEC-006 R111
    return info.value.reason


def rejection(outcome: Imported | ImportRejected) -> tuple[str, str | None]:
    assert isinstance(outcome, ImportRejected)
    return (outcome.reason, outcome.container_kind)


# --- run_import: parameters (R11, R20, R22) ---------------------------------------------------------------


# SPEC-006 R11, R20, R22: every malformed parameter is bad_params with no container, before the importer runs.
@pytest.mark.parametrize(
    "params",
    [
        cast(ImportParams, {"dump_kind": "bench_full", "source_tool": None, "options": {}}),
        ImportParams(cast(Any, "full"), None, {"memory_id": "pflash"}),
        ImportParams("bench_full", "", {"memory_id": "pflash"}),
        ImportParams("bench_full", " leading space", {"memory_id": "pflash"}),
        ImportParams("bench_full", "x" * 65, {"memory_id": "pflash"}),
        ImportParams("bench_full", "Tool/1.0", {"memory_id": "pflash"}),
        ImportParams("bench_full", cast(Any, 7), {"memory_id": "pflash"}),
        ImportParams("bench_full", None, cast(Any, [("memory_id", "pflash")])),
        ImportParams("bench_full", None, cast(Any, "pflash")),
        ImportParams("bench_full", None, {"memory_id": "pflash", "scale": cast(Any, 0.5)}),
        ImportParams("bench_full", None, {"memory_id": "pflash", "offset": -1}),
        ImportParams("bench_full", None, {"memory_id": "pflash", "big": 2**53}),
        ImportParams("bench_full", None, {"memory_id": "pflash", "blob": cast(Any, b"\x00")}),
        ImportParams("bench_full", None, {"memory_id": "pflash", "name": "\ud800"}),
        ImportParams("bench_full", None, {"memory_id": "pflash", "ç": 1}),
        ImportParams("bench_full", None, cast(Any, {1: "pflash"})),
        ImportParams("bench_full", None, {"nested": [{"deep": cast(Any, 1.5)}]}),
    ],
)
def test_bad_params_never_reach_the_importer(params: ImportParams) -> None:
    importer = scripted(Dump("bench_full", (Memory("pflash", None, b"\x00"),)))
    assert rejection(run_import(importer, b"\x00", params)) == ("bad_params", None)
    assert importer.calls == []


# SPEC-006 R22: a source tool is a tool name and version.
@pytest.mark.parametrize("tool", ["A", "Synthetic Reader 1.0", "x+y_z-2.0", "a" * 64])
def test_valid_source_tool(tool: str) -> None:
    outcome = run_import(RAW_IMPORTER, b"\x00", ImportParams("bench_full", tool, {"memory_id": "pflash"}))
    assert isinstance(outcome, Imported)
    assert outcome.record.source_tool == tool


# SPEC-006 R11, R20: options are frozen JCS values; the record holds them as given and later edits cannot reach it.
def test_options_are_copied_and_frozen() -> None:
    options: dict[str, Any] = {"flag": True, "list": [1, "a", None, False], "obj": {"k": 0}}
    seen: list[ImportParams] = []

    def behavior(data: bytes, params: ImportParams) -> Dump:
        seen.append(params)
        return Dump(params.dump_kind, (Memory("pflash", None, data),))

    outcome = run_import(ScriptedImporter(behavior), b"\x01", ImportParams("virtual", None, options))
    options["flag"] = False
    options["list"].append(9)
    assert isinstance(outcome, Imported)
    assert isinstance(seen[0].options, FrozenObject)
    assert outcome.record.options == {"flag": True, "list": (1, "a", None, False), "obj": {"k": 0}}
    assert jcs(outcome.record.to_json()) == rfc8785.dumps(cast(Any, thaw(outcome.record.to_json())))
    with pytest.raises(TypeError):
        cast(Any, outcome.record.options)["flag"] = False


# SPEC-006 R17, R20: the input is the bytes of one file.
def test_data_must_be_bytes() -> None:
    with pytest.raises(TypeError):
        run_import(RAW_IMPORTER, cast(bytes, bytearray(b"\x00")), RAW)


# --- run_import: limits (R16) -----------------------------------------------------------------------------


# SPEC-006 R16, R20: too_large is checked before the importer is called.
def test_too_large_before_the_importer() -> None:
    importer = scripted(ImportRejected("malformed", None))
    assert rejection(run_import(importer, bytes(MAX_INPUT_BYTES + 1), RAW)) == ("too_large", None)
    assert importer.calls == []


# SPEC-006 R16: more than MAX_MEMORIES memories is limit_exceeded.
def test_too_many_memories() -> None:
    memories = tuple(Memory(f"m{i}", None, b"\x00") for i in range(MAX_MEMORIES + 1))
    importer = scripted(Dump("bench_full", memories))
    assert rejection(run_import(importer, b"\x00", RAW)) == ("limit_exceeded", "scripted")
    at_limit = scripted(Dump("bench_full", memories[:MAX_MEMORIES]))
    assert isinstance(run_import(at_limit, b"\x00", RAW), Imported)


# SPEC-006 R16: memories totalling more than MAX_INPUT_BYTES is limit_exceeded (decompression can grow a file).
def test_memories_total_too_large() -> None:
    half = bytes(MAX_INPUT_BYTES // 2 + 1)
    importer = scripted(Dump("bench_full", (Memory("a", None, half), Memory("b", None, half))))
    assert rejection(run_import(importer, b"\x00", RAW)) == ("limit_exceeded", "scripted")


# --- run_import: contract errors (R12, R35, R111) ---------------------------------------------------------


# SPEC-006 R12: an exception from import_file is importer_exception.
@pytest.mark.parametrize("error", [ValueError("x"), KeyError("k"), RecursionError(), TypeError()])
def test_importer_exception(error: Exception) -> None:
    assert contract_error(raising(error)) == "importer_exception"


# SPEC-006 R12: reading the importer's identity must not raise either.
def test_identity_raising_is_importer_exception() -> None:
    class Broken:
        version = "1.0.0"
        contract_version = 1
        container_kind = "broken"

        @property
        def importer_id(self) -> str:
            raise RuntimeError

        def import_file(self, data: bytes, params: ImportParams) -> Dump | ImportRejected:
            raise AssertionError((data, params))

    assert contract_error(cast(Importer, Broken())) == "importer_exception"


# SPEC-006 R12: any return value other than a Dump or an ImportRejected is bad_return.
@pytest.mark.parametrize("value", [None, True, False, b"\x00", {"dump_kind": "bench_full"}, 0])
def test_bad_return_type(value: object) -> None:
    assert contract_error(scripted(value)) == "bad_return"


# SPEC-006 R10, R12, R25: an importer never returns ambiguous_container, an unknown reason or another container.
@pytest.mark.parametrize(
    "value",
    [
        ImportRejected("ambiguous_container", None),
        ImportRejected(cast(Any, "nope"), None),
        ImportRejected("malformed", "other"),
        ImportRejected("unsupported_container", "scripted"),
    ],
)
def test_bad_rejection(value: ImportRejected) -> None:
    assert contract_error(scripted(value)) == "bad_return"


# SPEC-006 R12: an ImportRejected with unset fields is bad_return.
def test_uninitialized_rejection() -> None:
    assert contract_error(scripted(object.__new__(ImportRejected))) == "bad_return"


# SPEC-006 R10: valid rejections pass through, naming the importer's container or none.
@pytest.mark.parametrize(
    "value",
    [
        ImportRejected("unsupported_container", None),
        ImportRejected("malformed", "scripted"),
        ImportRejected("malformed", None),
        ImportRejected("too_large", None),
    ],
)
def test_valid_rejection(value: ImportRejected) -> None:
    assert run_import(scripted(value), b"\x00", RAW) == value


# SPEC-006 R12, R35: a malformed identity is refused before the importer runs.
@pytest.mark.parametrize(
    ("identity", "reason"),
    [
        ({"contract_version": 2}, "contract_version"),
        ({"contract_version": cast(Any, True)}, "contract_version"),
        ({"contract_version": 0}, "contract_version"),
        ({"importer_id": "raw"}, "bad_return"),
        ({"importer_id": "Impact.raw"}, "bad_return"),
        ({"version": "1.0"}, "bad_return"),
        ({"version": "01.0.0"}, "bad_return"),
        ({"version": cast(Any, 1)}, "bad_return"),
        ({"container_kind": "Raw"}, "bad_return"),
        ({"container_kind": "x" * 33}, "bad_return"),
    ],
)
def test_bad_identity(identity: dict[str, Any], reason: str) -> None:
    importer = scripted(ImportRejected("malformed", None), **identity)
    assert contract_error(importer) == reason
    assert importer.calls == []


def _tampered(attribute: str, value: object, target: str = "dump") -> Dump:
    dump = Dump("bench_full", (Memory("pflash", None, b"\x00"),))
    obj: object = dump if target == "dump" else dump.memories[0]
    object.__setattr__(obj, attribute, value)
    return dump


# SPEC-006 R12, R15: a Dump violating SPEC-001 R1 or §2.1 formats, or overriding dump_kind, is bad_dump.
@pytest.mark.parametrize(
    "build",
    [
        lambda: _tampered("memories", ()),
        lambda: _tampered("memories", None),
        lambda: _tampered("dump_kind", "full"),
        lambda: _tampered("memories", (Memory("a", None, b"\x00"), Memory("a", None, b"\x01"))),
        lambda: _tampered("memory_id", "PFlash", "memory"),
        lambda: _tampered("data", b"", "memory"),
        lambda: _tampered("data", bytearray(b"\x00"), "memory"),
        lambda: _tampered("base_address", -1, "memory"),
        lambda: object.__new__(Dump),
        lambda: Dump("virtual", (Memory("pflash", None, b"\x00"),)),
    ],
)
def test_bad_dump(build: Callable[[], Dump]) -> None:
    assert contract_error(scripted(build())) == "bad_dump"


# SPEC-006 R20: the record is built by run_import, never taken from the importer.
def test_record_is_built_by_run_import() -> None:
    data = b"\x10\x20"
    outcome = run_import(RAW_IMPORTER, data, ImportParams("obd_full", "T 1", {"memory_id": "dflash"}))
    assert isinstance(outcome, Imported)
    record = outcome.record
    assert record.schema == "impact.import-record.v1"
    assert record.input_sha256 == hashlib.sha256(data).hexdigest()
    assert (record.importer_id, record.container_kind, record.dump_kind) == ("impact.raw", "raw", "obd_full")
    assert outcome.import_record_hash == hashlib.sha256(rfc8785.dumps(cast(Any, thaw(record.to_json())))).hexdigest()


# --- raw importer (R26-R29) ------------------------------------------------------------------------------


# SPEC-006 R28: memory_id exactly, no defaults, SPEC-001 §2.1 format.
@pytest.mark.parametrize(
    "options",
    [{}, {"memory_id": "pflash", "x": 1}, {"memory_id": 1}, {"memory_id": "1flash"}, {"memory_id": "a" * 33}],
)
def test_raw_bad_options(options: dict[str, Any]) -> None:
    assert rejection(run_import(RAW_IMPORTER, b"\x00", ImportParams("bench_full", None, options))) == (
        "bad_params",
        "raw",
    )


# SPEC-006 R12, R28: called directly with an invalid dump_kind, the raw importer still does not raise.
def test_raw_direct_call_bad_dump_kind() -> None:
    result = RAW_IMPORTER.import_file(b"\x00", ImportParams(cast(Any, "full"), None, {"memory_id": "pflash"}))
    assert result == ImportRejected("bad_params", "raw")


# SPEC-006 R29, SPEC-001 R1: empty data is empty_input.
def test_raw_empty_input() -> None:
    assert rejection(run_import(RAW_IMPORTER, b"", RAW)) == ("empty_input", "raw")


# SPEC-006 R29: one memory, bytes unchanged (the same object), base_address null.
def test_raw_output() -> None:
    data = bytes(range(256))
    outcome = run_import(RAW_IMPORTER, data, RAW)
    assert isinstance(outcome, Imported)
    (memory,) = outcome.dump.memories
    assert (memory.memory_id, memory.base_address, memory.data) == ("pflash", None, data)


# SPEC-006 R112: the R29 runtime assertion aborts with an invariant error, not a rejection.
def test_runtime_assertion() -> None:
    ensure(True, "SPEC-006 R29")
    with pytest.raises(KernelInvariantError, match="SPEC-006 R29"):
        ensure(False, "SPEC-006 R29")


# --- synthetic container: R13, R15 through a real importer ------------------------------------------------


# SPEC-006 R15: several memories give one Dump; base_address only where the container records it.
def test_container_with_several_memories() -> None:
    outcome = run_import(SynthImporter(), CONTAINER, SYNTH)
    assert isinstance(outcome, Imported)
    assert [(m.memory_id, m.base_address, m.data) for m in outcome.dump.memories] == [
        ("pflash", 0x8000_0000, b"\x01\x02\x03"),
        ("eeprom", None, b"\xff\xff"),
    ]


# SPEC-006 R11, R13: encrypted, malformed, conflicting read mode, foreign file.
@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"random bytes", ("unsupported_container", None)),
        (encode_synth([("pflash", None, b"\x01")], encrypted=True), ("encrypted_container", "synth")),
        (CONTAINER[:-1], ("malformed", "synth")),
        (CONTAINER[:-32] + bytes(32), ("malformed", "synth")),
        (encode_synth([("pflash", None, b"\x01"), ("pflash", None, b"\x02")]), ("malformed", "synth")),
        (encode_synth([]), ("malformed", "synth")),
        (encode_synth([("pflash", None, b"\x01")], read_mode=3), ("dump_kind_conflict", "synth")),
    ],
)
def test_container_rejections(data: bytes, expected: tuple[str, str | None]) -> None:
    assert rejection(run_import(SynthImporter(), data, SYNTH)) == expected


# --- dispatch (R25, R26) ---------------------------------------------------------------------------------


class OtherSynth(SynthImporter):
    importer_id = "test.zsynth"


# SPEC-006 R25: exactly one importer recognizes the file: its outcome is the result.
def test_dispatch_single_recognizer() -> None:
    importers: list[Importer] = [scripted(ImportRejected("unsupported_container", None)), SynthImporter()]
    outcome = dispatch(importers, CONTAINER, SYNTH)
    assert isinstance(outcome, Imported)
    assert outcome.record.importer_id == "test.synth"
    encrypted = encode_synth([("pflash", None, b"\x01")], encrypted=True)
    assert rejection(dispatch(importers, encrypted, SYNTH)) == ("encrypted_container", "synth")


# SPEC-006 R25: nobody recognizes the file.
def test_dispatch_none() -> None:
    assert rejection(dispatch([SynthImporter()], b"random", SYNTH)) == ("unsupported_container", None)
    assert rejection(dispatch([], b"random", SYNTH)) == ("unsupported_container", None)


# SPEC-006 R25: two recognizers are ambiguous even when one imports; never resolved by priority.
def test_dispatch_ambiguous() -> None:
    importers: list[Importer] = [scripted(ImportRejected("malformed", "scripted")), SynthImporter()]
    assert rejection(dispatch(importers, CONTAINER, SYNTH)) == ("ambiguous_container", None)
    assert rejection(dispatch([OtherSynth(), SynthImporter()], CONTAINER, SYNTH)) == ("ambiguous_container", None)


# SPEC-006 R25: run in importer_id order, whatever the registration order.
def test_dispatch_order() -> None:
    order: list[str] = []

    def recorder(name: str) -> ScriptedImporter:
        def behavior(_data: bytes, _params: ImportParams) -> ImportRejected:
            order.append(name)
            return ImportRejected("unsupported_container", None)

        return ScriptedImporter(behavior, importer_id=name)

    dispatch([recorder("test.c"), recorder("test.a"), recorder("test.b")], b"\x00", RAW)
    assert order == ["test.a", "test.b", "test.c"]


# SPEC-006 R26: the raw importer is never chosen by dispatch, even when it is registered.
def test_dispatch_never_uses_raw() -> None:
    assert rejection(dispatch([RAW_IMPORTER], b"\x00", RAW)) == ("unsupported_container", None)
    assert rejection(dispatch([RAW_IMPORTER, SynthImporter()], b"\x00", SYNTH)) == ("unsupported_container", None)


# SPEC-006 R35: two importers with one importer_id are refused.
def test_dispatch_duplicate_ids() -> None:
    with pytest.raises(ValueError, match="importer_id"):
        dispatch([SynthImporter(), SynthImporter()], CONTAINER, SYNTH)


# SPEC-006 R12, R25: a contract error from any importer propagates; the file is not imported.
def test_dispatch_contract_error() -> None:
    with pytest.raises(ImporterContractError):
        dispatch([raising(ValueError())], b"\x00", RAW)


# --- outcomes and JSON (R1, R2, R14) ----------------------------------------------------------------------


# SPEC-006 R14: the outcome JCS that determinism and versioning compare.
def test_outcome_jcs() -> None:
    assert outcome_jcs(ImportRejected("malformed", None)) == (
        b'{"outcome":"rejected","rejection":{"container_kind":null,"reason":"malformed"}}'
    )
    outcome = run_import(RAW_IMPORTER, b"\x00", RAW)
    assert isinstance(outcome, Imported)
    expected = {"outcome": "imported", "record": thaw(outcome.record.to_json()), "hash": outcome.import_record_hash}
    expected["import_record_hash"] = expected.pop("hash")
    assert outcome_jcs(outcome) == rfc8785.dumps(cast(Any, expected))


# SPEC-006 R1: JCS of every value kind, against the third-party rfc8785.
def test_jcs_matches_rfc8785() -> None:
    value: dict[str, Any] = {
        "z": [True, False, None, 0, 2**53 - 1, ""],
        "a": {"esc": '"\\\b\f\n\r\t\x01\x1f é 😀', "empty": {}, "list": []},
    }
    assert jcs(freeze_json(value)) == rfc8785.dumps(value)


# SPEC-006 R1, R2: values outside the domain.
@pytest.mark.parametrize("value", [1.0, -1, 2**53, b"x", bytearray(b"x"), "\udc00", {"é": 1}, {1: 1}, [object()]])
def test_not_json(value: object) -> None:
    with pytest.raises(NotJsonError):
        freeze_json(value)


def test_frozen_object() -> None:
    frozen = freeze_json({"b": 1, "a": [2]})
    assert isinstance(frozen, FrozenObject)
    assert (len(frozen), list(frozen), frozen["a"]) == (2, ["b", "a"], (2,))
    assert repr(frozen) == "FrozenObject({'b': 1, 'a': (2,)})"
