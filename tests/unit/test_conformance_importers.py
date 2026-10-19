"""SPEC-006 §3.5: core-side importer conformance checks, report, admission and versioning."""

import hashlib
from dataclasses import replace
from typing import Any, cast

import pytest
import rfc8785

from core.conformance import (
    PREFIX_SIZES,
    Check,
    Failure,
    Limit,
    OracleRecord,
    ReportInputs,
    admit_importers,
    check_determinism,
    check_encrypted,
    check_fuzz_input,
    check_negative,
    check_positive,
    check_prefixes,
    importer_report,
    outcomes_differ,
    prefix_sizes,
    report_hash,
    version_bump_ok,
)
from core.importers import RAW_IMPORTER, Importer, ImporterContractError, ImportParams, ImportRejected
from core.kernel import Dump, Memory
from tests.unit.importer_fakes import ScriptedImporter, SynthImporter, encode_synth

SYNTH = ImportParams("bench_full", None, {})
PAYLOAD = bytes(range(100))
SAMPLE = encode_synth([("pflash", 0x1000, PAYLOAD)])


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# Expected image hash built by hand from SPEC-001 R62 and the third-party rfc8785, not by the importer (R31).
EXPECTED_IMAGE = sha(
    rfc8785.dumps(
        {
            "dump_kind": "bench_full",
            "memories": [{"memory_id": "pflash", "base_address": 0x1000, "size": 100, "sha256": sha(PAYLOAD)}],
        }
    )
)
ORACLE = OracleRecord(sha(SAMPLE), EXPECTED_IMAGE, "Synthetic Reader", "1.0", "tool raw export", "2026-10-19")


def reasons(failures: list[Failure]) -> list[str]:
    return [failure.reason for failure in failures]


# SPEC-006 R31: positive samples against an external oracle record.
def test_check_positive() -> None:
    assert check_positive(SynthImporter(), SAMPLE, SYNTH, ORACLE) == []
    wrong = replace(ORACLE, expected_image_hash="0" * 64)
    assert check_positive(SynthImporter(), SAMPLE, SYNTH, wrong) == [
        Failure("SPEC-006 R31", sha(SAMPLE), "image_hash_mismatch")
    ]
    assert reasons(check_positive(SynthImporter(), SAMPLE + b"x", SYNTH, ORACLE)) == ["oracle_input_mismatch"]
    broken = SAMPLE[:-1] + bytes([SAMPLE[-1] ^ 1])
    assert reasons(check_positive(SynthImporter(), broken, SYNTH, replace(ORACLE, input_sha256=sha(broken)))) == [
        "malformed"
    ]


# SPEC-006 R32: negatives are unsupported_container; a contract error is a failure, not an exception.
def test_check_negative() -> None:
    assert check_negative(SynthImporter(), b"\x00" * 10, SYNTH) == []
    assert reasons(check_negative(SynthImporter(), SAMPLE, SYNTH)) == ["imported"]
    assert reasons(check_negative(raising_importer(), b"\x00", SYNTH)) == ["contract_error:importer_exception"]


# SPEC-006 R32: encrypted samples are encrypted_container.
def test_check_encrypted() -> None:
    encrypted = encode_synth([("pflash", None, b"\x01")], encrypted=True)
    assert check_encrypted(SynthImporter(), encrypted, SYNTH) == []
    assert reasons(check_encrypted(SynthImporter(), b"\x00", SYNTH)) == ["unsupported_container"]


# SPEC-006 R32: 64 seeded strict-prefix sizes, deterministic, distinct; all of them for short samples.
def test_prefix_sizes() -> None:
    assert prefix_sizes(3, 7) == (0, 1, 2)
    assert prefix_sizes(PREFIX_SIZES, 7) == tuple(range(PREFIX_SIZES))
    sizes = prefix_sizes(10_000, 7)
    assert len(sizes) == PREFIX_SIZES == len(set(sizes))
    assert all(0 <= size < 10_000 for size in sizes)
    assert sizes == prefix_sizes(10_000, 7) != prefix_sizes(10_000, 8)


# SPEC-006 R32: every strict prefix of a positive sample is rejected, never a Dump.
def test_check_prefixes() -> None:
    assert check_prefixes(SynthImporter(), SAMPLE, SYNTH, seed=1) == []
    failures = check_prefixes(RAW_IMPORTER, b"\x01\x02\x03", ImportParams("bench_full", None, {"memory_id": "p"}), 1)
    assert reasons(failures) == ["imported", "imported"]
    assert [failure.input_sha256 for failure in failures] == [sha(b"\x01"), sha(b"\x01\x02")]


# SPEC-006 R33: a fuzz input never raises and never exceeds R16.
def test_check_fuzz_input() -> None:
    assert check_fuzz_input(SynthImporter(), SAMPLE, SYNTH) == []
    assert check_fuzz_input(SynthImporter(), b"junk", SYNTH) == []
    assert reasons(check_fuzz_input(raising_importer(), b"\x00", SYNTH)) == ["contract_error:importer_exception"]
    memories = tuple(Memory(f"m{i}", None, b"\x00") for i in range(9))
    too_many = ScriptedImporter(lambda _d, p: Dump(p.dump_kind, memories))
    assert reasons(check_fuzz_input(too_many, b"\x00", SYNTH)) == ["limit_exceeded"]


# SPEC-006 R14, R33: two orders, JCS-identical outcomes.
def test_check_determinism() -> None:
    cases = [(SAMPLE, SYNTH), (b"junk", SYNTH)]
    assert check_determinism(SynthImporter(), cases) == []
    counter = [0]

    def drifting(data: bytes, params: ImportParams) -> Dump | ImportRejected:
        counter[0] += 1
        return Dump(params.dump_kind, (Memory("pflash", counter[0], data),))

    assert reasons(check_determinism(ScriptedImporter(drifting), [(b"\x01", SYNTH)])) == ["nondeterministic"]
    assert check_determinism(raising_importer(), [(b"\x01", SYNTH)]) == []


# SPEC-006 R35: contract_version and unique importer_id.
def test_admit_importers() -> None:
    admitted = admit_importers([SynthImporter(), RAW_IMPORTER])
    assert sorted(admitted) == ["impact.raw", "test.synth"]
    with pytest.raises(ValueError, match="importer_id"):
        admit_importers([SynthImporter(), SynthImporter()])
    for version in (2, cast(Any, True)):
        rejecting = ScriptedImporter(lambda _d, _p: ImportRejected("malformed", None), contract_version=version)
        with pytest.raises(ImporterContractError) as info:
            admit_importers([rejecting])
        assert info.value.reason == "contract_version"


# SPEC-006 R36: any outcome difference requires a major bump.
def test_versioning() -> None:
    assert outcomes_differ([b"a", b"b"], [b"a", b"c"])
    assert not outcomes_differ([b"a"], [b"a"])
    with pytest.raises(ValueError, match="different inputs"):
        outcomes_differ([b"a"], [])
    assert version_bump_ok("1.2.3", "2.0.0", differ=True)
    assert not version_bump_ok("1.2.3", "1.3.0", differ=True)
    assert version_bump_ok("1.2.3", "1.2.4", differ=False)
    assert version_bump_ok("0.9.0", "1.0.0-rc.1", differ=True)
    with pytest.raises(ValueError, match="semver"):
        version_bump_ok("v1", "2.0.0", differ=True)


def inputs(**changes: object) -> ReportInputs:
    base = ReportInputs(
        core_version="0.1.0",
        core_git_sha="a" * 40,
        importer=SynthImporter(),
        wheel_sha256="b" * 64,
        samples_revision="rev1",
        positive=3,
        encrypted=1,
        negative=5,
        run_kind="pr",
        seed=42,
        checks=[Check("SPEC-006 R32", True, 10, 0), Check("SPEC-006 R31", True, 3, 0)],
        fuzz_inputs=100_000,
        fuzz_exceptions=0,
        fuzz_timeouts=0,
        limits=[Limit("import_file", 2000, 15, 1024)],
        failures=[],
    )
    return replace(base, **cast(dict[str, Any], changes))


# SPEC-006 R34: report shape, sorting, deduplication, verdict and report_hash.
def test_report_conformant() -> None:
    report = importer_report(inputs())
    assert report["verdict"] == "conformant"
    assert [check["rule"] for check in cast(Any, report["checks"])] == ["SPEC-006 R31", "SPEC-006 R32"]
    assert cast(Any, report["importer"]) == {
        "importer_id": "test.synth",
        "version": "1.0.0",
        "contract_version": 1,
        "wheel_sha256": "b" * 64,
    }
    assert report_hash(report) == sha(rfc8785.dumps(cast(Any, report)))


@pytest.mark.parametrize(
    "changes",
    [
        {"checks": [Check("SPEC-006 R31", False, 3, 1)]},
        {"fuzz_exceptions": 1},
        {"fuzz_timeouts": 1},
        {"limits": [Limit("import_file", 2000, 2001, 1)]},
        {"failures": [Failure("SPEC-006 R32", "c" * 64, "imported")]},
    ],
)
def test_report_nonconformant(changes: dict[str, Any]) -> None:
    assert importer_report(inputs(**changes))["verdict"] == "nonconformant"


def test_report_failures_sorted_and_deduplicated() -> None:
    first = Failure("SPEC-006 R32", "d" * 64, "imported")
    second = Failure("SPEC-006 R31", "e" * 64, "malformed")
    report = importer_report(inputs(failures=[first, second, first]))
    assert cast(Any, report["failures"]) == [
        {"rule": "SPEC-006 R31", "input_sha256": "e" * 64, "reason": "malformed"},
        {"rule": "SPEC-006 R32", "input_sha256": "d" * 64, "reason": "imported"},
    ]


@pytest.mark.parametrize(
    "changes",
    [
        {"checks": [Check("SPEC-006 R31", True, 1, 0), Check("SPEC-006 R31", True, 2, 0)]},
        {"limits": [Limit("import_file", 1, 1, 1), Limit("import_file", 2, 2, 2)]},
    ],
)
def test_report_duplicate_keys(changes: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="unique"):
        importer_report(inputs(**changes))


def raising_importer() -> Importer:
    def behavior(_data: bytes, _params: ImportParams) -> Dump:
        raise RuntimeError

    return ScriptedImporter(behavior)
