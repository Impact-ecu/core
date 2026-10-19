"""SPEC-006 §12: every importer value of specs/vectors/spec-006/vectors.json (`raw_import` I1-I8).

Expected values come from generate.py (third-party rfc8785) and are cross-checked by crosscheck.py;
nothing here is computed by the core and then compared with itself.
"""

import hashlib
import json
import tomllib
from pathlib import Path
from typing import Any

import pytest

import core
from core.importers import (
    MAX_INPUT_BYTES,
    RAW_IMPORTER,
    Imported,
    ImportParams,
    ImportRejected,
    import_record_hash,
    import_record_jcs,
    run_import,
)
from core.kernel import Dump, image_hash

ROOT = Path(__file__).resolve().parents[2]
VECTORS: dict[str, Any] = json.loads((ROOT / "specs" / "vectors" / "spec-006" / "vectors.json").read_text("utf-8"))
RAW: dict[str, Any] = VECTORS["raw_import"]
CASES: list[dict[str, Any]] = RAW["cases"]


class VectorRaw:
    """The raw importer under the synthetic version the vectors were generated with (R27 binds the real one)."""

    importer_id = RAW_IMPORTER.importer_id
    version: str = RAW["importer_version"]
    contract_version = RAW_IMPORTER.contract_version
    container_kind = RAW_IMPORTER.container_kind

    def import_file(self, data: bytes, params: ImportParams) -> Dump | ImportRejected:
        return RAW_IMPORTER.import_file(data, params)


def input_bytes(spec: dict[str, Any]) -> bytes:
    if "hex" in spec:
        return bytes.fromhex(spec["hex"])
    return bytes([spec["fill"]["byte"]]) * int(spec["fill"]["size"])


def params_of(case: dict[str, Any]) -> ImportParams:
    p = case["params"]
    return ImportParams(p["dump_kind"], p["source_tool"], p["options"])


def test_all_cases_present() -> None:
    assert [case["id"][:2] for case in CASES] == ["I1", "I2", "I3", "I4", "I5", "I6", "I7", "I8"]


# SPEC-006 R16: the provisional input limit.
def test_max_input_bytes() -> None:
    assert RAW["max_input_bytes"] == MAX_INPUT_BYTES


# SPEC-006 R27: identity of the built-in raw importer; its version is the core package's.
def test_raw_identity() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))
    assert pyproject["project"]["version"] == core.__version__ == RAW_IMPORTER.version
    assert (RAW_IMPORTER.importer_id, RAW_IMPORTER.container_kind, RAW_IMPORTER.contract_version) == (
        "impact.raw",
        "raw",
        1,
    )


# SPEC-006 R10, R11, R16, R17, R20, R21, R27-R29.
@pytest.mark.parametrize("case", CASES, ids=[case["id"] for case in CASES])
def test_raw_import_vector(case: dict[str, Any]) -> None:
    data = input_bytes(case["input"])
    outcome = run_import(VectorRaw(), data, params_of(case))
    want = case["expect"]
    if want["outcome"] == "rejected":
        assert isinstance(outcome, ImportRejected)
        assert {"reason": outcome.reason, "container_kind": outcome.container_kind} == want["rejection"]
        return
    assert isinstance(outcome, Imported)
    memory = outcome.dump.memories[0]
    (want_memory,) = want["dump"]["memories"]
    assert (outcome.dump.dump_kind, len(outcome.dump.memories)) == (want["dump"]["dump_kind"], 1)
    assert (memory.memory_id, memory.base_address) == (want_memory["memory_id"], want_memory["base_address"])
    assert memory.data == input_bytes(want_memory["data"])
    assert image_hash(outcome.dump) == hashlib.sha256(want["image_jcs"].encode("utf-8")).hexdigest()
    assert outcome.record.to_json() == want["record"]
    assert import_record_jcs(outcome.record).decode("utf-8") == want["record_jcs"]
    assert outcome.import_record_hash == import_record_hash(outcome.record) == want["import_record_hash"]
    assert hashlib.sha256(want["record_jcs"].encode("utf-8")).hexdigest() == want["import_record_hash"]


# SPEC-006 R27: the shipped raw importer gives the same dump and record, with the core version.
def test_shipped_raw_importer_matches_vector_but_version() -> None:
    case = CASES[0]
    outcome = run_import(RAW_IMPORTER, input_bytes(case["input"]), params_of(case))
    assert isinstance(outcome, Imported)
    assert dict(outcome.record.to_json()) == {**case["expect"]["record"], "importer_version": core.__version__}
