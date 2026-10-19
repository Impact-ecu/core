"""SPEC-005 R70-R78: the reproduction script on every SPEC-005 vector, as shipped (`python -I`, one file, stdlib).

Expected results come from the vectors (generate.py, third-party rfc8785 and cryptography) and RFC 8032 §7.1;
nothing here is computed by the script and compared with itself.
"""

import ast
import copy
import json
import runpy
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import reproduce
from core.provenance import ReportBindingError, check_report_file
from tests.reproduce.bundles import (
    SCRIPT,
    TAMPERS,
    audit_bundle,
    record_bundle,
    t5_bundle,
    t6_bundle,
    vector_bundle,
    vector_cases,
    write,
)
from tests.unit.provenance_support import ROOT, SPEC005, VERIFIER

# SPEC-005 R61 reasons of the core, as the script's step-1 fields.
R61_FIELDS = {
    "report_hash_mismatch": {"report_file.report_hash"},
    "record_hash_mismatch": {"report.record_hash"},
    "key_id_mismatch": {"report.signer.key_id"},
    "bad_signature": {"event.payload.signature"},
}


def run_script(path: Path, *flags: str) -> tuple[int, dict[str, Any]]:
    done = subprocess.run(
        [sys.executable, *flags, str(SCRIPT), str(path)], capture_output=True, check=False, timeout=120
    )
    result: dict[str, Any] = json.loads(done.stdout)
    return done.returncode, result


# SPEC-005 R71, R73, R74, R76: the report_file vector reproduces when run exactly as the contract says.
def test_report_file_vector_reproduces_as_shipped(tmp_path: Path) -> None:
    path = write(tmp_path / "bundle.json", vector_bundle())
    code, result = run_script(path, "-I")
    assert code == 0
    assert result["status"] == "reproduced"
    assert result["reproducibility"] == "full"
    assert result["mismatches"] == []
    assert len(result["limits"]) == 3


# SPEC-005 R71: `-S` drops every site-packages directory, so the script runs with the standard library alone.
def test_runs_without_site_packages(tmp_path: Path) -> None:
    bundle = vector_bundle()
    bundle["gate_report"]["verdict"] = "block"
    code, result = run_script(write(tmp_path / "bundle.json", bundle), "-I", "-S")
    assert code == 1
    assert result["status"] == "not_reproduced"
    assert [(m["step"], m["field"]) for m in result["mismatches"]] == [(7, "gate_report_hash")]


# SPEC-005 R73, R74, R76: every export record vector, re-signed with the published test key.
@pytest.mark.parametrize(
    ("name", "expected"),
    [("provenance", "full"), ("provenance_no_findings", "full"), ("provenance_lockfile", "best_effort")],
)
def test_record_vectors_reproduce(name: str, expected: str) -> None:
    result = reproduce.reproduce(rfc8785.dumps(record_bundle(name)))
    assert result["status"] == "reproduced"
    assert result["mismatches"] == []
    assert result["reproducibility"] == expected
    # R74: a best_effort record says so and is never upgraded.
    limits = result["limits"]
    assert isinstance(limits, list)
    assert any("best_effort" in line for line in limits) == (expected == "best_effort")


def _step1_fields(bundle: dict[str, Any]) -> set[str]:
    result = reproduce.reproduce(rfc8785.dumps(bundle))
    assert result["status"] == "not_reproduced"
    mismatches = result["mismatches"]
    assert isinstance(mismatches, list)
    assert {m["step"] for m in mismatches} == {1}
    return {m["field"] for m in mismatches}


def _core_reasons(report_file: dict[str, Any]) -> tuple[str, ...]:
    with pytest.raises(ReportBindingError) as caught:
        check_report_file(report_file, VERIFIER)
    return caught.value.reasons


# SPEC-005 R61, R73 step 1, R76: the report_file tamper T6 (vector reasons) and the export-event tamper T5.
def test_report_tampers() -> None:
    t6 = TAMPERS["T6-report-verdict-edited"]
    bundle = t6_bundle()
    expected = set().union(*(R61_FIELDS[e["reason"]] for e in t6["expect"]))
    assert _step1_fields(bundle) == expected == {"report_file.report_hash", "report.record_hash"}
    assert set(_core_reasons(bundle["report_file"])) == {e["reason"] for e in t6["expect"]}
    bundle = t5_bundle()
    assert _step1_fields(bundle) == {"event.payload.signature"}
    assert _core_reasons(bundle["report_file"]) == ("bad_signature",)


# SPEC-005 R73 step 1, R78: an audit report has no release, so it is not reproduced.
def test_audit_report_is_not_reproduced() -> None:
    result = reproduce.reproduce(rfc8785.dumps(audit_bundle()))
    assert result["mismatches"] == [
        {"step": 1, "field": "report.kind", "expected": "export (an audit has no release to reproduce)", "got": "audit"}
    ]


# SPEC-005 R76: the bundles CI writes for the runner's own python3 (one per applicable vector).
def test_vector_cases_as_written_for_ci(tmp_path: Path) -> None:
    cases = vector_cases()
    assert set(cases) == {
        "report_file",
        "provenance",
        "provenance_no_findings",
        "provenance_lockfile",
        "T5",
        "T6",
        "audit",
    }
    done = subprocess.run(
        [sys.executable, "-m", "tests.reproduce.bundles", str(tmp_path)], cwd=ROOT, check=True, timeout=120
    )
    assert done.returncode == 0
    written = sorted(p.name for p in tmp_path.iterdir())
    assert written == sorted(
        f"{'reproduced' if ok else 'not_reproduced'}.{name}.json" for name, (_, ok) in cases.items()
    )
    for name, (bundle, reproduces) in cases.items():
        result = reproduce.reproduce(rfc8785.dumps(bundle))
        assert (result["status"] == "reproduced") == reproduces, name


RFC8032 = [
    # RFC 8032 §7.1 TEST 1, TEST 2, TEST 3: (public key, message, signature).
    (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
]


# SPEC-005 R72: the script's own Ed25519 against RFC 8032 §7.1, cross-checked with `cryptography`.
@pytest.mark.parametrize(("public", "message", "signature"), RFC8032)
def test_rfc8032_vectors(public: str, message: str, signature: str) -> None:
    key, msg, sig = bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature)
    Ed25519PublicKey.from_public_bytes(key).verify(sig, msg)
    assert reproduce.ed25519_verify(key, msg, sig)
    assert not reproduce.ed25519_verify(key, msg + b"\x00", sig)
    assert not reproduce.ed25519_verify(key, msg, sig[:63] + bytes([sig[63] ^ 0x01]))


# SPEC-005 R72: the SPEC-005 vector key (the crosscheck's TEST 1 constant is the same as RFC8032[0]).
def test_spec005_signature_vector() -> None:
    vector = SPEC005["report_file"]
    public = bytes.fromhex(SPEC005["key"]["public_key"])
    assert reproduce.ed25519_verify(public, vector["signing_input"].encode(), bytes.fromhex(vector["signature"]))
    crosscheck = (ROOT / "specs" / "vectors" / "spec-005" / "crosscheck.py").read_text("utf-8")
    assert RFC8032[0][0] in crosscheck
    assert RFC8032[0][2] in crosscheck


STDLIB_IMPORTS = {"collections.abc", "dataclasses", "hashlib", "heapq", "json", "re", "sys"}


# SPEC-005 R71, R77: one file outside `src/`, standard library only, no core, plugin or third-party import, no
# environment read.
def test_script_contract() -> None:
    tree = ast.parse(SCRIPT.read_text("utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0
            assert node.module is not None
            imported.add(node.module)
    assert imported == STDLIB_IMPORTS
    assert {name.split(".")[0] for name in imported} <= sys.stdlib_module_names
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    assert not {"environ", "getenv", "putenv", "urlopen", "socket"} & attributes
    assert "__import__" not in names
    assert "eval" not in names
    assert "exec" not in names
    opens = [
        n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "open"
    ]
    assert len(opens) == 1
    # One file: nothing else lives beside it, and it is outside the `core` package (not in the wheel).
    shipped = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "tools/reproduce"], capture_output=True, check=True, text=True
    ).stdout.split()
    assert shipped in ([], ["tools/reproduce/reproduce.py"])
    assert sorted(p.name for p in SCRIPT.parent.iterdir() if p.name != "__pycache__") == ["reproduce.py"]
    assert not (ROOT / "src" / "core" / "reproduce.py").exists()


# SPEC-005 R70: the output never carries the original's bytes, even when they are malformed.
def test_output_never_echoes_dump_bytes() -> None:
    bundle = vector_bundle()
    data = bundle["original"]["memories"][0]["data"]
    bundle["original"]["memories"][0]["data"] = data.upper()
    output = json.dumps(reproduce.reproduce(rfc8785.dumps(bundle)))
    assert data not in output
    assert data.upper() not in output
    assert "not lowercase hex" in output


# SPEC-005 R74, R78: exit status and the usage error.
def test_main_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    good = write(tmp_path / "good.json", vector_bundle())
    assert reproduce.main(["reproduce.py", str(good)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "reproduced"
    bad = copy.deepcopy(vector_bundle())
    bad["schema"] = "impact.reproduction-bundle.v0"
    assert reproduce.main(["reproduce.py", str(write(tmp_path / "bad.json", bad))]) == 1
    assert json.loads(capsys.readouterr().out)["mismatches"][0]["field"] == "bundle.schema"
    assert reproduce.main(["reproduce.py"]) == 2
    assert "usage" in capsys.readouterr().err
    assert reproduce.main(["reproduce.py", str(tmp_path / "missing.json")]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["mismatches"] == [
        {"step": 0, "field": "bundle", "expected": "a readable file", "got": "No such file or directory"}
    ]
    assert result["reproducibility"] is None


# SPEC-005 R71: the `python reproduce.py` entry point.
def test_entry_point(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(sys, "argv", ["reproduce.py", str(write(tmp_path / "b.json", vector_bundle()))])
    with pytest.raises(SystemExit) as caught:
        runpy.run_path(str(SCRIPT), run_name="__main__")
    assert caught.value.code == 0
    assert json.loads(capsys.readouterr().out)["status"] == "reproduced"
