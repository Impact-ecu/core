"""SPEC-009 guardrail tests. Marker strings are built by concatenation so this file never contains one."""

from __future__ import annotations

import json
import runpy
import subprocess
import sys
import tomllib
from dataclasses import replace
from pathlib import Path

import pytest

import check

ROOT = Path(__file__).resolve().parents[2]
NOQA = "# no" + "qa"
TYPE_IGNORE = "# type" + ": ignore"
NO_COVER = "# pragma" + ": no cover"
XFAIL = "@pytest.mark.x" + "fail"
SHA_A = "a" * 40
SHA_B = "b" * 40

RATCHET = json.dumps(
    {
        "format": 1,
        "ratchets": {
            "coverage_line_branch_percent": 100,
            "invariant_files": 2,
            "hypothesis_ci_examples": 2000,
            "fuzz_minutes_per_parser": None,
            "corpus_min_dumps_per_variant": None,
            "mutation_score_percent": None,
        },
    }
)
PYPROJECT = """
[tool.pytest.ini_options]
addopts = ["--strict-markers", "--cov-fail-under=100"]
[tool.coverage.report]
fail_under = 100
"""
CONFTEST = """
from hypothesis import settings
settings.register_profile("dev", max_examples=100)
settings.register_profile("ci", max_examples=2000, derandomize=True)
"""
INVARIANTS = frozenset({"tests/properties/test_inv_01_determinism.py", "tests/properties/test_inv_02_composition.py"})


def ratchet(**changes: int | None) -> str:
    doc = json.loads(RATCHET)
    doc["ratchets"].update(changes)
    return json.dumps(doc)


BASE = check.PullRequest(
    labels=frozenset(),
    body="",
    changed=("README.md",),
    head_paths=INVARIANTS | {"README.md"},
    base_paths=INVARIANTS,
    added_lines=(),
    base_ratchet=RATCHET,
    head_ratchet=RATCHET,
    pyproject=PYPROJECT,
    conftest=CONFTEST,
)


def rules(findings: list[check.Finding]) -> list[str]:
    return [f.rule for f in findings]


# SPEC-009 R10
@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("src/core/kernel/_apply.py", True),
        ("src/core/gate/_rules.py", True),
        ("src/core/provenance/_json.py", True),
        ("src/core/conformance/_checks.py", True),
        ("src/core/plugins/_contract.py", True),
        ("specs/SPEC-001-kernel.md", True),
        ("guardrails/ratchet.json", True),
        (".github/workflows/ci.yml", True),
        ("src/core/plugins/_checks.py", False),
        ("src/core/definitions/_xdf.py", False),
        ("tests/unit/test_model.py", False),
        ("README.md", False),
    ],
)
def test_foundation_paths(path: str, expected: bool) -> None:
    assert check.is_foundation(path) is expected


# SPEC-009 R11
@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("src/core/kernel/_apply.py", True),
        ("src/core/gate/_rules.py", True),
        ("src/core/plugins/_contract.py", True),
        ("src/core/provenance/_json.py", False),
        ("specs/SPEC-001-kernel.md", False),
    ],
)
def test_spec_bound_paths(path: str, expected: bool) -> None:
    assert check.is_spec_bound(path) is expected


# SPEC-009 R20
def test_foundation_change_needs_label() -> None:
    changed = ("README.md", "src/core/gate/_rules.py")
    findings = check.check_foundation_label(replace(BASE, changed=changed))
    assert findings == [
        check.Finding("R20", "foundation path changed without the 'foundation-change' label: src/core/gate/_rules.py")
    ]
    assert check.check_foundation_label(replace(BASE, changed=changed, labels=frozenset({"foundation-change"}))) == []
    assert check.check_foundation_label(replace(BASE, changed=("README.md",))) == []


# SPEC-009 R12, R21
def test_spec_bound_change_needs_spec_document() -> None:
    code = "src/core/kernel/_apply.py"
    spec = "specs/SPEC-001-kernel.md"
    adr = "specs/adr/ADR-003-something.md"
    head = frozenset({code, spec, adr, "specs/vectors/spec-001/vectors.json"})
    assert rules(check.check_spec_alongside(replace(BASE, changed=(code,), head_paths=head))) == ["R21"]
    assert check.check_spec_alongside(replace(BASE, changed=(code, spec), head_paths=head)) == []
    assert check.check_spec_alongside(replace(BASE, changed=(code, adr), head_paths=head)) == []
    vectors_only = (code, "specs/vectors/spec-001/vectors.json")
    assert rules(check.check_spec_alongside(replace(BASE, changed=vectors_only, head_paths=head))) == ["R21"]
    deleted_spec = (code, "specs/SPEC-002-ecu-plugin.md")
    assert rules(check.check_spec_alongside(replace(BASE, changed=deleted_spec, head_paths=head))) == ["R21"]
    assert check.check_spec_alongside(replace(BASE, changed=("src/core/provenance/_json.py",))) == []


# SPEC-009 R13, R22, R23, R24
def test_golden_rules() -> None:
    golden = ("tests/golden/med17.json",)
    ok = replace(BASE, changed=golden, labels=frozenset({"golden-change"}), body="Why.\n  oracle: att-1, att-2\n")
    assert check.check_golden(ok) == []
    assert rules(check.check_golden(replace(ok, changed=(*golden, "src/core/kernel/_apply.py")))) == ["R22"]
    assert rules(check.check_golden(replace(ok, labels=frozenset()))) == ["R23"]
    assert rules(check.check_golden(replace(ok, body="oracle:   \nno oracle here"))) == ["R24"]
    assert rules(check.check_golden(replace(ok, body="the oracle: x"))) == ["R24"]
    assert check.check_golden(BASE) == []


# SPEC-009 R14, R25
@pytest.mark.parametrize(
    "line",
    [
        f"x = 1  {NOQA}: E501",
        f"x = 1  {NOQA.upper()}",
        f"y: int = f()  {TYPE_IGNORE}[assignment]",
        f"if x:  {NO_COVER}",
        XFAIL,
        "    pytest." + "skip('later')",
        "    pytest." + "importorskip('numpy')",
        "@pytest.mark." + "skip",
        "@pytest.mark." + "skipif(True, reason='x')",
        "@unittest." + "skip('x')",
        "    raise unittest." + "Skip" + "Test('x')",
        "        self." + "skip" + "Test('x')",
        "@" + "skip",
        "from pytest " + "import skip",
        "from unittest " + "import skip",
    ],
)
def test_markers_are_findings(line: str) -> None:
    for path in (
        "src/core/kernel/_apply.py",
        "tests/unit/test_model.py",
        "tools/reproduce/reproduce.py",
        "guardrails/check.py",
    ):
        findings = check.check_markers(replace(BASE, added_lines=((path, line),)))
        assert rules(findings) == ["R25"], (path, line)


# SPEC-009 R14, R25
@pytest.mark.parametrize(
    ("path", "line"),
    [
        ("src/core/gate/_input.py", "    def skip(self, reason: str, *kinds: str) -> None:"),
        ("src/core/gate/_input.py", '            self.skip("gate_unavailable", "identify")'),
        ("src/core/gate/_output.py", "        self.skip_after(kind, reason)"),
        ("src/core/plugins/_schema.py", "    skip_self: bool"),
        ("README.md", f"x  {NOQA}"),
        ("pyproject.toml", "x" + "fail_strict = true"),
        ("specs/SPEC-009-guardrails.md", f"`{TYPE_IGNORE}`"),
    ],
)
def test_non_markers(path: str, line: str) -> None:
    assert check.check_markers(replace(BASE, added_lines=((path, line),))) == []


# SPEC-009 R25
@pytest.mark.parametrize("path", ["guardrails/check.py", "tests/guardrails/test_check.py"])
def test_guardrail_files_do_not_match_their_own_patterns(path: str) -> None:
    source = (ROOT / path).read_text(encoding="utf-8")
    lines = tuple((path, line) for line in source.splitlines())
    assert check.check_markers(replace(BASE, added_lines=lines)) == []


# SPEC-009 R26
def test_invariant_files() -> None:
    assert (
        check.count_invariant_files(
            INVARIANTS | {"tests/properties/test_spec004_gate.py", "tests/properties/strategies.py"}
        )
        == 2
    )
    one = frozenset({"tests/properties/test_inv_01_determinism.py"})
    assert rules(check.check_ratchets(replace(BASE, head_paths=one))) == ["R26", "R26"]
    assert rules(
        check.check_ratchets(replace(BASE, head_ratchet=ratchet(invariant_files=1), base_ratchet=None, head_paths=one))
    ) == ["R26"]
    three = INVARIANTS | {"tests/properties/test_inv_03_containment.py"}
    assert rules(check.check_ratchets(replace(BASE, head_paths=three, base_paths=three))) == []
    assert (
        rules(
            check.check_ratchets(
                replace(BASE, head_paths=three, base_paths=three, head_ratchet=ratchet(invariant_files=3))
            )
        )
        == []
    )
    assert (
        rules(check.check_ratchets(replace(BASE, head_ratchet=ratchet(invariant_files=None), base_ratchet=None))) == []
    )


# SPEC-009 R30
@pytest.mark.parametrize(
    "text",
    [
        "not json",
        "[]",
        '{"format": 1}',
        '{"format": 2, "ratchets": {}}',
        '{"format": true, "ratchets": {}}',
        '{"format": 1, "ratchets": []}',
        '{"format": 1, "ratchets": {"invariant_files": 1}}',
        ratchet(invariant_files=-1),
        ratchet().replace('"invariant_files": 2', '"invariant_files": 2.0'),
        ratchet().replace('"invariant_files": 2', '"invariant_files": NaN'),
        ratchet().replace('"invariant_files": 2', '"invariant_files": true'),
        ratchet().replace('"invariant_files": 2', '"invariant_files": "2"'),
        ratchet().replace('"invariant_files": 2', '"invariant_files": 2, "invariant_files": 3'),
        ratchet().replace('"invariant_files": 2', '"invariant_files": 2, "extra": 1'),
    ],
)
def test_malformed_ratchet_is_input_error(text: str) -> None:
    with pytest.raises(check.InputError):
        check.parse_ratchets(text)


# SPEC-009 R30, R33
def test_repository_ratchet_is_well_formed_and_records_the_baselines() -> None:
    values = check.parse_ratchets((ROOT / "guardrails" / "ratchet.json").read_text(encoding="utf-8"))
    assert values == {
        "coverage_line_branch_percent": 100,
        "invariant_files": 12,
        "hypothesis_ci_examples": 2000,
        "fuzz_minutes_per_parser": None,
        "corpus_min_dumps_per_variant": None,
        "mutation_score_percent": None,
    }


# SPEC-009 R26, R32, R33: the repository's own files satisfy the rules at this commit.
def test_repository_satisfies_ratchets() -> None:
    paths = frozenset(str(p.relative_to(ROOT)) for p in (ROOT / "tests" / "properties").glob("test_inv_*.py"))
    current = replace(
        BASE,
        head_paths=paths,
        base_paths=paths,
        base_ratchet=(ROOT / "guardrails" / "ratchet.json").read_text(encoding="utf-8"),
        head_ratchet=(ROOT / "guardrails" / "ratchet.json").read_text(encoding="utf-8"),
        pyproject=(ROOT / "pyproject.toml").read_text(encoding="utf-8"),
        conftest=(ROOT / "tests" / "conftest.py").read_text(encoding="utf-8"),
    )
    assert check.check_ratchets(current) == []


# SPEC-009 R31
def test_ratchets_only_go_up() -> None:
    assert rules(check.check_ratchets(replace(BASE, head_ratchet=ratchet(hypothesis_ci_examples=1999)))) == [
        "R31",
        "R32",
    ]
    assert rules(check.check_ratchets(replace(BASE, head_ratchet=ratchet(hypothesis_ci_examples=None)))) == ["R31"]
    assert rules(check.check_ratchets(replace(BASE, head_ratchet=ratchet(mutation_score_percent=90)))) == []
    raised = ratchet(mutation_score_percent=91)
    assert rules(
        check.check_ratchets(replace(BASE, base_ratchet=raised, head_ratchet=ratchet(mutation_score_percent=90)))
    ) == ["R31"]
    assert rules(check.check_ratchets(replace(BASE, base_ratchet=None))) == []
    assert rules(check.check_ratchets(replace(BASE, head_ratchet=None))) == ["R30"]


# SPEC-009 R32
def test_mirrored_numbers() -> None:
    assert rules(
        check.check_ratchets(replace(BASE, pyproject=PYPROJECT.replace("fail_under = 100", "fail_under = 99")))
    ) == ["R32"]
    assert rules(
        check.check_ratchets(replace(BASE, pyproject=PYPROJECT.replace("--cov-fail-under=100", "--cov-fail-under=99")))
    ) == ["R32"]
    two = PYPROJECT.replace('"--strict-markers"', '"--cov-fail-under=100"')
    assert rules(check.check_ratchets(replace(BASE, pyproject=two))) == ["R32"]
    assert rules(check.check_ratchets(replace(BASE, pyproject="[project]\n"))) == ["R32", "R32"]
    assert rules(check.check_ratchets(replace(BASE, conftest=CONFTEST.replace("2000", "1000")))) == ["R32"]
    assert rules(check.check_ratchets(replace(BASE, conftest="x = 1\n"))) == ["R32"]
    odd = 'name = "ci"\nsettings.register_profile(name, max_examples=2000)\nregister_profile("ci")\n'
    odd += 'settings.register_profile("ci", max_examples=N)\nsettings.register_profile()\n'
    assert rules(check.check_ratchets(replace(BASE, conftest=odd))) == ["R32"]
    off = ratchet(coverage_line_branch_percent=None, hypothesis_ci_examples=None)
    assert check.check_ratchets(replace(BASE, base_ratchet=off, head_ratchet=off, pyproject=None, conftest=None)) == []


# SPEC-009 R3, R32
@pytest.mark.parametrize(
    "current",
    [
        replace(BASE, pyproject=None),
        replace(BASE, pyproject="[tool"),
        replace(BASE, conftest=None),
        replace(BASE, conftest="def (:"),
    ],
)
def test_unreadable_mirror_is_input_error(current: check.PullRequest) -> None:
    with pytest.raises(check.InputError):
        check.check_ratchets(current)


# SPEC-009 R40
def test_foundation_age() -> None:
    foundation = ("specs/SPEC-009-guardrails.md",)
    assert rules(check.evaluate_age(foundation, committed_at=1000, now=1000 + 86_399)) == ["R40"]
    assert check.evaluate_age(foundation, committed_at=1000, now=1000 + 86_400) == []
    assert rules(check.evaluate_age(foundation, committed_at=10_000, now=0)) == ["R40"]
    assert check.evaluate_age(("README.md",), committed_at=1000, now=1000) == []


def test_parse_added_lines() -> None:
    diff = "\n".join(
        [
            "diff --git a.py a.py",
            "index 1..2 100644",
            "--- a.py",
            "+++ a.py",
            "@@ -1,0 +1,2 @@",
            "+first",
            "+++ not a header",
            "-removed",
            "diff --git b.py b.py",
            "deleted file mode 100644",
            "--- b.py",
            "+++ /dev/null",
            "@@ -1 +0,0 @@",
            "-gone",
        ]
    )
    assert check.parse_added_lines(diff) == (("a.py", "first"), ("a.py", "++ not a header"))
    with pytest.raises(check.InputError):
        check.parse_added_lines('diff --git "a\\tb.py" "a\\tb.py"\n+++ "a\\tb.py"\n')


# SPEC-009 R4
def test_report(capsys: pytest.CaptureFixture[str]) -> None:
    assert check.report("guardrails", []) == 0
    assert capsys.readouterr().out == "guardrails: no findings\n"
    assert check.report("guardrails", [check.Finding("R25", "50%\nx\r")]) == 1
    assert capsys.readouterr().out == "::error title=guardrails R25::50%25%0Ax%0D\nR25: 50%25%0Ax%0D\n"


def test_evaluate_combines_rules() -> None:
    bad = replace(
        BASE, changed=("src/core/kernel/_apply.py",), added_lines=(("src/core/kernel/_apply.py", f"x  {NOQA}"),)
    )
    assert rules(check.evaluate(bad)) == ["R20", "R21", "R25"]
    assert check.evaluate(BASE) == []


def write_event(path: Path, **pull_request: object) -> Path:
    doc = {"labels": [], "body": None, "base": {"sha": SHA_A}, "head": {"sha": SHA_B}} | pull_request
    path.write_text(json.dumps({"pull_request": doc}), encoding="utf-8")
    return path


# SPEC-009 R2, R3
def test_read_event(tmp_path: Path) -> None:
    event = check.read_event(write_event(tmp_path / "e.json", labels=[{"name": "foundation-change"}], body="b"))
    assert event == check.Event(frozenset({"foundation-change"}), "b", SHA_A, SHA_B)
    assert check.read_event(write_event(tmp_path / "e.json")).body == ""
    bad: list[dict[str, object]] = [
        {"base": {"sha": "A" * 40}},
        {"head": {"sha": "b" * 39}},
        {"head": {"sha": 1}},
        {"body": 3},
        {"labels": [{}]},
        {"labels": None},
    ]
    for changes in bad:
        with pytest.raises(check.InputError):
            check.read_event(write_event(tmp_path / "e.json", **changes))
    for text in ("{", "{}", "[]"):
        (tmp_path / "e.json").write_text(text, encoding="utf-8")
        with pytest.raises(check.InputError):
            check.read_event(tmp_path / "e.json")
    with pytest.raises(check.InputError):
        check.read_event(tmp_path / "missing.json")


def git(repo: Path, *args: str, date: str = "2026-10-01T00:00:00+00:00") -> str:
    env = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
        "GIT_AUTHOR_DATE": date,
        "GIT_COMMITTER_DATE": date,
        "PATH": "/usr/bin:/bin",
    }
    out = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=True, env=env)
    return out.stdout.decode().strip()


def commit_files(repo: Path, files: dict[str, str | None], date: str = "2026-10-01T00:00:00+00:00") -> str:
    for name, text in files.items():
        target = repo / name
        if text is None:
            target.unlink()
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "c", date=date)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/dev/null")
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    path = tmp_path / "repo"
    path.mkdir()
    git(path, "init", "-q", "-b", "main")
    files: dict[str, str | None] = dict.fromkeys(INVARIANTS, "def test() -> None: ...\n")
    files |= {"guardrails/ratchet.json": RATCHET, "pyproject.toml": PYPROJECT, "tests/conftest.py": CONFTEST}
    commit_files(path, files)
    return path


def run_main(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    code = check.main(args)
    return code, capsys.readouterr().out


# SPEC-009 R1, R2, R4: end to end on a real repository, comparing against the merge base.
def test_main_guardrails(repo: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    base = git(repo, "rev-parse", "HEAD")
    git(repo, "checkout", "-q", "-b", "feature")
    head = commit_files(
        repo,
        {
            "src/core/kernel/_apply.py": f"x = 1  {NOQA}\n",
            "README.md": "readme\n",
            "tests/properties/test_inv_02_composition.py": None,
        },
    )
    git(repo, "checkout", "-q", "main")
    # main raised a ratchet after the branch was cut: the merge base, not the tip, is the base (D1).
    main_tip = commit_files(repo, {"guardrails/ratchet.json": ratchet(mutation_score_percent=90)})
    event = write_event(tmp_path / "e.json", base={"sha": main_tip}, head={"sha": head})
    code, out = run_main(["guardrails", "--repo", str(repo), "--event", str(event)], capsys)
    assert code == 1
    assert [line.split(":")[0] for line in out.splitlines() if not line.startswith("::")] == [
        "R20",
        "R21",
        "R25",
        "R26",
        "R26",
    ]
    clean = write_event(tmp_path / "e.json", base={"sha": base}, head={"sha": base})
    assert run_main(["guardrails", "--repo", str(repo), "--event", str(clean)], capsys) == (
        0,
        "guardrails: no findings\n",
    )


# SPEC-009 R40, R41
def test_main_foundation_24h(repo: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    base = git(repo, "rev-parse", "HEAD")
    head = commit_files(repo, {"specs/SPEC-009-guardrails.md": "x\n"}, date="2026-10-10T00:00:00+00:00")
    committed = int(git(repo, "show", "-s", "--format=%ct", head))
    event = write_event(tmp_path / "e.json", base={"sha": base}, head={"sha": head})
    args = ["foundation-24h", "--repo", str(repo), "--event", str(event)]
    code, out = run_main([*args, "--now", str(committed + 60)], capsys)
    assert code == 1
    assert out.splitlines()[-1] == "R40: foundation change: last commit is 60 s old, needs 86400 s"
    assert run_main([*args, "--now", str(committed + 86_400)], capsys) == (0, "foundation-24h: no findings\n")
    code, out = run_main(args, capsys)
    assert (code, out.splitlines()[-1]) == (2, "R3: --now is required for foundation-24h")


# SPEC-009 R3
def test_main_input_errors_exit_2(repo: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    head = git(repo, "rev-parse", "HEAD")
    unknown = write_event(tmp_path / "e.json", base={"sha": "c" * 40}, head={"sha": head})
    code, out = run_main(["guardrails", "--repo", str(repo), "--event", str(unknown)], capsys)
    assert code == 2
    assert out.splitlines()[-1].startswith("R3: git merge-base")
    code, _ = run_main(["guardrails", "--repo", str(repo), "--event", str(tmp_path / "missing.json")], capsys)
    assert code == 2


def test_script_entry_point(repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    head = git(repo, "rev-parse", "HEAD")
    event = write_event(tmp_path / "e.json", base={"sha": head}, head={"sha": head})
    monkeypatch.setattr(sys, "argv", ["check.py", "guardrails", "--repo", str(repo), "--event", str(event)])
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(str(ROOT / "guardrails" / "check.py"), run_name="__main__")
    assert exc.value.code == 0


def test_pyproject_measures_guardrails_coverage() -> None:
    doc = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert "check" in doc["tool"]["coverage"]["run"]["source"]
