"""SPEC-009 guardrail. The workflow runs the base branch's copy of this file; it never runs code from the head."""

from __future__ import annotations

import argparse
import ast
import calendar
import json
import re
import subprocess
import sys
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Final

FOUNDATION_LABEL: Final = "foundation-change"
GOLDEN_LABEL: Final = "golden-change"
FOUNDATION_PREFIXES: Final = (
    "src/core/kernel/",
    "src/core/gate/",
    "src/core/provenance/",
    "src/core/conformance/",
    "src/core/evidence/",
    "src/core/stock/",
    "src/core/importers/",
    "src/core/definitions/",
    "tools/reproduce/",
    "specs/",
    "guardrails/",
    ".github/",
)
CONTRACT_FILE: Final = "src/core/plugins/_contract.py"
FOUNDATION_FILES: Final = frozenset({CONTRACT_FILE, "pyproject.toml", "uv.lock"})
SPEC_BOUND_PREFIXES: Final = ("src/core/kernel/", "src/core/gate/")
SPEC_DOCUMENT: Final = re.compile(r"specs/(?:SPEC-\d{3}-[^/]+|adr/ADR-\d{3}-[^/]+)\.md")
GOLDEN_PREFIX: Final = "tests/golden/"
SCANNED_PREFIXES: Final = ("src/", "tests/", "tools/", "guardrails/")
INVARIANT_FILE: Final = re.compile(r"tests/properties/test_inv_\d{2}_[a-z0-9_]+\.py")
ORACLE_LINE: Final = re.compile(r"^[ \t]*oracle:[ \t]*\S", re.MULTILINE)
# Character classes keep this file from matching its own patterns (R25 scans guardrails/ too).
MARKERS: Final = (
    ("noqa comment", re.compile(r"#\s*noqa\b", re.IGNORECASE)),
    ("type-ignore comment", re.compile(r"#\s*type\s*:\s*ignore\b")),
    ("no-cover pragma", re.compile(r"pragma\s*:\s*no\s*cover", re.IGNORECASE)),
    ("expected-failure marker", re.compile(r"\bx[f]ail\b")),
    (
        "test skip",
        re.compile(
            r"\bpytest\s*\.\s*(?:skip|importorskip)\b|\bmark\s*\.\s*skip(?:if)?\b|\bunittest\s*\.\s*skip"
            r"|\bSkip[T]est\b|\bskip[T]est\s*\(|^\s*@skip\b|\bfrom\s+(?:pytest|unittest)\s+import\b.*\bskip\b"
        ),
    ),
)
RATCHET_PATH: Final = "guardrails/ratchet.json"
RATCHET_KEYS: Final = (
    "coverage_line_branch_percent",
    "invariant_files",
    "hypothesis_ci_examples",
    "fuzz_minutes_per_parser",
    "corpus_min_dumps_per_variant",
    "mutation_score_percent",
)
MIN_AGE_SECONDS: Final = 86_400
TIMESTAMP: Final = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")

type Ratchets = dict[str, int | None]


class InputError(Exception):
    """R3: an input that cannot be read or parsed fails the job."""


@dataclass(frozen=True, slots=True)
class PullRequest:
    labels: frozenset[str]
    body: str
    changed: tuple[str, ...]
    head_paths: frozenset[str]
    base_paths: frozenset[str]
    added_lines: tuple[tuple[str, str], ...]
    base_ratchet: str | None
    head_ratchet: str | None
    pyproject: str | None
    conftest: str | None


@dataclass(frozen=True, slots=True)
class Finding:
    rule: str
    message: str


def is_foundation(path: str) -> bool:
    return path.startswith(FOUNDATION_PREFIXES) or path in FOUNDATION_FILES


def is_spec_bound(path: str) -> bool:
    return path.startswith(SPEC_BOUND_PREFIXES) or path == CONTRACT_FILE


def is_scanned(path: str) -> bool:
    return path.endswith(".py") and path.startswith(SCANNED_PREFIXES)


def count_invariant_files(paths: frozenset[str]) -> int:
    return sum(1 for p in paths if INVARIANT_FILE.fullmatch(p))


def _reject_float(text: str) -> int:
    raise InputError(f"{RATCHET_PATH}: non-integer number {text}")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise InputError(f"{RATCHET_PATH}: duplicate key")
    return dict(pairs)


def parse_ratchets(text: str) -> Ratchets:
    """R30."""
    try:
        doc: object = json.loads(
            text, parse_float=_reject_float, parse_constant=_reject_float, object_pairs_hook=_unique_object
        )
    except ValueError as exc:
        raise InputError(f"{RATCHET_PATH}: invalid JSON: {exc}") from exc
    if (
        not isinstance(doc, dict)
        or set(doc) != {"format", "ratchets"}
        or type(doc["format"]) is not int
        or doc["format"] != 1
    ):
        raise InputError(f"{RATCHET_PATH}: expected exactly {{format: 1, ratchets}}")
    ratchets = doc["ratchets"]
    if not isinstance(ratchets, dict) or set(ratchets) != set(RATCHET_KEYS):
        raise InputError(f"{RATCHET_PATH}: ratchets must have exactly the keys {', '.join(RATCHET_KEYS)}")
    out: Ratchets = {}
    for key in RATCHET_KEYS:
        value = ratchets[key]
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
            raise InputError(f"{RATCHET_PATH}: {key} must be a non-negative integer or null")
        out[key] = value
    return out


def check_foundation_label(pr: PullRequest) -> list[Finding]:
    """R20."""
    hits = [p for p in pr.changed if is_foundation(p)]
    if hits and FOUNDATION_LABEL not in pr.labels:
        return [Finding("R20", f"foundation path changed without the '{FOUNDATION_LABEL}' label: {hits[0]}")]
    return []


def check_spec_alongside(pr: PullRequest) -> list[Finding]:
    """R21."""
    bound = [p for p in pr.changed if is_spec_bound(p)]
    docs = [p for p in pr.changed if SPEC_DOCUMENT.fullmatch(p) and p in pr.head_paths]
    if bound and not docs:
        return [Finding("R21", f"kernel, gate or contract changed without a spec or ADR in specs/: {bound[0]}")]
    return []


def check_golden(pr: PullRequest) -> list[Finding]:
    """R22, R23, R24."""
    golden = [p for p in pr.changed if p.startswith(GOLDEN_PREFIX)]
    if not golden:
        return []
    findings: list[Finding] = []
    others = [p for p in pr.changed if not p.startswith(GOLDEN_PREFIX)]
    if others:
        findings.append(Finding("R22", f"golden files changed together with other files: {others[0]}"))
    if GOLDEN_LABEL not in pr.labels:
        findings.append(Finding("R23", f"golden files changed without the '{GOLDEN_LABEL}' label"))
    if not ORACLE_LINE.search(pr.body):
        findings.append(Finding("R24", "golden files changed without an 'oracle:' line in the body"))
    return findings


def check_markers(pr: PullRequest) -> list[Finding]:
    """R25."""
    return [
        Finding("R25", f"{name} added in {path}: {line.strip()}")
        for path, line in pr.added_lines
        if is_scanned(path)
        for name, pattern in MARKERS
        if pattern.search(line)
    ]


def check_ratchets(pr: PullRequest) -> list[Finding]:
    """R26, R30, R31, R32."""
    if pr.head_ratchet is None:
        return [Finding("R30", f"{RATCHET_PATH} is missing at the head")]
    head = parse_ratchets(pr.head_ratchet)
    findings: list[Finding] = []
    if pr.base_ratchet is not None:
        base = parse_ratchets(pr.base_ratchet)
        for key in RATCHET_KEYS:
            old, new = base[key], head[key]
            if old is not None and (new is None or new < old):
                findings.append(Finding("R31", f"ratchet {key} went down: {old} -> {new}"))
    head_count = count_invariant_files(pr.head_paths)
    base_count = count_invariant_files(pr.base_paths)
    if head_count < base_count:
        findings.append(Finding("R26", f"invariant files dropped: {base_count} -> {head_count}"))
    floor = head["invariant_files"]
    if floor is not None and head_count < floor:
        findings.append(Finding("R26", f"{head_count} invariant files, below the ratchet {floor}"))
    findings.extend(_check_mirrors(pr, head))
    return findings


def _check_mirrors(pr: PullRequest, head: Ratchets) -> list[Finding]:
    """R32."""
    findings: list[Finding] = []
    coverage = head["coverage_line_branch_percent"]
    if coverage is not None:
        report, addopts = _coverage_settings(pr.pyproject)
        if report != coverage:
            findings.append(Finding("R32", f"[tool.coverage.report] fail_under is {report}, ratchet is {coverage}"))
        if addopts != coverage:
            findings.append(Finding("R32", f"--cov-fail-under in addopts is {addopts}, ratchet is {coverage}"))
    examples = head["hypothesis_ci_examples"]
    if examples is not None:
        found = _ci_max_examples(pr.conftest)
        if found != examples:
            findings.append(Finding("R32", f"ci profile max_examples is {found}, ratchet is {examples}"))
    return findings


def _coverage_settings(text: str | None) -> tuple[object, int | None]:
    if text is None:
        raise InputError("pyproject.toml is missing at the head")
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise InputError(f"pyproject.toml: {exc}") from exc
    tool = doc.get("tool", {})
    report = tool.get("coverage", {}).get("report", {}).get("fail_under")
    addopts = tool.get("pytest", {}).get("ini_options", {}).get("addopts", [])
    values = [
        int(m.group(1)) for opt in addopts if (m := re.fullmatch(r"--cov-fail-under=(\d+)", str(opt))) is not None
    ]
    return report, values[0] if len(values) == 1 else None


def _ci_max_examples(text: str | None) -> object:
    if text is None:
        raise InputError("tests/conftest.py is missing at the head")
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        raise InputError(f"tests/conftest.py: {exc}") from exc
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "register_profile"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "ci"
        ):
            for kw in node.keywords:
                if kw.arg == "max_examples" and isinstance(kw.value, ast.Constant):
                    return kw.value.value
    return None


def evaluate(pr: PullRequest) -> list[Finding]:
    """Layer 2 and 3 rules of the `guardrails` job."""
    return [
        *check_foundation_label(pr),
        *check_spec_alongside(pr),
        *check_golden(pr),
        *check_markers(pr),
        *check_ratchets(pr),
    ]


def evaluate_age(changed: tuple[str, ...], updated_at: int, now: int) -> list[Finding]:
    """R40: the age runs from GitHub's `updated_at`, never from a commit date the author writes."""
    if not any(is_foundation(p) for p in changed):
        return []
    age = now - updated_at
    if age < MIN_AGE_SECONDS:
        return [Finding("R40", f"foundation change: pull request updated {age} s ago, needs {MIN_AGE_SECONDS} s")]
    return []


def parse_added_lines(diff: str) -> tuple[tuple[str, str], ...]:
    """Added lines of a `git diff -U0 --no-prefix` patch, as (path, line)."""
    out: list[tuple[str, str]] = []
    path = ""
    in_header = False
    for line in diff.split("\n"):
        if line.startswith("diff --git "):
            in_header = True
        elif in_header and line.startswith("+++ "):
            # git ends the header with a tab when the path has a space; a path ending in a tab would be quoted.
            path = line[4:].removesuffix("\t")
            if path.startswith('"'):
                raise InputError(f"path git had to quote: {path}")
        elif line.startswith("@@"):
            in_header = False
        elif not in_header and line.startswith("+"):
            out.append((path, line[1:]))
    return tuple(out)


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=False)
    if result.returncode != 0:
        raise InputError(f"git {' '.join(args)}: {result.stderr.decode(errors='replace').strip()}")
    return result.stdout.decode(errors="replace")


def _show(repo: Path, commit: str, path: str, present: frozenset[str]) -> str | None:
    return _git(repo, "show", f"{commit}:{path}") if path in present else None


def _paths(repo: Path, commit: str) -> frozenset[str]:
    return frozenset(p for p in _git(repo, "ls-tree", "-r", "-z", "--name-only", commit).split("\0") if p)


@dataclass(frozen=True, slots=True)
class Event:
    labels: frozenset[str]
    body: str
    base: str
    head: str
    updated_at: int


def _epoch(value: object) -> int:
    """R2: `pull_request.updated_at`, ISO 8601 UTC with second precision, as Unix seconds."""
    if not isinstance(value, str) or TIMESTAMP.fullmatch(value) is None:
        raise InputError("event payload: updated_at must be YYYY-MM-DDTHH:MM:SSZ")
    try:
        return calendar.timegm(time.strptime(value, "%Y-%m-%dT%H:%M:%SZ"))
    except ValueError as exc:
        raise InputError(f"event payload: updated_at {value}: {exc}") from exc


def read_event(path: Path) -> Event:
    """R2: labels, body, both SHAs and `updated_at` from the event payload."""
    try:
        pr = json.loads(path.read_text(encoding="utf-8"))["pull_request"]
        labels = frozenset(str(label["name"]) for label in pr["labels"])
        body = pr["body"] or ""
        base, head = pr["base"]["sha"], pr["head"]["sha"]
        updated_at = pr["updated_at"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise InputError(f"event payload: {exc!r}") from exc
    if not all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{40}", v) for v in (base, head)):
        raise InputError("event payload: base and head SHAs must be 40 lowercase hex characters")
    if not isinstance(body, str):
        raise InputError("event payload: body must be a string")
    return Event(labels, body, base, head, _epoch(updated_at))


def changed_paths(repo: Path, event: Event) -> tuple[str, str, tuple[str, ...]]:
    merge_base = _git(repo, "merge-base", event.base, event.head).strip()
    names = _git(repo, "diff", "--no-renames", "--name-only", "-z", merge_base, event.head)
    return merge_base, event.head, tuple(p for p in names.split("\0") if p)


def collect(repo: Path, event: Event) -> PullRequest:
    """R2: everything the rules read, from git objects only; nothing from the head is executed."""
    merge_base, head, changed = changed_paths(repo, event)
    head_paths, base_paths = _paths(repo, head), _paths(repo, merge_base)
    diff = _git(
        repo,
        "diff",
        "--no-renames",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--no-prefix",
        "-U0",
        merge_base,
        head,
    )
    added_lines = parse_added_lines(diff)
    stray = sorted({path for path, _ in added_lines} - set(changed))
    if stray:
        # R3, fail-closed: an added line whose path the header parse got wrong would escape R25.
        raise InputError(f"diff names a path outside the change set: {stray[0]}")
    return PullRequest(
        labels=event.labels,
        body=event.body,
        changed=changed,
        head_paths=head_paths,
        base_paths=base_paths,
        added_lines=added_lines,
        base_ratchet=_show(repo, merge_base, RATCHET_PATH, base_paths),
        head_ratchet=_show(repo, head, RATCHET_PATH, head_paths),
        pyproject=_show(repo, head, "pyproject.toml", head_paths),
        conftest=_show(repo, head, "tests/conftest.py", head_paths),
    )


def _escape(message: str) -> str:
    """Head-controlled text (paths, added lines) must not start a new workflow-command line."""
    return message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _out(line: str) -> None:
    sys.stdout.write(line + "\n")


def report(job: str, findings: list[Finding]) -> int:
    """R4."""
    for f in findings:
        message = _escape(f.message)
        _out(f"::error title={job} {f.rule}::{message}")
        _out(f"{f.rule}: {message}")
    if findings:
        return 1
    _out(f"{job}: no findings")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="SPEC-009 guardrail")
    parser.add_argument("job", choices=["guardrails", "foundation-24h"])
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--event", type=Path, required=True)
    parser.add_argument("--now", type=int)
    args = parser.parse_args(argv)
    try:
        event = read_event(args.event)
        if args.job == "guardrails":
            findings = evaluate(collect(args.repo, event))
        else:
            if args.now is None:
                raise InputError("--now is required for foundation-24h")
            _, _, changed = changed_paths(args.repo, event)
            findings = evaluate_age(changed, event.updated_at, args.now)
    except InputError as exc:
        message = _escape(str(exc))
        _out(f"::error title={args.job} R3::{message}")
        _out(f"R3: {message}")
        return 2
    return report(args.job, findings)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
