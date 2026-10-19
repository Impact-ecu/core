# SPEC-009 · Guardrails

Status: draft
Date: 2026-10-19
Governs: `guardrails/check.py`, `guardrails/ratchet.json`, `guardrails/ruleset.json` and `.github/workflows/guardrails.yml`: the CI guardrail (SPEC-000 layer 2), the ratchet file and its checks (layer 3), the exported ruleset (layer 1) and the 24 h rule of the foundation change ritual.
Derives from: SPEC-000 §Four layers of assurance (layers 1 to 3), §CI pipeline for the `core` repository (`guardrails` row), §Foundation change ritual (steps 2, 3, 5 and 6), §Golden files: who is the oracle, §Core engineering practices (coverage, property testing, mutation testing, review), §Pipeline security, §`core` repository structure; `CLAUDE.md` (the list of foundation paths).

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Every numbered rule (`R<n>`) is normative and MUST be cited by at least one test (`# SPEC-009 R<n>`). A rule marked **(decision Dn)** settles a point SPEC-000 leaves open and is listed in §8 for Luiz to review.

## 1. Problem

SPEC-000 says the standards of the core are hard to loosen because a job, run from `main`, fails any pull request that loosens them. It names what the job fails on but not the exact paths, patterns, file format or inputs, so two implementations could disagree on whether a pull request passes. This spec fixes them.

Out of scope: the hourly re-evaluation of the 24 h rule (§8, D4), the release workflow's mutation-score check (it reads `ratchet.json` but is not written yet), and applying the ruleset to the host.

## 2. Inputs and execution

- **R1. Executed from the base.** The workflow runs on `pull_request` with types `opened`, `synchronize`, `reopened`, `labeled`, `unlabeled` and `edited`. It checks out only the base commit (`pull_request.base.sha`), so the `guardrails/check.py` that judges a pull request is the base branch's, and fetches the head commit as git objects; it MUST NOT import, execute or install anything from the head. **(decision D5)** (SPEC-000 layer 2)
- **R2. Inputs.** The inputs are the event payload (`pull_request.labels[].name`, `pull_request.body`, `pull_request.base.sha`, `pull_request.head.sha`) and the git objects of both commits. The pull request's change set is the diff from `M = merge-base(base, head)` to `head`, with rename detection off (a rename is a deletion plus an addition). Every comparison "at the base" below is against `M`. **(decision D1)**
- **R3. Fail-closed.** Any input that cannot be read or parsed (a git command fails, the event lacks a field, `ratchet.json` is malformed) fails the job; the guardrail never passes for lack of information.
- **R4. Output.** The job prints one line per finding, `<rule>: <message>`, plus a GitHub `::error::` annotation per finding, and exits 1 if there is at least one finding. With none, it prints `guardrails: no findings` and exits 0. An input error (R3) exits 2.
- **R5. Pipeline security.** The workflow declares `permissions: contents: read`, uses no secret, runs on a GitHub-hosted runner, pins every action by full commit SHA, and checks out with `persist-credentials: false`. `check.py` uses the Python standard library only and runs with `python3 -I`. (SPEC-000 §Pipeline security)

## 3. Paths

- **R10. Foundation paths.** A path is a foundation path if it starts with `src/core/kernel/`, `src/core/gate/`, `src/core/provenance/`, `src/core/conformance/`, `specs/`, `guardrails/` or `.github/`, or equals `src/core/plugins/_contract.py`. (CLAUDE.md; SPEC-000 §Foundation change ritual)
- **R11. Spec-bound paths.** A path is spec-bound if it starts with `src/core/kernel/` or `src/core/gate/`, or equals `src/core/plugins/_contract.py`. (SPEC-000 layer 2: "kernel, gate, or contract")
- **R12. Spec documents.** A spec document is a path matching `specs/SPEC-NNN-<name>.md` or `specs/adr/ADR-NNN-<name>.md` (`NNN` three digits, `<name>` without `/`).
- **R13. Golden paths.** A golden path starts with `tests/golden/`.
- **R14. Scanned sources.** A scanned source is a path ending in `.py` that starts with `src/`, `tests/`, `tools/` or `guardrails/`. **(decision D2)**

## 4. Layer 2 rules (job `guardrails`)

- **R20. Foundation label.** If a changed path is a foundation path (R10), the pull request MUST carry the label `foundation-change`.
- **R21. Spec alongside.** If a changed path is spec-bound (R11), at least one changed path MUST be a spec document (R12) that exists at the head.
- **R22. Golden isolation.** If a changed path is a golden path (R13), every changed path MUST be a golden path.
- **R23. Golden label.** If a changed path is a golden path, the pull request MUST carry the label `golden-change`.
- **R24. Oracle.** If a changed path is a golden path, the body MUST contain a line that, after optional leading whitespace, starts with `oracle:` followed by optional whitespace and at least one non-whitespace character.
- **R25. Suppression markers.** No line added by the pull request to a scanned source (R14) may match any of: a comment `noqa`; a comment `type: ignore`; `pragma: no cover`; the word `xfail`; a test skip (`pytest.skip`, `pytest.importorskip`, `mark.skip`, `mark.skipif`, `unittest.skip`, `SkipTest`, `skipTest(`, a decorator `@skip`, or importing `skip` from `pytest` or `unittest`). The exact patterns are the `MARKERS` table of `check.py`. A line moved unchanged still counts as added. **(decision D2)**
- **R26. Invariant files.** An invariant file is a path matching `tests/properties/test_inv_NN_<name>.py` (`NN` two digits, `<name>` of `[a-z0-9_]`). The number of invariant files at the head MUST NOT be lower than at the base, nor lower than the ratchet `invariant_files`.

## 5. Layer 3: ratchets

`guardrails/ratchet.json` is a JSON object:

```
{ "format": 1,
  "ratchets": { "coverage_line_branch_percent": int | null,
                "invariant_files": int | null,
                "hypothesis_ci_examples": int | null,
                "fuzz_minutes_per_parser": int | null,
                "corpus_min_dumps_per_variant": int | null,
                "mutation_score_percent": int | null } }
```

- **R30. Format.** The file MUST have exactly the keys above, `format` equal to 1, and every ratchet a non-negative integer or `null`. `null` means "not measured yet". Floats, booleans, duplicate keys and unknown or missing keys are malformed (R3). Percentages are integers, the floor of the measured value.
- **R31. Only up.** For every ratchet, compared with `ratchet.json` at the base: an integer MUST NOT decrease and MUST NOT become `null`; `null` MAY become an integer. If the file does not exist at the base, there is nothing to compare. Lowering a ratchet takes its own ADR (SPEC-000 ritual step 6) and a change to this rule; the job has no override.
- **R32. Mirrored numbers.** At the head, `coverage_line_branch_percent` MUST equal `[tool.coverage.report] fail_under` in `pyproject.toml` and the `--cov-fail-under=` value in `[tool.pytest.ini_options] addopts`; `hypothesis_ci_examples` MUST equal the `max_examples` of the `register_profile("ci", ...)` call in `tests/conftest.py`. A `null` ratchet is not mirrored. (SPEC-000 layer 3: "CI checks that `pyproject.toml` reflects the same numbers")
- **R33. Baselines.** The first `ratchet.json` records the values measured on 2026-10-19: coverage 100, 12 invariant files, 2,000 CI examples; `fuzz_minutes_per_parser`, `corpus_min_dumps_per_variant` and `mutation_score_percent` are `null` because the PR CI runs no timed fuzz and the corpus and nightly that measure the other two do not exist yet. The release workflow, when written, MUST fail if the last nightly mutation score is below `mutation_score_percent` (SPEC-000 layer 3); a `null` there fails the release.

## 6. The 24 h rule (job `foundation-24h`)

- **R40. Age.** If a changed path is a foundation path (R10), the job fails unless `now − t ≥ 86,400 s`, where `t` is the committer timestamp of the head commit and `now` the runner clock. Otherwise it passes with "not applicable". (SPEC-000 ritual step 3)
- **R41. Separate job.** The rule runs as its own job, `foundation-24h`, so it can be required or not in the ruleset independently of `guardrails`. SPEC-000 asks for it to be required; it is non-required in `ruleset.json` while Luiz's temporary waiver stands. **(decision D3)**
- **R42. Limit.** The committer timestamp is written by whoever makes the commit, so R40 prevents merging in haste, not by bad intent (SPEC-000 layer 2, "what it does not prevent"). The check does not run by itself when the 24 h expire; re-run the job or touch the pull request (label, edit) to re-evaluate. **(decision D4)**

## 7. Layer 1: ruleset

- **R50. Exported ruleset.** `guardrails/ruleset.json` is the organization ruleset for `core`'s default branch in the GitHub REST representation (`name`, `target`, `enforcement`, `conditions`, `bypass_actors`, `rules`): merge only via pull request with 0 required approvals, required status checks `checks (ubuntu-24.04)`, `checks (ubuntu-24.04-arm)` and `guardrails` from GitHub Actions, no force push (`non_fast_forward`), no deletion, empty bypass list. It is versioned here as the trail; CI does not apply it, and any edit to it is a foundation change (R10).

## 8. Decisions for Luiz to review

- **D1.** Base for comparisons is the merge base, not the base branch tip: a branch behind `main` would otherwise "lower" a ratchet or an invariant count that `main` raised after the branch was cut, though the merge keeps `main`'s value.
- **D2.** SPEC-000 says the markers must not appear "in `core/`"; this spec scans `src/`, `tests/`, `tools/` and `guardrails/` Python files, because skips and xfails live in tests and `tools/reproduce` is under the 100% coverage gate. The bare word `skip` is not a marker: `src/core/gate` has methods named `skip`; R25 lists the test-skip forms instead.
- **D3.** `foundation-24h` is a separate, non-required job during the waiver; making it required is a one-line change to `ruleset.json` plus applying the ruleset.
- **D4.** The hourly `schedule` re-evaluation of SPEC-000 ritual step 3 needs `checks: write` to update a check run, which this read-only workflow does not have. Pending until the waiver ends; until then the job is re-run by hand. SPEC-000's `pull_request_review` trigger is also not used: no rule here depends on reviews (reference-tuner approval on golden is a CODEOWNERS matter for the ruleset, and there is no CODEOWNERS yet).
- **D5.** SPEC-000 layer 2 names `pull_request_target`, under which the workflow file itself also comes from the base. This spec uses `pull_request` with a base-only checkout, as requested when the work was assigned: the script and its rules come from the base, but the workflow file is the head's, so a pull request that edits `guardrails.yml` could stop calling the script for itself. That edit is a foundation change (R10) and shows in the diff: visible, not prevented. Moving to `pull_request_target` (same steps; nothing from the head is executed) is a decision for Luiz.
