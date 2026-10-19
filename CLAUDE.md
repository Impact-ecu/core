# Impact · context for Claude (chat and terminal)

Trigger: **"Retome Impact ECU"** means resume this project from this file and `specs/SPEC-000-adr.md`.

## What it is
- Impact is an automotive ECU/TCU verification and recalibration platform (competing with StageX, WinOLS, ECM Titanium), owned by Luiz (platform engineer, personal GitHub `eusouluizlacerda`).
- GitHub organization `Impact-ecu`. This repository is the public `core` (AGPL-3.0). The dump corpus and family plugins live in private repositories in the organization.
- The full ADR (architecture, adversarial reviews, comparison with market leaders) is in `specs/SPEC-000-adr.md`. The diagrams exist only in the original HTML artifact in Claude.
- No fixed partner (ADR-002): files enter through `Importer` contracts and field evidence through signed `FieldAttestation`s from any enrolled attester.

## Settled decisions (2026-10-18), do not reopen without Luiz
- Reliability is the product. The critical core comes first and is built very well: binary kernel (`apply`/`release`, patches immutable by hash, diff, 12 invariants with property tests), per-ECU-family plugin contract with a conformance suite, verification gate (verdict `block | warn | no findings`, fail-closed) and reproducible provenance (JCS, hash chain). Nothing is sold before that.
- Zero cost in the MVP: everything free or open source, in test mode. Anything paid is Phase 1 or later.
- Software only: no hardware or bench of our own. The checksum oracle is delegated through a contract: enrolled attesters flash and sign a `FieldAttestation`; `golden_field` is computed from attestations (ADR-002); `golden_concordant` (two free tools agreeing) is for development, not for releasing a plugin.
- Principles: agnosticism (manufacturer, read tool, definition format, cloud, client), immutability of the original, determinism, verification before trust, the user teaches the system. ML only in a later phase, behind a precision gate. No emissions delete function, ever; the corresponding regions are `protected` and a plugin never disables TPROT or patches a verification routine.
- First product: audit and verification of third-party files (independent verify with `bypassed`/`signature_unverifiable`/`not_applicable`, per-map diff, provenance report as PDF+JSON). Checksum recalculation is an add-on.
- First family: Bosch MED17, per checksum variant (hardware + method), not per family.
- Business and legal (car-owner consent form, insurance, terms for attesters) only enter in Phase 1, when the first file goes to a third party's car.

## Core engineering rules (summary; details in SPEC-000)
- Repository language is English: code, docs, specs, commit messages.
- `src/core/` is pure Python: no I/O, network, subprocess or framework. Enforced by import-linter.
- Input is `Dump{dump_kind, memories}` (multi-memory), never a blob. `Patch` carries `memory_id`.
- No dump bytes in this public repository: `tests/golden/` holds only hashes + `oracle:`.
- 100% coverage including branches, mypy `--strict`, Hypothesis ≥ 2,000 examples per invariant, fuzzing on parsers, mutation score ≥ 90% measured nightly, ratchets in `guardrails/ratchet.json` only go up.
- Foundation paths (`src/core/kernel`, `gate`, `provenance`, `plugins/_contract.py`, `conformance`, `specs/`, `guardrails/`, `.github/`) change only with the `foundation-change` label, a spec or ADR in the same PR, and the PR open ≥ 24 h since its last commit.
- Layout: `src/core/{kernel,plugins,gate,provenance,definitions,conformance,importers,evidence}`, `tests/{properties,golden,fuzz}`, `specs/`, `guardrails/`, `.github/workflows/`.

## Claude Code setup (once per machine)
Skills, the `integrity-guardian` agent and guard hooks come from the private marketplace `Impact-ecu/skills`, declared in `.claude/settings.json`. Headless runs (`claude -p`) ignore project-declared marketplaces, so install once, from this directory:
```sh
claude plugin marketplace add Impact-ecu/skills --scope project
claude plugin install impact-common@impact --scope project
claude plugin install impact-core@impact --scope project
```
The machine needs git access to `Impact-ecu/skills` as an org member. If the default GitHub identity is another account, route the org through the right SSH host: `git config --global url."git@<host-alias>:Impact-ecu/".insteadOf "https://github.com/Impact-ecu/"` (and the same for `git@github.com:Impact-ecu/`).

## Status and next steps
- No external dependency (ADR-002). Phase −1 exit is software: SPEC-006 (`Importer`, `FieldAttestation`) and the raw importer.
- SPEC-001 to SPEC-005 are written with test vectors. Now: kernel per SPEC-001, then SPEC-006, provenance, gate, definitions, plugin contract and conformance; then local CLI and MED17 plugin per variant, released per variant when attestations reach `golden_field`.
- Infra pending: the Claude GitHub App must be installed on the `Impact-ecu` organization for chat Claude to push (today it is only on the personal account).
