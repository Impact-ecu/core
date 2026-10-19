# SPEC-007 · Local CLI

Status: draft
Date: 2026-10-19
Governs: the `Impact-ecu/cli` repository (to be created; not part of `core`): the `impact` command, its local store, its I/O adapters (files, clock, randomness, keys), its hosting of plugins and importers, and its output and exit-code contract. It governs nothing inside `src/core/`.
Derives from: SPEC-000 §First wins (items 2, 3, 4, 6), §Foundations ("The checksum CLI exists to force the core to exist"), §What is inside and outside the core, §`core` repository structure (consumers pin `core`), §Gaps that still require a decision ("Offline export", "Original that is not stock"), §High-value improvements #2, #6 and #7, §Binary kernel invariants (10, 12: `build.kind = lockfile`), §Verification gate, §Security and compliance, §Regulatory compliance (emissions), §Gaps and adopted improvements ("Workflow: report for the end customer", "License: model"); ADR-002; SPEC-001 R2, R8, R9, R62; SPEC-002 R34, R103–R106, R130–R135; SPEC-003 (definitions); SPEC-004 R1, R8, R9, R12–R16, R20, R29, R50–R53, R60; SPEC-005 R13–R17, R32, R36, R41, R45, R46, R50–R57, R60–R64, R80–R83, open question 12; SPEC-006 R5, R16, R17, R20, R25–R29, R35, R60, R82–R84.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Every numbered rule (`R<n>`) is normative and MUST be cited by at least one test in the CLI repository (`# SPEC-007 R<n>`). Rules of other specs are written `SPEC-00N R<n>`. A rule marked **(decision Dn)** settles a point the sources leave open; it is listed in §13 for Luiz to review, and the spec stays `draft` until he accepts it.

## 1. Problem

The moment without internet is the car on the lift (SPEC-000 §Gaps, "Offline export"). The shop needs to know, on its own laptop and without sending the file anywhere, whether a file is intact, whether it is stock or already modified, what a file service changed against the original, and, later, to export an edited file that went through the gate with provenance. SPEC-000 decided that "the core runs locally via CLI with gate and provenance" and made the CLI the first consumer, because "the checksum CLI exists to force the core to exist" (§Foundations, §High-value improvements #6).

A CLI that carries its own rules would be a second, untested core: a diff, a verdict or a hash computed in the CLI is exactly the bypass SPEC-001 R8 and SPEC-004 R9 forbid by structure. This spec fixes what the CLI may do (I/O, presentation, hosting), what it must delegate to `core` (every rule), which bytes it may write, how it signs offline, and what its exit codes and machine output mean, precisely enough that a reviewer can check every command against a rule.

Out of scope: every domain rule (SPEC-001 to SPEC-006 own them); the server, workers, API and verify page; the editor (SPEC-000 §First wins item 6, beyond `export` of a given version); tool container formats (separate importers, SPEC-006 §3.5); the PDF rendering (deferred, R54).

## 2. Scope, phase and dependencies

- **R1. Repository (decision D1).** The CLI lives in its own repository `Impact-ecu/cli`, separate from `core`, depending on `core` as a package pinned by exact version and git SHA (SPEC-000 §`core` repository structure: "API, workers, CLI, and editor depend on `core` at a pinned version"). Its visibility is decided by Luiz in an ADR before the repository is created; this spec assumes private, because it will hold the build lockfile with the private plugin and importer wheels (R93, R96). Nothing in this spec creates the repository.
- **R2. Phase.** The CLI is a Phase 0 consumer (SPEC-000 §First wins item 2, "Local CLI"). Its implementation starts only after `core` implements the functions it calls (§2.1); a command whose core function is missing is not shipped, and is never replaced by an implementation in the CLI (R10). (SPEC-000 §Foundations: "until the core meets these criteria, no consumer is a priority")
- **R3. Commands.** Phase 0 has exactly these commands; each maps to the core functions named, and to nothing else:

| Command | What it answers | Core functions (all public API) | Writes |
|---|---|---|---|
| `impact import FILE` | turn a tool's export into a `Dump` and record it | `core.importers.dispatch` or `run_import` with `RAW_IMPORTER` (SPEC-006 R20, R25, R26), `core.conformance.admit_importers` (R35), `core.provenance.append` (`import` event, SPEC-005 R36) | store copy of the original (R72), event |
| `impact verify` | "is this file intact?" | `core.gate.check_input` (SPEC-004 §3) | nothing but output; optional event (R33) |
| `impact identify` | which family, hardware, software and checksum variant | `plugin.identify` through the gate host (R86); `core.plugins.identification_json`; `core.provenance.append` (`identification_confirmed`) | optional event (R35) |
| `impact stock-check` | "stock or already modified?" | the stock-registry lookup of `core` (gap CG3; not yet specified) | nothing but output |
| `impact audit` | original vs third-party file | the core audit function (gap CG2), which uses `core.kernel.diff`, `core.definitions.span`, `core.gate.check_input`, `core.provenance.audit_record`, `audit_report`, `issue_report` | `ReportFile`, `audit` event |
| `impact export` | write an edited file | `core.kernel.apply`, `core.gate.release`, `ReleasedImage.to_dump`, `core.provenance.export_provenance`, `export_report`, `issue_report` | output binary (R71), `ReportFile`, events |
| `impact original` | emergency copy of a stored original | none (byte copy, R72) | the original's bytes |
| `impact forget` | erase a stored original | `core.provenance.append` (`erasure`, SPEC-005 R83) | event; deletes the store copy |
| `impact chain verify \| export \| ref` | is the local chain intact; carry it to sync | `verify_chain`, `verify_tenant`, `sign_key_event`, `append` (SPEC-005 R40, R45, R46, R57) | chain segment file; `chain_ref` event |
| `impact evidence load \| show` | which variants are admitted now | `core.evidence.evidence_admission` (SPEC-006 R83) | store copy of the bundle |
| `impact key init \| rotate \| show` | the installation's signing key | `core.provenance.genesis`, `sign_key_event`, `append` (SPEC-005 R32, R36, R57) | age-encrypted key file, events |

  There is one export command, named `export`, which calls `gate.release` internally; no alias `release` exists, so scripts and documentation use one name. (decision D2)

### 2.1 Core functions the CLI needs that do not exist yet

The CLI calls only public `core` API. On `main` at the date of this spec, these are missing; each is a `core` change under its owning spec, never CLI code:

| Id | Missing in `core` | Needed by | Owning spec |
|---|---|---|---|
| CG1 | `core.gate.check_input`, `core.gate.release`, `ReleasedImage`, `InputResult` (`core.gate.release` is a fail-closed stub that raises) | `verify`, `audit`, `export` | SPEC-004 |
| CG2 | One pure audit function that, from the original, the candidate, the plugin with its conformance report, the evidence bundle, `as_of`, the definition and the rule table, runs the input gate on both files, computes the layout itself, the diff, the per-map attribution and the `AuditRecord`. Today `audit_record` takes `verify_original`, `verify_candidate` and `layout` from the caller, so a consumer would have to orchestrate the plugin itself | `audit` | SPEC-005 §4 (revision), SPEC-004 |
| CG3 | Stock hash registry: object shape, signature and freshness, which bytes are compared (the whole `image_hash` changes with a VIN in EEPROM, SPEC-005 open question 4), and a pure `stock_status(...) -> stock \| modified \| unknown` | `stock-check` | new spec or SPEC-006 revision |
| CG4 | Per-map attribution of patches (`patch_hash -> map_id`) from a `Definition`, used by `export_report` and `audit_report` (`map_ids` is caller-supplied today) | `audit`, `export` | SPEC-003 or SPEC-005 revision |
| CG5 | Re-basing a `Dump` whose `base_address` is `null` with the addresses `identify` found (SPEC-001 R2: "the ingestion builds a new `Dump` with it"; SPEC-002 R4) | `import` of raw files before `diff`/`apply` | SPEC-001 or SPEC-002 revision |
| CG6 | A published `RegistryTrust` and a published `RuleTable` (SPEC-006 R60; SPEC-004 R70, blocked by SPEC-003 open question 8) | every gate call | SPEC-006, SPEC-004 |
| CG7 | Choosing a plugin when several are installed (SPEC-000 §Gaps and adopted improvements, `probe`, Phase 1) | `identify`, `verify` | SPEC-002 |

- **R4. Honest degradation.** Until CG6 is published, `check_input` and `release` report `G-UNAVAILABLE-RULES` (no identify threshold, SPEC-004 R10) and block; until a variant reaches `golden_field` with a current registry head, it is `unknown_variant` and `verify` blocks (SPEC-004 R13, R16; ADR-002 Decision 7). The CLI shows these outcomes as the gate reports them and MUST NOT soften, hide or work around them. (SPEC-000 §Verification gate, "Fail-closed")

## 3. Thin consumer boundary

- **R10. No domain logic.** The CLI MUST NOT compute any hash defined by SPEC-001 R61–R64, SPEC-004 R43, SPEC-005 or SPEC-006, any diff, verdict, finding, admission, golden level, stock classification or chain status. It obtains each from the `core` function that owns it. The only hash the CLI computes itself is the plain SHA-256 of bytes it read (`received_sha256`, SPEC-004 §3; `input_sha256` is still computed by `run_import`, SPEC-006 R20) and of its own lockfile (R93). Logic a command needs that `core` lacks goes into `core` (§2.1). (SPEC-000 §Principles, Client row: "No domain logic in the front end")
- **R11. Pinned core.** The CLI depends on exactly one `core` version, pinned by version and git SHA, installed from a hash-pinned lockfile (R93). Bumping it is a PR whose body carries the corpus report of the new version (SPEC-000 §`core` repository structure). The CLI records `core.__version__` in every output (R61).
- **R12. Private modules.** The CLI repository MUST carry an import-linter contract that forbids importing `core.kernel._internal` (SPEC-001 R8), the module of `core.gate` that constructs `InputResult` (SPEC-004 R9), `core.plugins.descriptor` (SPEC-002 R47) and any module whose name starts with `_` in any `core` package. (SPEC-001 R8; SPEC-004 R9)
- **R13. Only `ReleasedImage` becomes an output binary.** The single function of the CLI that writes an exported binary accepts only a `ReleasedImage` and obtains the bytes from `ReleasedImage.to_dump(ack)` (SPEC-004 R51). No other function writes bytes derived from a `Dump`, an `UnverifiedImage`, a diff or a version. An architecture test walks every code path that opens a file for writing and asserts R13 and R71. (SPEC-001 R8; SPEC-000 §Four layers, layer 4)
- **R14. No caller-supplied truths.** The CLI never passes to `core` a value that `core` is specified to compute (an identification to the gate, a layout to the gate, an admission, a level, a hash field of a record), and never offers a flag that would let the user supply one. (SPEC-004 R12, R16, R23; SPEC-005 R10)
- **R15. Verdict words.** No command, output field, message or exit-code name uses "pass", "passed", "approved", "valid file" or "OK" for a gate outcome. The verdict is printed exactly as the gate token (`block`, `warn`, `no findings`). (SPEC-004 R1)

## 4. I/O boundary

`core` is pure (SPEC-001 R71, SPEC-004 R80, SPEC-005 R90, SPEC-006 R4). Every effect lives in the CLI, in one adapter module per kind, injected into the command code so tests replace them (§11).

- **R20. Files.** The CLI reads each input file exactly once into memory, after checking its size with `stat` against `MAX_INPUT_BYTES` (SPEC-006 R16) and reading at most that many bytes plus one; `received_sha256` and every later step use those same bytes. It never memory-maps an input and never re-reads it mid-command. (SPEC-004 §3, `received_sha256`)
- **R21. Clock.** `as_of` (SPEC-004 R16, SPEC-006 R82) and every event `ts` (SPEC-005 R5) come from the system clock in UTC, second precision, read once per command. `as_of` is printed in the command's output envelope (R61), because no core object records it (SPEC-006 open question 10). `presented_ms` and `confirmed_ms` of an `alert_ack` are read from the same clock when the warnings are shown and when the user confirms (SPEC-004 R50).
- **R22. Clock regression (decision D3).** If `as_of` is earlier than the `ts` of the head of the installation's own chain, the CLI passes `evidence = None` to the gate for that command, which makes every variant `unknown_variant` (SPEC-004 R16), and says why. Setting the clock back would otherwise keep an expired registry head usable indefinitely offline, defeating SPEC-006 R82; with this rule a clock moved back cannot extend a head beyond the time already recorded in the chain.
- **R23. Randomness.** `EventId`s (SPEC-005 R5), commitment nonces (SPEC-005 R82), `project_id`s (R74) and key seeds come from the operating system CSPRNG (`secrets`). Nothing random is derived from time or input bytes.
- **R24. Signer and Verifier.** The CLI implements `core.provenance.Signer` and `Verifier` (SPEC-005 R53, R55) with one pinned open-source RFC 8032 PureEd25519 library (decision D4: `cryptography`, already pinned with hashes by the SPEC-005 and SPEC-006 vector generators; this closes SPEC-005 open question 1 for the CLI only). At startup the adapter checks that the library reproduces RFC 8032 §7.1 TEST 1 and refuses to sign or verify otherwise (exit 8). (SPEC-005 R50, R55)
- **R25. Plugin hosting.** The CLI is the consumer that hosts plugins, importers and region references (SPEC-002 R105). It enforces the SPEC-002 R103 time budgets per call and measures peak memory (SPEC-002 R104); a call past its budget is aborted and surfaces to `core` as the exception SPEC-002 R11 maps to an unavailable plugin, so the gate fails closed. Aborting requires running the calls outside the CLI's own interpreter: plugin, importer and reference calls run in a child process speaking JCS over stdin/stdout, the framing of SPEC-002 R106 (SPEC-002 open question 3). Seccomp and the other SPEC-002 R106 controls are REQUIRED before the first third-party plugin or importer, as SPEC-002 R106 states. (decision D5)

## 5. Commands

### 5.1 import

- **R30.** `impact import FILE --dump-kind K --origin O [--source-tool T]` runs `dispatch` over the admitted installed importers (R88); `--raw --memory-id M` runs `run_import` with the raw importer instead, and is the only way raw is chosen (SPEC-006 R26). `--dump-kind` and, for raw, `--memory-id` have no default (SPEC-006 R28). `--origin` takes one of the SPEC-000 `Artifact.origin` values (`obd_read`, `bench_read`, `boot_read`, `virtual_read`, `file_service`) and has no default. (SPEC-006 R11, R25–R28; SPEC-005 R36 `import`)
- **R31.** An `ImportRejected` is printed with its `reason` and `container_kind` and exits 6; the CLI never retries with another importer or with raw. An `ImporterContractError` also exits 6, with its reason. (SPEC-006 R10, R12, R25)
- **R32.** On success the CLI stores the original (R72), generates a `project_id` for it (R74), appends an `import` event `{artifact_sha256, image_hash, dump_kind, origin}` to its chain, and prints the `ImportRecord`, `import_record_hash`, `artifact_sha256` and `image_hash`. Importing a file whose `artifact_sha256` is already in the store prints the existing record and appends nothing. (SPEC-006 R17, R21; SPEC-005 R36)

### 5.2 verify, identify

- **R33.** `impact verify (FILE | --artifact SHA256)` runs `check_input` on the imported original (a `FILE` not yet imported is imported first per R30, with the same required flags). `declared_sha256` is the `artifact_sha256` recorded at import, and `received_sha256` is the SHA-256 of the bytes read now (R20), so a stored or re-presented file that changed on disk is reported by `G-INPUT-HASH`. At first import the declared hash is the one the user gives with `--expect-sha256` (for example the hash a tool or file service displays); without it, the declared hash is the received one and the output carries the notice `declared_hash_self` (R63). (decision D6; SPEC-004 R11, open question 11)
- **R34.** `verify` prints the input gate report and `report_hash`, the artifact state (`accepted | suspect`) and the identification, and maps the verdict to the exit code (R62). It appends no event unless the user confirms a suspect acknowledgment interactively (R36).
- **R35.** `impact identify` prints, for every installed admitted plugin, the result of `identify` as `identification_json` or `null`, sorted by family, never a VIN or other value of a `pii` location (only `memory_id` and kind). A command that needs one plugin uses the single plugin whose `identify` returned non-`null`; zero or several are `no_family` / `ambiguous_family` (exit 8), never resolved by priority or confidence, until `core` specifies selection (CG7). `identify --confirm` shows the identification and, after interactive confirmation (R37), appends an `identification_confirmed` event with exactly the SPEC-005 R36 payload. (SPEC-004 R12; SPEC-006 R25 by analogy; decision D7)
- **R36. suspect_ack.** When the input verdict is `block` and every block finding is `G-INPUT-VERIFY` (SPEC-004 R14), `verify` MAY offer to record a `suspect_ack` with the SPEC-005 R36 payload, only through R37. `G-INPUT-HASH` and `G-INPUT-IDENTIFY` are never offered an acknowledgment. (SPEC-004 R14, R22)
- **R37. Interactive confirmation only.** Every event that records a human decision (`identification_confirmed`, `suspect_ack`, `alert_ack`) is created only after the CLI shows the exact texts it covers on an interactive terminal and the user types a confirmation word that the CLI states. There is no flag, environment variable or configuration that pre-answers it; without a TTY the command stops before the decision, writes nothing and exits with the verdict code. (SPEC-000 §Verification gate, "explicit confirmation recorded in an event with the warning text"; SPEC-004 R50)

### 5.3 stock-check

- **R40.** `impact stock-check (FILE | --artifact SHA256) --registry PATH` loads a stock registry file and passes it with the dump to the core lookup (CG3), printing `stock | modified | unknown`, the registry's hash and version, and the identification used. `modified` is printed as "differs from every registered stock image of this software version", never as "tampered" or "remapped". The classification is information, not a verdict: the command exits 0 for all three (R62). Until CG3 exists the command is not shipped (R2). (SPEC-000 §Gaps, "Original that is not stock"; §High-value improvements #2)
- **R41.** The registry file is read from local disk only (R80). The CLI MUST NOT accept a registry whose shape, signature or freshness `core` rejects, and MUST NOT ship an embedded registry newer than the `core` it pins. (R10)

### 5.4 audit

- **R45.** `impact audit --original SHA256 --candidate FILE --candidate-origin O [--definition PATH]` imports the candidate (R30), calls the core audit function (CG2) and writes the `ReportFile` (SPEC-005 §8) as JCS to `--out` (R71), after appending the `audit` event through `issue_report`. It prints the per-map diff (`what_changed.patches` with `map_id`, and `foreign` runs with their region kind and name), both verify statuses, the candidate's input gate report and the `not_verified` and `notices` codes. (SPEC-000 §First wins item 4; SPEC-005 §4, R60–R63)
- **R46.** A definition is read from a local XDF or A2L file through `core.definitions.import_xdf` / `import_a2l` (SPEC-003). Its content never leaves the machine and is never written into the store. Without a definition the patches print with `map_id: null` and the report carries what the core puts in `not_verified`. (SPEC-000 §Firmware copyright and A2L: "only referenced locally by the customer")
- **R47.** The audit exit code is the verdict of the input gate on the candidate (R62); the report is written whatever the verdict. A `candidate_origin` of `file_service` or `virtual_read` shows the `origin_not_evidence` notice (SPEC-005 R22).

### 5.5 export

- **R50.** `impact export --original SHA256 --version PATH --definition PATH --combustion C --fuel F --out PATH` reads a SPEC-001 `Version` in canonical JSON, calls `apply` and then `gate.release` with the plugin, its conformance report, the evidence bundle, `as_of`, the region references, the definition, the engine context, the published rule table, the input result of `check_input` on the original, a `suspect_ack` if one exists for that input report, and `silences = []`. (SPEC-004 §4; SPEC-001 §3)
- **R51.** `GateBlocked` prints the report, writes no binary and exits 4. A `warn` verdict shows every `warn` finding's `text` and asks for the R37 confirmation; on confirmation the CLI appends the `alert_ack` event and calls `to_dump(ack)`; without it, it writes nothing and exits 3. `ExportRefused` exits 4 with its reason. (SPEC-004 R29, R50–R52)
- **R52.** After `to_dump` succeeds, the CLI builds `ExportProvenance` (with `build` per R93), the report, and the `export` event through `issue_report`, then writes the binary and the `ReportFile` (R71). If any of these steps fails, no binary is left on disk. (SPEC-005 R10–R17, R60)
- **R53. Output shape (decision D8).** Phase 0 writes an exported binary only for a single-memory dump, as the bytes of that memory. A multi-memory `Dump` has no file format until an export contract exists (open question 4): the command refuses with `unsupported_export_shape` (exit 7) after the gate has run, so the report still exists. (SPEC-006 R15, R17)
- **R54. Version from an audit.** `--version` MAY be the diff of an audit (SPEC-001 R31 `as_version`), which SPEC-000 calls "import patches from another version". The CLI then lists every `foreign` run of that audit and states that those changes are not carried into the export, because `diff` never turns them into patches (SPEC-001 R32). (SPEC-000 §Gaps and adopted improvements, "Workflow: diff between projects")
- **R55. PDF deferred.** Phase 0 renders the report as JCS JSON (authoritative, SPEC-005 R60) and as plain text on stdout; no PDF. A PDF renderer is added only with free and open-source libraries and once the verify host for the QR code exists (SPEC-005 R64; open question 5). (SPEC-000 §High-value improvements #7)

### 5.6 original, forget

- **R56. Emergency copy (decision D9).** `impact original --artifact SHA256 --out PATH` writes the stored original's bytes after re-hashing them and checking they equal `artifact_sha256`; a mismatch writes nothing and exits 5. It is the only write of binary bytes other than R13, and it never writes anything but the exact bytes received at import. (SPEC-000 §Gaps, "Offline export": "Emergency download of the original in one click, without complex login")
- **R57. Erasure.** `impact forget --artifact SHA256` deletes the store copy and appends an `erasure` event `{subject: "artifact", ref: artifact_sha256, reason}`. Earlier events and reports keep verifying (SPEC-005 R83). Confirmation follows R37.

### 5.7 chain, evidence, key

- **R58. Chain.** `impact chain verify` runs `verify_chain` on the installation's chain and prints its `ChainReport`, always with `anchored_through` and the statement that a `role: cli` chain is protected only up to the highest `seq` named by an anchored `chain_ref` in the tenant's server chain (SPEC-005 R41, R45). `chain export [--from-seq N]` writes the events as a JCS list for carrying to a sync (R81). `chain ref --server-head PATH` verifies a server chain segment the user brought and appends a `chain_ref` to its head (SPEC-005 R45: "The CLI MAY also append a `chain_ref` to the server head it last saw").
- **R59. Evidence.** `impact evidence load PATH` reads a `FieldEvidence` bundle (SPEC-006 §7.3), runs `evidence_admission` with the `RegistryTrust` and `HeadPolicy` published in the pinned `core` and `as_of` (R21), and stores the bundle only if the status is `current`. `evidence show` prints the admission of the stored bundle at the current `as_of`: status, reasons, `head_digest`, head `expires_at`, and per variant `golden_field` with reasons. The trust anchor and policy are never read from a file, flag or environment variable. (SPEC-006 R60, R82, R83)
- **R60. Key.** `impact key init --tenant T` generates an Ed25519 key, writes it age-encrypted with a passphrase to the store (R73), and appends the `genesis` event of a new `role: cli` chain enrolling exactly that key (SPEC-005 R32, R53). `key rotate` generates a new key, appends `key_enrolled` signed by the current key and `key_revoked` (`retired`) for the old one, both per SPEC-005 R57. `key show` prints `key_id`, public key, `genesis_hash` and `tenant_id`. No command prints, exports or copies the private key; the passphrase is read from the terminal or from a file descriptor named with `--passphrase-fd`, never from argv or an environment variable. A lost key is replaced by a new `key init` with a new chain; nothing is escrowed (SPEC-005 R53).

## 6. Output and exit codes

- **R61. Machine output.** With `--json`, every command writes exactly one JSON value to stdout, encoded as JCS by `core.kernel.canonical_json`, in an envelope `{schema: "impact.cli-output.v1", command, as_of, core_version, cli_version, result, notices}`, where `result` holds the core objects unchanged (reports, records, `ChainReport`, `EvidenceAdmission`) and `notices` the CLI codes of R63, sorted. Files the CLI writes that `core` hashes (`ReportFile`, chain segments, `Version`s it emits) are written as JCS bytes so their hashes recompute. Human text goes to stdout without `--json`; diagnostics go to stderr. (SPEC-001 R60; SPEC-005 R60)
- **R62. Exit codes.**

| Code | Meaning |
|---|---|
| 0 | completed; gate verdict `no findings` where a gate ran; chain `intact`; classification printed (`identify`, `stock-check`, `evidence show`) |
| 2 | usage error |
| 3 | gate verdict `warn` (for `export`, nothing was written unless the warnings were acknowledged, R51) |
| 4 | gate verdict `block`, `GateBlocked`, `ExportRefused` |
| 5 | integrity failure outside the gate: chain or tenant report `broken`, `ReportFile` binding failure (SPEC-005 R61), stored original hash mismatch (R56) |
| 6 | file not imported: `ImportRejected` or `ImporterContractError` |
| 7 | refused by a CLI data rule: output path exists or is an input or a stored original (R71), wrong permissions (R73), build drift (R94), `unsupported_export_shape` (R53) |
| 8 | precondition unavailable outside the gate: no key or wrong passphrase, `no_family`, `ambiguous_family`, Ed25519 self-test failure (R24) |
| 70 | internal error: an unexpected exception; nothing is written |

  A command that runs the gate and also hits a later failure exits with the higher code. A finding with `incident: "S1"` exits 4 and prints on stderr that an S1 incident must be opened (SPEC-004 R2). (decision D10)
- **R63. Notices.** CLI notices are fixed codes with fixed texts, never interpolating a cell value, file content, VIN or path: `declared_hash_self` (R33), `evidence_suppressed_clock` (R22), `evidence_stale` (the stored head is expired at `as_of`), `origin_unconfirmed` (R82), `best_effort_build` (R93), `foreign_not_carried` (R54).
- **R64. Disclaimer first.** Every rendering of a gate report or customer report, in text or JSON, starts with the SPEC-004 R8 disclaimer verbatim, in English. A pt-BR rendering follows only when SPEC-005 open question 9 is settled. (SPEC-004 R8; SPEC-005 R63)
- **R65. What was not verified.** The text rendering of every report lists `not_tested` (gate reports) or `not_verified` (customer reports) entries with the same prominence as findings, and states `reproducibility: best_effort` for every export the CLI made (R93). (SPEC-000 §"Done" criteria Gate: "the report always lists what was tested and what was not")

## 7. Data rules

- **R70. Nothing leaves the machine.** The CLI contains no network code: no import of `socket`, `http`, `urllib.request`, `ssl` or any HTTP client in the CLI package, enforced by import-linter and by a test that runs every command under an audit hook that fails on any `socket.*` event. It sends no telemetry, checks no license and checks for no update. Dump bytes, definitions, reports and keys move only as files the user copies. (SPEC-000 §High-value improvements #6: "the file never leaves the machine"; §Gaps and adopted improvements, License: "local CLI without license check, the paid value stays on the server")
- **R71. Writes never clobber.** Every file the CLI writes is created with `O_CREAT | O_EXCL` (written to a temporary name in the same directory, then hard-linked to the final name and the temporary removed), mode `0600`. The CLI refuses (exit 7) an output path that exists, or that resolves (same device and inode, or same real path) to any input of the command or to a stored original. There is no `--force`. (SPEC-000 §Principles, immutability of the original)
- **R72. Store copy of the original.** `import` copies the original's exact bytes into the store under its `artifact_sha256`, mode `0400`, and never modifies or rewrites it; every later read re-checks the hash (R33, R56). (SPEC-000 §Principles; SPEC-001 R2)
- **R73. Store and permissions.** The store is a directory (default `$XDG_DATA_HOME/impact`, overridable by `--store`), mode `0700`, holding the originals, the chain, the encrypted key, the evidence bundle and an index from `artifact_sha256` to `project_id` and import record. The CLI refuses to use a store or key file readable or writable by group or others (exit 7). (SPEC-000 §Protection of binaries and data)
- **R74. Identifiers.** `tenant_id` is fixed at `key init`; `project_id` is one random opaque id per imported original; `actor.id` is the opaque id of the installation's operator set at `key init`. None is derived from a name, plate, VIN, e-mail or file name. (SPEC-005 R5, R81)
- **R75. No personal data in clear.** The CLI never prints, logs, stores outside the original copy, or puts into an event or output a VIN, an ECU serial, an immobilizer or odometer value, or any byte of a dump. Output identifies files by hashes; input paths appear only in the human text of the command that received them, never in a stored object, event, JSON output or log. A plugin's `pii` locations are shown as memory and kind only. (SPEC-000 §Protection of binaries, Logs; SPEC-005 R37, R80; SPEC-006 R5)
- **R76. Emissions boundary.** No command, flag, option, plugin hook or output offers to remove, disable or hide an emissions function (DPF, EGR, SCR/AdBlue, catalyst, lambda, emissions DTC). Changes a third-party file made outside `calibration` regions are reported as the `foreign` runs `core` returns, with their region kind and name, never with an offer to keep, carry or "fix" them; `export` never carries them (R54), and the gate blocks a version that touches a protected region (SPEC-004 R23, R24). (SPEC-000 §Out of scope, §Regulatory compliance)
- **R77. Untrusted input.** Every file the CLI reads (dumps, definitions, versions, bundles, registries, chain segments) is untrusted: parsed only by `core` functions or by the JSON parser into `core` shape checks, never evaluated, unpickled or imported. (SPEC-000 §Application security)

## 8. Offline behavior and sync

- **R80. Offline is the default.** Every command works with no network (R70). Freshness-bound inputs degrade as `core` decides: with no bundle, an expired head, or R22, variants are `unknown_variant`, so `verify` and `export` block and the reason is shown (SPEC-004 R16; SPEC-006 R82). The CLI states in `evidence show` and in every gate output when the stored head expires or has expired (`evidence_stale`).
- **R81. Sync is a file.** Syncing with a tenant server is done by carrying files: `chain export` out, a server chain segment in for `chain ref` (R58). The server side appends the `chain_ref` that protects the CLI chain (SPEC-005 R45) and is outside this spec.
- **R82. Origin before sync.** A `ReportFile` the CLI issues proves integrity offline (SPEC-005 R61) but not origin until an anchored `chain_ref` in the tenant's server chain names the CLI chain at or beyond the report's event. Until then every rendering carries `origin_unconfirmed`, and the text says the report can be checked for integrity now and for origin after sync. (SPEC-005 R41, R45, R61)
- **R83. Offline-only installations: pending author decision.** Whether a CLI that never syncs may keep exporting, or must sync within a deadline, is SPEC-005 open question 12 and is **not decided here**. Until Luiz decides, the CLI exports offline under R80–R82 and enforces no sync deadline; the decision, when taken, changes this rule and its tests. Note that SPEC-006 R82 already bounds recalculation offline: an installation whose registry head is older than 24 hours cannot admit any variant.

## 9. Plugins, importers and references

- **R86. Discovery.** Installed packages are discovered only by entry points: `impact.importers` (SPEC-006 R35), `impact.ecu_plugins` for `EcuPlugin`s and `impact.region_references` for `RegionReference`s (SPEC-002 R34, R135 say "by entry point" without naming the groups; decision D11). The CLI loads only distributions listed in its lockfile (R93); an entry point from any other distribution is ignored and listed by `impact identify` as `not_in_lockfile`.
- **R87. Published report.** A plugin is used only with its published conformance report (SPEC-002 R126, R130), and an importer only with its published importer report (SPEC-006 R34, R35), both shipped as package data of the same distribution. The CLI additionally requires the report's `wheel_sha256` to be one of the hashes pinned for that distribution in its lockfile (decision D12). This is a consumer-side check: it does not close SPEC-004 open question 12, which stays Luiz's decision.
- **R88. Admission.** Importers pass `core.conformance.admit_importers` and are used only with a matching `conformant` report (SPEC-006 R35). Plugins pass `core.plugins.check_plugin`; the gate takes the plugin and its report and decides admission itself (SPEC-004 R15, R16); the CLI never filters, reorders or overrides the admitted set. Recalculation and `verify` therefore run only for variants admitted by the conformance report **and** at `golden_field` in a current evidence bundle (SPEC-006 R84).
- **R89. Versions recorded.** Every output and every report records the `family`, `version` and conformance `report_hash` of the plugins used and the `id` and `version` of the references used, as `core` builds them (SPEC-002 R135; SPEC-005 §3). The CLI's own output envelope adds the `importer_id` and `version` of the importer used and `import_record_hash`.

## 10. Distribution and build

- **R93. Lockfile build.** The CLI is installed at zero cost with `uv tool install` or `pipx install` from a hash-pinned lockfile shipped in the CLI wheel. Every export and audit record carries `build = {kind: "lockfile", value: "sha256:" + SHA-256 of that lockfile's bytes, platform: "<os>/<arch>", attestation_id: null}` and therefore `reproducibility: best_effort`; such a record is never evidence for a golden file or an `oracle:` record. (SPEC-005 R16, R17; SPEC-000 invariant 12: "An export with `kind = lockfile` (CLI on a laptop) gets `reproducibility: best_effort` and is not valid for golden")
- **R94. Build drift.** Before signing a record, the CLI checks with `importlib.metadata` that every installed distribution named in the lockfile has the pinned version; any difference refuses the signing command (exit 7, `build_drift`), so `build.value` never names a lockfile the environment does not match. (SPEC-005 R16)
- **R95. Python.** The CLI supports the Python versions `core` supports; `python` in records is read by `core` itself (SPEC-005 R15).
- **R96. Dependencies.** Runtime dependencies are free and open source, pinned with hashes: `core`, the Ed25519 library (R24), an age implementation for the key file (R60; open question 2), and the installed plugins and importers. The command-line parser is the standard library's `argparse` (decision D13). Adding a runtime dependency needs a PR stating its license and why the standard library is not enough. (SPEC-000 §Principles, zero cost; §Free or open-source stack)

## 11. Tests

- **R100. Synthetic only.** Every CLI test uses synthetic files: the SPEC-001 vector fixture dump (`pflash` 64 bytes, `dflash` 16 bytes) and dumps generated in the test, a synthetic test plugin and test importer installed through entry points in the test environment, and synthetic conformance reports and evidence bundles. No real dump, real definition or real attestation is ever used or committed. (SPEC-000 §Firmware copyright; SPEC-006 R30)
- **R101. Injected effects.** Tests run the command code in process with injected clock, randomness, file system root, terminal and Signer/Verifier (§4). Test keys and trust anchors are injected through that in-process API only; no flag, environment variable or configuration of the shipped CLI enables `test_mode` or replaces `RegistryTrust`, `HeadPolicy` or the rule table (SPEC-005 R56; SPEC-006 R66).
- **R102. Golden outputs by hash.** Each command case fixes its inputs, `as_of` and random seed, and compares the SHA-256 of its JCS stdout and of every file it wrote with an expected hash committed in the CLI repository, plus the exit code. Expected hashes for core objects are cross-checked against the `core` vectors where one exists (SPEC-005 `report_file`, `audit`, `chain`; SPEC-006 `raw_import`); a CLI output hash is a regression value, not a golden file, and needs no `oracle:`.
- **R103. Rule coverage.** Every rule of this spec has at least one test citing it (`# SPEC-007 R<n>`). The minimum list:

| Area | Cases | Rules |
|---|---|---|
| Boundary | import-linter contracts; architecture test of write paths; no `core` private import; every hash in output equals the `core` function's result | R10, R12, R13, R14 |
| Words | no output or exit name contains "pass", "approved", "OK" for a verdict | R15 |
| Import | dispatch with zero, one and two recognizing test importers (`unsupported_container`, `Dump`, `ambiguous_container`); raw only with `--raw`; missing `--dump-kind`; re-import idempotent; `too_large` at 64 MiB + 1 by `stat` | R20, R30–R32 |
| Verify | `no findings` → 0; `warn` (signed region) → 3; `block` (`bypassed`) → 4; on-disk change of the stored original → `G-INPUT-HASH`; `declared_hash_self`; rule table unpublished → `G-UNAVAILABLE-RULES` → 4 | R4, R33, R34, R62 |
| Admission | variant admitted by report but no bundle → `unknown_variant` → 4; expired head → 4 and `evidence_stale`; clock earlier than chain head → evidence suppressed | R22, R80, R88 |
| Confirmation | `alert_ack`, `suspect_ack`, `identification_confirmed` refused without a TTY; created with the exact payload with one; no pre-answer flag exists | R36, R37, R51 |
| Audit | V8-shaped original and candidate: foreign runs in protected and checksum regions listed; `origin_not_evidence`; exit = candidate input verdict; report recomputes per SPEC-005 R61 | R45–R47, R76 |
| Export | `GateBlocked` writes nothing; `warn` without ack writes nothing and exits 3; with ack writes the binary and `ReportFile`; failure after `to_dump` leaves no binary; multi-memory → `unsupported_export_shape`; audit diff as version lists foreign runs not carried; record has `best_effort` | R50–R54, R93 |
| Files | output exists → 7; output is the input, a hard link to it, or a stored original → 7; written files are `0600`, store `0700`, original copy `0400`; group-readable key → 7 | R71–R73 |
| Original | byte-identical emergency copy; corrupted store copy → 5, nothing written; `forget` appends `erasure` and the chain still verifies | R56, R57 |
| Chain | intact chain → 0 with `anchored_through: null` and the R41 statement; tampered event → 5; `chain_ref` to a brought server head; rotation events verify | R58, R60, R82 |
| Keys | private key never on stdout, stderr, logs or JSON; passphrase not accepted from argv or env; Ed25519 self-test failure → 8 | R24, R60 |
| Privacy | a synthetic dump with a VIN-shaped string in `dflash`: the string appears in no output, event, log or store object except the original copy; paths absent from JSON and events | R75 |
| Offline | every command under an audit hook that fails on any socket event | R70, R80 |
| Plugins | entry point outside the lockfile ignored; report `wheel_sha256` not in lockfile → plugin unavailable; plugin call past budget → plugin unavailable → block | R25, R86, R87 |
| Build | drifted installed version → `build_drift`, nothing signed | R94 |

## 12. Compatibility

The CLI follows semver. Changing an exit code, an output envelope field, a notice code, a command or flag name, or a file the CLI writes is breaking (major). Adding a command, a flag, a notice code or an output field is minor. A `core` bump that changes any output hash of R102 is a CLI PR with the corpus report (R11) and the changed expected hashes in the same PR, each with the reason. This spec changes only through a PR in `core`'s `specs/` with the `foundation-change` label, as any spec.

## 13. Decisions for Luiz to review

| Id | Decision | Why (with sources) |
|---|---|---|
| D1 | Separate repository `Impact-ecu/cli`, assumed private, visibility confirmed by ADR before creation | SPEC-000 §`core` repository structure (consumers pin `core`); the lockfile pins private plugin wheels (R93, R96); Impact memory records "CLI local (Fase 0) com visibilidade a decidir por ADR" |
| D2 | One export command named `export`, calling `gate.release`; no `release` alias | SPEC-000 calls the user action "export" (§Gaps, "Offline export"); one name avoids two documented paths to the same write |
| D3 | `as_of` earlier than the own chain head suppresses evidence for that command | SPEC-006 R82 assumes the caller's clock; offline, a clock set back would keep an expired head usable forever (freeze attack, SPEC-006 D18); the chain head is the only local monotonic time |
| D4 | Ed25519 through `cryptography`, with the RFC 8032 TEST 1 self-test at startup | Already pinned with hashes by the SPEC-005 and SPEC-006 generators, which run the same self-test; SPEC-005 open question 1 is left open for other consumers |
| D5 | Plugins, importers and references run in a child process from Phase 0, JCS over stdin/stdout | SPEC-002 R105 makes the CLI responsible for aborting calls past budget, which cannot be done in process; R106's framing is reused so the third-party sandbox is an addition, not a rewrite |
| D6 | `declared_sha256` = hash recorded at import; at first import, `--expect-sha256` or self-declared with the `declared_hash_self` notice | SPEC-004 R11 needs a declared hash and SPEC-004 open question 11 notes the core cannot see the file; recording at import makes the check meaningful for every later command |
| D7 | Plugin choice: exactly one non-`null` `identify`, else `no_family` / `ambiguous_family` | Mirrors SPEC-006 R25 "ambiguity is never resolved by priority"; a `probe` in `core` (CG7) replaces it |
| D8 | Phase 0 exports single-memory dumps only, as that memory's bytes | No export container contract exists (SPEC-006 covers import only); writing a guessed multi-memory format would be domain logic in the CLI |
| D9 | `original` writes the stored original's exact bytes after re-hashing; it is the only binary write besides `ReleasedImage.to_dump` | SPEC-000 §Gaps "Emergency download of the original in one click"; a blanket "no bytes other than `to_dump`" rule would forbid it, so this exception is explicit and narrow |
| D10 | Exit codes of R62 (0, 2, 3, 4, 5, 6, 7, 8, 70) | Scripts at the shop must tell `warn` from `block` from "not imported" without parsing text; 2 matches `argparse`, 70 is `EX_SOFTWARE` |
| D11 | Entry-point groups `impact.ecu_plugins` and `impact.region_references` | SPEC-002 R34 and R135 require entry points without naming them; `impact.importers` is SPEC-006 R35. To be added to SPEC-002 as a minor revision |
| D12 | A plugin or importer report is used only if its `wheel_sha256` is pinned in the CLI lockfile | Binds the caller-supplied report (SPEC-004 R15 accepted limitation) to the installed wheel on the consumer side; does not decide SPEC-004 open question 12 |
| D13 | `argparse`, no CLI framework | Zero extra dependency in the lockfile and in the `best_effort` build; the CLI has no logic that needs more |

## 14. Open questions

1. **Offline-only installations (pending author decision; SPEC-005 open question 12).** May a CLI that never syncs keep exporting, or must it sync within a deadline? Not decided here (R83).
2. **age implementation.** Which free and open-source age library or binary encrypts the CLI key file with a passphrase (SPEC-005 R53), pinned with hashes; a subprocess to the `age` binary needs it installed, a Python binding adds a compiled dependency.
3. **Encryption of the store.** Originals in the store hold VIN and immobilizer data (SPEC-000 §Plugin SDK `pii_in_flash`). R72–R73 rely on file permissions; whether the store copy must also be encrypted at rest (with which key custody) is open (SPEC-005 gap G5).
4. **Export container.** Writing a multi-memory `Dump` back into a tool's container needs an export contract, the inverse of SPEC-006 importers, with its own conformance (R53).
5. **PDF and QR.** Which free renderer, and what the QR encodes while no verify host exists (SPEC-005 R64, R65; SPEC-000 §High-value improvements #7).
6. **Windows.** Shops often use Windows laptops. `O_EXCL`, POSIX modes, hard links and the R25 child process work differently there; whether Phase 0 supports Windows, and how R71–R73 map to ACLs, is open.
7. **Stock registry (CG3).** Shape, signer, freshness and which bytes are compared, so that a stock file with a different VIN in EEPROM is still `stock`.
8. **Rule table and engine context.** Where `--combustion` and `--fuel` come from when the definition does not say (SPEC-004 open question 5), and whether a tenant table is ever accepted by the CLI (SPEC-004 open question 10). Until then only the table published with `core` is used.
9. **Silences.** Phase 0 passes `silences = []` (R50); whether the CLI ever creates `rule_silence` events, and where it stores the justification and its nonce (SPEC-005 R82).
10. **Reviewer in Phase 1.** Where SPEC-006 R90 (approved review before a file goes to a third party's car) is enforced for CLI exports (SPEC-006 open question 8).

### Gaps found in other specs

| Id | Where | Gap | Handled by |
|---|---|---|---|
| G1 | SPEC-006 R82 vs SPEC-004 R13, R16 | R82 says an offline installation with an old head "fails closed [for recalculation] while audit and verify keep working", but SPEC-004 R16 removes the variant from the admitted set and R13 then blocks the input `verify` (`unknown_variant`). With an expired head, `verify` blocks too | R4, R80 state the SPEC-004 behavior; SPEC-006 R82 wording to be aligned |
| G2 | SPEC-005 §4, `audit_record` | Verify statuses and layout are caller-supplied, so the audit's integrity depends on the consumer's orchestration | CG2 |
| G3 | SPEC-002 R34, R135 | Entry-point groups not named | D11 |
| G4 | SPEC-004 open question 11 | No declared hash exists for a first, local import | D6 |
