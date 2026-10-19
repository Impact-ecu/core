# SPEC-006 · Importers and field evidence

Status: draft
Date: 2026-10-18
Governs: `src/core/importers/` (the `Importer` contract, dispatch and the built-in raw importer), `src/core/evidence/` (`FieldAttestation`, the attester registry, the disqualifying DTC set, `golden_field` evaluation, signed registry heads and variant admission, `review` verification), the commitment service contract, the importer conformance suite, and the shape of golden records.
Derives from: ADR-002 (all decisions; N = K = E = 2); SPEC-000 §Principles (agnosticism, read tool axis), §Phase −1 (exit criterion), §Golden files, §Security and compliance (LGPD); SPEC-001 §2 (`Dump`, `Memory`), §7 (R60–R65, reused and never redefined); SPEC-002 R2, R100–R106, R110, R121, R122, R126, R130–R135 (contract style, admission, conformance); SPEC-004 R15, R16 (admission at the gate); SPEC-005 R1–R5, R36, R50–R57, R80–R83 (hashing rules, event payloads, signing, commitments). Event payload shapes stay owned by SPEC-005 R36 (SPEC-005 revision 1 adds the four types this spec uses); this spec defines their semantics.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Every numbered rule (`R<n>`) is normative and MUST be cited by at least one test (`# SPEC-006 R<n>`). Rules of other specs are written `SPEC-00N R<n>`. A rule marked **(decision Dn)** settles a point ADR-002 leaves open; it is listed in §13 for Luiz to review, and the spec stays `draft` until he accepts it.

## 1. Problem

ADR-002 removed the fixed partner shop. Files now enter through any tool's export, and the proof that a checksum variant is right comes from any attester who writes a file to a real ECU and signs what the ECU did. Both are trust boundaries. An importer that guesses a container format feeds garbage to the kernel as if it were a dump; an importer that is not deterministic makes `image_hash` meaningless. A field attestation that can be forged, replayed, counted twice, or kept after its key is revoked turns `golden_field` into a label anyone can grant, and `golden_field` is what releases checksum recalculation to a customer's car. This spec fixes the importer contract and the raw importer, the attestation record, its hash and signature, the ECU commitment, the attester registry, and the evaluation of `golden_field` as a pure function, precisely enough that two independent implementations reach the same level, the same reasons and the same hashes.

Out of scope: tool container formats (each is a separate importer repository), definition importers (SPEC-003, a different contract), the kernel (SPEC-001), plugin verification and admission mechanics beyond what changes here (SPEC-002), gate verdicts (SPEC-004), and event chain verification (SPEC-005). Business terms for attesters are Phase 1 (SPEC-000 §Phase −1).

## 2. Common rules

- **R1.** Every hash in this spec is `sha256(JCS(x))` of the named object, per SPEC-005 R1: lowercase hex, byte strings as lowercase hex (SPEC-001 R60), no floats, integers in `[0, 2⁵³ − 1]`. `image_hash` is SPEC-001 R62, reused and never recomputed another way. (SPEC-001 §7; SPEC-005 R1)
- **R2.** Every object defined here carries a `schema` string `impact.<name>.v<major>`, part of its hash. Every listed field is required; an absent value is `null`, never an omitted key; an unknown key, a missing key or a wrongly typed value is rejected with reason `bad_shape`. Keys are ASCII; strings are hashed as given and MUST NOT contain lone surrogates. (SPEC-005 R2–R4)
- **R3.** Formats, in addition to SPEC-005 R5 (`Hex32`, `Timestamp`, `Day`, `EventId`, `TenantId`):
  ```
  ImporterId    = string matching ^[a-z][a-z0-9]*(\.[a-z0-9][a-z0-9_]*)+$     # e.g. "impact.raw"
  ContainerKind = string matching ^[a-z][a-z0-9_]{0,31}$                      # e.g. "raw"
  ToolName      = string matching ^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,63}$         # a tool name or "name version"
  Family        = SPEC-002 R2 family;  VariantId = SPEC-002 R2 checksum_variant_id (non-null here)
  Dtc           = string matching ^[PCBU][0-3][0-9A-F]{3}(-[0-9A-F]{2})?$       # R43
  UnitId        = string matching ^[A-Z0-9]{4,40}$                            # R46
  Sig           = string matching ^[0-9a-f]{128}$                             # Ed25519 signature
  ```
  (SPEC-005 R5)
- **R4. Placement and purity (decision D1).** The contract, dispatch and raw importer live in `core.importers`, which imports `core.kernel` only. Attestations, registry, DTC set, evaluation and review verification live in `core.evidence`, which imports `core.kernel` and `core.provenance` only. Neither imports `core.gate`, `core.plugins` or `core.conformance`; `core.conformance` MAY import both. Both are pure as SPEC-001 R71: no I/O, network, clock, randomness, environment reads, threads or global state. Bytes, parameters, events, identifiers and the `Verifier` (SPEC-005 R55) are inputs. (SPEC-000 §Four layers; SPEC-001 R71; SPEC-005 R90)
- **R5.** No object of this spec contains a VIN, an ECU serial number, a name, an e-mail, a file name or free text typed by a person, in clear or hashed without a secret (SPEC-005 R80). The only per-unit value is the pseudonymous commitment of R46. (SPEC-000 §LGPD; SPEC-005 R37, R80)

## 3. Importer contract

### 3.1 Protocol and outcome

```python
class Importer(Protocol):
    importer_id: str              # ImporterId, unique in the registry (R35)
    version: str                  # semver (R36)
    contract_version: int         # major of this spec's §3; 1 here
    container_kind: str           # the ContainerKind it reads; one per importer in contract version 1

    def import_file(self, data: bytes, params: ImportParams) -> Dump | ImportRejected: ...
```
```
ImportParams  = { dump_kind: DumpKind, source_tool: ToolName | null, options: object }
ImportRejected = { reason: RejectReason, container_kind: ContainerKind | null }
RejectReason  = "unsupported_container" | "encrypted_container" | "malformed" | "too_large"
              | "limit_exceeded" | "empty_input" | "bad_params" | "dump_kind_conflict"
              | "ambiguous_container"                                  # dispatch only, R25
```
- **R10.** The protocol is exactly the one above. `import_file` receives the exact bytes of one file as received and returns either a SPEC-001 `Dump` or an `ImportRejected`. It never returns `None`, a boolean or a partial `Dump`. `container_kind` in a rejection names the container the importer recognized, or `null` when it recognized none. (ADR-002 Decision 2; SPEC-001 §2.1)
- **R11. Parameters.** `dump_kind` is declared by the caller, who knows how the ECU was read; an importer never overrides it. If the container records a read mode that contradicts it, the result is `dump_kind_conflict`. `source_tool` is the declared tool that produced the file, or `null`. `options` is importer-specific: its exact key set is fixed by each importer's documentation, unknown or missing keys are `bad_params`, and it holds only JCS values (R1). (ADR-002 Decision 2; SPEC-001 R3)
- **R12. Never raise.** `import_file` MUST NOT raise for any input. The core calls it only through `run_import` (R20); an exception, a return value of another type, or a `Dump` that violates SPEC-001 R1 or the formats of SPEC-001 §2.1 is an `ImporterContractError` (reason `importer_exception`, `bad_return` or `bad_dump`), and the consumer treats the file as not imported. (SPEC-002 R11, R12 analogue)
- **R13. Never guess.** An importer that does not positively recognize its own container returns `unsupported_container`. One that recognizes an encrypted container it cannot open returns `encrypted_container`; it never tries keys, passwords or decryption by guessing. A recognized container that is truncated, has inconsistent lengths, fails its own integrity check, or maps two memories to one `memory_id` is `malformed`. No importer ever repairs, pads or truncates data to make it fit. (ADR-002 Decision 2; SPEC-000 §Principles, verification before trust)
- **R14. Determinism and purity.** For the same `(importer_id, version, data, params)` the outcome is JCS-identical, on x86-64 and arm64, whatever the call order and however often called. Importers obey SPEC-001 R70 (explicit byte order, no floats) and SPEC-001 R71. (SPEC-000 invariant 1; SPEC-001 R70, R71)
- **R15. Memories.** A container that holds several memories gives one `Dump` with all of them (decision D2). A `Dump` from an importer has `memory_id`s in SPEC-001 form, carries each memory's bytes exactly as stored in the container (decompression is allowed, any other transformation is not), and has `base_address` only where the container records it; otherwise `null` (SPEC-001 R2). (SPEC-001 R1, R2)
- **R16. Limits (decision D5).** Provisional, until measured (open question 2): `data` larger than `MAX_INPUT_BYTES = 67108864` (64 MiB) is `too_large`, checked by `run_import` before the importer is called; a `Dump` with more than `MAX_MEMORIES = 8` memories, or whose memories total more than `MAX_INPUT_BYTES` bytes, is `limit_exceeded`. Wall-time and peak-memory budgets are enforced by the hosting consumer as SPEC-002 R103–R105, with a provisional 2 s per call. (SPEC-000 §Non-functional requirements; SPEC-002 R103–R105)
- **R17. One file per import (decision D2).** An import consumes exactly one file. `input_sha256` (R21) is the SHA-256 of that file and equals the `artifact_sha256` of the SPEC-005 `import` event, so the artifact keeps one identity (SPEC-001 R2). A dump read as several separate files is not importable as one `Dump` in contract version 1 (open question 1). (SPEC-001 R2; SPEC-005 R36 `import`)

### 3.2 ImportRecord and run_import

```
ImportRecord = {
  schema: "impact.import-record.v1",
  importer_id: ImporterId,
  importer_version: string,
  source_tool: ToolName | null,              # declared, ADR-002 Decision 2
  container_kind: ContainerKind,
  input_sha256: Hex32,                       # SHA-256 of the file bytes as received
  dump_kind: DumpKind,                       # as declared in ImportParams
  options: object,                           # ImportParams.options as given
  image_hash: Hex32                          # SPEC-001 R62 of the returned Dump
}
Imported = { dump: Dump, record: ImportRecord, import_record_hash: Hex32 }
```
- **R20. run_import.** `run_import(importer, data, params) -> Imported | ImportRejected` is the only entry point. It validates `params` against the shape and formats above (`bad_params`; `options` is validated by the importer), checks R16 size, calls `import_file`, checks R12 and R16, and builds the record itself: `input_sha256 = sha256(data)`, `image_hash` from the `Dump` (SPEC-001 R62), `container_kind` from the importer, the other fields from the importer and `params`. No hash in the record is accepted from the importer. (SPEC-005 R10 analogue)
- **R21. Hash.** `import_record_hash = sha256(JCS(ImportRecord))`. The record carries `dump_kind`, `options` and `image_hash` in addition to the ADR-002 fields so that re-running the same importer version on the same file with the record's parameters reproduces `image_hash`; a record that does not reproduce is evidence of a non-conformant importer. (decision D3; SPEC-000 invariant 1)
- **R22. source_tool.** `source_tool` is a tool name and version, never a person, shop, customer or file name (R5). `run_import` validates it against `ToolName`; an invalid value is `bad_params` (R20). (ADR-002 Decision 2; SPEC-005 R37)

### 3.3 Dispatch

- **R25. dispatch.** `dispatch(importers, data, params) -> Imported | ImportRejected` runs `run_import` with every registered importer except the raw importer, in `importer_id` order. An importer recognizes the file when it returns anything other than `unsupported_container`. If exactly one importer recognizes the file, its outcome is the result (a `Dump`, or its rejection such as `encrypted_container`, `malformed` or `dump_kind_conflict`). If none recognizes it, the result is `unsupported_container` with `container_kind: null`. If two or more recognize it, the result is `ImportRejected{reason: "ambiguous_container", container_kind: null}`, even if one of them returned a `Dump`; ambiguity is never resolved by priority. (ADR-002 Decision 2, "never a guess")
- **R26.** The raw importer is never chosen by `dispatch`. It runs only when the caller selects `container_kind: raw` explicitly, so an encrypted or unknown container is never imported as raw bytes by default. (ADR-002 Decision 2)

### 3.4 Built-in raw importer

- **R27. Identity.** The core ships exactly one importer: `importer_id = "impact.raw"`, `container_kind = "raw"`, `contract_version = 1`, `version` = the version of the `core` package that contains it (it is part of `core` and versioned with it, like `versions.core` of SPEC-005 §3). (ADR-002 Decision 2)
- **R28. Parameters (decision D4).** `options = { memory_id: MemoryId }`, exactly that key, with no default: a raw file carries no memory name, and naming it `pflash` by default would mislabel an EEPROM read. `dump_kind` has no default either: a default would claim a read mode nobody declared, and SPEC-002 R41 changes verify applicability by `dump_kind`. A `memory_id` not matching SPEC-001 §2.1 or a missing or extra key is `bad_params`. (SPEC-001 R2, R3; SPEC-002 R41)
- **R29. Output.** For non-empty `data` within R16, the raw importer returns `Dump{dump_kind: params.dump_kind, memories: [Memory{memory_id: options.memory_id, base_address: null, data: data}]}`: one memory, the bytes unchanged, `base_address` always `null`, because a raw file carries no address; `identify` supplies it later and the ingestion builds a new `Dump` (SPEC-001 R2). It never returns `unsupported_container`, `encrypted_container`, `malformed`, `limit_exceeded` or `dump_kind_conflict`. Empty `data` is `empty_input` (SPEC-001 R1). (SPEC-001 R1, R2)

### 3.5 Conformance, admission and versioning

The raw importer is covered by core tests and the vectors of §12. Every other importer is a separate repository and passes this suite, whose checks live in `core.conformance` as pure functions; the runner, samples and fuzzing live outside `src/core`, as SPEC-002 §7.

- **R30.** An importer repository runs the suite of a core release pinned by git SHA, against its private sample set: positive samples (files of its container), encrypted samples where the container has an encrypted form, and negative samples (other importers' containers and random files). The runner never runs in public CI, and no sample byte is in a public repository. (SPEC-002 R110; SPEC-000 §Firmware copyright)
- **R31. Positive.** Every positive sample imports to a `Dump` whose `image_hash` equals an expected value from an oracle record `{input_sha256, expected_image_hash, oracle: {tool, version, method, date}}`, where `method` is how the expected dump was obtained outside the importer (for example the same tool's own raw export of the same read). An expected value produced by the importer's own code is forbidden, as for golden files. (SPEC-000 §Golden files)
- **R32. Negative and encrypted.** Every negative sample, and 10,000 random byte strings per run, give `unsupported_container`; every encrypted sample gives `encrypted_container`; for every positive sample, every strict prefix at 64 sizes (seeded) gives a rejection, never a `Dump`. (R13)
- **R33. Fuzz and determinism.** At least 100,000 inputs per run (random and mutated positive samples) never raise and never exceed R16; every positive sample is imported twice, in two orders, with JCS-identical outcomes. (SPEC-002 R114, R124)
- **R34. Report.** The suite emits `{ report_version: 1, core: {version, git_sha}, importer: {importer_id, version, contract_version, wheel_sha256}, samples: {revision, positive, encrypted, negative}, run: {kind, seed}, checks: [{rule, passed, cases, failures}], fuzz: {inputs, exceptions, timeouts}, limits: [{method, budget_ms, max_ms, peak_bytes}], failures: [{rule, input_sha256, reason}], verdict: "conformant" | "nonconformant" }`, integers only, lists sorted as SPEC-002 R126, no sample bytes and no file names; `report_hash = sha256(JCS(report))`. (SPEC-002 R126, R127)
- **R35. Admission.** An importer version is published only from a `release` run with `verdict: conformant` for the exact wheel in the report. Importers are discovered by the entry-point group `impact.importers`; the consumer loads one only with its matching published report, refuses a `contract_version` it does not implement (`ImporterContractError`, reason `contract_version`), refuses two importers with the same `importer_id`, and records `import_record_hash` with each artifact. (SPEC-002 R130, R132, R135)
- **R36. Versioning.** Importers use semver. Any difference in the JCS of `run_import` outcomes between the published and the candidate version, on any sample or on the stored fuzz corpus, requires a major bump; the release fails otherwise. (SPEC-002 R134)
- **R37. Sandbox.** SPEC-002 R100–R106 apply to importers unchanged (import allowlist, purity, limits, subprocess sandbox before the first third-party importer). An importer is a parser of untrusted input. (SPEC-002 R100–R106; SPEC-000 §Core engineering practices, fuzzing)

## 4. FieldAttestation

```
FieldAttestation = {
  schema: "impact.field-attestation.v1",
  subject_image_hash: Hex32,                   # SPEC-001 R62 of the image written to the ECU
  identification: { family: Family, hw_id: string | null, sw_id: string | null, checksum_variant_id: VariantId },
  write_tool: { name: ToolName, version: string },
  readback_image_hash: Hex32 | null,           # SPEC-001 R62 of the image read back after writing
  communicates: bool,
  dtcs_after_clear_and_reread: list[Dtc],      # canonical, R43
  tool_checksum_status: "ok" | "mismatch" | "not_reported",
  ecu_commitment: Hex32 | null,                # R46; null iff the unit has no readable serial (R45)
  ecu_commitment_epoch: Hex32 | null,          # R47; null iff ecu_commitment is null
  attester_key_id: Hex32,                      # SPEC-005 R50 key_id
  created_at: Timestamp
}
SignedFieldAttestation = { attestation: FieldAttestation, attestation_hash: Hex32, signature: Sig }
```
- **R40.** The shape is exactly the one above (R2). It realizes ADR-002 Decision 3, adding `schema` (R2), `family` (a `checksum_variant_id` is opaque and unique only within its family, SPEC-002 R2) and `ecu_commitment_epoch` (R47). `checksum_variant_id` is never `null`: evidence for an unknown variant counts for nothing. `write_tool.version` is a non-empty string of at most 64 characters. `ecu_commitment` and `ecu_commitment_epoch` are both `null` or both non-null. (ADR-002 Decision 3; decision D7)
- **R41. What is attested.** An attestation states that its attester wrote the image `subject_image_hash` to one physical ECU of that identification with `write_tool`, then cleared the fault memory, re-read it, and observed `communicates`, `dtcs_after_clear_and_reread` and `tool_checksum_status`. `communicates` is `true` only if the ECU answered diagnostic requests after the write. The attester reports what the tool showed; it never edits a value. (ADR-002 Decision 3; SPEC-000 §Golden files)
- **R42. Tool checksum status.** `ok`: the write tool reported that the ECU's internal checksum check passed; `mismatch`: it reported a failure; `not_reported`: the tool does not report it. `not_reported` is not evidence either way. (ADR-002 Decisions 3, 4)
- **R43. DTC canonical form.** A DTC is the SAE J2012 five-character code, uppercase, optionally followed by `-` and the two-digit uppercase hex failure type byte (the third byte of an ISO 14229 DTC), e.g. `P0601` or `U0100-87`. The list is sorted by code point with no duplicates; an empty list means none were present. `canonical_dtcs(raw: list[str]) -> list[Dtc]` strips ASCII whitespace, uppercases ASCII letters, validates each against `Dtc` (`EvidenceError`, reason `bad_dtc`), removes duplicates and sorts. A `FieldAttestation` whose list is not already canonical is `bad_shape`, so each list has one form. (ADR-002 Decision 3; SPEC-005 R3)
- **R44. Readback.** `readback_image_hash` is `null` when no comparable readback was made. When it is not `null`, it MUST be the `image_hash` of a readback with the same `dump_kind` and memories as the subject, so that equality means "the ECU holds exactly the subject". An attester whose readback is partial records `null`. (ADR-002 Decision 3)

### 4.1 ECU commitment

- **R45. Unit identifier (decision D16).** The unit identifier is the ECU serial number read through UDS `ReadDataByIdentifier` of data identifier `0xF18C` (`ECUSerialNumber`, ISO 14229-1), canonicalized by `canonical_unit_id(raw: str) -> UnitId`: uppercase ASCII letters, remove every space, `-`, `.`, `/`, `:` and `_`, then match `UnitId`, else `EvidenceError`, reason `bad_unit_id`. Part and batch identifiers (`0xF187` spare part number, `0xF191` ECU hardware number, `0xF18B` ECU manufacturing date) and the VIN MUST NOT substitute for it: the first three identify a part or a batch, so two units would collapse into one commitment; the VIN identifies the car, not the ECU, and is personal data in any form (SPEC-005 R80). A unit whose `0xF18C` cannot be read has no unit identifier: its attestation carries `ecu_commitment: null` (R52). (ADR-002 Decision 3; SPEC-005 R80)
- **R46. Construction (decision D6).** The commitment is issued by a commitment service run by the registry operator, outside `core`. The service holds a secret `commitment_secret` (32 random bytes) and a lookup table. For a request `(family, unit_id)` it computes `lookup_key = HMAC-SHA-256(commitment_secret, UTF-8 JCS({ schema: "impact.ecu-unit.v1", family, unit_id }))` as lowercase hex, and returns `ecu_commitment = table[lookup_key]`, creating that entry with 32 fresh random bytes (lowercase hex) when absent. The same unit therefore gets the same commitment for every attester, which is what lets the evaluation tell one ECU from two (R75), and the commitment carries no information about the serial. `core` never holds the secret, never computes `lookup_key` or a commitment, and only checks shapes and compares commitments for equality. (ADR-002 Decision 3; SPEC-005 R80, R82)
- **R47. Secret, table and epoch.** `commitment_secret` is generated by the operator, stored only age-encrypted with the commitment service (SPEC-005 R53 custody), never given to attesters, and never written to any repository, chain, log or object of this spec. The table lives only with the service. Secret and table together form an epoch, identified by `ecu_commitment_epoch`, 32 random bytes assigned when the epoch is created and published. A new secret (after a compromise) starts a new epoch with an empty table: commitments of different epochs are not comparable, so an attestation of another epoch than the one the evaluation uses does not qualify (`foreign_epoch`, R73) and must be renewed. (SPEC-005 R53, R82, R83)

### 4.2 Hash, signature and verification

- **R48.** `attestation_hash = sha256(JCS(FieldAttestation))`. (SPEC-001 R60; SPEC-005 R1)
- **R49. Signature.** Ed25519 per SPEC-005 R50, over the UTF-8 JCS of `{ domain: "impact.field-attestation-signature.v1", hash: attestation_hash }` (SPEC-005 R51 lists this domain), with the private key of `attester_key_id`. The private key never enters `core`; signing goes through an injected `Signer` (SPEC-005 R53). (ADR-002 Decision 3; SPEC-005 R50, R51, R53)
- **R50. verify_attestation.** `verify_attestation(signed, registry, verifier) -> list[str]` returns the empty list or exactly one reason, checking in this order: `bad_shape` (R2, R40, R43); `attestation_hash_mismatch` (R48 recomputed); `unknown_attester` (key not enrolled in `registry`, R65); `revoked_attester` (key revoked in `registry` and the attestation not saved by R77); `not_attester` (key enrolled without the `attester` role, R62); `bad_signature` (R49, through the injected `Verifier`). The public key comes only from the registry, never from the attestation, so a self-signed attestation by an unenrolled key fails at `unknown_attester`. (ADR-002 Decisions 3, 5; SPEC-005 R55, R61)
- **R51. created_at.** `created_at` is the attester's clock, self-asserted and signed by the same key. It is informational: no rule of this spec compares it with any other time, so clock skew cannot change an outcome and a key holder cannot backdate evidence into validity. The only trusted time of an attestation is the `seq` of its inclusion event (R67). (SPEC-005 R38)
- **R52. Unit without a serial (decision D17).** An attestation with `ecu_commitment: null` is valid evidence: it is authenticated and classified like any other (R73), and a negative outcome from it blocks `golden_field` (R74). It is never `qualifying` (reason `no_unit_commitment`) and counts toward none of N, K and E: without a unit identity it cannot be told apart from a re-flash of a unit already counted, so counting it toward N would let N be met by repeated writes of one unknown unit, and N, K and E stay counts over the same set of identified units. (ADR-002 Decision 4)

## 5. Disqualifying DTC set

```
DisqualifyingDtcSet = { schema: "impact.disqualifying-dtcs.v1", version: int, codes: list[string] }   # codes: 5-char Dtc, sorted, unique
```
- **R55. Matching.** A DTC of an attestation disqualifies iff its first five characters are in `codes`, so a failure type byte never hides a code. The set is data passed to the evaluation and identified by `dtc_set_hash = sha256(JCS(set))`; no rule hard-codes a code. (ADR-002 Decision 4; SPEC-000 §Golden files)
- **R56. Version 1 (decision D8).** `{ schema: "impact.disqualifying-dtcs.v1", version: 1, codes: ["P0601", "P0602", "P0603", "P0604", "P0605", "P0606", "P0607", "P060A", "P062F"] }`: the generic internal control module memory checksum, programming, KAM, RAM, ROM, processor, performance, monitoring processor and EEPROM codes, i.e. the faults a wrong checksum or bad code can raise. SPEC-000 names P0601 and P062F "and similar". `P060B`–`P060F` and `P061x` are excluded: they name specific monitoring or sensor-processing functions, not the memory or the processor. The titles were taken from public, non-SAE DTC lists, because SAE J2012 is paywalled; the set is versioned data and a later version can correct it with a source. Manufacturer-specific codes are added in later versions (open question 5). Its hash is in `specs/vectors/spec-006/vectors.json`. (SPEC-000 §Golden files)
- **R57. Publication.** `core.evidence` holds the list of published set hashes; the evaluation refuses any other set (`EvidenceError`, reason `unpublished_dtc_set`). A new version is added, never edited in place; adding one is minor. A conformance `release` run evaluates with the newest published version. (SPEC-002 R134 analogue)

## 6. Attester registry

The registry is the set of keys whose attestations and reviews count, the inclusion time of attestations, and the reviews of golden records, built from events of one SPEC-005 chain. The event payload shapes are SPEC-005 R36 (`attester_enrolled`, `attester_revoked`, `attestation_included`, `review`); this section fixes what they mean.

- **R60. Registry chain.** The registry is read from one `role: server` chain (SPEC-005 R32) of the project operator's tenant. Its trust anchor `RegistryTrust = { tenant_id, genesis_hash, key_id, public_key }` (the chain's signing key) is published with each core release. Registry events in any other chain have no effect. The chain is anchored like any server chain (SPEC-005 R42). (ADR-002 Decision 5; SPEC-005 R32, R42)
- **R61. Empty start.** The genesis enrolls the chain's signing key only; it enrolls no attester. Only `attester_enrolled` events add registry keys, so a new registry is empty and every variant is below `golden_field`. Registry keys and chain signing keys are separate sets: a registry key cannot sign chain events, and a chain key counts as an attester only if enrolled by `attester_enrolled`. (decision D14; ADR-002 Decision 5; SPEC-005 R52)
- **R62. Enrollment.** `attester_enrolled` is a human decision: `actor.kind` is `user`, the reason is stored outside the chain and referenced by `reason_commitment` (SPEC-005 R82; a reason is required), and the event is signed per SPEC-005 R57 by a key valid in the chain. `roles` is a non-empty sorted subset of `["attester", "reviewer"]`. `attester_key_id = sha256(public_key)`. Enrolling a key already in the registry (enrolled or revoked) has no effect (finding `already_enrolled`). (ADR-002 Decisions 5, 8; SPEC-005 R37, R57, R82)
- **R63. Revocation (decision D9).** `attester_revoked` names an enrolled key with a `reason` and a `reason_commitment`, signed per SPEC-005 R57. Reasons: `compromised` (the private key is or may be known to others), `misconduct` (the holder reported falsely), `error` (the enrollment itself was a mistake), all *retroactive*; and `retired` (the holder stopped attesting or rotated, R64), *not retroactive* for included attestations (R77). Revocation is permanent: a revoked key is never enrolled again. Revoking a key not in the registry, or already revoked, has no effect (findings `unknown_attester`, `already_revoked`). (ADR-002 Decision 5)
- **R64. Rotation and identity (decision D10).** `rotates` names the key the new key succeeds: `null` for a new attester. A rotation is effective only if all hold, else the enrollment has no effect (finding `bad_rotation`): the old key is in the registry at a lower `seq`, has no other successor, and is not revoked with a retroactive reason; and `rotation_signature` is the old key's Ed25519 signature over the UTF-8 JCS of `{ domain: "impact.attester-rotation-signature.v1", hash }`, with `hash = sha256(JCS({ schema: "impact.attester-rotation.v1", tenant_id, genesis_hash, old_key_id, new_key_id, new_public_key }))`. `rotation_signature` is `null` iff `rotates` is `null`. The old key's signature proves its holder chose the successor; the operator's enrollment is the human decision. A key's `identity` is the `attester_key_id` of the first key of its rotation chain, and identities, not keys, are what R75 counts as distinct attesters, so rotating cannot double an attester. After a rotation the old key is normally revoked as `retired`; its included attestations keep counting (R77), so nothing is re-signed. (ADR-002 Decision 5)
- **R65. attester_registry.** `attester_registry(events, anchors, verifier, *, test_mode=False) -> AttesterRegistry` runs SPEC-005 `verify_chain` on the events; if its status is `broken`, it raises `EvidenceError`, reason `registry_broken`, and no evaluation runs. Otherwise it applies the registry events in `seq` order per R61–R68 and returns:
  ```
  AttesterRegistry = {
    schema: "impact.attester-registry.v1",
    tenant_id: TenantId, genesis_hash: Hex32, head: { seq: int, hash: Hex32 },
    attesters: list[{ attester_key_id: Hex32, public_key: Hex32, roles: list[string], identity: Hex32,
                      enrolled_seq: int, revoked: { seq: int, reason: string } | null }],   # sorted by attester_key_id
    inclusions: list[{ attestation_hash: Hex32, attester_key_id: Hex32, seq: int }],       # sorted by attestation_hash
    record_reviews: list[{ golden_record_hash: Hex32, decision: string, reviewer_key_id: Hex32, seq: int }],  # sorted by (golden_record_hash, seq)
    findings: list[{ seq: int, reason: string }]                                          # sorted by (seq, reason)
  }
  ```
  `registry_hash = sha256(JCS(AttesterRegistry))`. The registry at a given head is a pure function of the chain up to that head. (ADR-002 Decision 5; SPEC-005 R40)
- **R66. Test keys.** The synthetic keys of §12 are test keys, as SPEC-005 R56 (which lists them): outside `test_mode` an `attester_enrolled` naming one has no effect (finding `test_key`), and a chain whose genesis enrolls one is reported by `verify_chain` as `test_key`, so `attester_registry` on the vector chain outside `test_mode` raises `registry_broken`, and a registry head signed by one is `untrusted_head` (R82). (SPEC-005 R56)
- **R67. Inclusion.** When the operator receives a signed attestation, it appends `attestation_included { attestation_hash, attester_key_id }`, signed per SPEC-005 R57. The inclusion takes effect only if the key is in the registry with role `attester` and not revoked at that `seq` (else findings `unknown_attester`, `not_attester`, `revoked_attester`) and the hash was not already included (finding `already_included`; the first inclusion stands). The inclusion `seq` is the attestation's trusted time: it is ordered by the chain and protected by its anchors, unlike `created_at` (R51). (decision D9; SPEC-005 R33, R41)
- **R68. Golden record reviews.** A `review` event with `subject_kind: golden_record` in the registry chain records a human decision on a golden record (R89). It takes effect only if `reviewer_key_id` is in the registry with role `reviewer` and not revoked at that `seq`, and its signature (R91) verifies (else findings `unknown_reviewer`, `not_reviewer`, `revoked_reviewer`, `bad_signature`). A `review` with `subject_kind: export` has no effect on the registry. (ADR-002 Decision 8; decision D11)

## 7. golden_field evaluation

### 7.1 Golden record

```
GoldenRecord = {
  schema: "impact.golden-record.v1",
  family: Family, checksum_variant_id: VariantId,
  base_image_hash: Hex32,                      # SPEC-001 R62 of the original
  version_hash: Hex32,                         # SPEC-001 R64 of the edit
  expected_image_hash: Hex32,                  # SPEC-001 R62 of the image the field accepted: the golden hash
  oracle: {
    tools: list[{ name: ToolName, version: string, image_hash: Hex32, date: Day }],   # sorted by (name, version), unique
    attestations: list[Hex32]                                                       # attestation hashes, sorted, unique
  }
}
```
- **R70.** A golden record is the shape above; `golden_record_hash = sha256(JCS(GoldenRecord))`. Its key is `(family, checksum_variant_id, base_image_hash, version_hash)`. `oracle.tools` holds what external tools produced for the same original and edit (each tool's resulting `image_hash`), and `oracle.attestations` the field evidence (ADR-002 Decision 3). The level is never stored: it is computed by R72 against the registry, so a revocation cannot leave a stale level in a file (decision D12). A tool `name` that starts with `impact` in any letter case is `EvidenceError`, reason `impact_oracle`: no golden hash comes from this project's code. (SPEC-000 §Golden files; SPEC-002 R122)
- **R71. Thresholds.** `N = 2` attestations, `K = 2` attester identities, `E = 2` ECU commitments. They are constants of `core.evidence`, never parameters; changing them needs an ADR and a major version. (ADR-002 Decision 4)

### 7.2 Evaluation

`evaluate_golden(record, attestations, registry, dtc_set, commitment_epoch, verifier) -> GoldenEvaluation`

- **R72. Inputs and purity.** `record` is a `GoldenRecord`; `attestations` a list of `SignedFieldAttestation` (any order, duplicates allowed); `registry` an `AttesterRegistry` (R65); `dtc_set` a published set (R57); `commitment_epoch` the current `ecu_commitment_epoch` (R47). The function is pure and deterministic: input order never changes the output. A malformed `record` is `EvidenceError`, reason `bad_shape`. (ADR-002 Decision 4; SPEC-001 R71)
- **R73. Per attestation.** For each hash `h` in `record.oracle.attestations`, the supplied attestations whose `attestation_hash` field equals `h` are collapsed to one: the one whose recomputed hash (R48) equals `h` if any, otherwise the first in code-point order of their JCS. A supplied attestation not listed is ignored. The entry is classified in four stages, and its `reasons` are those of the first stage that has any:
  1. **Authenticity**, first failure only: `missing` (none supplied), then the R50 reasons in R50 order.
  2. **Relevance**, every one that applies: `wrong_variant` (`family` or `checksum_variant_id` differs from the record's), `wrong_subject` (`subject_image_hash ≠ record.expected_image_hash`), `foreign_epoch` (`ecu_commitment_epoch` not null and `≠ commitment_epoch`), `impact_write_tool` (`write_tool.name` starts with `impact` in any letter case, R87).
  3. **Outcome**, every one that applies: `no_communication` (`communicates = false`), `disqualifying_dtc` (R55), `tool_checksum_mismatch` (`tool_checksum_status = mismatch`), `readback_mismatch` (`readback_image_hash` not null and `≠ subject_image_hash`).
  4. **Countability**: `no_unit_commitment` (`ecu_commitment` is `null`, R52).
  
  `reasons` is sorted by code point. An entry is `qualifying` iff `reasons` is empty, and `negative` iff its reasons come from stage 3. (ADR-002 Decision 4)
- **R74. Negative evidence (decision D11).** If any entry is `negative`, the record cannot be `golden_field` (record reason `negative_field_evidence`). A negative entry is authentic, from a key currently trusted, about this variant and this exact image: a file that one ECU of the variant rejected is not known good, whatever other units did. A negative is never resolved by removing it: a record only gains attestations (R86). It is resolved only by new evidence, a record with another key (R70), together with an approved review of the record that holds the negative (R89); or, if the negative itself was false, by revoking its key with a retroactive reason (R63), itself a recorded human decision. An enrolled attester can therefore block a golden by reporting a failure; that is fail-closed. A readback that differs from the subject (R44) is negative because the ECU does not hold the attested image. (SPEC-000 §Golden files; SPEC-000 §Verification gate, fail-closed)
- **R75. Counting.** Over qualifying entries: `attestations` is their number (distinct by `attestation_hash`, R73), `attesters` the number of distinct registry `identity` values of their keys (R64), `units` the number of distinct `ecu_commitment` values. The record reasons add `below_attestations` if `attestations < N`, `below_attesters` if `attesters < K`, `below_units` if `units < E`. With N = K = E = 2 these counts are equivalent to requiring two qualifying entries that differ in both identity and unit. Two attestations by one identity on one unit (a re-flash) count twice toward `attestations` and once toward the other two. (ADR-002 Decision 4)
- **R76. Level.** Let `matching` be the tools whose `image_hash = expected_image_hash`; the record reason `tool_disagreement` is added if any tool has a different `image_hash`. The level is the first that holds:
  1. `golden_field`: no `below_*` and no `negative_field_evidence` reason;
  2. `golden_concordant`: at least two `matching` tools with distinct `name`s and no `tool_disagreement`;
  3. `candidate`: at least one `matching` tool;
  4. `none`.
  
  Tools never raise a level to `golden_field` and never lower it from there; `tool_disagreement` is still reported. (SPEC-000 §Golden files, three levels; ADR-002 Decisions 4, 7)
- **R77. Revocation and time (decision D9).** The evaluation uses the registry state it is given. An attestation by a key revoked at that state counts only if the revocation reason is `retired` and the attestation's inclusion `seq` (R67) is lower than the revocation `seq`; otherwise it is `revoked_attester`. A retroactive reason (`compromised`, `misconduct`, `error`) removes every attestation of the key, included or not, because the key's claims can no longer be trusted at any time. The time compared is always the chain `seq`, never `created_at` (R51): a compromised key can backdate `created_at` freely but cannot insert an event below an anchored `seq`. This follows the practice of time-stamping and certificate revocation: a revocation for key compromise invalidates everything the key signed, while a revocation for supersession or cessation leaves earlier, independently time-stamped signatures valid (§13, D9). A negative entry by a key whose attestation is `revoked_attester` is not negative (it fails stage 1). (ADR-002 Decision 5)
- **R78. Output.**
  ```
  GoldenEvaluation = {
    schema: "impact.golden-evaluation.v1",
    golden_record_hash: Hex32, registry_hash: Hex32, dtc_set_hash: Hex32, commitment_epoch: Hex32,
    thresholds: { attestations: 2, attesters: 2, units: 2 },
    counts: { attestations: int, attesters: int, units: int },
    attestations: list[{ attestation_hash: Hex32, qualifying: bool, negative: bool, reasons: list[string] }],   # sorted by hash
    reasons: list[string],                                                                                 # sorted, unique
    level: "golden_field" | "golden_concordant" | "candidate" | "none"
  }
  ```
  `evaluation_hash = sha256(JCS(GoldenEvaluation))`. The result is never a boolean. (SPEC-000 §Verification gate, never a boolean)
- **R79. Re-evaluation.** Every consumer that relies on a level (the conformance `release` run, SPEC-002 R131; the gate, R83; any golden listing) evaluates against a registry head and records `registry_hash` and the head. A level computed at one head is never reused at another: after any registry event, levels are computed again, and the gate does so itself at every run (R83). (ADR-002 Decision 5)
- **R80. Errors.** Precondition failures raise `EvidenceError` with a stable reason: `bad_shape`, `bad_dtc`, `bad_unit_id`, `unpublished_dtc_set`, `unpublished_head_policy`, `registry_broken`, `impact_oracle`, `duplicate_record`. Classification outcomes (R73–R76, R83) are data, never exceptions. Each reason MUST have at least one test. (SPEC-001 R72; SPEC-005 R91)

### 7.3 Signed registry head and variant admission

```
RegistryHead       = { schema: "impact.registry-head.v1", tenant_id: TenantId, genesis_hash: Hex32,
                       seq: int, head_hash: Hex32, registry_hash: Hex32, issued_at: Timestamp, expires_at: Timestamp }
SignedRegistryHead = { head: RegistryHead, head_digest: Hex32, key_id: Hex32, signature: Sig }
HeadPolicy         = { schema: "impact.head-policy.v1", version: int, max_validity_s: int }
FieldEvidence      = { head: SignedRegistryHead, registry: AttesterRegistry, records: list[GoldenRecord],
                       attestations: list[SignedFieldAttestation], dtc_set: DisqualifyingDtcSet, commitment_epoch: Hex32 }
EvidenceAdmission  = { schema: "impact.evidence-admission.v1", status: "current" | "unavailable", reasons: list[string],
                       head_digest: Hex32 | null,
                       variants: list[{ family, checksum_variant_id, golden_field: bool, reasons: list[string],
                                        evaluations: list[Hex32] }] }   # sorted by (family, checksum_variant_id)
```
- **R81. Head.** The operator signs a `RegistryHead` after every registry event and at least once per validity period: `head_digest = sha256(JCS(head))`, signed with the `RegistryTrust` key (R60) over the UTF-8 JCS of `{ domain: "impact.registry-head-signature.v1", hash: head_digest }` (SPEC-005 R51). `seq` and `head_hash` name the registry chain's head and `registry_hash` the R65 registry at it. `issued_at` and `expires_at` are the operator's clock. (decision D18; SPEC-005 R50, R51)
- **R82. Freshness (decision D18).** `HeadPolicy` is published data like the DTC set (R57; reason `unpublished_head_policy`); version 1 is `{ schema: "impact.head-policy.v1", version: 1, max_validity_s: 86400 }`. No standard fixes the number: 24 hours is proposed and **pending author decision**. A head is usable at time `as_of` (a `Timestamp` the caller supplies, as `core` has no clock) only if: its `tenant_id`, `genesis_hash` and `key_id` equal the trust anchor's, the key is not a test key outside `test_mode` (R66), `head_digest` recomputes and the signature verifies (else `untrusted_head`); `issued_at ≤ as_of` (else `head_not_yet_valid`); `as_of < expires_at` (else `head_expired`); `expires_at − issued_at ≤ max_validity_s` in seconds (else `head_validity_too_long`); and `registry_hash(evidence.registry)` equals `head.registry_hash` and `evidence.registry.head` equals `{seq, hash: head_hash}` (else `registry_mismatch`). Timestamps are compared as UTC instants. An expired head is never used, even when nothing newer is reachable: without a fresh head a revocation could be hidden by withholding it (a freeze attack), so the outcome is fail-closed. (ADR-002 Decision 5)
- **R83. evidence_admission.** `evidence_admission(evidence, trust, policy, as_of, verifier, *, test_mode=False) -> EvidenceAdmission` is pure. If `evidence` is `None` the status is `unavailable` with reason `missing_evidence`; if R82 fails, `unavailable` with its reasons (all that apply after the first `untrusted_head`, which stops the checks); in both cases `variants` is `[]` and nothing is admitted. Otherwise the status is `current`, `head_digest` is set, and for each `(family, checksum_variant_id)` of `records` (two records with one R70 key → `EvidenceError`, reason `duplicate_record`) it evaluates every record of the variant (R72) and sets `golden_field: true` iff at least one evaluation is `golden_field` and every record of the variant whose evaluation has `negative_field_evidence` has an effective `approved` review (R68) and no effective `rejected` one in `registry.record_reviews`, by a reviewer whose identity is not the identity of any key that attested in that record (R89). Variant reasons: `no_golden_field`, `unreviewed_negative`, `rejected_negative`. `evaluations` lists the `evaluation_hash`es, sorted. (ADR-002 Decisions 4, 5)
- **R84. Gate enforcement.** The gate admits a variant for `verify` and recalculation only if it is admitted by the conformance report (SPEC-004 R15) **and** `evidence_admission` run by the gate itself at that job reports it with `golden_field: true` under status `current`. The gate never takes an admission or a level from the caller. (SPEC-004 R15, R16; ADR-002 Decision 5)

## 8. Golden records and the oracle

- **R85. Oracle record.** The `oracle:` block of a golden record is `oracle.tools` plus `oracle.attestations`, a sorted list of attestation hashes (ADR-002 Decision 3). SPEC-002 R121 and R122 use this shape. (ADR-002 Decision 3; SPEC-002 R122)
- **R86. Storage and change (decision D15).** `tests/golden/` in this public repository holds golden records (hashes only). Signed attestations live in the private corpus, because they carry an ECU commitment and identify an attester's key; the corpus steward supplies them to evaluation runs and to the evidence bundle the gate receives (R83). A record only gains attestation hashes: a golden change that removes one fails the guardrail. Adding one changes `golden_record_hash` and is a golden change: a separate PR with only golden files, label `golden-change`, and an `oracle:` body listing the attestation hashes and tools (SPEC-000 §Foundation change ritual item 5). (SPEC-000 §Golden files)
- **R87. Not produced by this project.** The subject of a counted attestation is an image whose checksums an external tool produced; `impact_write_tool` (R73) excludes attestations that declare an Impact component as write tool. This check rests on a declaration; the guarantee is the golden-change review of R86. (SPEC-000 §Golden files, "No hash in `tests/golden/` may have been produced by code from this repository")

## 9. Review (second human)

- **R89. Review of a golden record.** When a record of a variant carries a negative entry, a reviewer (a registry key with role `reviewer`) examines the negative and the new evidence and appends a `review` with `subject_kind: golden_record`, `subject_hash` the `golden_record_hash` of the record holding the negative, and `decision` `approved` (the negative is explained and the new evidence stands) or `rejected`, in the registry chain (R68). A rejection wins over any approval. (ADR-002 Decision 8; decision D11)
- **R90. Export requirement.** From Phase 1, a file goes to a third party's car only after an `approved` review (R92) of its export by a registry key with the `reviewer` role. Before Phase 1 nothing requires an export review; the event and verification exist so the requirement can be switched on without a format change. (ADR-002 Decision 8; SPEC-000 §Phase −1, Phase 1 entry)
- **R91. Event.** The `review` event (payload shape: SPEC-005 R36) has `subject_kind` `export` (appended to the chain that holds the `export` event, at a higher `seq`, with `export_ref` naming it and `subject_hash` its `report_hash`) or `golden_record` (appended to the registry chain, `export_ref: null`, `subject_hash` the `golden_record_hash`). Its `signature` is the reviewer key's Ed25519 signature (SPEC-005 R50) over the UTF-8 JCS of `{ domain: "impact.review-signature.v1", hash }`, with `hash = sha256(JCS({ schema: "impact.review.v1", tenant_id, genesis_hash, subject_kind, export_ref, subject_hash, decision }))`, binding chain, subject and decision. SPEC-005 `verify_chain` checks only its payload shape, since the reviewer key belongs to the registry, not to the chain. (ADR-002 Decision 8; SPEC-005 R36, R51)
- **R92. review_status.** `review_status(export_event, report_hash, reviews, registry, verifier) -> { status: "approved" | "rejected" | "none", reasons: list[{ seq: int, reason: string }] }` checks each `review` event with `subject_kind: export` whose `export_ref` names `export_event` by `event_id`: `export_ref` equals that event's `event_id`, `seq` and `hash`, and the review's `seq` is higher (`bad_export_ref`); `subject_hash` equals the export's `report_hash` (`report_mismatch`); the key is enrolled with role `reviewer` and not revoked in `registry` (`unknown_reviewer`, `revoked_reviewer`, `not_reviewer`); `reviewer_key_id` differs from the export's `key_id` and the review's `actor.id` differs from the export's (`same_person`); the signature verifies (`bad_signature`). An invalid review is listed and ignored. Status: `rejected` if any valid review rejects; else `approved` if at least one valid review approves; else `none`. A rejection is never overridden by a later approval: a new export is needed. (decision D13; ADR-002 Decision 8)
- **R93. Limit.** Distinct keys and distinct opaque actor ids do not prove two humans. The registry operator enrolls a reviewer key for a person other than the exporting user or the attesters; that human decision is the guarantee, and the residual risk is stated in §10. (ADR-002 Decision 8)

## 10. Security and personal data

- **R100. Threats.** The rules above answer:
  - *Forged attestation:* only registry keys verify (R50); the key comes from the anchored registry chain or a head signed by its pinned key (R60, R82), never from the attestation; registry events are signed per SPEC-005 R57, so a store writer cannot enroll a key or include an attestation without a chain key.
  - *Tampering:* any change breaks `attestation_hash` or the signature (R48–R50).
  - *Replay:* an attestation is bound to one image, one variant and one unit commitment (R40, R46), so replaying it into another record yields `wrong_subject` or `wrong_variant`; replaying it twice in one record counts once (R73).
  - *Revoked or stolen key:* a compromise revocation is retroactive (R77); a retired key's evidence is bounded by the anchored inclusion `seq`, never by `created_at` (R51, R67).
  - *Clock skew:* attestation times are never compared (R51). The only clock comparison is head freshness (R82), against the caller's `as_of`; a caller with a wrong clock can at most use a head up to `max_validity_s` old, or block itself.
  - *Freeze or rollback:* a stale registry cannot hide a revocation for longer than one head validity period (R82, R84).
  - *Rotation hijack:* a rotation needs the old key's signature and the operator's enrollment (R64); a key revoked as compromised cannot be rotated.
  - *Negative suppression:* records only gain attestations (R86), negatives block (R74), and the variant needs a review of every negative (R83, R89).
- **R101. Residual risks, stated honestly.** (a) *Sybil:* one person who obtains the enrollment of several keys under different identities satisfies K alone; R64 only links keys that declare rotation. Enrollment is a human decision (R62) and the only defense; the registry starts empty and every enrollment is a signed, reasoned chain event that can be audited. (b) *Collusion or a lie:* two enrolled attesters who agree to sign false observations produce `golden_field`; the thresholds raise the cost, they do not remove it. (c) *Same unit, two serial readings:* a tool that reports `0xF18C` in two forms that differ after R45 canonicalization makes one ECU count as two. (d) *Per-unit erasure:* after a unit's table entry is deleted (R102), a later attestation of the same unit gets a new commitment and can count as a different unit. (e) *Commitment service:* whoever operates it can link serials to commitments; it is the operator's, under its custody rules (R47). (f) *Declared fields:* `write_tool`, `source_tool` and DTC readings are declarations. (ADR-002 Decisions 4, 5)
- **R102. LGPD.** An ECU serial can be linked to a car and its owner, so it is treated as personal data: it reaches only the attester and the commitment service, never `core`, a chain or a record (R5, R46). The commitment is pseudonymous: only the holder of the secret can compute a lookup key from a serial, and the commitment itself is random. Erasure of one unit deletes its table entry, after which its commitment cannot be linked to the serial by anyone; erasure of all units destroys the secret and the table (crypto-shredding, SPEC-005 R83). Commitments already in signed attestations stay and stay comparable with each other, so no evaluation changes. Attester keys are pseudonymous: the mapping from a key to a person lives outside the chain and is erasable (SPEC-005 R81); enrollment and revocation reasons are commitments (SPEC-005 R82). (SPEC-000 §LGPD; SPEC-005 R80–R83)

## 11. Determinism, purity and errors

- **R110.** `run_import`, `dispatch`, the raw importer, `canonical_dtcs`, `canonical_unit_id`, the hash functions, `verify_attestation`, `attester_registry`, `evaluate_golden`, `evidence_admission` and `review_status` are pure (R4) and give JCS-identical results on x86-64 and arm64. The commitment service (R46) is outside `core`. (SPEC-001 R71)
- **R111.** Importer rejections are `ImportRejected` values (R10); contract violations by an importer are `ImporterContractError` (reasons `importer_exception`, `bad_return`, `bad_dump`, `contract_version`); evidence preconditions are `EvidenceError` (R80). None is a subclass of `KernelError`. Each reason MUST have at least one test. (SPEC-001 R72)
- **R112.** R29, R50, R73–R77 and R82–R84 are also runtime assertions in their functions; a failed assertion aborts the job and opens an S1. (SPEC-001 R73)

## 12. Test vectors

`specs/vectors/spec-006/vectors.json` is produced by `generate.py` in the same directory. Neither script uses the core. All data is synthetic.
- **JCS:** third-party `rfc8785`; **Ed25519:** third-party `cryptography`; both pinned with hashes in `requirements.txt`, versions in the `generator` block. `generate.py` first checks that `cryptography` reproduces RFC 8032 §7.1 TEST 1. **HMAC-SHA-256:** Python `hmac`.
- **Keys:** synthetic Ed25519 seeds `sha256("impact spec-006 synthetic <name> key; never use outside test vectors")` for the registry signer `S` and the registry keys `A`, `A2` (rotation of `A`), `B`, `C` (revoked as `compromised`), `D` (never enrolled), `E`, `F` (reviewer only) and `R` (revoked as `retired`). Test keys per R66; the vectors run with `test_mode = true` except case G27.
- **Commitments:** a fixed test `commitment_secret` `sha256("impact spec-006 synthetic commitment secret; never use outside test vectors")`, the lookup keys it gives for units X, Y and Z, and a hand-written table of synthetic pseudonyms standing for the service's random values; epochs are fixed synthetic ids.
- **Golden hash:** the released image of SPEC-001 case V9 and the base and version of case V4, read from `specs/vectors/spec-001/vectors.json` (its SHA-256 in `generator`), never recomputed by `generate.py`. A second, synthetic version and image stand for "new evidence" (R74).
- **Expected values:** every expected registry, per-attestation classification, count, reason, level and admission is written by hand in `generate.py`; only hashes, HMACs and signatures are computed there. `crosscheck.py` derives them with its own code.
- **Cross-check:** `crosscheck.py` is stdlib only and independent: canonical JSON by sorted `json.dumps` (SPEC-005 R72), its own Ed25519 transcribed from RFC 8032 §6 and checked against TEST 1, its own raw importer, canonicalizers, registry builder (event hashes, links, SPEC-005 R57 signatures, rotation and review signatures), attestation verifier, evaluator, head check and admission. It re-signs with the seeds and compares bytes, and exits non-zero on any disagreement.

| Vector | Rules | Checks |
|---|---|---|
| `keys` | R49, R66 | public keys and `key_id`s from the seeds |
| `raw_import` I1–I8 | R10, R11, R16, R17, R20, R21, R27–R29 | `Dump` with `base_address: null`, `image_hash`, `ImportRecord` and its hash; `empty_input`, `bad_params` (bad `memory_id`, extra option, bad `dump_kind`), `too_large` at 64 MiB + 1 and acceptance at exactly 64 MiB |
| `dtcs` | R43 | canonicalization, rejection of non-canonical codes |
| `unit_ids`, `commitment_service` | R45–R47 | canonical serials, `bad_unit_id`, lookup keys (HMAC), table, epochs |
| `dtc_set`, `head_policy` | R55, R56, R82 | version 1 and their hashes |
| `registry_chain`, `registries` | R60–R68 | event hashes, R57, rotation and review signatures; registry before revocations (seq 9), after (seq 12) and after a golden-record review (seq 13), with rotation identity, inclusions, the reviewer-only key and the late-inclusion finding; `registry_hash` |
| `attestations` (pool), `attestation_verify` | R48–R50, R77 | `attestation_hash`, signing input, signature; tampered with and without rehash; signed by the wrong key; unenrolled key; revoked and retired keys |
| `evaluations` G01–G33 | R42, R44, R47, R50–R52, R55, R56, R62, R64–R66, R70–R80 | the matrix below; each case carries its golden record, `golden_record_hash`, the supplied attestations, and the expected `GoldenEvaluation` and `evaluation_hash` (or error) |
| `heads`, `admissions` A1–A8 | R81–R84, R89 | signed heads; current, not yet valid, expired, too long, bad signature, registry mismatch; negative without and with an approved review |

Evaluation matrix (A, B, C, E, A2, R attesters; X, Y, Z units, W a unit without serial; `pre` = registry at seq 9, `post` at seq 12):

| Case | Setup | Level | Point |
|---|---|---|---|
| G01 | A·X, B·Y | `golden_field` | baseline N = K = E = 2 |
| G02 | A·X, A·Y; two matching tools | `golden_concordant` | one attester, two ECUs |
| G03 | A·X, B·X; one tool | `candidate` | two attesters, one ECU |
| G04 | A·X | `none` | one attestation, no tools |
| G05 | A·X, A·Y, B·X | `golden_field` | N = 3, one pair distinct in both |
| G06 | A·X, A·Y, B·Y wrong subject | `none` | the other attester has zero qualifying |
| G07 | A·X, C·Y, `pre` | `golden_field` | before revocation |
| G08 | A·X, C·Y (included before), `post` | `none` | compromise is retroactive even for included attestations |
| G09 | A·X, C·Y backdated, `post` | `none` | `created_at` never compared |
| G10 | A·X, D·Y | `none` | unenrolled key |
| G11 | A·X, A·X again (re-flash), B·Y listed, B·Y supplied twice | `golden_field` | duplicates collapse; re-flash counts once per unit |
| G12 | A·X, A2·Y | `none` | rotation: one identity |
| G13 | A·X, B·Y with a field edited after signing, rehashed | `none` | `bad_signature` |
| G14 | A·X, B·Y edited without rehash | `none` | `attestation_hash_mismatch` |
| G15 | A·X, B·Y for another variant | `none` | `wrong_variant` |
| G16 | A·X, B·Y, E·Z not communicating | `none` | negative evidence blocks |
| G17 | A·X, B·Y, E·Z with `P0601-00` | `none` | DTC with failure type byte disqualifies |
| G18 | A·X with `P0120` and `U0100`, B·Y | `golden_field` | non-disqualifying DTCs |
| G19 | A·X, B·Y with `tool_checksum_status: mismatch`; one tool | `candidate` | tool mismatch is negative |
| G20 | A·X `not_reported`, B·Y | `golden_field` | `not_reported` qualifies |
| G21 | A·X, B·Y with readback ≠ subject | `none` | readback mismatch is negative |
| G22 | A·X, B·Y of another epoch | `none` | `foreign_epoch` |
| G23 | A·X, B·Y listed, B·Y not supplied | `none` | `missing` |
| G24 | A·X, B·Y, C·Z not communicating, `post` | `golden_field` | a revoked key's negative is ignored |
| G25 | A·X, F·Y | `none` | reviewer-only key is `not_attester` |
| G26 | no attestations; tools disagree (one matches) | `candidate` | `tool_disagreement` |
| G27 | A·X, B·Y, registry built with `test_mode = false` | `EvidenceError` `registry_broken` | the vector chain's signer is a test key |
| G28 | A·X, B·Y; one matching and one disagreeing tool | `golden_field` | tools never lower a field level |
| G29 | A·X, B·Y, E·W | `golden_field` | a unit without serial does not count and does not block |
| G30 | A·X, B·W | `none` | it counts toward none of N, K, E |
| G31 | A·X, B·Y, E·W not communicating | `none` | its negative still blocks |
| G32 | A·X, R·Y included before retirement, `post` | `golden_field` | `retired` is not retroactive |
| G33 | A·X, R·Z included after retirement, `post` | `none` | inclusion after revocation does not count |

Not covered by vectors, so they need dedicated tests: R2–R5 (shapes, formats, import-linter contracts, no personal data), R11–R15 and R25–R26 (with fake importers), R22, R30–R37 (suite behavior), R40–R42 and R44 beyond the cases above, R57, R62–R64 findings `already_enrolled`, `already_revoked`, `bad_rotation` (unsigned, wrong signer, rotation from a compromised key), R66 finding `test_key` on an enrollment, R67 `already_included`, R68 invalid reviews, R70 `impact_oracle`, R72 order independence (property test over permutations), R79, R80 `duplicate_record`, `unpublished_head_policy`, R86, R87, R90–R93 (`review_status`), R100–R102, R110–R112, and the reasons of R80 and R111 not exercised above.

Vectors are test data, not golden files: no hash in them is a checksum result of a real image.

## 13. Compatibility

Changing a shape, a hash or commitment construction, a signing domain, a reason, a threshold, a stage of R73, the level rule of R76 or the admission rule of R83 is breaking: it requires a SPEC-006 revision in a `foundation-change` PR, a new `schema` major and a **major** version of `core`; verifiers keep every published schema. A new `DisqualifyingDtcSet` or `HeadPolicy` version, a new importer option of the raw importer, or a new optional API is minor. Vectors change only together with the rule they test.

### Decisions for Luiz to review

| Id | Decision | Why (with sources) |
|---|---|---|
| D1 | New packages `core.importers` (imports kernel) and `core.evidence` (imports kernel, provenance) | Keeps importers below provenance and evidence outside the gate; SPEC-000 §`core` repository structure aligned |
| D2 | One file per import in contract v1; a container with several memories is one `Dump` (R15); a multi-file manifest is deferred to contract v2 | `input_sha256` stays the file hash and the SPEC-005 `import` identity. Tool containers already bundle memories: Autotuner, https://help.autotuner.com/en/articles/2984768-files-formats: "The backup file contains all the memories of the MCU" (a `.bak` zip of `iflash0/1`, `dflash0/1`, `eflash`) |
| D3 | `ImportRecord` adds `schema`, `dump_kind`, `options`, `image_hash` to the ADR fields | Without the parameters and the output hash an import cannot be reproduced or bound to its dump |
| D4 | Raw importer: caller declares `memory_id` and `dump_kind`, no defaults; `base_address` always `null`; only by explicit choice | A default would mislabel; SPEC-001 R2 lets `identify` supply the address; raw by default would import encrypted containers as garbage |
| D5 | Limits 64 MiB input, 8 memories, 2 s, provisional | Above the largest common flash sizes; to be replaced by measurement |
| D6 | `ecu_commitment` = random pseudonym from a lookup table keyed by `HMAC-SHA-256(commitment_secret, JCS{schema, family, unit_id})`, run by an operator commitment service; attesters never hold the secret; per-unit erasure = delete the row, total erasure = destroy secret and table | EDPB Guidelines 01/2025 on pseudonymisation, https://www.edpb.europa.eu/our-work-tools/documents/public-consultations/2025/guidelines-012025-pseudonymisation_en: ¶88 "Only possession of the secret information should enable the computation of the pseudonym given the identifier"; ¶107 keyed one-way functions "like HMACs"; ¶92 lookup tables. Same unit gives the same commitment across attesters (needed for E) |
| D7 | `identification.family` added; `checksum_variant_id` non-null; `ecu_commitment_epoch` added | Variant ids are unique per family; an epoch change must be detectable |
| D8 | Disqualifying DTC set v1 = P0601–P0607, P060A, P062F, matched on the 5-character code; P060B–P060F and P061x excluded | SPEC-000 names P0601, P062F "and similar". Titles from public non-SAE lists: SAE J2012 is paywalled and was not consulted, so the set is versioned data that a later version can correct |
| D9 | Revocation by reason: `compromised`, `misconduct`, `error` retroactive; `retired` keeps attestations whose inclusion `seq` precedes the revocation; trusted time is the chain `seq`, never `created_at`; no re-signing on rotation | RFC 3161 §4, https://www.rfc-editor.org/rfc/rfc3161#section-4: for "unspecified (0), affiliationChanged (3), superseded (4) or cessationOfOperation (5) … tokens generated before the revocation time will remain valid", while after keyCompromise "Any token signed by the TSA using that private key cannot be trusted anymore". Reason codes: RFC 5280 §5.3.1, https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1. Same practice in Authenticode timestamping (Microsoft) and Sigstore ("signed while the certificate was valid") |
| D10 | K counts identities (rotation chains); rotation needs the old key's signature plus the operator's enrollment; Sybil stays a human enrollment control | TUF TAP-8, https://github.com/theupdateframework/taps/blob/master/tap8.md: the rotate file is "signed by a threshold of old public keys". TUF specification, https://theupdateframework.github.io/specification/latest/: "each KEY MUST only contribute one SIGNATURE" toward a threshold |
| D11 | Any authentic negative attestation blocks `golden_field`; resolved only by new evidence plus an approved `review`, never by deleting the negative | Fail-closed (SPEC-000 §Verification gate); a file one ECU of the variant rejected is not known good |
| D12 | Levels below field computed from `oracle.tools`; the level is never stored | ADR-002: computed, not granted; stale levels after revocation are impossible |
| D13 | One registry with roles `attester` and `reviewer`; review event signed by the reviewer key; any valid rejection wins | ADR-002 Decision 8 "second enrolled key" with one enrollment mechanism |
| D14 | Registry keys are separate from chain signing keys | Enrolling an attester must not let it sign reports |
| D15 | Signed attestations live in the private corpus; `tests/golden/` holds only records with hashes; records only gain attestations | Attestations carry commitments and key ids; removing a negative must be impossible |
| D16 | Unit identifier = UDS DID `0xF18C` ECUSerialNumber; part and batch identifiers (`0xF187`, `0xF191`, `0xF18B`) and the VIN never substitute | ISO 14229-1 defines the DID; the standard is paywalled, so the DID name was taken from the public DID table of the `pyudskit` package, not from the standard itself. A part number is shared by every unit of the part, so two units would collapse |
| D17 | A unit without a readable serial: `ecu_commitment: null`; valid evidence whose negative blocks; counts toward none of N, K, E | Keeps N, K and E over the same set of identified units; an unidentified write cannot be told from a re-flash |
| D18 | The gate checks the registry itself: a head signed by the pinned registry key, with `expires_at`; an expired, not-yet-valid or over-long head is fail-closed; maximum validity is data (`HeadPolicy`, 86400 s proposed, **pending author decision**: no standard fixes the number) | RFC 5280 §6.1.3(a)(3), https://www.rfc-editor.org/rfc/rfc5280#section-6.1.3: path validation checks the certificate "is not revoked at time T"; RFC 6960 §4.2.2.1, https://www.rfc-editor.org/rfc/rfc6960#section-4.2.2.1: responses whose nextUpdate is in the past "SHOULD be considered unreliable"; TUF specification (freeze attack): "Clients MUST NOT trust an expired file" |

## 14. Open questions

1. **Multi-file input.** Bench reads often produce separate PFlash and EEPROM files. Contract v1 imports one file (R17). Contract v2: a manifest object whose hash becomes the artifact identity (changes SPEC-005 `import`), or a `merge` step over imported dumps with its own record. Also whether one importer may read several container kinds (R10).
2. **Limits.** Measured time and memory budgets and the real maximum dump size (SPEC-001 open question 2, SPEC-002 open question 2).
3. **Is an ECU serial personal data,** and is a pseudonymous commitment enough under the LGPD (lawyer).
4. **Commitment service.** Where it runs, how attesters authenticate to it, and its availability; it is the only holder of the secret (R46, R47). Also a tombstone policy for erased units (R101 d).
5. **Manufacturer-specific DTCs.** Family-scoped disqualifying codes (P1xxx and others), each with a source, in set version 2; and checking version 1 against SAE J2012 itself.
6. **Head validity.** The 86400 s maximum of R82 is a proposal pending author decision.
7. **Thresholds per variant.** N = K = E = 2 for every variant; whether a high-risk variant should need more.
8. **Reviewer independence.** Whether a reviewer may also be one of the attesters of the variant being exported, and where the Phase 1 rule of R90 is enforced (CLI, workers).
9. **Attester terms.** The legal terms an attester accepts (truthful reporting, consent of the ECU owner) are Phase 1, but enrollment before Phase 1 happens without them.
10. **Gate report.** The gate report does not yet record `head_digest` and the evaluation hashes of R83; adding them changes SPEC-004 §6 and its vectors.
