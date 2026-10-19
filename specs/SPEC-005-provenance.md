# SPEC-005 · Provenance

Status: draft
Date: 2026-10-18
Revision: 1 (2026-10-18), proposed with SPEC-006 (ADR-002): R36 adds the `attester_enrolled`, `attester_revoked` and `review` payloads; R40 step 3, R51, R56 and R57 cover them. Adding event types is minor under §13.
Governs: `src/core/provenance/`, the export and audit records the gate builds, the `Event` hash chain, the customer report, and the contract of the independent reproduction script.
Derives from: SPEC-000 invariant 12, §Data model (Event row and Modeling decisions), §"Done" criteria (Provenance), §Gaps and adopted improvements ("Workflow: report for the end customer"), §CI pipeline (`release`), §Security and compliance, §Gaps that still require a decision (WORM vs LGPD, bus factor), §Core engineering practices (Reproducible build). Hash base: SPEC-001 §7 (R60–R65), reused and never redefined. This spec is the only owner of `Event` payload shapes (R36); SPEC-004 cites them.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Every numbered rule (`R<n>`) is normative and MUST be cited by at least one test (`# SPEC-005 R<n>`). Each rule names its source. A rule marked **(decision Dn)** settles a point SPEC-000 and SPEC-001 leave open; it is listed in §13 for Luiz to review, and it stays `draft` until he accepts it.

## 1. Problem

SPEC-000 promises that every export is reproducible from its report alone by an independent script on a clean machine, and that the audit trail proves nothing was removed even though database permissions cannot be checked from outside. The shop sells this to the car owner as protection: "this is exactly what was changed, and here is the proof". If the record omits a field, the export cannot be rebuilt; if the hash is computed differently by two programs, the proof is worthless; if the chain can be truncated silently, the audit lies. This spec fixes the record, the chain, the signature, the report and the reproduction contract precisely enough that two independent implementations agree on every hash.

Out of scope: the hashes of patches, images, layouts and versions (SPEC-001 §7), the gate report content and the verdict rules (SPEC-004), plugin identification and verify statuses (SPEC-002), storage, transport and the user interface of the verify page.

## 2. Common rules

- **R1.** Every hash in this spec is `sha256(JCS(x))` of the named object `x`, as lowercase hex, with byte strings encoded per SPEC-001 R60 and the prohibitions of SPEC-001 R65. No float appears in any object of this spec. Integers are non-negative and ≤ 2⁵³ − 1 (SPEC-001 R60, §2). Hashes of patches, images, layouts and versions are exactly SPEC-001 R61–R64; this spec never recomputes them another way. (SPEC-001 §7, SPEC-000 invariant 12)
- **R2.** Every object defined here carries a `schema` string of the form `impact.<name>.v<major>`, and `schema` is part of its hash. (decision D1; SPEC-001 §10 versioning)
- **R3.** Every listed field is required. An absent value is JSON `null`, never an omitted key. An unknown key, a missing key, or a value of the wrong type is rejected (`ProvenanceError`, reason `bad_shape`), so each object has exactly one canonical form. Inside chain verification the same defect is the finding `bad_shape` (R40), not an exception. (SPEC-001 R65)
- **R4.** All object keys are ASCII. String values are hashed as given, without Unicode normalization, and MUST NOT contain lone surrogates. (SPEC-001 R60)
- **R5.** Identifiers and timestamps are supplied by the caller; `core.provenance` never generates them (SPEC-001 R71 purity applies to this package, see R90). Formats:
  ```
  TenantId, ProjectId, ActorId = string matching ^[a-z0-9][a-z0-9-]{0,63}$     # opaque, R81
  EventId   = string matching ^[0-9a-f]{32}$                                     # 128 random bits from the caller
  Hex32     = string matching ^[0-9a-f]{64}$                                     # a SHA-256 hash
  Timestamp = string matching ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$   # UTC, second precision
  Day       = string matching ^[0-9]{4}-[0-9]{2}-[0-9]{2}$                       # UTC date
  Digest    = string matching ^sha256:[0-9a-f]{64}$
  ```
  (decision D2)

## 3. ExportProvenance

What every exported binary carries (SPEC-000 invariant 12).

```
ExportProvenance = {
  schema: "impact.export-provenance.v1",
  dump_kind: DumpKind,                         # SPEC-001 §2.1
  image_hash_original: Hex32,                  # SPEC-001 R62, of o
  image_hash_apply: Hex32,                     # SPEC-001 R62, of apply(o, v)
  image_hash_release: Hex32,                   # SPEC-001 R62, of the ReleasedImage
  layout_hash: Hex32,                          # SPEC-001 R63
  version_hash: Hex32,                         # SPEC-001 R64
  definition_hash: Hex32,                      # SPEC-003 R52, the definition the gate evaluated (SPEC-004 R31)
  patch_hashes: list[Hex32],                   # SPEC-001 R61, canonical order (SPEC-001 R25)
  overlaps: list[[Hex32, Hex32]],              # sorted as in SPEC-001 R64
  checksum_patch_hashes: list[Hex32],          # SPEC-001 R61, sorted by (memory_id, offset)
  versions: {
    core: string,                              # semver of the core package, which contains the kernel
    plugins: list[{ family: string, version: string, conformance_report_hash: Hex32 }],   # sorted by family; SPEC-000 §Plugin SDK; SPEC-002 R135
    gate_rules: string,                        # version of the gate rule tables (SPEC-004)
    references: list[{ id: string, version: string }]      # sorted by id; independent references used (SPEC-002 R34); [] if none
  },
  gate_report_hash: Hex32,                     # sha256(JCS(gate_report)) = SPEC-004 report_hash (R43 there)
  verdict: "no findings" | "warn",
  alert_ack: EventRef | null,
  input_verify: {
    status: VerifyStatus,                      # SPEC-000 §Plugin SDK: ok | fail | bypassed | signature_unverifiable | not_applicable
    result: "ok" | "failed_acknowledged",
    suspect_ack: EventRef | null
  },
  python: { implementation: string, version: string },   # e.g. "cpython", "3.12.3"
  build: { kind: "image" | "lockfile", value: Digest, platform: string, attestation_id: string | null },
  reproducibility: "full" | "best_effort"
}
EventRef = { event_id: EventId, seq: int, hash: Hex32 }   # §5; always an event of the chain the export event is appended to (R13, R14)
```

- **R10.** The gate builds the record from the kernel objects it already holds (`Dump`, `Version`, `MemoryLayout`, `UnverifiedImage`, `ReleasedImage`) and computes every hash field itself. No hash field is accepted from a caller. `definition_hash` is computed from the `Definition` the gate received (SPEC-004 R31), and `versions.references` lists the `RegionReference`s the gate used for the dual step (SPEC-004 R27), with the versions they declare. (SPEC-000 invariant 12, SPEC-001 R9; SPEC-002 R34)
- **R11.** Consistency, asserted at runtime before any export: `image_hash_original == v.base_image_hash`; `layout_hash == v.layout_hash`; recomputing SPEC-001 R64 from `image_hash_original`, `layout_hash`, `patch_hashes` and `overlaps` yields `version_hash`; `patch_hashes` is the canonical order of SPEC-001 R25; every pair in `overlaps` references hashes in `patch_hashes`; `definition_hash`, `layout_hash` and `versions.references` equal the gate report's output `subject` fields of the same names (SPEC-004 §6). Failure → `ProvenanceError`, reason `inconsistent_record`. (SPEC-001 R25, R64, R73)
- **R12.** `checksum_patch_hashes` lists the patches `q` that `apply_checksum_patches` applied to obtain the release, sorted by `(memory_id, offset)`; SPEC-001 R40 makes them disjoint, so the order is total. It is required for reproduction (§9) even though invariant 12 does not name it. (SPEC-000 §"Done" criteria Provenance, SPEC-001 R40; gap G3)
- **R13.** `verdict` is never `block` (SPEC-001 R42). With `warn`, `alert_ack` MUST reference an `alert_ack` event (R36) in the same chain as the record's `export` event, the signer's chain named by the report's `genesis_hash` (R32), whose payload has `image_hash_release` and `gate_report_hash` equal to the record's, and whose `warnings` are the `warn` findings of that gate report (SPEC-004 R50). With `no findings`, `alert_ack` MUST be `null`. Otherwise `ProvenanceError`, reason `missing_alert_ack` or `alert_ack_mismatch`. The verdict tokens are SPEC-004's (`no findings`, `warn`). (SPEC-000 invariant 10, SPEC-001 R42, SPEC-004 R1)
- **R14.** `input_verify.status` is the `VerifyReport.status` of the original. The original is suspect if and only if its input gate verdict was `block` (SPEC-004 R14); `signature_unverifiable` is a green `verify` (SPEC-004 `G-INPUT-SIGNED` is a `warn`) and leaves `result = ok`. A suspect original requires `result = failed_acknowledged` and a `suspect_ack` reference to a `suspect_ack` event (R36) in that same chain whose payload `image_hash` equals `image_hash_original` and whose `verify_status` equals `input_verify.status`, which is the input gate report's `subject.verify_status` (SPEC-004 §6, R22); a non-suspect original requires `result = ok` and `suspect_ack: null`. Otherwise `ProvenanceError`, reason `missing_suspect_ack`. (SPEC-000 §Verification gate, Input; §Ingestion pipeline step 5)
- **R15.** `python` is read by `core.provenance` from the running interpreter (`sys.implementation.name`, `platform.python_version()`), never passed in, so a caller cannot misstate it. (SPEC-000 invariant 12)
- **R16.** `build` is supplied by the packaging that runs the core:
  - `kind = image`: `value` is the OCI digest of the image the export ran in; `platform` is the OCI platform string (`linux/amd64`, `linux/arm64`); `attestation_id` is the SLSA attestation `build_id` when the image came from the `release` workflow, else `null`.
  - `kind = lockfile`: `value` is `sha256:` + the SHA-256 of the exact bytes of the hash-pinned lockfile the environment was installed from; `platform` is `<os>/<arch>` of the machine; `attestation_id` is `null`.
  (SPEC-000 invariant 12, §Core engineering practices Reproducible build, §CI pipeline `release`; gap G1)
- **R17.** `reproducibility` is `best_effort` if and only if `build.kind = lockfile`, else `full`. A `best_effort` record is never evidence for a golden file or an `oracle:` record. (SPEC-000 invariant 12, §Golden files)
- **R18.** `provenance_hash = sha256(JCS(ExportProvenance))`. (SPEC-000 §Standards SPEC-005, SPEC-001 R60)
- **R19.** The record contains no tenant, project, actor, timestamp, VIN or other personal data in its own fields. For a `no findings` export, the same export inputs on the same build therefore give the same `provenance_hash`. A `warn` record embeds the `alert_ack` `EventRef` (SPEC-000 invariant 12 requires the ack's `event_id`), whose `hash` covers that event's `tenant_id`, `ts` and `event_id`: such a `provenance_hash` is bound to tenant and time indirectly and is reproduced only with the same ack event. Binding to tenant and time is otherwise the job of the `export` event (§5). (SPEC-000 invariant 1 and 12; decision D3)

## 4. AuditRecord

The record of the first product, the audit of a third-party file against its original (SPEC-000 §First wins, item 4; §Gaps and adopted improvements, "Workflow: diff between projects"). No binary is exported, so there is no release.

```
AuditRecord = {
  schema: "impact.audit-record.v1",
  dump_kind: DumpKind,
  image_hash_original: Hex32,                  # SPEC-001 R62
  image_hash_candidate: Hex32,                 # SPEC-001 R62, of the third-party file as a Dump
  candidate_origin: Origin,                    # SPEC-000 §Data model Artifact.origin
  layout_hash: Hex32,                          # SPEC-001 R63
  diff_patch_hashes: list[Hex32],              # SPEC-001 R31, in its (memory_id, offset) order
  foreign: list[{ memory_id, offset, length, region_kind, region_name }],   # SPEC-001 R32, in its order
  verify: { original: VerifyStatus, candidate: VerifyStatus },
  versions: { core, plugins, gate_rules },     # as in §3
  gate_report_hash: Hex32,                     # input gate report on the candidate (SPEC-004)
  python: { implementation, version },
  build: { kind, value, platform, attestation_id },
  reproducibility: "full" | "best_effort"
}
```

- **R20.** Every hash and list is computed by the core from `diff(o, x, layout)` (SPEC-001 R31, R32), never accepted from a caller. (SPEC-001 R31, R32)
- **R21.** R15–R17 and R19 apply unchanged. `audit_hash = sha256(JCS(AuditRecord))`. (SPEC-000 invariant 12)
- **R22.** `candidate_origin` of `virtual_read` or `file_service` adds the `origin_not_evidence` notice to the report (§8). (SPEC-000 §Modeling decisions)

## 5. Event and the per-signer chain

```
Event = {
  schema: "impact.event.v1",
  tenant_id: TenantId,
  seq: int,                                    # 0 for genesis, then +1 per event
  event_id: EventId,
  project_id: ProjectId | null,
  type: EventType,
  payload: object,                             # shape fixed by type, R36
  actor: { kind: "user" | "system", id: ActorId },
  ts: Timestamp,
  prev_hash: Hex32,
  hash: Hex32
}
```

- **R30.** An event has exactly the fields above. `seq` and `schema` are added to the SPEC-000 Event row because gap detection (R41) and versioning (R2) need them; the SPEC-000 row is aligned in the same `foundation-change` PR as this spec, as SPEC-001 R3 did for `dump_kind`. (SPEC-000 §Data model Event; gap G8)
- **R31.** `hash = sha256(JCS(event without the "hash" member))`. (SPEC-000 §Data model Event)
- **R32. Genesis and chain identity (decisions D4, D10).** A chain belongs to exactly one signer (R53): the tenant's server instance (`role: server`, one per tenant) or one CLI installation (`role: cli`). Its first event has `seq = 0`, `type = genesis`, `prev_hash` = 64 `0` characters, `project_id = null`, `actor.kind = system`, and a payload that enrolls exactly one signing key, the signer's (R52). The chain is identified by `(tenant_id, signer_key_id, genesis_hash)`, where `signer_key_id` is the key the genesis enrolls and `genesis_hash` is the genesis event's `hash`. Only its signer appends to a chain, so an offline CLI never needs another writer's head and two writers never share one. (SPEC-000 §Data model Event; §Gaps that still require a decision, "Offline export": "The core runs locally via CLI with gate and provenance")
- **R33. Link.** For `seq = n > 0`: `prev_hash` equals the `hash` of the event with `seq = n − 1` of the same chain, and `tenant_id` equals the genesis `tenant_id`. (SPEC-000 §Data model Event)
- **R34. Append-only.** Events are never updated or deleted, including by an admin. A correction is a new event. The pure function `append(head: Event, draft) -> Event` sets `seq = head.seq + 1` and `prev_hash = head.hash` and computes `hash`; the storage MUST make `(genesis_hash, seq)` unique so concurrent appends to one chain cannot fork it. Monthly partitioning is storage only: the chain is continuous across partitions. (SPEC-000 §Modeling decisions, §Data model Event)
- **R35.** `event_id` is unique within a chain. (SPEC-000 §Data model Event key)
- **R36. Types.** This table is the only definition of event payloads: SPEC-004 (R12, R14, R22, R50, R52, R53, R60, R62) reads these shapes and defines none of its own. Payload fields are all required (R3); lists are sorted as stated. `VerifyStatus` is SPEC-002's.

| `type` | Required by | `payload` |
|---|---|---|
| `genesis` | R32 | `{ role: "server" \| "cli", signing_keys: [ {key_id, public_key} ] }`, exactly one key, the signer's |
| `key_enrolled` | R52, R57 | `{ key_id, public_key, signer_key_id: Hex32, signature }`; signed per R57 by a key already valid in this chain |
| `key_revoked` | R46, R52, R57 | `{ key_id, reason: "compromised" \| "retired", signer_key_id: Hex32, signature }`; signed per R57 by a key already valid in this chain (the revoked key itself MAY sign) |
| `import` | SPEC-000 §Ingestion pipeline step 1, SPEC-001 R2 | `{ artifact_sha256: Hex32, image_hash: Hex32, dump_kind, origin }`; `artifact_sha256` is the file's sha256 as received |
| `identification_confirmed` | SPEC-000 §Verification gate, Input ("recorded manual confirmation"); SPEC-004 R12 | `{ artifact_sha256: Hex32, image_hash: Hex32, family, plugin_version, hw_id: string \| null, sw_id: string \| null, checksum_variant_id: string \| null }`; it confirms exactly that identification of that file |
| `suspect_ack` | SPEC-000 §Ingestion pipeline step 5; SPEC-004 R14, R22 | `{ artifact_sha256: Hex32, image_hash: Hex32, input_report_hash: Hex32, verify_status: VerifyStatus }`; `input_report_hash` is the input gate report's `report_hash` |
| `alert_ack` | SPEC-000 invariant 10, §Verification gate; SPEC-001 R42; SPEC-004 R50, R52, R62 | `{ image_hash_release: Hex32, gate_report_hash: Hex32, warnings: [ {finding_id: Hex32, rule_id, text} ], presented_ms: int, confirmed_ms: int }`; `warnings` lists every `warn` finding of the gate report's `findings`, in report order, with the gate's `finding_id` and fixed `text`; `presented_ms` and `confirmed_ms` are the consumer's clock, integer milliseconds since the Unix epoch, when the warnings were shown and confirmed; `presented_ms ≤ confirmed_ms` |
| `rule_silence` | SPEC-000 §Verification gate ("silence a rule per project with a recorded justification"); SPEC-004 R60 | `{ rule_id, justification_commitment: Hex32 \| null }`; the justification typed by a person is stored outside the chain and referenced by an R82 commitment; the consumer MUST NOT create a silence with an empty justification; `null` means no justification and the silence has no effect |
| `chain_ref` | R45, R57 (decision D10) | `{ chain_signer_key_id: Hex32, genesis_hash: Hex32, seq: int, head_hash: Hex32, signer_key_id: Hex32, signature }`: the head (`seq`, `head_hash`) of another chain of the same tenant, identified by `chain_signer_key_id` and `genesis_hash`, as seen by this chain's signer; signed per R57 by a key already valid in this chain |
| `export` | SPEC-000 invariant 12 | `{ provenance_hash, report_hash, key_id, signature }` (§7, §8) |
| `audit` | SPEC-000 §First wins item 4 | `{ audit_hash, report_hash, key_id, signature }` |
| `consent_granted` | SPEC-000 §Gaps (consent per dump), §LGPD | `{ artifact_sha256, purpose: "corpus", legal_basis: "consent" \| "legitimate_interest", record_commitment: Hex32 }` |
| `consent_revoked` | same | `{ artifact_sha256, purpose: "corpus", record_commitment: Hex32 }` |
| `erasure` | SPEC-000 §Gaps (WORM vs LGPD), §Deletion and retention | `{ subject: "artifact" \| "record", ref: Hex32, reason: "data_subject_request" \| "consent_revoked" \| "retention_expired" }` |
| `attester_enrolled` | ADR-002 Decisions 5, 8; SPEC-006 R62, R64 | `{ attester_key_id: Hex32, public_key, roles: list["attester" \| "reviewer"], rotates: Hex32 \| null, reason_commitment: Hex32, signer_key_id: Hex32, signature }`; `roles` non-empty, sorted, no duplicates; `reason_commitment` is an R82 commitment to the reason a person gave; signed per R57 by a key already valid in this chain; it enrolls an attester registry key (SPEC-006 §6), never a signing key of this chain (R52) |
| `attester_revoked` | ADR-002 Decision 5; SPEC-006 R63 | `{ attester_key_id: Hex32, reason: "compromised" \| "misconduct" \| "retired" \| "error", reason_commitment: Hex32, signer_key_id: Hex32, signature }`; signed per R57 by a key already valid in this chain |
| `review` | ADR-002 Decision 8; SPEC-006 R90–R92 | `{ export_ref: EventRef, report_hash: Hex32, decision: "approved" \| "rejected", reviewer_key_id: Hex32, signature }`; `signature` is made by the attester registry key `reviewer_key_id` per SPEC-006 R91; R40 checks the shape only, and SPEC-006 R92 checks the reference, the key and the signature |

  An unknown `type` → reason `unknown_type`; a payload with a wrong key set, a wrong value type, a list out of its stated order or size, or `presented_ms > confirmed_ms` → reason `bad_payload`. (SPEC-000 §Data model Event; decision D5)
- **R37.** Hashed event fields never hold personal data in clear: no VIN, plate, name, e-mail, phone, or free text typed by a person. `actor.id` is opaque (R81); personal content is referenced only by commitment (R82). (SPEC-000 §LGPD, §Logs)
- **R38.** `ts` is hashed metadata from the caller. Order is `seq`, never `ts`. A `ts` earlier than its predecessor's is reported as the informational finding `ts_regression`; it does not break the chain. (SPEC-001 R71; decision D2)

## 6. Verification, gaps and anchoring

`verify_chain(events, anchors, verifier, *, test_mode: bool = False) -> ChainReport`

```
ChainReport = {
  status: "intact" | "broken",
  genesis_hash: Hex32 | null,
  signer_key_id: Hex32 | null,
  head: { seq, hash } | null,
  anchored_through: int | null,                # highest seq covered by a matching anchor
  findings: list[{ seq: int, reason: string, informational: bool,
                   missing: { first: int, last: int } | null }]   # sorted by (seq, reason)
}
```

- **R40. Algorithm.** Given events sorted by `seq` (input order is not trusted; the verifier sorts):
  1. The first event MUST satisfy R32 (including `actor.kind = system` and exactly one enrolled key), else `not_genesis`. A `genesis` event at any `seq > 0` is also `not_genesis` and enrolls nothing. A genesis payload whose `signing_keys` has other than one entry is `not_genesis`, not `bad_payload`. A genesis that is `not_genesis` for any reason enrolls nothing.
  2. For each event, in order: an event without exactly the R30 keys is the finding `bad_shape` and skips the other checks of this step (a shape error found during verification is a finding, never an exception); recompute R31 (`hash_mismatch` if different); check `seq` equals predecessor `seq + 1` (`seq_gap`, with `missing` the range of absent `seq` values, or `seq_duplicate`); check `prev_hash` equals the predecessor's stored `hash` (`prev_mismatch`); check `ts` (R38, informational `ts_regression`); check `tenant_id` (`tenant_mismatch`); check R35 (`duplicate_event_id`); check R36 (`unknown_type`, `bad_payload`); an enrolled key equal to the R56 test key outside test mode → `test_key`.
  3. For each `export` and `audit` event, verify its signature (R51) through the injected `verifier` (R55) with the key it names; for each `key_enrolled`, `key_revoked`, `attester_enrolled`, `attester_revoked` and `chain_ref` event, verify its R57 signature with `signer_key_id`. The key MUST be enrolled at a lower `seq` (`unknown_key`) and not revoked at a lower `seq` (`revoked_key`); then the signature MUST verify (`bad_signature`). A `key_enrolled` with any of these findings enrolls nothing, and a `chain_ref` with any of them vouches for nothing (R45, R61); a `key_revoked` takes effect even with a finding (fail-closed: an unauthenticated revocation can only stop signatures, never admit one). Attester events have no effect on this chain's signing keys; with any finding the chain is `broken`, and SPEC-006 R65 builds no registry from it. A `review` signature is not checked here (SPEC-006 R92).
  4. For each anchor (R42), with findings at the anchored `seq`: recompute `statement_hash` (`bad_anchor`); the anchor's key MUST be enrolled at a `seq` ≤ the anchored `seq` (`unknown_key`) and not revoked at a `seq` ≤ the anchored `seq` (`revoked_key`; a revocation at exactly the anchored `seq` counts); then its signature MUST verify (R51, `bad_signature`); a `tenant_id` or `genesis_hash` different from the chain's → `anchor_mismatch`; else if the anchored `seq` is beyond the last event → `truncated`; else the event at that `seq` MUST have the anchored `head_hash` (`anchor_mismatch`).
  5. `status = broken` if any non-informational finding exists, else `intact`. Only `ts_regression` is informational. `missing` is null for every reason other than `seq_gap`. Verification continues after a finding, so the report lists every one.

  The result is never a boolean. (SPEC-000 §Data model Event "verifiable outside the database"; SPEC-000 §Verification gate, never a boolean)
- **R41. Gaps.** A removed event in the middle is detected by `seq_gap` and `prev_mismatch` even without anchors. A removed tail, or a rewritten history whose hashes were all recomputed, is detected only by an anchor that covers it (`truncated`, `anchor_mismatch`). Events after the latest anchor are not protected against either attack; every report surface that shows chain status MUST show `anchored_through`. A `role: cli` chain has no anchor of its own: it is protected only up to the highest `seq` named by an anchored `chain_ref` in the tenant's server chain (R45), and everything after that is unprotected in the same way. Within an unprotected window, anyone with write access to the store can also append events; R57 keeps such an append from enrolling a key or from vouching for a CLI chain through `chain_ref`, but not from adding unsigned events. (SPEC-000 §Modeling decisions)
- **R42. Anchor.** At least once per UTC day on which a `role: server` chain gained events, its head is anchored (a `role: cli` chain is anchored only through R45):
  ```
  AnchorStatement = { schema: "impact.anchor.v1", tenant_id, genesis_hash, seq, head_hash, day: Day }
  AnchorFile      = { statement: AnchorStatement, statement_hash: Hex32, key_id, signature }
  ```
  `statement_hash = sha256(JCS(statement))`; the signature follows R51. (SPEC-000 §Data model Event "head anchored daily in an external location")
- **R43. Anchor location.** Each `AnchorFile` is written to at least one external location that (a) cannot be modified or deleted with the credentials of the event database or of the host that runs it, (b) keeps every anchor, never only the latest, and (c) the tenant can read without the operator. A copy delivered to the tenant counts as one location. No vendor is fixed here (open question 2). An anchor's authenticity rests on this location, not on its signature alone: an anchor carries no `seq` of its own, so a key later revoked as `compromised` could sign a forged anchor for an earlier `seq`. After a `compromised` revocation, an anchor signed by that key is trusted only where the external location shows it was written before the revocation; that check is the consumer's, outside `core` (open question 11). (SPEC-000 §Data model Event, §Modeling decisions)
- **R44. Segment verification.** `verify_segment(checkpoint, events, anchors, verifier, server_chain: list[Event] | None)` runs R40 steps 2–5 from a checkpoint instead of genesis; `server_chain` is required for a `role: cli` chain and is the tenant's server chain, whose `chain_ref`s and anchors are checked with `verify_chain`. `Checkpoint = { seq, hash, keys: list[{ key_id, public_key, enrolled_seq: int, revoked_seq: int | null }] }` carries the key state at `seq`, so steps 3 and 4 apply R52 exactly as from genesis. A checkpoint is accepted only if an anchor (R42) of the same chain covers its `seq` and `hash` or, for a `role: cli` chain, an anchored `chain_ref` (R45) does (else `unanchored_checkpoint`). R35 is checked within the segment only, and the report says so. In the MVP the verify page (R65) runs `verify_chain` from genesis, since the operator holds the whole chain; checkpoints exist for a retention checkpoint (open question 6). (SPEC-000 §Gaps and adopted improvements, `verify/{report_hash}`)
- **R45. Cross-references between chains (decision D10).** When a CLI chain syncs, the server chain appends one `chain_ref` with the CLI chain's signer key (`chain_signer_key_id`), `genesis_hash` and synced head (`seq`, `head_hash`), signed per R57 by a key valid in the server chain; an unsigned or invalidly signed `chain_ref` protects nothing. A CLI chain is anchored only through these references: the server chain is anchored (R42), and an anchored `chain_ref` protects the CLI chain up to the referenced `seq` as R41 protects a chain up to its anchor. CLI events after the latest referenced head are unprotected against truncation and rewrite, like the unanchored events of R41. The CLI MAY also append a `chain_ref` to the server head it last saw. A `ReportFile` exported offline is valid before sync (R61 needs only its own chain) and stays valid after it, because the CLI chain is never rewritten.
- **R46. Tenant-level revocation (decision D10).** A CLI key MAY be revoked in its own chain or by a `key_revoked` event in the server chain naming it (lost or stolen device). `verify_tenant(chains, anchors, verifier) -> list[ChainReport]` runs `verify_chain` on each chain; checks every `chain_ref` against the chain it names (`chain_ref_mismatch` when the referenced `seq` does not carry `head_hash`); and, for a CLI key revoked in the server chain at server `seq` `n`, reports every `export` or `audit` event of that CLI chain beyond the highest `seq` referenced by a `chain_ref` at a server `seq` lower than `n` as `unconfirmed_after_revocation`. Result: `TenantReport = { status: "intact" | "broken", chains: list[ChainReport] (sorted by genesis_hash), findings: list[{ genesis_hash, seq, reason, informational: false }] (sorted by (genesis_hash, seq, reason)) }`; cross-chain findings (`chain_ref_mismatch`, `unconfirmed_after_revocation`) go only in `findings`, keyed by the chain they concern, and `status` is `broken` if any chain is broken or any cross-chain finding exists. `verify_tenant` is covered by dedicated tests, not by vectors.

## 7. Signing

SPEC-000 requires the exportable format to be signed (§Standards, SPEC-005) and the one-page report to be signed for the work order (§First wins item 4), with zero cost in the MVP (§Principles).

- **R50. Algorithm (decision D6).** Signatures are Ed25519 as defined in RFC 8032 (PureEd25519: no prehash, no context). Public keys are the 32-byte RFC 8032 encoding, signatures 64 bytes, both lowercase hex. `key_id = sha256(public key bytes)` in lowercase hex. (SPEC-000 §Standards SPEC-005, §Principles zero cost)
- **R51. Signing input.** The signed message is the UTF-8 JCS of `{ domain, hash }`, where `domain` is `impact.report-signature.v1` for reports (the `hash` is `report_hash`), `impact.anchor-signature.v1` for anchors (the `hash` is `statement_hash`), and `impact.key-event-signature.v1` for the events of R57 (the `hash` is R57's). SPEC-006 adds `impact.field-attestation-signature.v1` (SPEC-006 R49) and `impact.review-signature.v1` (SPEC-006 R91). The domains separate the uses, so a report signature can never be presented as an anchor or R57 event signature. (SPEC-001 R60, R65)
- **R52. Keys in the chain.** A signing key is valid only through its chain: enrolled by `genesis` or `key_enrolled`, ended by `key_revoked` (in the same chain or, for a CLI key, in the server chain, R46). A signature is accepted only if its key was enrolled at a lower `seq` than the event carrying it and not revoked at a lower `seq`. Revocation never invalidates earlier signatures. (SPEC-000 §Data model Event, §Licensing "signed metadata per tenant")
- **R53. Custody (decision D7).** One key pair and one chain (R32) per signer: the tenant's server instance, and each CLI installation that exports offline. A CLI installation creates its chain, enrolling its key in its own genesis, when it is installed. The private key never enters `core`: `core.provenance` builds the signing input and receives the signature from an injected `Signer { key_id, sign(message: bytes) -> bytes }` (R90). At rest the private key exists only encrypted with age: server keys with SOPS + age in the infra repository, CLI keys as an age-encrypted file on the device. It is never logged and never in a public repository. Signing keys are not escrowed: losing one only stops future signatures; earlier ones stay verifiable from the public keys in the chain, and a new key is enrolled. (SPEC-000 §Free stack Secrets, §Offline export, §Bus factor)
- **R54.** Release artifacts of `core` keep cosign keyless signing in the `release` workflow; that is a separate mechanism from R50. Why not sigstore for reports: the CLI exports offline (SPEC-000 §Offline export) and cannot reach Fulcio or Rekor; keyless needs an OIDC identity the shop does not have; and a public transparency log would publish a permanent, undeletable entry per export, the WORM-vs-LGPD conflict SPEC-000 resolved against. (SPEC-000 §CI pipeline `release`, §Gaps WORM vs LGPD)
- **R55. Verifier.** `core.provenance` checks signatures only through an injected `Verifier { verify(public_key: bytes, message: bytes, signature: bytes) -> bool }`, mirroring `Signer`; it contains no Ed25519 code and imports no cryptographic library, so it stays pure (R90). Consumers inject an RFC 8032 implementation (open question 1); the reproduction script carries its own (R72). (SPEC-000 §Four layers, layer 4)
- **R56. Test key.** The synthetic key of §12 (`key.key_id` in `specs/vectors/spec-005/vectors.json`), and the synthetic keys of SPEC-006 §12 (`keys` in `specs/vectors/spec-006/vectors.json`), are never valid in a real chain: enrollment and `verify_chain` report it as `test_key` unless called with `test_mode = true`, which only vector tests pass.
- **R57. Signed key and reference events.** A `key_enrolled`, `key_revoked`, `attester_enrolled`, `attester_revoked` or `chain_ref` event is signed by `signer_key_id` over `hash = sha256(JCS({ schema: "impact.key-event.v1", tenant_id, genesis_hash, seq, type, payload }))`, where `payload` is the event payload without `signature` and `genesis_hash` is the chain's. Binding the chain and the position means a key event cannot be replayed into another chain or another `seq`. Without it, anyone who can write to the store could enroll a key after the last anchor and sign reports with it, or append a `chain_ref` that puts a self-made CLI chain under the server chain's anchors. (SPEC-000 §Data model Event; decision D10)

## 8. Customer report

```
Report = {
  schema: "impact.report.v1",
  kind: "export" | "audit",
  tenant_id: TenantId,
  genesis_hash: Hex32,                         # identifies the chain, R32
  record: ExportProvenance | AuditRecord,
  record_hash: Hex32,                          # provenance_hash (R18) or audit_hash (R21)
  signer: { key_id, public_key },
  sections: {
    what_changed: {
      patches: list[{ memory_id, offset, length, region_name, map_id: string | null }],   # canonical order
      foreign: list[{ memory_id, offset, length, region_kind, region_name }]            # audit only; [] for export
    },
    integrity: {
      input_verify: VerifyStatus,
      input_result: "ok" | "failed_acknowledged",           # export; for audit: verify.original vs candidate below
      candidate_verify: VerifyStatus | null,                # audit only
      verdict: "no findings" | "warn" | null,               # null for audit
      reproducibility: "full" | "best_effort",
      checksum_patch_count: int
    },
    not_verified: list[NotVerifiedCode]                     # sorted, no duplicates
  },
  notices: list[NoticeCode],                                # sorted, no duplicates
  disclaimer: string
}
ReportFile = { report: Report, report_hash: Hex32, event: Event }   # the export or audit event
```

- **R60.** `report_hash = sha256(JCS(report))`. The JSON `ReportFile` is the authoritative report. The signature is not inside `report`: it is in the `export` or `audit` event payload, over `report_hash` (R51), so the report needs no self-reference. (SPEC-000 §Gaps and adopted improvements, report "with hash")
- **R61. Binding.** A `ReportFile` is valid only if: `report_hash` recomputes; `record_hash` recomputes from `record`; `signer.key_id = sha256(signer.public_key)`; `event` recomputes (R31), has `type` equal to `kind`, the same `tenant_id`, and a payload whose `report_hash`, record hash (`provenance_hash` or `audit_hash`) and `key_id` equal the report's; and `event.payload.signature` verifies (R51). Reasons: `report_hash_mismatch`, `record_hash_mismatch`, `key_id_mismatch`, `event_mismatch`, `bad_signature`. These checks prove integrity: the report is the one the key in `signer` signed. They do not prove origin: `signer.public_key` travels inside the report, so a self-signed forgery passes them. Origin requires, in addition: the chain named by `genesis_hash` is the tenant's `role: server` chain, or a `role: cli` chain named by an anchored `chain_ref` in that server chain (R45); and `signer.key_id` is enrolled and not revoked before `event.seq` in that chain and, for a CLI key, not revoked in the server chain (R52). It is checked with `verify_chain` on the report's chain and, for a CLI chain, `verify_tenant` (R46) on the tenant's chain export, which MUST report no `chain_ref_mismatch` and no `unconfirmed_after_revocation` for the report's chain. A self-made chain with a chosen `tenant_id` fails the first condition. (SPEC-000 §Standards SPEC-005; §First wins item 4)
- **R62. Plain-language sections.** `what_changed`, `integrity` and `not_verified` are the three sections SPEC-000 names. They are derived only from these inputs, and each code of R63 names its own: `record`; the version's patches and metadata; the output gate report (export) or the input gate report on the candidate (audit), both SPEC-004, including their `subject.signed_regions`; and the `import` event of the original (its `origin`, R36). Nothing in them is free text typed by a person. `region_name` and `map_id` are display metadata (SPEC-001 §2.3). (SPEC-000 §Gaps and adopted improvements, report)
- **R63. Codes.** `not_verified` always contains `map_interaction`, `firmware_behavior` and `real_engine` (the gate disclaimer), and adds `physical_range_unreviewed` when the gate report has a `G-UNREVIEWED` finding, `signature_unverifiable` when the gate report's `subject.signed_regions` is non-empty (SPEC-004 §6: the regions of `kind = signed` in that stage's verify report, SPEC-002 R7), whatever the aggregated status, so a file with a signed region and a failing region still lists it, and `best_effort_build` when `record.reproducibility = best_effort`. `notices` adds `input_verify_failed_acknowledged` when `record.input_verify.result = failed_acknowledged` (R14), `origin_not_evidence` when the original's `import` event has `origin` `virtual_read` or `file_service` (export) or `candidate_origin` is one of them (audit, R22), and always `emissions_and_regulation`. `disclaimer` is exactly: `This gate verifies file integrity and cell-by-cell plausibility. It does not verify the combination between maps, firmware behavior, or the real engine.` Adding a code is minor; removing or renaming one is major. (SPEC-000 §Verification gate, §Modeling decisions, §Regulatory compliance "the export report states this", §Plugin SDK `signed`)
- **R64. PDF.** The PDF is a non-normative rendering in the tenant's locale (pt-BR in the MVP). It MUST show the three sections in plain language, the disclaimer, the full `report_hash`, and a QR code that encodes `https://<verify-host>/verify/<report_hash>`, and MUST say that the JSON is authoritative. The PDF bytes are not hashed: PDF rendering is not deterministic. (SPEC-000 §Gaps and adopted improvements, report "PDF + JSON with hash and QR")
- **R65. Verify page.** `verify/{report_hash}` is a public consumer page outside `core`. For a stored `ReportFile` it recomputes R61, runs `verify_chain` (R40) from genesis on the report's chain and, for a `role: cli` chain, `verify_tenant` (R46) with the tenant's server chain, requiring no `chain_ref_mismatch` and no `unconfirmed_after_revocation` for the report's chain (R61; R44: the MVP page uses no checkpoint), and shows: the three sections, the verdict, the covering anchor's `day` and location (for a CLI chain, the server-chain anchor that covers its `chain_ref`), or "not yet anchored". It MUST NOT show original bytes, patch bytes, actor ids, other events' payloads or the reproduction bundle. It SHOULD also let a visitor drop a `ReportFile` and recompute `report_hash`, `record_hash` and the signature in the browser, so the check does not rest only on the operator; the page MUST state that this browser check proves integrity, not origin (R61), and that origin needs the tenant's chain export. A report whose original was erased (R83) still verifies, and the page says the original was erased. Limitation, stated on the page: the chain check runs on the operator's copy of the chain; the tenant can repeat it independently with the chain export and the anchors (R43). (SPEC-000 §Gaps and adopted improvements, "public page `verify/{report_hash}` that recalculates the chain")

## 9. Independent reproduction

```
ReproductionBundle = {
  schema: "impact.reproduction-bundle.v1",
  report_file: ReportFile,
  original: { dump_kind, memories: list[{ memory_id, base_address, data: hex }] },
  layout: MemoryLayout,                        # SPEC-001 §2.2
  patches: list[Patch],                        # SPEC-001 §2.3
  overlaps: list[[Hex32, Hex32]],
  checksum_patches: list[Patch],
  gate_report: object                          # SPEC-004
}
```

- **R70.** The bundle holds the original's bytes, which can contain VIN and immobilizer data (SPEC-000 §Plugin SDK `pii_in_flash`). It is delivered only to the tenant (the controller), encrypted like any artifact, and never sent to the verify page or stored in a public place. (SPEC-000 §LGPD, §Firmware copyright)
- **R71. Contract.** The reproduction script is one file, runs as `python -I reproduce.py <bundle.json>`, imports only the Python standard library, and MUST NOT import `core`, any plugin, or any third-party package. It reads only the bundle: no network, no environment variables, no other file. (SPEC-000 §"Done" criteria Kernel and Provenance)
- **R72. Independence.** Its canonical JSON, SHA-256 use, Kahn min-heap order, apply, and Ed25519 verification are its own code, written from SPEC-001, this spec and RFC 8032, not copied from `core`. Its canonical JSON MAY be the stdlib `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)`, which equals RFC 8785 for the objects of this spec because of R1 and R4 (ASCII keys, integers, no floats). (SPEC-000 §Golden files "dual implementation", §"Done" criteria Kernel)
- **R73. Steps.** In order: (1) R61 on `report_file`; (2) SPEC-001 R62 on `original` equals `image_hash_original`; (3) SPEC-001 R63 on `layout` equals `layout_hash`; (4) SPEC-001 R61 of every patch, the set equals `patch_hashes`, the Kahn order of SPEC-001 R25 equals the listed order, and SPEC-001 R64 equals `version_hash`; (5) apply in that order with SPEC-001 R21 and R23 checks, SPEC-001 R62 equals `image_hash_apply`; (6) apply `checksum_patches` with SPEC-001 R40 and R21 checks, their hashes equal `checksum_patch_hashes`, SPEC-001 R62 equals `image_hash_release`; (7) `sha256(JCS(gate_report))` equals `gate_report_hash`. (SPEC-000 §"Done" criteria Provenance)
- **R74. Output.** It prints a JSON result `{ status: "reproduced" | "not_reproduced", reproducibility, mismatches: [ {step, field, expected, got} ] }` and exits 0 only for `reproduced`. With `best_effort` it says so; it never upgrades a `best_effort` record. (SPEC-000 invariant 12)
- **R75. Limits.** The script proves that the released bytes are exactly the original plus the listed patches plus the recorded checksum patches. It does not recompute checksum values (that needs the plugin and is the gate's dual implementation and the golden files' job) and does not re-run gate rules. This is printed in its output. (SPEC-000 §Verification gate dual implementation, §Golden files)
- **R76.** CI runs the script against every vector in `specs/vectors/spec-005/` and in a differential test against `core` on generated exports; disagreement fails CI. (SPEC-000 §Core engineering practices)

## 10. Personal data and erasure

- **R80. VIN (decision D8).** No object of this spec contains a VIN, in clear, hashed, salted or keyed. Reproduction does not need it, and a hash of a short structured identifier can be reversed by enumeration, so a plain or salted hash is still personal data. If Phase 1 billing needs a per-car key (SPEC-000 §Gaps and adopted improvements, "credit per (sw_id, VIN hash)"), it is an HMAC-SHA-256 with a per-tenant key stored outside the chain, lives in billing, never in provenance or events, and is erased by destroying that key. (SPEC-000 §LGPD, §Logs)
- **R81.** `actor.id`, `tenant_id` and `project_id` are opaque. The mapping from `actor.id` to a person lives outside the chain and is erasable; erasing it leaves every hash intact. (SPEC-000 §LGPD "Event log contains data of the shops' employees")
- **R82. Commitments.** Personal content an event must refer to (a consent record, a justification typed by a person) is stored outside the chain, encrypted with its own data key, and referenced by `commitment = sha256(JCS({ schema: "impact.commitment.v1", nonce, content }))`, where `nonce` is 32 random bytes in hex supplied by the caller and stored encrypted with the content. Without the nonce, a low-entropy content cannot be confirmed by guessing. (SPEC-000 §Security, envelope encryption; decision D9)
- **R83. Crypto-shredding.** Erasure destroys the data key of the artifact or record, including copies in backups and in custody, and appends an `erasure` event naming its `artifact_sha256` or commitment. The content and nonce become unrecoverable; every event, anchor and report still verifies, because hashed fields contain only hashes and commitments. Reproduction of an erased original is no longer possible, and the verify page says so (R65). Object Lock stays in governance mode. (SPEC-000 §Gaps WORM vs LGPD, §Deletion and retention)
- **R84.** Corpus consent is per dump and decoupled from the account: cancelling a tenant without `consent_revoked` keeps the dump's consent events valid; `consent_revoked` is followed by `erasure` of the corpus copy. (SPEC-000 §Gaps "Consent and corpus after tenant cancellation")

## 11. Determinism, purity and errors

- **R90.** `core.provenance` is pure (SPEC-001 R71): no I/O, network, clock, randomness, environment reads beyond R15, threads or global state. Event ids, timestamps, nonces, `build`, the `Signer` and the `Verifier` are inputs. It imports `core.kernel` only and never `core.gate`; the gate passes verdicts and reports to it as data. (SPEC-000 §Four layers, layer 4; SPEC-001 R9, R71)
- **R91.** Every rejection raises a subclass of `ProvenanceError` with a stable `reason` (the reasons named in this spec); chain verification (`verify_chain`, `verify_segment`, `verify_tenant`) returns findings instead of raising. Each reason MUST have at least one test. (SPEC-001 R72)
- **R92.** R11, R13, R14 and R61 are runtime assertions in the gate's export path; a failure aborts the export and opens an S1. (SPEC-000 §Binary kernel invariants, SPEC-001 R73)

| SPEC-000 invariant | Rules |
|---|---|
| 10 Verified release (ack) | R13, R36 |
| 12 Provenance | R1, R10–R19, R30–R46, R50–R57, R60–R61, R70–R76 |

## 12. Test vectors

`specs/vectors/spec-005/vectors.json` is produced by `generate.py` in the same directory. Neither script uses the core. All data is synthetic.
- **Inputs from SPEC-001:** read from `specs/vectors/spec-001/vectors.json`, whose SHA-256 is recorded in the `generator` block. The export example is case V4 (P1, P2) released by V9 (Q1) on layout `base`; the audit example is case V8. No SPEC-001 hash is recomputed by `generate.py`.
- **JCS:** third-party `rfc8785`; **Ed25519:** third-party `cryptography`; both pinned in `requirements.txt`, versions recorded in `generator`. `generate.py` first checks that `cryptography` reproduces RFC 8032 §7.1 TEST 1.
- **Key:** a synthetic Ed25519 seed `sha256("impact spec-005 synthetic test key; never use outside test vectors")`, published in the file. It MUST NOT be enrolled in any real chain; R56 enforces this outside test mode, and the vectors run the chain verifier with `test_mode = true` except T10.
- **Placeholders:** the gate reports and the input gate report are synthetic placeholders (`synthetic.gate-report.v0`), standing in for SPEC-004 reports; only their hashes and their `findings` (for `finding_id` and the `alert_ack` warnings) are used.
- **Cross-check:** `crosscheck.py` is stdlib only and independent: canonical JSON by sorted `json.dumps`, its own Ed25519 transcribed from RFC 8032 §6 (checked against RFC 8032 TEST 1 constants embedded in the script), its own apply of P1, P2, Q1 from the original bytes, and its own chain verifier, which checks the R36 payload key sets, value types and list orders, the genesis rules of R32, `ts_regression` and `test_key`. It recomputes every hash and signature in the file, re-signs with the seed and compares bytes, runs each `tampers` case and compares the findings, and exits non-zero on any disagreement.

| Vector | Rules | Checks |
|---|---|---|
| `key` | R50 | public key and `key_id` from the seed |
| `chain` (genesis, `import`, `suspect_ack`, `alert_ack`, `export`) | R2, R5, R30–R33, R35, R36 | each event's JCS and `hash`, links, payload shapes, verifies `intact` with the anchor |
| `provenance` (warn, image, suspect original) | R10–R14, R16–R18 | `provenance_hash`, `alert_ack` binding and warnings, `suspect_ack` binding |
| `provenance_no_findings` | R11, R13, R14, R18 | `alert_ack` and `suspect_ack` null, accepted original |
| `provenance_lockfile` | R16–R18 | `best_effort` variant hash |
| `report_file` | R60–R63, R51 | `report_hash`, signature, event binding |
| `anchor` | R42, R51 | `statement_hash`, signature |
| `audit` | R20, R21 | `audit_hash` from V8 |
| `commitment` | R82 | commitment hash |
| `tampers` T1–T15, T4b | R38, R40, R41, R45, R51, R52, R56, R57, R61 | `hash_mismatch`; `seq_gap` (with `missing`) + `prev_mismatch`; `truncated`; a consistent rewrite caught only by `anchor_mismatch` (T4) and undetected without an anchor (T4b, the R41 limit); `bad_signature`; `record_hash_mismatch` + `report_hash_mismatch`; `revoked_key` on an export after a signed self-revocation (T7) and on an anchor whose key was revoked at the anchored `seq` (T8); informational `ts_regression` with status `intact` (T9); `test_key` outside test mode (T10); a genesis with two keys is `not_genesis` (T11); a `key_enrolled` signed by a key that is not enrolled is `unknown_key` and enrolls nothing (T12); a second `genesis` at `seq > 0` is `not_genesis` (T13); a `chain_ref` signed by the chain's key keeps the chain `intact` (T14), and one signed by a key not in the chain is `unknown_key` (T15) |

Not covered by vectors, so they need dedicated tests: R1, R3, R4 (shape rejection), R10 beyond `definition_hash` and `versions.references` (no caller-supplied hash), R15, R19 (record fields), R22, R34 (storage uniqueness), R37, R43, R44, R46 (anchor location, checkpoints, `verify_tenant`), R45 beyond the `chain_ref` signature, R53–R55, R62 beyond the vector's integrity section, R64–R65 (consumer pages), R70–R76 (script contract, CI), R80–R84 (privacy, by architecture and payload-schema tests), R90–R92.

Vectors are test data, not golden files: no hash is a checksum result.

## 13. Compatibility

Changing a field, a hash definition, a signing input, a domain string, an event payload shape or an error reason of this spec is breaking: it requires a SPEC-005 revision in a `foundation-change` PR, a new `schema` major (R2), and a **major** version of `core`. Old events and reports keep verifying under the schema they carry, so verifiers MUST keep every published schema version. Adding an event type, a `not_verified` or `notices` code, or an optional API is minor. Vectors change only together with the rule they test.

### Decisions for Luiz to review

| Id | Decision | Why |
|---|---|---|
| D1 | `schema` field in every object | Lets old records verify after a format change |
| D2 | Caller-supplied ids and second-precision UTC timestamps; `ts` not used for order | Core purity (SPEC-001 R71); clocks go backwards |
| D3 | No tenant, time or person in the provenance record | Deterministic `provenance_hash`; binding lives in the event |
| D4 | Genesis enrolls the signer's key and gives the chain its root of trust (refined by D10: one chain per signer) | Gives the chain a root of trust for signatures |
| D5 | The event type set of R36, the single owner of payload shapes, including `key_*`, `identification_confirmed`, `suspect_ack`, `alert_ack` (with `finding_id`s and ms timestamps), `rule_silence` (justification by commitment), `chain_ref`, `audit`, `erasure`; revision 1 adds `attester_enrolled`, `attester_revoked` and `review` | Each one is required by a rule in SPEC-000/001/004/006 or by R45, R52, R83 |
| D6 | Ed25519 (RFC 8032) per signer for reports and anchors, not sigstore | Offline CLI, no shop OIDC identity, no permanent public log entry, zero cost |
| D7 | One key per signer, private key outside core, age at rest, no escrow | Revoking a laptop does not stop the server; past signatures stay verifiable |
| D8 | No VIN in any form in provenance or events | Not needed for reproduction; hashing does not anonymize a short identifier |
| D9 | Nonce-salted commitments for personal content | Chain stays verifiable after crypto-shredding |
| D10 | One chain per signer, identified by `(tenant_id, signer_key_id, genesis_hash)`; `chain_ref` cross-references on sync; CLI keys revocable from the server chain; only server chains are anchored, CLI chains through anchored `chain_ref`s; key events signed (R57); origin = the server chain or a CLI chain it references (R32, R41, R42, R45, R46, R57, R61) | An offline CLI cannot know a shared tenant head; a single tenant chain would fork on sync and invalidate reports already handed to the shop |

## 14. Open questions

1. Which RFC 8032 library consumers inject as the `Verifier` (R55) and `Signer` (R53); `core` stays free of it.
2. Vendor-neutral anchor location for the MVP satisfying R43 at zero cost (a public repository commit, an e-mail to the shop, a separate bucket with versioning under other credentials). Not decided.
3. SPEC-000: SLSA 3 and cosign "from the first release" (§CI pipeline `release`, §Review by topic CI row) versus "cut from the MVP, return in v1" (§Cut from the MVP) versus "SLSA level 2 (target level 3)" (§Core engineering practices). R16 keeps `attestation_id` nullable until this is settled (gap G1).
4. `image_hash` (SPEC-001 R62) includes the SHA-256 of every memory, and DFlash or EEPROM can hold the VIN (SPEC-000 §Plugin SDK `pii_in_flash`). If that memory is otherwise low-entropy, its hash could be confirmed by enumerating VINs. Whether this makes `image_hash` personal data needs a lawyer; a change would touch SPEC-001 R62 (major).
5. Whether opaque `actor.id` with an erasable mapping is enough for LGPD, and whether the remaining artifact hashes after erasure are personal data. Lawyer.
6. Retention of the Event log (SPEC-000 §LGPD "retention defined for the Event log"): if old events must be deleted, a retention checkpoint that verifies from an anchored point (R44) is the candidate mechanism; it needs its own rule.
7. Closed: verdict tokens and rule ids are SPEC-004's; `suspect_ack` carries `input_report_hash` instead of reason codes (R36).
8. Where `reproduce.py` lives and how it ships with each report (repository path, whether it is signed with the core release).
9. Whether a pt-BR rendering of the disclaimer is normative text (R63 fixes the English text of SPEC-000).
10. Merkle-tree inclusion proofs so the public verify page can check chain inclusion without trusting the operator's chain check; would change R31 (major).
11. Anchors signed by a key later revoked as `compromised` (R43): how the consumer proves the external write time (location metadata, a third-party timestamp) without a paid service.
12. Offline-only shops (D10): a CLI that never syncs is never cross-referenced, so its chain has no anchor; whether such a CLI may export at all, or must sync within a deadline.
13. **Signed regions (pending author decision, SPEC-004 open question 1).** R14 accepts an original whose input verify is `signature_unverifiable` with `result: ok`, and R63 reports `signature_unverifiable` from `signed_regions`; both follow the `warn` reading of SPEC-000 §Plugin SDK. If the fail-closed alternative is chosen, such originals become suspect and R14 changes.

### Gaps found in SPEC-000 and SPEC-001

| Id | Where | Gap | Handled by |
|---|---|---|---|
| G1 | SPEC-000 §CI pipeline `release` and §Review by topic (CI row) vs §Cut from the MVP vs §Core engineering practices | SLSA 3 and cosign "from the first release", "cut until v1", and "level 2, target 3" at once | R16 `attestation_id` nullable; open question 3 |
| G2 | SPEC-000 invariant 10; SPEC-001 R42 | `sha256(release)` is undefined for a multi-memory image | R13 and R36 use `image_hash_release` (SPEC-001 R62); SPEC-000 invariant 10 and SPEC-001 R42 are aligned in the same `foundation-change` PR |
| G3 | SPEC-000 invariant 12 | The field list omits `overlaps`, `version_hash` and the checksum patch hashes, without which the report cannot reproduce the export (§"Done" criteria Provenance) | R12, §3 |
| G4 | SPEC-000 §Protection of binaries (Retention) vs §Regulatory compliance (Deletion and retention) | "Deletion on request within 30 days" vs "there is no 30-day deadline in the LGPD" | Not handled here; SPEC-000 to be fixed |
| G5 | SPEC-000 §Protection of binaries (Encryption at rest), §Data model Tenant `kms_key_id`, §Non-functional requirements vs §Free stack (SOPS + age) and §Infrastructure (MVP) | Per-tenant KMS key assumed; the MVP has no KMS, so custody of per-artifact data keys is unspecified | R53 covers signing keys only; data-key custody stays open |
| G6 | SPEC-000 invariant 12 "version of the kernel" | The kernel has no version of its own; it ships inside `core` | `versions.core` |
| G7 | SPEC-000 §Plugin SDK (`identify` extracts VIN, `pii_in_flash`); SPEC-001 R62 | `image_hash` hashes memories that may hold the VIN | Open question 4 |
| G8 | SPEC-000 §Data model Event; SPEC-001 §11 question 1 | No `seq` (gap detection) or `schema`; SPEC-001 deferred the fields here | R30; the SPEC-000 Event row is aligned in the same `foundation-change` PR |
