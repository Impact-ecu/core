# ADR-002 · Inputs and field evidence through contracts, with no fixed partner

Status: accepted (author's decision, 2026-10-18; thresholds N = K = E = 2 decided the same day)
Date: 2026-10-18

## Context

SPEC-000 up to this ADR assumed one partner shop in three places:

1. **Input.** The entry point was "the file the shop's tool exports" (Flex), discovered in an afternoon at the shop (SPEC-000 §Phase −1 item 1, §The workflow of StageX users).
2. **Field evidence.** `golden_field` was defined as "written by the shop to a real ECU", and the oracle was "delegated to the shop" (§Golden files, §First wins item 1, §High-value improvements #1).
3. **Corpus and variants.** The first real dump, the variant list ("buy by `hw_id`"), bench hours, the harness, the sacrificial ECU and the second human were all expected from the shop (§Phase −1 exit criterion).

The author rejected that coupling: the product must not depend on one shop, one tool or one person. The principle of agnosticism (SPEC-000 §Principles: manufacturer, read tool, definition format, cloud, client) already applies to everything the core consumes; it did not yet apply to where files and evidence come from.

What cannot be removed is physics: a recalculated checksum is only known good after a real ECU accepted it. This ADR keeps that requirement and removes the assumption about **who** provides the proof.

## Decision

1. **Every external dependency is a versioned contract, never a named party.** The core expects any source that satisfies the contract; a shop, an individual tuner, a file service or the user themself are instances, none is special. No spec, skill or test may name a specific partner as a requirement.

2. **Input contract (`Importer`).** Files enter only through an `Importer` that turns a tool's export into `Dump{dump_kind, memories}` (SPEC-001) plus an `ImportRecord{importer_id, importer_version, source_tool (declared, free text, may be null), container_kind, input_sha256}`. The core ships one importer: raw binary (`container_kind: raw`). Tool containers (Flex, KESS3, Autotuner and others) are separate importers with the same conformance discipline as ECU plugins. An encrypted or unknown container is an explicit `unsupported_container` result, never a guess. Which tools exist is a registry filled by whoever writes importers, not a Phase −1 deliverable.

3. **Field evidence contract (`FieldAttestation`).** Field evidence is a signed record any attester can produce:
   - `subject_image_hash` (`image_hash` of the file written, SPEC-001 §7) and `identification` (`hw_id`, `sw_id`, `checksum_variant_id`);
   - `write_tool` and version (declared), `readback_image_hash` (optional: the image read back after writing);
   - `communicates` (bool), `dtcs_after_clear_and_reread` (list of codes, may be empty), `tool_checksum_status` (`ok | mismatch | not_reported`);
   - `ecu_commitment`: a keyed commitment (HMAC by an operator-run service; SPEC-006 D6) to the physical unit's ECU serial number (UDS DID 0xF18C; SPEC-006 D16), so two attestations can be told apart as two ECUs — never the serial or VIN in clear (SPEC-005 LGPD rules);
   - `attester_key_id`, `created_at`, Ed25519 signature (same scheme as SPEC-005 reports).
   The `oracle:` block of a golden record becomes a list of `FieldAttestation` hashes.

4. **`golden_field` is computed from attestations, not granted to a party.** For a checksum variant, `golden_field` holds when there are at least **N** attestations, from at least **K** distinct attester identities (a key and its rotations count once; SPEC-006 D10), on at least **E** distinct `ecu_commitment`s, each with `communicates = true`, no memory or checksum DTC (SPEC-000 §Golden files list), `tool_checksum_status ≠ mismatch`, and `subject_image_hash` equal to the golden hash. **Decided (2026-10-18): N = 2, K = 2, E = 2**, because with no trusted partner a single key is a single point of failure, and one unit cannot distinguish a variant property from a unit quirk.

5. **Attester trust is explicit and revocable.** An attester key counts toward `golden_field` only while enrolled in the project's attester registry (an event in the SPEC-005 chain: `attester_enrolled`, `attester_revoked`). Revoking a key re-evaluates every golden that depended on it; a golden that drops below the thresholds returns to `golden_concordant` or `candidate` and plugin release for that variant is blocked again. Enrollment is a human decision recorded with reason; the registry starts empty.

6. **Corpus contract.** A dump is admitted to the corpus from any contributor with a consent record, `origin`, `dump_kind`, an `ImportRecord`, and identification. The variant list is whatever `identify` finds in the corpus, never a shopping list.

7. **The software is complete with zero external evidence.** With no attestations and no real dumps, every path still works and degrades honestly: import (raw), diff, provenance, gate, `verify` (variants without golden return `unknown_variant` or descriptors at `candidate`/`golden_concordant`), and export of a file whose checksum the write tool fixes. Only one thing is blocked: releasing a plugin's checksum recalculation for a variant without `golden_field`. That block is the product's reliability promise, not a dependency on anyone.

8. **Second human is a role, not a name.** Before a file goes to a third party's car (Phase 1), a second enrolled key must sign a `review` event over the export. Who holds it is an operational choice.

## Consequences

- Phase −1 no longer has external exit criteria. Its remaining work is software: this ADR, the `Importer` and `FieldAttestation` specs (SPEC-006), and the raw importer. The questions it used to answer (which tool, which container, which variants) become registries the system fills as importers, dumps and attestations arrive.
- Phase 0 exit for a family plugin is measured per variant by Decision 4, from any attesters.
- The partner shop, if it participates, is one attester and one corpus contributor among many, enrolled like any other.
- ADR-001 Decision 4 ("`golden_field` from the partner shop") reads "`golden_field` per Decision 4 of ADR-002".
- SPEC-002 R122 and the `oracle:` record shape change to the attestation list; SPEC-005 gains the `attester_enrolled`, `attester_revoked` and `review` event types. Both follow in SPEC-006 and a revision of SPEC-005.

## Alternatives considered

| Option | Why not |
|---|---|
| Keep one partner shop as the oracle | Single point of failure; the author rejected the coupling; contradicts agnosticism |
| Accept any single attestation as `golden_field` | Without a trusted partner, one key or one unit is not enough evidence for a variant |
| Drop `golden_field` and release on `golden_concordant` | Two tools agreeing does not prove an ECU accepts the file; a MED17 with a wrong checksum starts, logs a DTC and cuts injection (SPEC-000 §Golden files) |
| Own bench hardware as oracle | Violates the software-only and zero-cost constraints |
