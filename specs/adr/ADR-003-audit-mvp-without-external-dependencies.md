# ADR-003 · Audit MVP with no external dependency

Status: accepted (author's decision, 2026-10-19)
Date: 2026-10-19

## Context

After SPEC-001 to SPEC-009 were implemented, no real use was possible:
- Every gate run blocks, because no rule table or `RegistryTrust` anchor is published (SPEC-007 CG6).
- The audit refuses without a published rule table (SPEC-005 open question 14).
- The audit needs a family plugin to identify the ECU and give the layout (SPEC-005 R24), and the first plugin (Bosch MED17) needs real dumps and field attestations (ADR-001, ADR-002).
- The CLI cannot create its key, because the age library was undecided (SPEC-007 open question 2).

The author's position: a minimum viable product to validate the idea must not depend on any of that, while staying robust and reliable.

SPEC-000 already names the first product: **audit and verification of third-party files**, which "exercises kernel, diff, plugin, and provenance without the responsibility of writing to the car" (§First wins). Auditing writes nothing to a car, so it needs no proven checksum. ADR-002 Decision 7 already requires the software to be complete with zero external evidence.

## Decision

1. **The MVP is the audit.** Given an original and a candidate file (for example, what a file service returned), Impact reports exactly which bytes changed, which known maps they belong to, and which changes fall **outside any known map**, in a signed, reproducible report. The MVP does not export, recalculate checksums or write to an ECU. In the OBD workflow the write tool corrects the checksum itself (SPEC-000 §The workflow of StageX users).

2. **Generic audit without a family plugin.** When no admitted plugin identifies the file, core runs a generic audit:
   - The diff covers every byte of every memory.
   - Attribution comes from a user-supplied definition (XDF, SPEC-003), when one is given.
   - Identification, layout, verify and map plausibility rules are reported as **`not_evaluated`**, each with its reason.
   - A change outside every map of the definition is reported as **`outside_known_maps`**, the strongest signal of a hidden modification.
   - Without a definition, every change is `outside_known_maps`, and the report says no definition was supplied.
   - The family-plugin audit (SPEC-005 R23–R28) stays as it is and is used when a plugin is admitted.

3. **Honest verdicts, never "ok".**
   - The generic audit never states that a file is intact, stock or safe; its checksum status is `not_verified`.
   - Its report is not an export and never yields a `ReleasedImage`. Invariant 10 and the gate's release path are untouched.

4. **No published rule table needed for auditing.** Closes SPEC-005 open question 14. An audit without a published rule table still runs: map rules are `not_evaluated` with reason `no_rule_table`, and the rest of the record stands. Export keeps requiring the table (SPEC-004 R70).

5. **CLI key at rest: PKCS#8 with scrypt** (`cryptography` `BestAvailableEncryption`), the OpenSSL-standard encrypted private key format. The library is already pinned for Ed25519, and no new dependency or binary is added. Closes SPEC-007 open question 2; age is not used.

6. **The human report is a self-contained HTML file**, with no network, scripts or external assets, next to the JCS JSON report whose hash it shows. PDF is deferred.

## Consequences

- SPEC-005 (generic audit record, R24 alternative, open question 14 closed), SPEC-004 (gate entry point for the generic audit) and SPEC-007 (`audit` flow, key format, HTML report; open question 2 closed) get revisions.
- The product can be put in front of any shop with only the shop's own files and, optionally, an XDF. Nothing is published, attested or decided by a third party first.
- Everything still blocked (export, recalculation, family plugins, the `golden_field` claim) stays blocked, exactly as ADR-001 and ADR-002 require.

## Alternatives considered

| Option | Why not |
|---|---|
| Publish a provisional rule table and trust anchor to unblock the gate | Makes up thresholds and trust nobody has decided; violates "verification before trust" |
| Ship a MED17 plugin from public descriptions without golden | ADR-001: constants not confirmed against our own corpus; a wrong verify would claim "intact" falsely |
| Wait for the decisions | The author rejected waiting: the idea needs validation now |
| age through a subprocess or binding | Extra install or compiled dependency; PKCS#8 + scrypt is the same protection with what is already pinned |
