# SPEC-008 · Stock registry

Status: draft
Date: 2026-10-19
Governs: `src/core/stock/`: the stock registry object, its hash, signature and freshness, the per-memory fingerprint, and the pure lookup `stock_check` that classifies a dump as `stock`, `modified` or `unknown`.
Derives from: SPEC-000 §Gaps that still require a decision ("Original that is not stock": "Registry of stock file hashes per software version; every upload is classified as stock, modified or unknown", decided), §First wins item 3 ("this file is stock or already modified (stock hash registry)"), §High-value improvements #2, §Modeling decisions (`virtual_read` and `file_service` are not evidence; "the stock hash registry is consulted"), §Plugin SDK (`pii_in_flash`), §Verification gate (fail-closed), §LGPD; SPEC-001 R2, R60–R65; SPEC-002 R2, R4, R6, R22; SPEC-005 R1–R5, R50, R51, R55, R80; SPEC-006 R81, R82 (signed head and freshness, the pattern reused here); SPEC-007 R40, R41 and §2.1 gap CG3.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Every numbered rule (`R<n>`) is normative and MUST be cited by at least one test (`# SPEC-008 R<n>`). Rules of other specs are written `SPEC-00N R<n>`. A rule marked **(decision Dn)** settles a point the sources leave open and is listed in §9 for Luiz to review; a point marked **pending author decision** is not settled here, and the code fails closed until it is.

## 1. Problem

Cars arrive already remapped by third parties. A shop that labels maps on top of someone else's stage 1, or audits a file service's work against an "original" that was itself modified, is misled, and so is the corpus (SPEC-000 §Gaps, "Original that is not stock"). The registry answers "is this file what the factory shipped for this software version?" offline, on the shop's laptop (SPEC-007 R40).

Two facts make a naive answer wrong. The whole-image hash (SPEC-001 R62) differs between two cars with the same software, because DFlash or EEPROM holds the VIN, immobilizer data, coding and counters (SPEC-000 §Plugin SDK `pii_in_flash`; SPEC-005 open question 4), so a whole-image comparison would call every stock file `modified`. And a registry that can be forged or frozen would let anyone label a modified file `stock`. This spec fixes which bytes are compared, the signed and expiring registry object, and the classification, precisely enough that two implementations give the same answer.

Out of scope: how an entry is admitted to the registry (corpus process, pending author decision, §10 question 3), the CLI command (SPEC-007 R40), and any verdict: the classification is information and never enters the gate.

## 2. Common rules

- **R1. Hashing.** Every hash is `sha256(JCS(x))` per SPEC-005 R1: lowercase hex, byte strings never appear, no floats, integers in `[0, 2⁵³ − 1]`. (SPEC-001 R60, R65; SPEC-005 R1)
- **R2. Shape.** Every object carries its `schema` (`impact.<name>.v<major>`), part of its hash. Every listed field is required; an absent value is `null`; an unknown key, a missing key, a wrong type, or a list out of its stated order is `StockError`, reason `bad_shape`. Keys are ASCII. (SPEC-005 R2–R4)
- **R3. Formats.** `Hex32`, `Timestamp` and `Sig` are SPEC-005 R5 and SPEC-006 R3; `Family` is SPEC-002 R2; `MemoryId` is SPEC-001 §2.1; `SwId` is a string of 1 to 64 printable ASCII characters (`^[\x20-\x7e]{1,64}$`), as SPEC-003 R34 writes software versions. (SPEC-005 R5; SPEC-003 R34)

## 3. Registry

```
StockEntry  = { family: Family, sw_id: SwId, memory_id: MemoryId, size: int,          # size ≥ 1
                excluded: list[{ start: int, end: int }],                            # sorted, start < end ≤ size, gaps between
                kept_sha256: Hex32 }
StockRegistry       = { schema: "impact.stock-registry.v1", version: int, issued_at: Timestamp, expires_at: Timestamp,
                        entries: list[StockEntry] }                                  # sorted by (family, sw_id, memory_id, size, kept_sha256), unique
SignedStockRegistry = { registry: StockRegistry, registry_hash: Hex32, key_id: Hex32, signature: Sig }
StockTrust          = { key_id: Hex32, public_key: Hex32 }
StockPolicy         = { schema: "impact.stock-policy.v1", version: int, max_validity_s: int }
```

- **R10. Entry (decision D1).** An entry describes one memory of a stock image of one software version: its `family`, `sw_id`, `memory_id` and `size`, the byte ranges `excluded` from the comparison, and `kept_sha256`. `excluded` is sorted by `start`, each range has `start < end ≤ size`, and consecutive ranges are separated by at least one byte (`start > previous end`), so one set of bytes has one form. Comparing per memory, not per image, lets a dump that lacks a memory (an OBD read without DFlash, SPEC-002 R5) still be classified for the memories it has, and lets unit-specific memories be fingerprinted with their unit-specific bytes excluded. (SPEC-000 §Gaps, "per software version"; SPEC-002 R5)
- **R11. Fingerprint.** `kept_sha256` is the SHA-256, in lowercase hex, of the memory's bytes outside `excluded`, concatenated in offset order. `excluded` MUST cover every byte that differs between two cars with the same stock software: the plugin's protected regions named `vin*`, `immo*`, `coding*` and `counter*` (SPEC-002 R22) and its `pii_locations` (SPEC-002 R6). Because the mask is part of the signed entry, the lookup never depends on a layout computed at lookup time. (SPEC-000 §Plugin SDK; SPEC-005 open question 4)
- **R12. Registry.** `entries` is sorted by `(family, sw_id, memory_id, size, kept_sha256)` in code-point order and strictly increasing on that key. `version` is a positive integer chosen by the operator. `registry_hash = sha256(JCS(StockRegistry))`. (R1, R2)
- **R13. Signature.** The registry operator signs `registry_hash` with the `StockTrust` key: `signature` is Ed25519 (SPEC-005 R50) over the UTF-8 JCS of `{ domain: "impact.stock-registry-signature.v1", hash: registry_hash }` (SPEC-005 R51), and `key_id = sha256(public key bytes)`. `core` verifies it only through the injected `Verifier` (SPEC-005 R55). (SPEC-005 R50, R51, R55)
- **R14. Trust anchor (pending author decision).** `StockTrust` is published with each `core` release, like `RegistryTrust` (SPEC-006 R60), and is never read from a file, flag or environment variable (SPEC-007 R41, R101). It needs the operator's key, which only Luiz can create: until it is published, `core` publishes none and every lookup is `unknown` with reason `untrusted_registry` (R21). The synthetic key of §8 MUST NOT be published. (SPEC-006 R60; SPEC-007 CG6)
- **R15. Freshness (decision D2; validity period pending author decision).** A registry is used at `as_of` (a `Timestamp` the caller supplies; `core` has no clock) only if `issued_at ≤ as_of < expires_at` and `expires_at − issued_at ≤ max_validity_s` of the published `StockPolicy`. Without expiry, a registry from which a wrongly admitted entry was withdrawn could be kept by withholding the newer one, and that entry would keep calling a modified file `stock` (the freeze attack of SPEC-006 D18). The number is not decided: SPEC-006 R82 uses 86400 s for the field-evidence head, but a stock-check is information, not a release condition, and offline shops would lose it after a day. Until Luiz publishes a policy, `core` publishes none and every lookup with a trusted registry is `unknown` with reason `unpublished_stock_policy` (R21). (SPEC-006 R82, D18)

## 4. Lookup

`stock_check(dump: Dump, identification: Identification | None, registry: SignedStockRegistry, as_of: Timestamp, verifier: Verifier | None) -> StockCheck`

```
StockCheck = { schema: "impact.stock-check.v1", status: "stock" | "modified" | "unknown",
               reasons: list[string],                                     # sorted, unique
               registry_hash: Hex32 | null, registry_version: int | null,  # null unless the registry was used
               family: Family | null, sw_id: SwId | null,                # of the identification used
               memories: list[{ memory_id, status: "stock" | "modified" | "unknown", reason: string | null }] }   # sorted by memory_id
```

- **R20. Inputs (decision D3).** `stock_check` is pure. A malformed `registry` or `as_of` is `StockError`, reason `bad_shape` (R2; SPEC-007 R41: the CLI MUST NOT accept what `core` rejects). `identification` is SPEC-002's: it MUST satisfy SPEC-002 §2.1 and R4 for `dump`, else `StockError`, reason `bad_identification`. The consumer obtains it from `core` (SPEC-002 R15 `probe`), never builds it (SPEC-007 R14). The identification only selects which entries are compared: a `stock` answer always means the kept bytes equal a signed entry's, so a wrong identification can turn `stock` into `modified` or `unknown`, never `modified` into `stock`. (SPEC-002 R4, R15; SPEC-007 R14)
- **R21. Registry usability.** In order, stopping at the first group that applies: the published trust anchor is absent, the `verifier` is `None`, `key_id` differs from the anchor's, `registry_hash` does not recompute, or the signature does not verify → reason `untrusted_registry`; no published policy → `unpublished_stock_policy`; then every one that applies of `registry_not_yet_valid` (`as_of < issued_at`), `registry_expired` (`as_of ≥ expires_at`) and `registry_validity_too_long`. With any of these the registry is not used: `status` is `unknown`, `registry_hash` and `registry_version` are `null`, and `memories` is `[]`. Timestamps are compared as UTC instants. (SPEC-006 R82; SPEC-000 §Verification gate, fail-closed)
- **R22. Identification.** With a usable registry: `identification` `None` → `unknown`, reason `not_identified`; `sw_id` null → `unknown`, reason `no_sw_id`; in both `memories` is `[]`. (SPEC-002 R12, R13)
- **R23. Per memory (decision D4).** For each memory `m` of the dump, the candidates are the entries with `family` and `sw_id` equal to the identification's and `memory_id` and `size` equal to `m`'s. No candidate → `unknown`, reason `not_registered`. A candidate whose `excluded` does not cover every `pii_locations` range of the identification in `m` is not used; if no candidate is left → `unknown`, reason `pii_not_excluded`, because comparing a unit-specific byte would call a stock file `modified`. Otherwise `stock` if the kept bytes of `m` (R11, with the candidate's `excluded`) hash to the `kept_sha256` of at least one remaining candidate, else `modified`: the memory differs from every registered stock image of that software version. (SPEC-000 §Gaps; SPEC-002 R6; SPEC-007 R40)
- **R24. Status.** With per-memory results: `modified` if any memory is `modified`; else `stock` if every memory is `stock`; else `unknown`, with `reasons` the sorted, unique reasons of the `unknown` memories. `stock` and `modified` carry `reasons: []`. A dump with one memory `stock` and another `unknown` is `unknown`: `stock` is said only of every byte the registry could compare. (SPEC-000 §Gaps, "stock, modified or unknown")
- **R25. Output.** `stock_check_json(result)` is the `StockCheck` above. `family` and `sw_id` are the identification's (both `null` without one). No hash of a `StockCheck` is defined: it is information shown to a person, not a record. (SPEC-007 R40, R61)
- **R26. Information, never a verdict.** No gate rule reads a `StockCheck`, and the classification never changes a verdict, an admission or a record (SPEC-004 R7: the original's content is never a rule input). `modified` means "differs from every registered stock image of this software version"; it never means tampered, remapped or illegal, and no output calls it so (SPEC-007 R40). A `stock` original is not evidence that the car's ECU holds that file (SPEC-000 §Modeling decisions, `virtual_read`, `file_service`).

## 5. Personal data

- **R30.** No object of this spec contains a VIN, serial, immobilizer value, person, file name or dump byte. An entry holds a hash of stock bytes with the unit-specific ranges excluded (R11), so it is not a hash of a VIN either (SPEC-005 R80). Entries are built by the corpus steward from consented originals (SPEC-000 §Gaps, consent per dump); the registry is published data like the DTC set (SPEC-006 R57). (SPEC-005 R80; SPEC-006 R5)

## 6. Placement, purity and errors

- **R40. Placement (decision D5).** The registry and the lookup live in the package `core.stock`, which imports `core.kernel`, `core.provenance` (the `Verifier`) and `core.plugins` (the `Identification` and its R4 check), and is imported by no layer below the gate; import-linter enforces the layer and keeps its private modules private. It is pure (SPEC-001 R71): no I/O, network, clock, randomness, environment reads or threads. (SPEC-000 §Four layers; SPEC-001 R71)
- **R41. Errors.** Precondition failures raise `StockError` with a stable reason: `bad_shape`, `bad_identification`. Usability and classification outcomes (R21–R24) are data, never exceptions. Each reason MUST have at least one test. (SPEC-001 R72)

## 7. Compatibility

Changing a shape, the fingerprint (R11), a hash or signing domain, a reason, or the classification rules (R21–R24) is breaking: a SPEC-008 revision in a `foundation-change` PR, a new `schema` major and a **major** version of `core`. Publishing a `StockTrust` or a `StockPolicy` version, adding a reason, or a new optional API is minor. Vectors change only together with the rule they test.

## 8. Test vectors

`specs/vectors/spec-008/vectors.json` is produced by `generate.py` in the same directory. Neither script uses the core. All data is synthetic.
- **JCS:** third-party `rfc8785`; **Ed25519:** third-party `cryptography`; both pinned with hashes in `requirements.txt` (the same pins as SPEC-006), versions in the `generator` block. `generate.py` first checks that `cryptography` reproduces RFC 8032 §7.1 TEST 1.
- **Key:** a synthetic Ed25519 seed `sha256("impact spec-008 synthetic stock registry key; never use outside test vectors")`, published in the file; R14 forbids publishing it. A synthetic `StockPolicy` (`version: 0`, `max_validity_s: 86400`) stands for the unpublished policy; it is test data, not a decision of R15.
- **Fixture:** a synthetic two-memory image, `pflash` (64 bytes) and `dflash` (32 bytes, with a synthetic unit block at `[16, 24)` named in the identification's `pii_locations`), and two synthetic software versions.
- **Expected values:** every `kept_sha256`, the registry, its hash and signature are computed in `generate.py`; every expected `StockCheck` is written by hand there, never computed by a lookup.
- **Cross-check:** `crosscheck.py` is stdlib only and independent: canonical JSON by sorted `json.dumps` (SPEC-005 R72), its own Ed25519 transcribed from RFC 8032 §6 and checked against TEST 1, its own fingerprint and lookup written from this spec. It recomputes every hash and signature, re-signs with the seed and compares bytes, runs every case, and exits non-zero on any disagreement.

| Vector | Rules | Checks |
|---|---|---|
| `key` | R13 | public key and `key_id` from the seed |
| `fingerprints` | R11 | `kept_sha256` with and without excluded ranges |
| `registry` | R10, R12, R13 | registry JCS, `registry_hash`, signing input, signature |
| `cases` K01–K14 | R20–R25 | stock with a different unit block; modified in one memory; not registered; other software version; `pii_not_excluded`; partial dump; one memory unknown; no identification; no `sw_id`; untrusted (bad signature, other key); not yet valid; expired; validity too long |

Not covered by vectors, so they need dedicated tests: R2 and R3 (shape errors), R14 (no published anchor; the vector key is not published), R15 (no published policy), R20 (`bad_identification`), R26 and R30 (architecture), R40 and R41.

## 9. Decisions for Luiz to review

| Id | Decision | Why |
|---|---|---|
| D1 | Per-memory entries with explicit excluded ranges and a hash of the kept bytes | A whole-image hash differs per car (VIN in DFlash or EEPROM, SPEC-005 open question 4); per memory lets partial reads be classified; a signed mask removes any dependency on a layout computed at lookup |
| D2 | The registry is signed and expires, like the SPEC-006 registry head | A withdrawn wrong entry must not survive by withholding the newer registry (SPEC-006 D18, TUF freeze attack); the validity number stays pending (R15) |
| D3 | The identification selects entries only; `stock` is always a byte equality with a signed entry | A wrong identification can lower the answer, never raise `modified` to `stock` |
| D4 | `modified` only when the memory is registered for that software and differs from every registered stock image; a pii range not excluded gives `unknown` | Fail towards `unknown`, never a false `modified` caused by a unit-specific byte, never a false `stock` |
| D5 | New package `core.stock` between plugins and gate | It needs `Identification`; `core.evidence` may not import `core.plugins` (SPEC-006 R4) |

## 10. Open questions

1. **Trust anchor (pending author decision, R14).** Who operates the registry key and its custody (SOPS + age like other server keys, SPEC-005 R53); published together with the SPEC-006 `RegistryTrust` (SPEC-007 CG6).
2. **Validity period (pending author decision, R15).** `max_validity_s` of the first `StockPolicy`: 24 hours as SPEC-006 R82, or longer because the answer is information and the CLI works offline.
3. **Admission of an entry (pending author decision).** What makes a memory image "stock": how many independent reads of distinct cars (by `origin` `bench_read`, `boot_read` or `obd_read`, never `file_service` or `virtual_read`), with which consent, and who reviews it. Until decided, nothing is registered.
4. **Rollback across versions.** A consumer could keep the highest `version` it has seen and refuse a lower one; `core` is stateless and cannot. Whether the CLI must (SPEC-007).
5. **Key rotation.** One key per anchor; rotating it needs a new `core` release, like `RegistryTrust`.
6. **Original stock status in the audit report.** Whether `AuditRecord` or the audit report should carry the original's classification (SPEC-005 §4); not done here.

### Gaps found in other specs

| Id | Where | Gap | Handled by |
|---|---|---|---|
| G1 | SPEC-000 §`core` repository structure; CLAUDE.md layout | The package list did not name `core.stock` | SPEC-000 aligned in the same change; CLAUDE.md left to Luiz |
| G2 | SPEC-007 open question 7 | Stock registry shape, signer, freshness and compared bytes were open | R10–R15, R20–R24; anchor, validity and admission stay pending |
