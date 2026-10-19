# ADR-001 · Source of the Bosch MED17 checksum algorithm

Status: accepted
Date: 2026-10-18

## Context

SPEC-000 §Three questions before writing code, question 1: where does the MED17 checksum algorithm come from, and what is the truth about it? Without an answer, golden files do not exist. Phase −1 (SPEC-000 §Phase −1, item 3) required mapping what the community has published, per variant, before any core code.

Findings of the Phase −1 survey (2026-10-18, sources below; every source was retrieved, nothing inferred):

1. **One open implementation exists:** [ConnorHowell/medc17-checksum-tool](https://github.com/ConnorHowell/medc17-checksum-tool) (MIT, Python, last push 2026-08-27). It describes Bosch MED17/EDC17 flash images as blocks (Startup, Customer, ASW, Dataset, Absolute constants, Variant dataset), each with checksum structures of type CRC32, ADD32 or ADD16 plus a compensation word, and a per-variant monitoring checksum. It locates blocks by pattern, not by per-variant tables. Its author states testing is mostly on calibration changes and that the multi-variant path ran against a single file. The same tool also contains RSA-signature and CVN forging, which are outside Impact's scope (SPEC-000 §Vision and scope; skill `emissions-boundary`).
2. **The algorithm constants are single-source.** No second public source confirms them. [reverseengineer.net](https://reverseengineer.net/bosch-med17-edc17-ecu-reverse-engineering/) describes per-block CRC32 descriptor tables without additive sums, which conflicts with item 1.
3. **No public source ties a checksum scheme to a MED17 sub-variant or TriCore MCU** (TC1766, TC1796, TC1797, TC1724, TC1728…).
4. **No public source lists which MED17 variants are RSA-signed.** Signals only: a vendor page states MED17.1.1 on TC1796 is RSA-signed ([CHIPOK](https://chipoktuning.com/checksum/bosch-med17-1-1-irom-tc1796-tprot-vag-checksum-fix-online/?lang=en)); WinOLS OLS807 lists a "Bosch MED17-RSA" type requiring an unmodified original ([EVC OLS807](https://www.evc.de/en/product/ols/plugins_detail.asp?cksName=OLS807)); an EVC FAQ on protected checksums states "In general a simple checksum correction is impossible, because the used algorithm is still secure" without naming variants ([EVC FAQ](https://evc.de/en/service/q1304.asp)).
5. **Community forums** document EEPROM block CRCs, not program-flash checksums ([NefMoto](https://nefariousmotorsports.com/forum/index.php?topic=3574.0)). EEPROM blocks carry immobilizer data and are out of scope.
6. **Commercial modules** (EVC OLS807 and others) describe coverage in marketing terms only, are paid, and publish no terms for embedding.

## Decision

1. **Impact writes its own checksum implementation.** The MED17 checksum is expressed as declarative descriptors (SPEC-000 §Plugin SDK per ECU family) interpreted by the core, with variant-specific descriptors in the private `ecu-plugin-bosch-med17` repository. The block structure and algorithm families published by the community are a starting hypothesis to be confirmed against our own corpus, not a specification.
2. **ConnorHowell/medc17-checksum-tool is inspiration and an independent reference only.** No code, tables or constants are copied into any Impact repository. The tool may be run, unmodified and outside Impact's codebase, as a second implementation from a different source for cross-checking (SPEC-000 §Golden files, dual implementation). Agreement between our implementation and the tool yields at most `golden_concordant`: valid for development, never for release.
3. **Its RSA and CVN forging features are never used, run, studied for implementation, or referenced in Impact code or docs.**
4. **Release of any variant requires `golden_field`**, computed from field attestations per ADR-002 Decision 4, per checksum variant (SPEC-000 §Golden files). No constant, block layout or algorithm is trusted until a `golden_field` case confirms it on that variant.
5. **Verification comes first.** The first deliverable is `verify` on unmodified originals; recalculation (`checksum_patches`) follows only for variants with `golden_field`.
6. **Signed regions:** a region whose integrity depends on an RSA signature is `kind: signed`; `verify` returns `signature_unverifiable`; no correction is attempted.
7. **Unknown variants:** a variant without a confirmed descriptor and golden is `unknown_variant`; Impact verifies nothing and recalculates nothing for it (SPEC-000 §Phase −1 fallback).
8. **Variant identity is ours to establish.** The list of MED17 checksum variants (hardware + method) and which are signed is built from our corpus and oracle records, because no public list exists.

## Alternatives considered

| Alternative | Why not |
|---|---|
| Community documentation as the algorithm source | Not enough to implement program-flash checksums without inferring, and inferring an algorithm is forbidden (skill `checksum-descriptor`). |
| Vendor or port the MIT tool into Impact | Single-source constants, thin validation by its author's own account, and the file mixes out-of-scope forging code. Owning the implementation keeps the dual-implementation check honest: two codebases from different sources. |
| Licensed commercial module (e.g. WinOLS OLS807) | Paid, which violates the zero-cost MVP (SPEC-000 §Principles); requires WinOLS; no public embedding terms. Revisit in Phase 1 if a second commercial oracle is worth paying for. |
| Own reverse engineering of the ECU firmware | Months per hardware variant and legal risk (SPEC-000 §Gaps, Lei 9.610 art. 107); not justified while public structure descriptions exist as a starting hypothesis. Would need its own ADR. |

## Consequences

- The timeline risk in SPEC-000 §Phase −1 materializes partly: per-variant mapping and signature status must come from our own corpus. Weeks 3 to 6 (independent verify) depend on how fast the partner shop provides dumps and `golden_field` records.
- `corpus` needs, per variant: ≥ 5 unmodified originals with `hw_id`/`sw_id`, at least one `golden_field` flash record, and a recorded result of running the reference tool (version and hash), stored as `golden_concordant` evidence.
- The cross-check runs only where real dumps live (`corpus`, private), never in public `core` CI.
- Licensing: no third-party code enters Impact, so no license compatibility question arises. (For the record, the FSF lists Expat/MIT as GPL-compatible, [license list](https://www.gnu.org/licenses/license-list.html); the page does not state AGPL compatibility explicitly.)
- Open: which MED17 variants are signed; whether the documented block structure holds across sub-variants; the "Compatibility Test Checksum" EVC describes ([FAQ](https://www.evc.de/en/service/q1307.asp)) is not mapped to any block type by any source.

## Sources (retrieved 2026-10-18)

- https://github.com/ConnorHowell/medc17-checksum-tool (README, LICENSE, repository metadata)
- https://nefariousmotorsports.com/forum/index.php?topic=24076.0 (tool announcement)
- https://reverseengineer.net/bosch-med17-edc17-ecu-reverse-engineering/
- https://chipoktuning.com/checksum/bosch-med17-1-1-irom-tc1796-tprot-vag-checksum-fix-online/?lang=en
- https://www.evc.de/en/product/ols/plugins_detail.asp?cksName=OLS807
- https://evc.de/en/service/q1304.asp
- https://www.evc.de/en/service/q1307.asp
- https://nefariousmotorsports.com/forum/index.php?topic=3574.0
- https://www.gnu.org/licenses/license-list.html
