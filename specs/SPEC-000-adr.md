# SPEC-000 · Impact ADR (ECU verification and recalibration platform)

Canonical source: this markdown file in the repository. It started as version 12 of the ADR HTML artifact in Claude (2026-10-18), which now holds only the diagrams; every later change is made here through a `foundation-change` PR.

Product name: **Impact**. GitHub organization: `Impact-ecu`. This repository is the public `core` (AGPL-3.0); corpus and family plugins live in private repositories of the organization.

Decisions fixed by the author (Luiz, 2026-10-18): reliability is the product; the critical core (binary kernel, per-family plugins, verification gate, provenance) is built first and built very well, before any sale; zero cost in the MVP (everything free or open source, in test mode); the project is software only, with no hardware of its own, with the oracle delegated to the partner tuning shop; business and legal enter only in Phase 1.

---

ADR-000 · Architecture document

# ECU Recalibration Platform

2026-10-18 · Luiz · version 12 · zero cost in the MVP fixed as a principle; per-topic comparison with the leaders

## Vision and scope

A SaaS platform that receives the dump of an ECU/TCU, identifies the controller family, locates the calibration tables, lets the tuner edit them safely, and returns a binary with a valid checksum. The MVP is software only: physical read and write stay on the equipment the shop already has (KESS3, Flex, Autotuner), and the platform consumes the file they export.

### In scope

- Dump ingestion (full read, partial read, bench) and automatic ECU/TCU identification.
- Map detection by heuristics and by imported definitions, with 2D/3D visualization and editing.
- Diff between versions, history, rollback, and comparison with the original file.
- Checksum recalculation per ECU family (plugin).
- Definition library (equivalent to XDF/A2L/map pack), versioned and shareable across tenants.
- Multi-tenant: master shop, sub-dealers, credits per file.

### Out of scope (a decision, not a limitation)

- Any function that removes or disables an emissions control: DPF, EGR, SCR/AdBlue, catalytic converter, lambda, emissions DTC. It does not exist in the product, not even as a hidden flag.
- ECU communication driver (OBD/bench/boot) in the MVP. It comes in a later phase as an integration with third-party hardware, not as own hardware.
- Guarantee of power gain: the platform delivers tooling and data, not a ready-made file.

### Target audience

1.  Remap shops that today pay for WinOLS, ECM Titanium, or StageX and want a faster workflow on cars from the Brazilian market.
2.  Independent tuners who work with Speeduino/FuelTech/MegaSquirt and want the same editor for the original ECU.
3.  Phase 2: manufacturers of read hardware who want to embed the editor as white-label.

## Principles

Agnosticism is principle number one: the core does not know which manufacturer the ECU is from, which tool the file came from, or which cloud it runs on. Everything specific lives behind an interface, and the interface is the product.

| Axis                        | What the core knows                                      | What stays behind an interface                                                           | How it is ensured                                                                                            |
|-----------------------------|----------------------------------------------------------|------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| ECU manufacturer and family | A binary, a memory layout, a list of maps                | Signatures, checksums, offsets, endianness, protected regions                            | `EcuPlugin`; no `if family ==` outside the plugin; the contract test runs identically for every family       |
| Read tool                   | Bytes + hash + declared origin                           | Container format (KESS, Flex, Autotuner, CMD, bdm), headers, dump encryption             | Ingestion adapters that normalize to raw `.bin`; the pipeline never sees the container                       |
| Definition format           | Internal `MapDef` model                                  | XDF, A2L, DAMOS, CSV, third-party map pack format                                        | Edge converters in both directions; round-trip test (import, export, compare)                                |
| Cloud and infra             | Queue, object store, database, secrets, as abstractions  | S3 vs GCS vs MinIO, NATS vs SQS, Vault vs KMS                                            | Thin interfaces per resource (not a framework); MinIO + NATS + Postgres run in `docker compose` on a laptop  |
| Client                      | REST API + SSE                                           | Web, desktop, CLI, embedded integration in third-party hardware                          | No domain logic in the front end; the editor is a consumer of the API like any other                         |
| Detection engine            | Interface `Detector.detect(blob, layout) -> [Candidate]` | Heuristics, definitions, ML                                                              | Detectors are pluggable and combinable by score; swapping one does not change the API                        |

The other principles derive from this one: **immutability** (the original never changes, everything is a patch), **determinism** (same input, same hash), **verification before trust** (nothing is exported without a green verify), and **the user teaches the system** (every correction becomes data).

**Fixed MVP constraint: zero cost.** Everything free or open source, and everything still in test mode, with no sellable product. This does not loosen the architecture by a single byte: the rigor of the core is a reliability requirement and is independent of money. What changes is what stays out until Phase 1: a market-tool license as a second oracle, paid simulators, any paid SaaS, hardware. In the MVP, the `golden_concordant` oracle comes only from what the shop already has plus open source implementations (TunerPro, RomRaider, public checksum descriptions); a variant with no free concordance stays `unknown_variant` and is not admitted. Any improvement to the comparison that costs money is Phase 1 or later, by definition.

## Market coverage

The range is the domestic market first, imports next; the architecture is the same, what changes is the cost of each plugin. Premium imports bring two good things: a high ticket per file and ECUs well documented by the community; and one bad thing: more protection (signature, encrypted boot) in recent years.

| Segment                   | Typical brands and engines                                                                             | Main ECUs                                                                                                                                                                                                                | Typical protection                                                                                                                                                                            | Priority            |
|---------------------------|--------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------|
| Domestic mass-market      | Fiat Fire Evo/T-Jet/Firefly, VW TSI 1.0/1.4, GM 1.0/1.4 and 1.0/1.2 turbo, Renault 1.0/1.6 SCe and 1.3 TCe | Marelli IAW 7GF/9GF (Fire), IAW 8GMF (T-Jet), Firefly to be verified (likely 10GF); Bosch MED17.5.21/.25 and MG1CS002 (VW); ACDelco E83/E80/E78 (GM; turbo to be verified); Continental EMS31xx (Renault SCe; TCe to be verified) | Low to medium; much reading over OBD still possible                                                                                                                                           | Phase 0 and 1       |
| Domestic pickups and diesel | Toro/Ranger/Hilux/S10/Amarok 2.0 to 3.2                                                              | Bosch EDC17C59/C69/CP20, Continental SID209 (Ranger 2.2/3.2), Denso (Hilux)                                                                                                                                              | Medium; more complex checksums                                                                                                                                                                | Phase 1             |
| German premium imports    | BMW B48/B58/N55, Audi/VW EA888 and EA839, Mercedes M264/M256, Porsche 9A2                              | Bosch MG1/MD1, MEVD17, Siemens/Continental SIM2xx, Bosch MED40 (Mercedes)                                                                                                                                                | High: RSA signature and encrypted boot in recent generations (SA2 is a VAG unlock procedure, not ECU protection); depends on bench/boot and on exploits from the hardware manufacturers       | Phase 2             |
| Asian imports             | Hyundai/Kia Smartstream and TGDi, Toyota, Honda                                                        | Kefico CPEGD2.x (MG1 base), Continental SIM2K-24x (older Kappa), Denso, Keihin                                                                                                                                           | Medium to high; Toyota and Honda have little community                                                                                                                                        | Phase 2, on demand  |
| TCUs                      | VW DQ200/DQ250/DQ381, ZF 8HP (BMW, Audi, Jeep), Mercedes 9G-Tronic                                     | Temic/Continental, ZF, Bosch                                                                                                                                                                                             | Medium; proprietary checksums                                                                                                                                                                 | Phase 2             |

Entry rule for a family into the catalog: it only enters with a minimum corpus of 20 distinct dumps, verified checksum golden files, and a reference tuner who validates the initial definition. Without that, the family stays in *beta* behind a feature flag.

## Critical points and first wins

This section says where the project breaks and where structure must exist from the first commit; the rest can be improvised and redone. The rule: invest early where a mistake is irreversible or costs a customer's car; improvise where a mistake costs a refactor.

| Critical point                    | Why it is critical                                                                             | Structure from the start                                                                                | Can wait                                  |
|-----------------------------------|------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------|-------------------------------------------|
| Checksum per family               | An error bricks the car; it is the only defect the customer does not forgive                   | Golden files, mandatory verify before and after export, versioned plugin, contract test                 | Coverage of many families                 |
| ECU identification                | Wrong identification applies the wrong layout and releases a patch in a forbidden region       | Explicit confidence, manual fallback always available, protected region as the default when in doubt    | High accuracy in automatic identification |
| Patch model and immutability      | Changing this later requires migrating every project of every customer                         | `Artifact`, `Patch`, `Version`, and `Event` as in the model, with property tests (determinism)          | Nice history UI                           |
| ECU plugin interface              | It is the contract that the community and partners will program against; breaking it later costs adoption | Stable, versioned protocol, with a conformance suite                                           | Plugins beyond the first family           |
| Labeled dump corpus               | Without a corpus there is no testing, no detection, no ML; it is the asset nobody can copy     | Agreement with pilot shops, anonymization and consent pipeline from day 1                               | Large volume                              |
| Tenant isolation                  | Cross-tenant binary leakage ends the business                                                  | RLS, bucket prefix, per-tenant key, in the initial schema                                               | SSO, sub-dealers, fine-grained billing    |
| Decision on emissions             | A prohibition cannot be "added later" once the product has already violated it                 | Protected regions in the layout and terms of use from the MVP                                           | Formal certifications                     |
| 2D/3D editor                      | It is where the tuner spends the day; but it is only front end and can be redone               | Nothing beyond consuming the API                                                                        | WebGL, offline, desktop                   |
| Multi-cloud and full Kubernetes   | Important in v1, irrelevant with 5 customers                                                   | Thin interfaces for queue, storage, and secrets                                                         | Mesh, Karpenter, multi-region             |

### Phase −1: discovery (two weeks, in parallel with family-agnostic core code)

The three questions in the Review section have no answer today, and that defines the first phase: discover what only the field can answer. **Author's decision (2026-10-18), replacing "not a single line of the kernel before the exit criterion":** the family-agnostic core (kernel, provenance, gate engine, definitions, plugin contract, conformance harness) needs no dump and no shop, so its code starts now, against SPEC-001 to SPEC-005 and their synthetic test vectors. The exit criterion below gates only what depends on the field: any per-variant checksum descriptor or family plugin, any golden file, any `golden_field` claim, and Phase 0 exit.

**Superseded by ADR-002 (author's decision, 2026-10-18): no fixed partner.** Items 1 and 2 below originally named one partner shop (an afternoon following a job; an oracle agreement). They are replaced by contracts any source can satisfy: an `Importer` for any tool's export, and a signed `FieldAttestation` from any enrolled attester, with `golden_field` computed from attestations (ADR-002 Decisions 2 to 5). The original text is kept for history.

1.  ~~One afternoon at the partner shop, following an entire job~~ → importers and a tool registry filled by whoever writes importers (ADR-002 Decision 2).
2.  ~~Oracle agreement with the shop~~ → `FieldAttestation` contract and attester registry (ADR-002 Decisions 3 to 5).
3.  **Map what the community knows about MED17 checksum**: forums, open repositories, documentation of open source tools. This decides whether a public description per variant exists and whether declarative checksum is viable in the MVP.

No lawyer enters here: as long as the work is kernel, bench, and an own ECU on the desk, there is no third party involved. The car owner's terms, the contract with the shop, and insurance are an **entry criterion for Phase 1**, when the first file goes to a customer's car. What is legal but becomes an engineering rule from day 1, at no cost: no byte of a dump in a public repository; corpus with VIN treated as personal data (encrypted, access logged, anonymized per family when the flash allows); the plugin never disables TPROT nor patches the verification routine.

**Exit criterion (ADR-002):** ADR-001 recorded (done); SPEC-006 (`Importer` and `FieldAttestation` contracts) written with vectors; the raw importer implemented. Nothing external. Per-variant plugin release is measured separately, by `golden_field` computed from attestations (ADR-002 Decision 4). The original criterion (shop tool table, a real dump from the shop, purchased ECUs, bench hours, harness, named sacrificial ECU and second human) is superseded.

If Phase −1 concludes that there is no public description of the MED17 checksum, weeks 3 to 6 become 3 to 12, and the audit MVP ships only with `verify` on the variants with golden and `unknown_variant` on the rest, with no recalculation.

### The workflow of StageX users (market reference)

StageX users almost always read and write with the **Flex**, from Magicmotorsport itself; the two were developed in parallel as an ecosystem. The workflow is file-based, with no live link: the Flex reads the ECU (OBD, bench, or boot) and generates a file; the file is uploaded to StageX in the browser, which identifies family and version, shows maps and one-click solutions, and returns the modified file for download; the Flex writes it back and does the checksum correction. StageX does not do the final correction. File extension and any container encryption do not appear in public sources; that is what the afternoon at the shop answers.

Consequences: the entry point of this platform is the same as theirs, a file exported by the tool; checksum recalculation is worth less in the OBD workflow, because the tool already does it, and the value is in the independent *verify* and in the audit; own recalculation becomes worthwhile again on bench/boot and on the families the tool does not cover (phase 1). Sources: [Viezu, StageX with Flex](https://viezu.com/blog/why-use-magic-motorsport-stagex-with-flex/), [Viezu, StageX features](https://viezu.com/blog/key-features-stagex-tuning-software/), [Tuning-shop, Flex functions](https://tuning-shop.com/blogs/magic-motorsport-flex-functions-and-benefits-guide/).

### First wins (delivery order, revised in v5)

The review changed the MVP: most Brazilian shops buy a file from a file service, they do not edit maps. The first product is **audit and verification**, which exercises kernel, diff, plugin, and provenance without the responsibility of writing to the car. The timelines are for one person; week 1 starts with the answer to question 1 of the Review section (where the checksum algorithm comes from), otherwise nothing below that depends on a family holds. Item 2 (SPEC-001 and kernel) does not wait for item 1 (author's decision, 2026-10-18; see Phase −1).

1.  **Week 1: `Importer` and `FieldAttestation` contracts (SPEC-006, ADR-002).** Any enrolled attester writes, reads the diagnostics and signs an attestation. Without enough attestations there is no `golden_field`; with `golden_concordant` you can develop, but not release a plugin's recalculation.
2.  **Weeks 1 to 3: SPEC-001 and kernel** with multi-memory, `dump_kind`, `apply`/`release`, the 12 invariants. Local CLI.
3.  **Weeks 3 to 6: independent MED17 verify** per checksum variant, golden on the bench. The CLI says "this file is intact" and "this file is stock or already modified" (stock hash registry).
4.  **Weeks 6 to 9: third-party file audit.** The shop uploads the original + the file service's file, and receives a per-map diff (imported XDF), verify, and a one-page report signed for the work order. First billable product.
5.  **Weeks 9 to 12: automatic identification and heuristic detection** for files without XDF, with level 1 gate and labels in `proposed` state.
6.  **Weeks 12 to 16: editing and export** via CLI/simple HTML table, full gate, paid pilot with the first shops that adopt it, single-tenant (one instance per customer).

## Foundations: the trusted core

The product is reliability; the software around it is packaging. That is why the architecture has a small core, built to critical-software rigor, and everything else is a consumer of it. If the core is right, a bug in the API or the editor costs a fix; if the core is wrong, it costs a customer's car and the product's reputation.

### What is inside and outside the core

*(diagram: see the ADR's HTML artifact)*
*core · 4 pieces + corpus; all consumers import the same package*

The boundary is clear: the core is a pure Python library. It does not open files, talk to a database, or know about HTTP. It receives bytes and objects and returns bytes and objects. That is what allows it to be tested exhaustively and to run in the CLI, in a worker, and even in the browser (via Pyodide or a port) with the same behavior.

### Why everyone depends on this being 100% correct

| Consumer              | What it does                                      | What happens if the core fails                                                             |
|-----------------------|---------------------------------------------------|--------------------------------------------------------------------------------------------|
| Export (worker)       | Materializes original + patches and fixes checksum | The file written to the car does not start, or starts with a wrong value in a cell nobody edited |
| Editor                | Shows maps and accepts edits                      | Shows a table at the wrong offset; the tuner edits "ignition" and is changing something else |
| Diff and audit        | Compares versions and answers "what changed"      | The audit lies; the shop cannot prove what it delivered                                    |
| Virtual bench         | Validates before export                           | Approves a dangerous file or blocks a good one; either way, trust in the gate is gone      |
| Hardware partners     | Embed the core in their workflow                  | The bug ships under their name; the contract ends                                          |
| Corpus and detection  | Labels originate from confirmed edits             | A wrong core produces wrong labels; the data that should improve the system poisons it     |

### Two stages: `apply` and `release`

Materialization is split into two stages with two hashes, because checksum correction breaks invertibility. `apply(o, P) → UnverifiedImage` is pure and invertible, with no checksum. `release(UnverifiedImage, plugin) → ReleasedImage` applies `checksum_patches` and runs the gate. `UnverifiedImage` does not expose `.bytes` and is not serializable; only `gate.release()` constructs `ReleasedImage`, and import-linter forbids `kernel` and `plugins` from importing `gate`. The bypass is prevented by structure, not by a single test: import-linter contracts, export functions that accept only `ReleasedImage`, and the layer-4 architecture test (SPEC-001 R7–R9).

### Binary kernel invariants

Each invariant is a property test that runs in CI with thousands of generated inputs, plus a runtime assertion in the corresponding function. If the assertion fails in production, the job aborts and automatically opens an S1 incident. Invariants 1 to 8 hold over `apply`; 9 to 12 over `release` and provenance.

1.  **Determinism.** `apply(o, P)` called twice, on different machines (x86 and arm64), returns identical bytes. `struct` with native format (`@`, `=`) and `numpy.frombuffer` without explicit byte order are forbidden; blocking lint. The kernel contains no float.
2.  **Composition.** For every `k`, `apply(o, P) == apply(apply(o, P[:k]), P[k:])`. Reapplying an already-applied patch fails on the precondition (4); it never applies silently.
3.  **Containment.** For every patch `p`, `(p.memory_id, [p.offset, p.offset + p.length))` lies entirely within a `calibration` region of that memory. `offset` is relative to the start of the memory (`base_address` never enters a kernel offset; SPEC-001 R2); `len(before) == len(after) == length > 0`. Any byte outside is rejected before any write.
4.  **Patch precondition.** `before` of `P[i]` is compared against `apply(o, P[:i])`, never against `o`. A failure is a conflict, never a silent overwrite.
5.  **Locality.** Bytes outside the union of the ranges of `P` are identical between `o` and `apply(o, P)`, in all memories.
6.  **Invertibility.** `invert(P)` is `P` with `before` and `after` swapped and every overlap pair reversed (exact definition: SPEC-001 R30); `apply(apply(o, P), invert(P)) == o` byte for byte. `diff(o, apply(o, P))` returns the canonical set of disjoint patches, ordered by `(memory_id, offset)`, such that `apply(o, diff(...)) == apply(o, P)`.
7.  **Canonical order.** The kernel normalizes disjoint patches to `(memory_id, offset)` order before hashing, so reordering disjoint patches does not change the hash. Overlapping patches require `Version.overlaps[]` (ordered pairs of `patch_hash`); without it, `apply` rejects.
8.  **Preserved shape.** The output has the same `dump_kind`, the same memories, and the same `base_address` and sizes as the original. Exporting a partial yields a partial. A patch never resizes.
9.  **Contained checksum and release locality.** Every patch returned by `checksum_patches` is in a `checksum` region; otherwise the kernel rejects the whole set. `release(u)` differs from `u` only in bytes of `checksum` regions. `calibration` and `checksum` regions are disjoint; a layout that violates this is rejected.
10. **Verified release and immutable verdict.** `release` returns `ReleasedImage` only with a green `verify` (status `ok`, or `signature_unverifiable` when no region is `fail` or `bypassed`, which exports only with `warn`, §Plugin SDK; pending author decision, SPEC-004 open question 1) and a verdict of `no findings` or `warn`; `block` raises. `ReleasedImage.verdict` is immutable, and export with `warn` requires an `Event{alert_ack}` referencing `image_hash(release)` (SPEC-005 R36).
11. **Patch migration.** Re-analysis with a new plugin creates a new `Version` and migrates only patches whose `before` still matches *and* that satisfy Containment under the new layout; the rest become explicit conflicts with a reason (`before_mismatch` or `out_of_region`).
12. **Complete, reproducible provenance.** `patch_hash = sha256(JCS({memory_id, offset, length, before, after}))`; author, timestamp, and `map_id` are outside the hash. `image_hash = sha256(JCS({dump_kind, memories: [{memory_id, base_address, size, sha256(bytes)}]}))` with sorted memories. Every output carries `image_hash(o)`, `image_hash(apply)`, `image_hash(release)`, the canonical list of `patch_hash`, `layout_hash`, the version of the kernel, of each plugin, and of the gate rules, `sha256(gate_report)`, `verdict` (and the ack's `event_id` if `warn`), the exact Python version, and `build = {kind: image | lockfile, value, platform}`. An export with `kind = lockfile` (CLI on a laptop) gets `reproducibility: best_effort` and is not valid for golden. Canonical JSON is RFC 8785 (JCS).

### ECU plugin contract and conformance suite

A plugin is code written by someone who knows an ECU family, often from outside the team. The core does not trust it: each plugin goes through a conformance suite that runs against that family's corpus, and is published only with a green verdict.

| Function                                    | What conformance requires                                                                                                                                                                                                                           | How it is measured                                                                                                                                     |
|---------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
| `identify`                                  | Correctly identifies every dump in the family corpus; discriminates 100% of pairs with the same `sw_id` and a different checksum variant; returns `None` or confidence \< 0.5 for dumps from other families and for random bytes; never raises an exception | Positive and negative corpus; fuzzing with 10⁵ random and mutated inputs                                                                               |
| `verify` on a file with checksum disabled   | Returns `bypassed`, with the verification routine's patch located, for every corpus file labeled "checksum off"; never `fail`                                                                                                                       | Negative corpus of file-service files and files from other tools                                                                                       |
| `layout`                                    | Regions do not overlap, cover the entire file, and emission regions are marked `protected`; for known dumps, matches the human-reviewed reference layout                                                                                            | Structural validation + comparison with golden layout                                                                                                  |
| `checksums` and `verify`                    | Every original corpus dump passes `verify`; 1 byte changed in a covered region fails `verify`; 1 byte changed outside any checksum region does not change the result (detects a wrongly declared region)                                           | Per region: 1,000 uniform positions + 64 bytes at each edge + the edges of each block, 100% detection on the sample in PR; full coverage in the nightly |
| `checksum_patches`                          | After applying, `verify` passes; the result matches the golden file byte for byte; all patches are in a `checksum` region                                                                                                                           | Golden files (oracle rules below) + invariant 9                                                                                                        |
| `hints`                                     | Optional; every hint points to a `calibration` region; no hint points to a `protected` region                                                                                                                                                       | Structural validation                                                                                                                                  |
| General behavior                            | Pure: no I/O, no network, no global state, no threads; maximum time per call; maximum memory                                                                                                                                                        | Sandbox in the suite with limits; import of `os`, `socket`, `subprocess` forbidden                                                                     |

The suite is the same for internal and external plugins, and its result is published alongside the plugin (how many dumps, which checksum variants, which mutations). The tenant sees this before trusting a family. In the MVP there is no third-party plugin; when there is, it runs in a subprocess with seccomp, no network, no credentials in the environment, communicating via bytes over stdin/stdout. Forbidding imports in Python is not a sandbox.

### Golden files: who is the oracle

- The oracle is **delegated through a contract** (ADR-002): the project is software and has no hardware of its own, and no fixed partner. Three golden levels, strongest to weakest: `golden_field`, the binary was written by enrolled attesters to real ECUs (at least 2 attestations from 2 distinct attesters on 2 distinct ECUs, ADR-002 Decision 4) and then the ECU communicates over diagnostics, shows zero memory or checksum DTCs (P0601, P062F, and similar) after clearing and re-reading, and, when the tool reports the internal checksum, it matches; each attester returns data only, as a signed `FieldAttestation`, and `oracle:` lists the attestation hashes. "It booted" is not enough: a MED17/EDC17 with a wrong checksum starts and communicates, it just logs a DTC and cuts injection. `golden_concordant`, two independent tools produce the same result for the same file; 100% software, good for development, not for release. `candidate`, a single tool. Tools disagree (one recalculates, another patches the verification routine); a tool's opinion is not truth. Plugin release requires `golden_field` per variant.
- No hash in `tests/golden/` may have been produced by code from this repository. Each hash records oracle, version, and date; a PR without `oracle:` in the body fails the guardrail.
- Golden is per **checksum variant** (hardware + method), not per family. The plugin's definition of done counts variants, not dumps.
- Dual implementation in the MVP is honest: the "second implementation" is the external oracle (tool + bench) over the corpus, not a second piece of code by the same author. When a second codebase exists, it comes from a different source and the ADR records the source of each.
- Anonymization and golden do not mix: zeroing the VIN in flash breaks the checksum. Decision: the checksum corpus is not anonymized; it is personal data with consent, encrypted, access-logged, never in a public repository. Anonymized bytes serve only for map detection.

### Verification gate: the only way out

No binary leaves the system without passing the gate, and the gate is a core function, not an API step someone can skip. It runs twice: before accepting the original (is the file that came in intact?) and after materialization (is the file about to go out intact and plausible?).

- **Input:** hash matches the declared one; `identify` with confidence above the threshold or a recorded manual confirmation; green `verify`. A failure in any of them marks the artifact `suspect` and blocks editing.
- **Output:** all kernel invariants; green `verify` after the fix; level 1 plausibility rules per map category; no patch in a `protected` region.
- **Ternary verdict:** `block` only for the physically impossible or structural: outside the sensor range, non-monotonic axis, protected region, checksum, injector duty above 100%. `warn` only for plausibility; exports with explicit confirmation recorded in an event with the warning text. `no findings` (never "pass": the gate does not approve, it only found nothing). Every report opens with: "This gate verifies file integrity and cell-by-cell plausibility. It does not verify the combination between maps, firmware behavior, or the real engine." The gate never returns just a boolean.
- **Keyed ranges, not single ones:** the plausibility range is a function of (category, map type: base, correction, limit, or flag; SI or CI combustion; fuel: gasoline, E27, E100, flex by ethanol axis, diesel; canonical unit after raw→physical conversion). A correction map tests only relative amplitude; flags and limiters do not test range; smoothness only on maps ≥ 2×2 with non-binary values. A rule without a declared fuel does not run. Example (SI gasoline, base map): ignition −10° to 45°, capped at 30° in cells above 50 kPa relative boost; λ 0.75 to 1.15; CI: λ ≥ 1.15. Still missing, to be added per category: rail pressure, injector dead time and flow, torque and speed limiters, target EGT, VVT, absolute vs relative boost, wastegate duty, STFT/LTFT limits.
- **"Diff above threshold" is not an alert rule:** the tuner exists to leave the OEM range; a stage 1 changes boost by 30%. The diff goes in the report as information, not as a warning.
- **Dual implementation where possible:** for families with a known checksum algorithm, the core computes with its own implementation and with an independent reference implementation; export only with both agreeing. Divergence is a plugin bug and becomes S1.
- **Physical range only with a reviewed category:** for a map without a `reviewed` category, the gate tests only axis monotonicity and smoothness, lists the map under "not tested: physical range", and emits a fixed `warn`: "you edited a map whose meaning has not been confirmed".
- **Alert fatigue is measured per rule, not by a global target:** the fraction of alerts confirmed in under 5 s without changing the map; a rule above 50% on this fraction, per family, is downgraded to informational and reviewed. A tenant can silence a rule per project with a recorded justification. A global target of "fewer than 10% alerts" would become pressure to loosen rules.
- **Fail-closed:** if the range table, the dual implementation, or the plugin is unavailable, export is blocked, never released for lack of verification.

### Core engineering practices

| Practice                       | Tool                                                                               | CI rule                                                                                                                                                                                                          |
|--------------------------------|------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Property testing               | Hypothesis                                                                         | Each invariant has a test with ≥ 2,000 examples; `max_examples` goes up in the nightly build                                                                                                                     |
| Golden files                   | Versioned corpus (DVC or LakeFS), hashes in the repository                         | Any change to an expected hash requires a separate PR with justification and two reviewers                                                                                                                       |
| Fuzzing                        | Atheris (libFuzzer for Python)                                                     | Parsers and `identify` run 10 min per PR, 8 h nightly; a crash is blocking                                                                                                                                       |
| Mutation testing               | mutmut                                                                             | Score ≥ 90% on the `core` package, measured in the nightly with a ratchet that only goes up; does not block merge (costs hours per PR)                                                                           |
| Heuristic precision            | Validation set with `MapDef` in `reviewed` state                                   | Hit = byte-range IoU ≥ 0.95 and equal dims; precision, recall, and F1 at k = 50 per family; validation never contains dumps from the tenant that generated the label                                             |
| Design by contract             | Explicit pre/postconditions (`icontract` or own asserts), active in production     | A contract failure in production aborts the job and opens an incident                                                                                                                                            |
| Strict typing                  | mypy `--strict`, Pydantic on boundary models                                       | Zero `Any` in `core`                                                                                                                                                                                             |
| Coverage                       | coverage.py with branch coverage                                                   | 100% of lines and branches in `core`; the rest of the system has no hard target                                                                                                                                  |
| Reproducible build             | Dependencies pinned with hashes, image with fixed digest, SLSA level 2 (target level 3) | The image digest goes in each export's provenance report                                                                                                                                                    |
| Review (ritual for one person) | The team is one person; "two reviewers" would be switched off in the first week    | A PR on a foundation path stays open ≥ 24 h before merge (CI checks the timestamp), a self-review checklist filled in the body, and, when there is golden, approval by the reference tuner named in CODEOWNERS |
| Versioning                     | Semver in `core` and in each plugin                                                | Any change that alters one output byte for any corpus input is *major*; detected automatically by running the corpus on both versions                                                                            |
| Living regression              | Every production bug becomes a dump + a corpus case before the fix                 | The fix PR must reference the case                                                                                                                                                                               |

### Standards written before the code

- **SPEC-001 Kernel:** `Patch` format, `Version` semantics, ordering and overlap rules, provenance fields. With canonical examples and test vectors.
- **SPEC-002 EcuPlugin:** the protocol, the `MemoryLayout` and `Identification` schema, time and memory limits, compatibility policy (what is breaking), publication process, and the conformance suite as part of the spec.
- **SPEC-003 Definitions:** JSON schema for `MapDef` and `Definition`, units and factors, conversion rules to and from XDF and A2L, with mandatory round-trip.
- **SPEC-004 Gate and verdict taxonomy:** what blocks, what warns, report format, how the user confirms a warning and what is recorded.
- **SPEC-005 Provenance:** what every artifact and every event carries; exportable format (canonical JSON, signed).
- **One ADR per decision:** choice of Hypothesis, of dual checksum implementation, of pure Python in the core, of a versioned corpus outside git. This page is ADR-000.

### `core` repository structure

    core/                      # public repository
      src/core/
        kernel/                # Artifact, Patch, Version, apply, release, diff, invert
        plugins/_contract.py   # Protocol EcuPlugin, Dump, MemoryLayout, Identification
        gate/                  # input and output verify, level 1 rules, verdict
        provenance/            # event, report, JCS, hash chain
        definitions/           # MapDef, Definition, XDF/A2L converters
        conformance/           # suite every plugin runs (exposed as a reusable workflow)
        importers/             # Importer contract, dispatch, raw importer (SPEC-006)
        evidence/              # FieldAttestation, attester registry, golden_field evaluation (SPEC-006)
        stock/                 # stock registry and stock | modified | unknown lookup (SPEC-008)
      tests/
        properties/            # Hypothesis, one file per invariant (test_inv_*.py)
        golden/                # hashes + oracle only; no dump bytes
        fuzz/                  # Atheris targets
      specs/                   # SPEC-001 to 009, ADRs
      guardrails/              # check.py, ratchet.json, ruleset.json
      .github/workflows/

    ecu-plugin-bosch-med17/    # private repository; one per family
    corpus/                    # private repository; DVC, nightly, ephemeral runner

Tests live outside the package (they do not go into the wheel). Family plugins live in private repositories that consume conformance as a reusable workflow; the public `core` carries only the contract. API, workers, CLI, and editor depend on `core` at a pinned version; bumping the version in a consumer is a PR with the corpus report attached.

### "Done" criteria for each piece

| Piece                         | It is done when                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|-------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Kernel                        | All 12 invariants have a property test and a runtime assertion; SPEC-001 published with test vectors, multi-memory and `dump_kind` from the first version; `apply` + `release` of the entire corpus in \< 1 s per dump; determinism verified on x86 and arm64 over the corpus; a naive reference implementation of `apply` (≤ 50 lines, stdlib only) agreeing byte for byte in a differential test; the provenance reproduction script uses stdlib only |
| First plugin (Bosch MED17)    | Passes conformance for each covered checksum variant (hardware + method), with ≥ 5 dumps per variant; each variant has `golden_field` computed from signed field attestations (SPEC-006, ADR-002 Decision 4); the reference tuner, who is not the same person who requests the finished file, validated the layout                                                                                                                                                              |
| Gate                          | There is no code path that produces an output binary without going through it (verified by an architecture test, import-linter); the report always lists what was tested and what was not; dual implementation active in the first family                                                                                                                                                                                                                 |
| Provenance                    | Every export reproducible from the report alone (original + patches + versions + digest) by an independent script, on a clean machine                                                                                                                                                                                                                                                                                                                     |
| Corpus                        | Ingestion pipeline with anonymization and consent; versioned; each dump with origin, family, software version, and human review status                                                                                                                                                                                                                                                                                                                    |

**The point that organizes everything:** until the core meets these criteria, no consumer is a priority. The checksum CLI exists to force the core to exist; the editor exists to force the gate to be used. The order is from the center outward.

## Guardrails, CI, and free stack

A standard that can be loosened for convenience on a Friday night is not a standard. This section defines how the standards from the foundations become physically hard to remove, what CI runs, and with which tools, all free or open source, in the MVP.

### Four layers of assurance

No layer holds on its own; together, loosening a standard requires a visible change, reviewed by two people, with a written justification, and even then it leaves a trail.

| Layer                                             | What it does                                                                                                                                                                                                                                                                                                                                            | How it is implemented                                                                                                                                                                                                                                                                                                                                                                                 | What it does not prevent                                                                  |
|---------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------|
| 1 · Ruleset on the host                           | Merge only via PR, required checks, no force-push, no bypass list. With a one-person team, 0 approvals (the author does not approve their own PR; 2 approvals = merge impossible). An admin can always edit the ruleset; "including for admins" does not exist                                                                                          | Ruleset exported as JSON and versioned in `guardrails/ruleset.json`; the GitHub audit log shows when it was changed                                                                                                                                                                                                                                                                                   | It is an audit trail, not a barrier. The real barrier is layer 2                          |
| 2 · CI guardrail, executed from `main`           | A job that fails the PR if: a foundation path changed without the `foundation-change` label; kernel, gate, or contract changed without a spec or ADR alongside; golden files changed in the same PR as code or without `oracle:`; a ratchet went down; `skip`, `xfail`, `type: ignore`, `noqa`, or `pragma: no cover` appeared in `core/`; the number of invariant files dropped | On the `pull_request` event the workflow that runs is the PR branch's, so a PR that edits the guardrail would run the edited version. That is why the job uses `pull_request_target` (opened, synchronize, labeled, unlabeled) and `pull_request_review`, checks out **only the base ref**, and reads the diff and metadata via the API; it never executes code from the PR branch. The script that judges the PR is always the one from `main` | Someone with full access and bad intent; it prevents loosening out of haste, which is the real risk |
| 3 · Ratchets                                      | Thresholds that only go up: coverage (100%), number of invariants (12), Hypothesis examples, fuzz minutes, minimum dumps per variant in the corpus. Mutation score (≥ 90%) is a **release** ratchet: the release workflow reads the latest nightly report and fails if below the JSON                                                                    | File `guardrails/ratchet.json` compared with the version at the PR base; CI checks that `pyproject.toml` reflects the same numbers                                                                                                                                                                                                                                                                    | In a PR it only prevents lowering the number in the JSON; the real metric is enforced at release |
| 4 · Architecture tests                            | The code cannot violate the structure: `core` does not import I/O, network, subprocess, or framework; layers kernel → provenance → definitions → plugins → gate → conformance; plugins do not import each other; there is no path that produces an output binary without going through the gate                                                                       | `import-linter` with versioned contracts; a test that walks the `export` call graph                                                                                                                                                                                                                                                                                                                   | Logic errors inside the layers; invariants and golden files exist for that                |

### CI pipeline for the `core` repository

| Workflow             | When                                                                                                | What runs                                                                                                                                                                                                                                                                                                                                                                         | Blocks merge?                     |
|----------------------|-----------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------|
| `core-ci`            | Every PR and push to main                                                                           | ruff (lint + format); mypy `--strict` without `Any`; import-linter; pytest with branch coverage and `fail_under = 100`; Hypothesis with 2,000 examples and a fixed seed; golden of the fast corpus (≥ 20 dumps); 10-min fuzz per parser                                                                                                                                           | Yes                               |
| `guardrails`         | Every PR, including on label changes                                                                | The layer 2 and 3 rules above                                                                                                                                                                                                                                                                                                                                                     | Yes                               |
| `plugin-conformance` | Reusable; called by each plugin's repository                                                        | Sandbox (no import of os, socket, subprocess); identify on the positive and negative corpus; 10⁵ fuzz inputs; byte-by-byte mutation with 100% detection in checksum regions; golden of `checksum_patches`; JSON report published alongside the plugin                                                                                                                                | Yes, to publish the plugin        |
| `nightly`            | Daily, 03:17 UTC, or manual; lives in the **private corpus repository**, which clones `core` by SHA | Hypothesis with 50,000 examples and a random seed; fuzz in a matrix of targets × 2 h (a job cannot exceed 6 h) with accumulated fuzz corpus; full corpus byte by byte; mutation testing with score against the ratchet; a failure automatically opens an S1 issue                                                                                                                  | Does not block PR; blocks release |
| `release`            | Tag `vX.Y.Z`                                                                                        | Tag version equals `pyproject`; reproducible build with `SOURCE_DATE_EPOCH`; full corpus green and the last nightly's mutation score above the ratchet; SBOM (syft); scan (grype, fails on high); keyless signing with cosign; SLSA 3 provenance attestation via `slsa-github-generator` from the first release, and the export's provenance uses the attestation's `build_id`   | No release without everything green |

Automated semver rule: `nightly` and `release` run the corpus on both versions (base and candidate); any differing output byte for any corpus dump marks the change as *major*, and the release fails if the major version was not bumped.

### Foundation change ritual (one-person team)

1.  Open or update the spec or ADR in `specs/` in the same PR, stating what changes and why.
2.  Apply the `foundation-change` label; without it the guardrail fails.
3.  The PR stays open ≥ 24 h counted from the branch's **last commit** (counting from `created_at` would be gameable: open it empty, wait, push the real change). An hourly `schedule` workflow re-evaluates open PRs with the label and updates the check via the API, because the check does not run on its own when the 24 h expire.
4.  Self-review checklist filled in the PR body; when there is golden, approval by the reference tuner named in CODEOWNERS.
5.  If golden files change, a separate PR with only them, label `golden-change`, and `oracle:` in the body; the code PR references that one.
6.  If any ratchet needs to go down (it should not), it takes its own ADR explaining why, and the number goes back up by a deadline.

### Pipeline security

- `permissions: contents: read` at the top of every workflow; `id-token: write` only in the signing job.
- All actions pinned by full SHA; Dependabot for `github-actions` and `pip` (updates the lockfile hashes).
- No workflow in the public repository uses a self-hosted runner: "only runs on main and member PRs" is intent, not configuration, and any `runs-on: self-hosted` triggered by `pull_request` runs fork code. The self-hosted runner is ephemeral (JIT, disposable VM) and registered only in the private corpus repository.
- Actions settings: mandatory approval for all external collaborators.
- `pull_request_target` never checks out the PR head.
- No dump bytes in a public repository: hashes only.

### Free or open-source stack for the MVP

Everything below costs zero money; the cost is a machine for the self-hosted runner and the time to set it up. The important constraint is in the first row.

| Function                  | Choice                                                                                            | Why                                                                                                                                                                                                   | Caveat                                                                                                                                                                                                                  |
|---------------------------|---------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Code hosting and CI       | GitHub: public `core`, corpus and family plugins in private repositories                          | Unlimited Actions on public; rulesets and required checks work on public on Free                                                                                                                      | On GitHub Free, branch protection and required reviewers exist only on a public repository; for private it is Pro (personal) or Team (organization). Self-hosted Forgejo is the emergency exit, with the same workflows |
| CI runner                 | Self-hosted runner (any Linux) for nightly and fuzz; hosted for PR                                | 8 h fuzz and mutation testing blow through any free quota                                                                                                                                             | Runner isolated from the production corpus; test corpus only                                                                                                                                                            |
| Versioned corpus          | DVC with remote on Backblaze B2 or Cloudflare R2 (free tier), private bucket, versioning on       | Dumps outside git, versioned by hash, with `dvc pull` only in the private repository; MinIO community went into maintenance mode in 2025 and exposing a VPS to hosted CI is unnecessary surface        | Monthly copy with `rclone` to local disk; credential only in the private repository                                                                                                                                     |
| Tests                     | pytest, Hypothesis, Atheris, mutmut, coverage.py                                                  | All OSS, mature, no external service                                                                                                                                                                  | Atheris needs clang on the runner                                                                                                                                                                                       |
| Static quality            | ruff, mypy, import-linter, pre-commit                                                             | Fast, no SaaS                                                                                                                                                                                         | —                                                                                                                                                                                                                       |
| Supply chain              | pip-tools with hashes, syft, grype, cosign (sigstore keyless), SLSA 3 via the official generator  | Reproducibility and signing without managing a key                                                                                                                                                    | Keyless depends on GitHub OIDC                                                                                                                                                                                          |
| Secrets                   | SOPS + age in the infra repository                                                                | Versioned, encrypted secrets, no Vault in the MVP                                                                                                                                                     | age key in two physical locations                                                                                                                                                                                       |
| Local observability       | Prometheus, Grafana, Loki, Tempo in docker compose                                                | Same stack as v1, just smaller                                                                                                                                                                        | —                                                                                                                                                                                                                       |
| Database, queue, storage  | Postgres, NATS JetStream, MinIO in docker compose                                                 | Identical to production; the core does not even know they exist                                                                                                                                       | —                                                                                                                                                                                                                       |
| Work tracking             | Forgejo/GitHub's own issues, ADRs in markdown                                                     | Nothing to pay for, everything next to the code                                                                                                                                                       | —                                                                                                                                                                                                                       |

**Runner and public repository:** a fork PR never runs on a self-hosted runner with corpus credentials (a known RCE). The self-hosted runner only executes on `main` and on member PRs; the corpus used in PRs is a subset with no personal data and no firmware, accessible without credentials. No dump bytes enter a public repository: hashes only.

**Recorded decision (2026-10-17):** GitHub from the start. While the plan is Free, `core` stays public (the value is in the corpus and in the family plugins, which stay in private repositories); if `core` needs to be private, the Pro plan unlocks branch protection and required reviewers. Forgejo remains the emergency exit, since the workflows are compatible.

## Adversarial review and v5 decisions

An independent reviewer (staff engineer for critical systems, bench tuner and investor, in a single persona) attacked version 4 of this document. What was clearly right has already been applied in the earlier sections; what remains here are the gaps that still require a decision, what was cut from the MVP, the high-value improvements, and the open questions.

### What changed in earlier sections because of the review

- Data model: `Artifact` gained `origin`, `dump_kind` and `memories[]`; `Patch` gained `memory_id`; `MapDef.dtype` is now complete; labels have state.
- Kernel: `apply` and `release` separated, 12 invariants, determinism proven on two architectures, no floats, JCS, `build_id` for the CLI.
- Plugin: `checksum_patches` in place of `fix_checksums`; `protected` by default; declarative checksum; real subprocess sandbox once a third party is involved.
- Golden: the oracle is an ECU that boots on the bench; per checksum variant; never produced by the code itself; checksum corpus is not anonymized and never public.
- Gate: physical range only with the `reviewed` category; alert rate measured.
- Rite: for one person (24 h + checklist + reference tuner on golden); mutation testing in the nightly.
- First gains: the MVP became audit and verification; physical bench in week 1.
- CI: self-hosted runner protected from fork PRs; zero dump bytes in a public repository.

### Gaps that still require a decision

| Gap | Why it bites | Proposed decision | Status |
|---|---|---|---|
| Table per read tool | KESS3, Flex, Autotuner export different containers, some encrypted by the manufacturer's cloud; some fix the checksum on write and it cannot always be turned off. Decides whether the MVP works with the partner shop's equipment | Survey with the shop: tool, exported format, whether it accepts an external file back, whether it fixes the checksum on write, whether OBD write is full or partial. Turn it into a table in this section | Open |
| Offline export | The moment without internet is the car on the lift; the gate runs on the worker | The core runs locally via CLI with gate and provenance; the SaaS is corpus, definitions and audit. Emergency download of the original in one click, without complex login | Decided |
| "Original" that is not stock | Cars arrive remapped by third parties; labeling maps on top of someone else's stage 1 poisons the corpus | Registry of stock file hashes per software version; every upload is classified as stock, modified or unknown | Decided |
| WORM vs LGPD | Object Lock in compliance mode prevents deletion at the data subject's request | Governance mode, and effective deletion by destroying the artifact's encryption key | Decided |
| Consent and corpus after tenant cancellation | "Revoking the key erases everything" conflicts with a corpus derived from its dumps | Corpus consent is decoupled from the account and recorded per dump; cancellation without revoking consent keeps the dump in the corpus; revocation purges | Needs contract |
| Firmware copyright and A2L | A dump contains Bosch firmware; a forum A2L is a leaked trade secret; a public `core` makes any byte in `tests/` a DMCA target | No dump bytes in a public repository; definitions of unlicensed origin stay private to the tenant that imported them; shared library only with a definition created on the platform or a verifiable license | Decided |
| Anti-circumvention (Lei 9.610, art. 107) | Recalculating a checksum is probably not circumvention; disabling TPROT or patching the verification routine is arguable | The plugin recalculates; it never patches the verification routine nor touches TPROT. Written in SPEC-002 | Decided, confirm with a lawyer |
| CDC and joint liability | The terms of use bind the shop, not the car owner, who can sue the whole chain | Contract with the shop (data, labels, indemnification, continuity), car owner acknowledgment form in the pilot, sacrificial ECU budget, liability insurance (RC) assessment | Open, needs a lawyer |
| CONTRAN/PROCONVE | A remap itself may be a change to a vehicle characteristic | The terms of use say this explicitly; the product does not promise regularity | Decided |
| Bus factor 1 with third-party data | If the author stops, customers' originals are stuck | Bulk export of originals by the tenant at any time; decryption key in escrow with written instructions; paid reference tuner as the second human and CODEOWNER of plugins and golden | Partial |
| Watermark by map pack perturbation | Perturbing an offset breaks the map; perturbing a factor induces wrong edits; two tenants comparing packs find the mark | Cut. Signed metadata and, if needed, decoy maps | Decided |
| Real cost of the pilot | Storage is negligible; the cost is WinOLS with a checksum module as a secondary oracle, bench ECUs, self-hosted runner and the shop's time | Budget: ECUs R\$ 2 to 4 thousand; a second reference tool; runner machine; compensation to the shop that is not a "lifetime license" (perpetual liability) | Open |

### High-value improvements

| \# | What | Why it is worth it | Cost | Phase |
|---|---|---|---|---|
| 1 | Oracle delegated through the `FieldAttestation` contract from week 1 (any enrolled attester flashes and signs hash and log; ADR-002) | The only real checksum oracle, without own hardware; StageX and WinOLS do not give this to the user | 1 day of agreement + hours of the shop's Flex | 0 |
| 2 | Stock hash registry and "has this car already been modified?" | A product that sells on its own (shop, used-car resale, insurer, dealership); generates corpus without an editor; nobody does this in Brazil | 5 days | 0 |
| 3 | Third-party file audit as product number one | Sells to most of the market, zero write liability, exercises the entire core | 10 days | 0 |
| 4 | Declarative checksum (descriptors, not code) | Solves 80% of variants without a sandbox; dual implementation done once | 5 days | 0 |
| 5 | Multi-memory and `dump_kind` in SPEC-001 before the first commit | Avoids the migration the document fears | 2 days | 0 |
| 6 | Local core via CLI with gate and offline provenance | Solves internet at the shop, eliminates infrastructure in the MVP, and the file never leaves the machine of those who fear the cloud | 8 days | 0 to 1 |
| 7 | One-page PDF export report for the work order | Turns provenance into legal protection for the shop; a selling point WinOLS does not have | 3 days | 0 |
| 8 | Before/after datalog instead of the physical engine model | Real data, low cost, honest; the mean-value model would give false safety | 6 days | 1 |
| 9 | Legal kit for the pilot | Without it, the first car that does not start ends the project | 3 days + lawyer | 0 |
| 10 | Named and paid second human | Solves bus factor, validation independence and the review rite | ongoing | 0 |

### Cut from the MVP

- The entire v1 infrastructure inventory: Kubernetes, Karpenter, Linkerd, Temporal, Argo CD, Terraform, Kyverno, OpenFGA, Keycloak, OpenSearch, Redis, WAF, PagerDuty, status page, Intercom, PostHog, Stripe, per-tenant KMS, Sentry. In its place: one VPS, docker compose, Postgres, MinIO or disk, Caddy, e-mail. The thin interfaces stay.
- Multi-tenant, billing and sub-dealers: single-tenant per shop (one instance per customer) up to 5 paying customers.
- 2D/3D WebGL editor with CRDT: an editable HTML table solves it; 3D is a demo.
- Port of the core to the browser.
- SLSA 3, cosign, SBOM and grype: pinned hashes and a lockfile suffice until there are users; they return in v1.
- Mutation testing as a merge blocker and 8 h nightly fuzz: informative nightly with a ratchet.
- Watermark by perturbation.
- Virtual bench levels 2 and 3 (physical model, HIL): replaced by before/after datalog and a minimal physical bench. Level 1 stays.
- ML, TCUs, premium imports, white-label, public SDK, GDPR, SOC 2, bug bounty, chaos, k6, Schemathesis, formal SLO: nothing before 5 shops are paying.
- "Week 1 to 2: MED17 checksum from scratch": without an oracle and without the algorithm's source it is a month or more per hardware variant. The schedule starts with question 1.

### Review by topic (v7): six independent reviewers

Six reviewers, each seeing only the sections of their topic (kernel; plugins, checksum and corpus; gate and bench; legal and LGPD; CI and supply chain; business and roadmap). What was clearly right was applied in the sections. Summary of what changed and what remains as a decision.

| Topic | Applied in the sections | Remains as a decision |
|---|---|---|
| Kernel | Idempotence replaced by composition; `invert` and `diff` formally defined; canonical order and `overlaps[]`; `patch_hash` and `image_hash` without metadata; `warn` produces `ReleasedImage` with an immutable verdict and `alert_ack`; migration reevaluates containment; `Patch` immutable by hash and `Version` with a complete list; `Event` with hash chain; `suspect_ack` in provenance; pipeline without its own invariant list; naive reference implementation of `apply` | — |
| Plugins and corpus | Input is a `Dump` with memories; `Identification` with `hw_id`, `sw_id`, `checksum_variant_id`; `verify` with `bypassed`, `signature_unverifiable`, `not_applicable`; `ChecksumRegion.kind`; complete declarative descriptor; TPROT as a flag; `pii_in_flash`; golden requires diagnostics and zero DTCs; ECU table corrected; Phase −1 with variants and bench hours | Items marked "verify" in the market table (Firefly, GM turbo, Renault TCe) are confirmed in Phase −1 |
| Gate and bench | Ranges keyed by category, map type, combustion and fuel; `block` only for the impossible; `pass` became `no findings` with a disclaimer; diff stops being an alert; fatigue measured per rule; fail-closed; before/after datalog specified; gate NFRs | — |
| Legal and LGPD | Shop as controller and platform as processor; legal basis per purpose; data protection officer (encarregado) and RIPD (data protection impact report); no 30-day deadline; international transfer; firmware and A2L; art. 107; CDC; CTB and PROCONVE in place of EPA; ANPD (Brazilian data protection authority) in 3 business days | Everything marked "verify" requires a lawyer before the pilot; E&O insurance quote |
| CI and supply chain | Layer 1 rewritten as a trail, not a barrier; guardrail via `pull_request_target` from `main`; 24 h from the last commit with scheduled reevaluation; mutation score at release; pipeline security in six rules; runner only in the corpus's private repo; fuzz in a matrix; B2/R2 in place of MinIO; SLSA 3 from the start; MVP infrastructure reduced to one VPS; `src/` structure with plugins in private repos | — |
| Business | Four business risks added; 3 external shops in the Phase −1 exit criterion | See the tension below |

**Author's decision (2026-10-18): a well-made critical product, not a quickly sellable one.** The business reviewer argued that weeks of kernel, invariants and compliance before any customer contact is platform before product, and proposed selling diff + PDF in two weeks with the rule "no abstraction with fewer than two uses until the first sale". The position was heard and rejected: the thesis of this ADR is that reliability is the product, and a diff that does not rest on a kernel with proven invariants is exactly the kind of shortcut the document exists to prevent. The order stands, with one change made the same day: Phase −1 discovery runs in parallel with the family-agnostic core instead of before it (see Phase −1). The rest of the order: physical bench, SPEC-001, kernel with the 12 invariants, plugin per variant with golden, gate; only then does the first product (audit and verification) go to the partner shop. Revenue is not a Phase 0 gate; it is a Phase 1 gate. What is kept from the business review: the four risks added to the table; the pain hypothesis to validate in Phase −1 (the shop pays to avoid flashing a file with a hidden delete, to prove to the customer what was changed, and to choose between file services); resale and insurer out of the MVP; compensation to the partner by contract (lifetime license plus a share of the audits she refers, in exchange for labeled dumps and tuner hours); price validation at shops unrelated to her when the time comes; and the schedule converted from calendar weeks to declared available hours.

### Three questions before writing code

1.  **Where does the MED17 checksum algorithm come from and what is the truth about it?** Own reverse engineering (months, legal risk), community documentation (partial, per variant) or a third-party module license (cost, and the tool's output is not truth)? Is there an ECU on the table and who flashes it? Without an answer, "golden file" does not exist.
2.  **What set of tools and dump types must the MVP accept in order to sell to any shop, and which of them is validated end to end first?** The safeguards are agnostic; their validation is not. The partner shop is not the individual the product is being prepared for, it is the first concrete case that walks the entire path, like the first real driver that validates a database interface. The tool table maps the variation space (container, encryption, checksum correction on write, partial or full OBD) so that ingestion covers the space, not one vendor.
3.  **On the day an exported file does not start a customer's car, what happens, who pays for the ECU and who is the second human?** This question does not block Phase 0 (own ECU on the table); it blocks entry into Phase 1. If the answer is "nobody" for any of the three, no file goes to a third party's car.

## Non-functional requirements

The requirement that rules everything is integrity: one wrong byte in the binary bricks the car. Everything else is designed around that.

| Requirement | Target | How it is guaranteed |
|---|---|---|
| Binary integrity | Zero writes outside the edited range; original hash preserved | Immutable storage (WORM), every edit is a patch over the original, never an overwrite |
| Reproducibility | Same original + same patches = same binary, always | Ordered, deterministic patches; checksum computed by a versioned plugin |
| Auditability | Who edited what, when, and with which plugin version | Append-only event log per project; exportable to the customer |
| Tenant isolation | A tenant never reads another's file | Row-level security in Postgres + bucket prefix per tenant + KMS key per tenant |
| Analysis latency | Identification + heuristic detection in \< 30 s for a 4 MB dump | Asynchronous worker, result via streaming (SSE/WebSocket) |
| Availability | 99.5% in the MVP, 99.9% in v1 | Stateless API, durable queue, replicated storage |
| Partial offline | The editor keeps working without network on an already open file | Editor state on the client, sync by patches on reconnect |
| Definition portability | Import and export XDF, A2L, map CSV | Own internal format with edge converters |
| Cost per file | Predictable, dominated by storage and worker CPU | No GPU on the critical path |
| Gate quality | Zero `no findings` on the negative cases of the regression corpus; false block below 1% of the corpus exports | Labeled negative corpus; metric per release |
| Gate latency and failure | Under 5 s per export; fail-closed | Rules as in-memory data; unavailability of a rule or plugin blocks |
| Unit accuracy | Raw→physical conversion with error ≤ 0.5 LSB in round trip | Property test per `dtype` and factor |

## Architecture overview

Three layers: thin clients, stateless synchronous services behind a gateway, and asynchronous workers that do the heavy work on the binary. The binary never passes through the API: the client uploads directly to the object store with a signed URL and the API only receives the hash.

*(diagram: see the ADR's HTML artifact)*
*components · 3 layers, 1 queue, 2 stores*

The synchronous services only read and write metadata; any operation on the binary becomes a job on the queue and the workers write the result back to the object store and Postgres.

## Ingestion and analysis pipeline

The pipeline is a chain of idempotent stages; each one writes its result as a versioned artifact, so a stage can be rerun with a new plugin without redoing the previous ones.

1.  **Upload.** The client requests a signed URL, sends the `.bin`, and provides the SHA-256 and origin (OBD, bench, boot, tool). The API records `Artifact{original=true}` with a WORM bucket and retention lock.
2.  **Identify.** A worker reads the first and last KB and looks for signatures: software ID strings (Bosch `1037xxxxxx`, Siemens, Delphi), file size, endianness, boot patterns. Output: `EcuFamily`, `SoftwareVersion` (confidence 0 to 1). If confidence is low, the user chooses manually and the choice becomes a label.
3.  **Layout.** With the family known, the plugin returns the memory map: code, calibration, checksum and protected data regions. Only the calibration region is editable.
4.  **Map detect.** Two paths run in parallel and the results are merged by score:
    - *Heuristic*: searches for axes (monotonic sequences of 8 to 32 values, 8/16 bits, with a plausible factor), then adjacent rectangular blocks whose variation is smooth in both directions. This is what the tuner does by hand in WinOLS.
    - *Known definition*: if a `Definition` exists for the `SoftwareVersion` or for a close sibling, applies it by offset and validates by comparing axes.
5.  **Checksum verify.** Before any edit, the plugin recalculates the original's checksums and checks that they match. Failure marks the artifact as `suspect`; editing proceeds only with `Event{suspect_ack}`, and every export of that project carries `input_verify: failed_acknowledged` in the report.
6.  **Edit.** Every edit becomes a `Patch{memory_id, offset, length, before, after, map_id, author, ts}`. A whole edited binary is never stored; it is materialized on demand by applying the patches over the original.
7.  **Export.** A worker calls `apply` and `release` of the `core` with the pinned plugin version, stores the result as `Artifact{derived}` with `version_id`, `image_hash(apply)`, `image_hash(release)` and the gate report, and returns a short-lived signed URL.

The pipeline adds no invariants: each stage calls `apply` and `release` of the `core` and inherits the 12 from the Foundations section. There is no second list to diverge.

## Virtual test bench

Testing the map before flashing it to the car is the product's most defensible differentiator, but "virtual ECU" has three levels of very different difficulty. The plan builds from cheapest to most expensive and each level already delivers value on its own.

| Level | What it is | What it catches | What it does not catch | Cost and phase |
|---|---|---|---|---|
| 1 · Static and plausibility validation | Rules over the binary and over each map: checksum, axis monotonicity, physical range per category (ignition advance between −20° and 60°, lambda between 0.65 and 1.3, boost below the MAP sensor limit), smoothness (maximum gradient between neighboring cells), diff against the original above a threshold per category | Typing error, overflowed cell, broken axis, patch outside region, gross exaggeration | Interaction between maps (high ignition + lean mixture + high boost at the same time) | Low; MVP. Runs on the export worker and blocks |
| 1b · Before/after datalog (MVP, informative) | Imports CSV from the scanner or the tool, before and after the file. Minimum signals: rpm, MAP/load, TPS, measured and target λ, advance, knock retard, IAT, ECT, STFT/LTFT, injector duty, target vs measured boost, % ethanol (flex), EGT if available. Comparison by rpm × load bins with ≥ 20 samples in both logs; a cell without coverage stays "not compared" | Sustained knock retard \> 3°, \|λ − target\| \> 0.05 at WOT, injector duty \> 90%, LTFT outside ±10%, boost overshoot \> 15 kPa | It is post-flash: it diagnoses, does not prevent. Never blocks | Low; MVP. Real data, honest, no model |
| 2 · Engine simulation with a physical model | Mean-value model parameterized per engine, estimating torque, EGT, knock margin, injector and wastegate duty from the edited maps | Dangerous combination of maps, saturating injector, EGT out of range | ECU software behavior; and, without calibration for the specific engine, it gets knock and EGT wrong while looking like a dyno | Cut from the MVP. Returns only when there are enough datalogs per engine to validate predicted vs measured with torque error \< 10% |
| 3 · Real ECU on the bench with HIL | The physical ECU connected to a hardware-in-the-loop simulator that generates sensor signals and reads actuators; the firmware really runs with the edited map | Everything the ECU does: protections, limiters, DTCs; the file "boots" or not | Real load on the engine; real knock | Cut from the MVP (months per family). What remains is the minimal physical bench: ECU on the table for golden and start test, not a schedulable service |

### Why not emulate the ECU firmware

A complete virtual ECU would require emulating the microcontroller (TriCore at Bosch, PowerPC at Continental) and the peripherals, with closed and protected firmware. It is reverse-engineering team territory for years and high legal risk. Level 3 delivers the same practical result (the real firmware running the real map) with ordinary bench hardware; level 2 delivers the physical part that the firmware does not know.

### Bench architecture in the system

- A `validate` worker on the same queue, between `edit` and `export`. Level 1 is mandatory; levels 2 and 3 are optional and billed.
- Level 1 rules are data, not code: a table of ranges per category and per engine, versioned as a `Definition`, editable by an advanced tenant.
- The result of each validation is an `Artifact{report}` with a verdict (block, warn, no findings), charts and the hash of the tested binary, linked to the version.
- Level 2 exposes the same charts as a dynamometer: estimated torque and power by rotation, EGT, lambda, duty. This is what the tuner shows the customer.
- Real datalogs (CSV from the scanner or the tool) enter through the same path and calibrate the level 2 model; the tuner compares predicted vs. measured.
- Level 3: the bench is a schedulable resource; the job sends the binary to the bench, runs a standardized script (start, idle, simulated load ramp) and returns log and DTCs.

**What is truly "revolutionary" here** is not level 3, which calibration labs already have, but putting levels 1 and 2 into every shop's workflow, per file, with a verdict before export. Today the small shop tests by flashing the customer's car.

## Data model

The model separates what is immutable fact (binaries, patches, events) from accumulated knowledge (definitions, map packs). The two sides grow at different paces and have different owners.

| Entity | Key | Main fields | Owner |
|---|---|---|---|
| Tenant | `tenant_id` | name, plan, kms_key_id, parent_tenant (sub-dealer) | Billing |
| User | `user_id` | tenant_id, role (owner, tuner, viewer), OIDC subject | Gateway |
| Project | `project_id` | tenant_id, vehicle (VIN optional), ecu_family, software_version, status | Projects |
| Artifact | `artifact_id` | project_id, sha256, size, **origin** (obd_read, bench_read, boot_read, virtual_read, file_service), **dump_kind** (bench_full, boot_full, obd_full, obd_partial, virtual; SPEC-001 R3), **memories\[\]** (memory_id, base_address, size), original or derived, parent_artifact, retention_lock | Projects |
| Patch | `patch_hash` | Immutable, addressed by content hash: **memory_id**, offset, length, before_bytes, after_bytes. Metadata outside the hash: created_in_version (tracing), map_id, author, ts | Projects |
| Version | `version_id` | project_id, parent_version, **complete** and canonical list of patch_hash (materializing never walks parent_version), overlaps\[\], plugin_versions, layout_hash, label | Projects |
| EcuFamily | `family_id` | manufacturer, name (MED17.5.21, EDC17C46), plugin_id, layout_schema | Definitions |
| Definition | `definition_id` | family_id, software_version pattern, list of MapDef, origin, confidence | Definitions |
| MapDef | `mapdef_id` | definition_id, name, category, offset, dims, data type, factor, unit, axes | Definitions |
| MapPack | `mappack_id` | tenant_id (or public), family_id, list of definition_id, semantic version, license | Definitions |
| Event | `event_id` | schema, tenant_id, seq, project_id, type, payload, actor, ts, **prev_hash, hash = sha256(JCS(event without hash))**: per-signer chain of the tenant (SPEC-005) verifiable outside the database; the server chain's head is anchored daily in an external location, and each CLI chain is covered through an anchored reference in the server chain (append-only, partitioned by month) | Audit |
| Job | `job_id` | type, artifact_id, status, plugin_version, attempts, result_ref | Workers |

### Modeling decisions

- `Patch.before_bytes` exists to detect conflicts: if the original changed or two tuners edited the same range, the `before` does not match and the system refuses.
- `Definition` is decoupled from `Project`: updating the map pack does not silently alter old projects.
- Binaries stay out of Postgres. The database holds only hash, size and path; the object store is the source of truth.
- `Event` is the only table with no update or delete, including for admin; since database permissions are not verifiable from outside, the hash chain is what proves nothing was removed.
- An `Artifact` with `origin = virtual_read` or `file_service` is not evidence of what is in the car; the report says so, and the stock hash registry (Review section) is consulted to say whether the file is factory or already modified.
- `MapDef.dtype` is complete: int8/16/32, uint, float32, LE/BE, signed, factor and offset, `axis_source` (inline, pointer, shared), to cover Siemens/Continental by pointer and Delphi/MG1 in float.
- Labels have state: `proposed` (tuner marked), `reviewed` (reference tuner checked), `golden` (validated on the bench). The validation set uses only `reviewed` or above.

## Services, APIs and plugin SDK

The public API is REST with OpenAPI, and anything that takes longer than 2 s becomes a job tracked via SSE. The part that differentiates the product, knowledge per ECU family, lives in plugins with a stable interface, so that new families enter without touching the core.

### Main endpoints (v1)

| Method and route | Function | Mode |
|---|---|---|
| `POST /projects` | creates project | synchronous |
| `POST /projects/{id}/artifacts/upload-url` | signed URL for .bin upload | synchronous |
| `POST /projects/{id}/artifacts/{aid}/analyze` | enqueues identify + layout + detect + verify | job |
| `GET /jobs/{id}/events` | progress and partial results | SSE |
| `GET /projects/{id}/maps` | detected maps with score and applied definition | synchronous |
| `POST /projects/{id}/versions/{vid}/patches` | records patches (validates range and before) | synchronous |
| `POST /projects/{id}/versions/{vid}/export` | materializes + checksum + signed URL | job |
| `GET /projects/{id}/versions/{a}/diff/{b}` | per-map diff between two versions | synchronous |
| `POST /definitions/import` | imports XDF, A2L or CSV and normalizes | job |
| `GET /tenants/{id}/audit` | exports event log (NDJSON) | job |

### Queue and workers

- One stream per job type (`analyze`, `checksum`, `export`), consumer group per type, explicit ack, redelivery with backoff. Jobs are idempotent by `(artifact_id, plugin_version, type)`.
- Workers in Python (numpy for the heuristic, `struct` and `numpy.frombuffer` for bytes). One pod per job type, HPA by queue size.
- A job's result is written to the object store and publishes an event; the API only reads the event.

### Plugin SDK per ECU family

Each family implements the same interface in Python; the core loads plugins by entry point and pins the version used in each job.

    class EcuPlugin(Protocol):
        family: str                      # e.g. "bosch.med17"
        version: str                     # semver, recorded in each job

        # Dump = {dump_kind: bench_full | boot_full | obd_full | obd_partial | virtual,
        #         memories: list[{memory_id, base_address | None, data}]}   # PFlash, DFlash, external EEPROM... (SPEC-001 §2.1)
        def identify(self, dump: Dump) -> Identification | None: ...
        # Identification = {hw_id, sw_id, mcu, checksum_variant_id, memories_present (each with its base_address?), ...}   # full shape: SPEC-002 §2.1
        def layout(self, ident: Identification, dump_kind: DumpKind) -> MemoryLayout: ...
        def checksums(self, ident: Identification) -> list[ChecksumRegion]: ...
        # ChecksumRegion.kind = recalculable | signed
        def verify(self, dump: Dump, ident: Identification) -> VerifyReport: ...
        # VerifyReport.status = ok | fail | bypassed | signature_unverifiable | not_applicable
        def checksum_patches(self, dump: Dump, ident: Identification) -> list[Patch]: ...
        def hints(self, ident: Identification) -> list[MapHint]: ...   # likely offsets

- The input is a **set of memories**, not a blob: MED17 on TriCore has PFlash and DFlash (where VIN, immo and counters live); Marelli IAW and Delphi MT have external 95xxx EEPROM; the DQ200 TCU carries flash and EEPROM. An OBD read returns only the flash, sometimes partial, and on several VAG MED17.5 the Flex does a *virtual read* (a file matched by SW ID, not bytes from the ECU). `layout` receives `dump_kind` and describes only the memories present; absent ones are `unknown`, never `calibration`. `verify` on `virtual` returns `not_applicable`, never green.
- `checksum_patches` replaces the old `fix_checksums(bytearray)`: the plugin never receives a mutable buffer. It returns patches and the kernel applies them, rejecting the entire set if any byte falls outside a `checksum` region. Locality is enforced by the kernel, not entrusted to the plugin. For a `signed` region (MG1/MD1, Simos18, SIM2K-25x and recent Denso, with RSA signature) it returns an empty list and `verify` returns `signature_unverifiable`; the gate exports only with `warn`.
- `verify` returns `bypassed`, not `fail`, for files in which the verification routine was patched by another tool ("checksum off"): this is the most common case in file service files, and saying "invalid" for a file that starts the car destroys the audit's credibility.
- `identify` is a function of the `Dump` only; for a partial dump it returns `base_address` or `None`; it discriminates ECUs with the same `sw_id` and a different checksum variant (TC1766 vs TC1797). It extracts VIN and serial, when present, for the anonymization pipeline.
- `MemoryLayout` is `(memory_id, base_address, regions)` per memory. Every region not explicitly classified as `calibration` or `checksum` is `protected`; VIN, immo, coding and flash counters are `protected` and named. TPROT is not a region: it is the OBD flash seed-key, handled as a *detected protection flag*; the plugin never disables it. The plugin declares `pii_in_flash` per family: in MED17/EDC17 the VIN is usually in the DFlash/EEPROM, so the calibration flash can be anonymized; Marelli and Delphi, verify case by case.
- For the bulk of variants, the checksum is **declarative**: a descriptor interpreted by the core with `algorithm` (CRC32, sum16/32, XOR, polynomial), fixed `ranges` or `ranges_from_table` (block pointers inside the file), `init`, `xor_out`, `skip_self` (excludes the word itself) and `chain` (checksum of checksums); the complete schema, including `compensate` and `mirror_block`, is SPEC-002 §4. It covers older Continental SID2xx/SIM2K, Delphi MT, Marelli and a good part of MED17/EDC17. Python plugin only for the exotic. Dual implementation is done once, in the interpreter.
- `hints` is optional and feeds the detector with likely offsets for that software version.
- Plugins are tested against a corpus of labeled dumps with golden files: identify, verify and checksum_patches must reproduce the expected hash before the plugin is published.
- Suggested order: Bosch MED17/EDC17 (highest volume), Magneti Marelli IAW 8GMF/9GF (Fiat), ACDelco E8x (GM) and Kefico/SIM2K (Hyundai), then TCUs (DQ200/DQ250, ZF8HP).

## Infrastructure and operations

The inventory below is the **v2+ target**, one ADR per line once there is a paying tenant. The MVP and v1 run on far less, with a clear owner for each layer. The cloud choice is secondary; the design avoids lock-in on the parts that are expensive to swap (queue, storage, secrets).

**MVP and v1 infrastructure (decision v7):** one VPS; `docker compose` with Caddy, FastAPI, one worker, Postgres and NATS; external object store with versioning (B2 or R2, Brazilian region when personal data is involved); secrets with SOPS + age; Grafana Cloud free tier for metrics and logs. Daily `pg_dump` backup to the bucket (RPO 24 h, manual RTO 4 h). Vault, Keycloak, OpenFGA, Temporal, Linkerd, Karpenter, OpenSearch, Argo CD, Terragrunt, PagerDuty, Lago, Litmus and "RPO 0 cross-region" stay in the table as targets, not as plan.

### Full component inventory (v2+ target)

| Layer           | Component                  | Default choice                      | Alternative          | Notes                                                                      |
|-----------------|----------------------------|-------------------------------------|----------------------|----------------------------------------------------------------------------|
| Edge            | CDN + WAF                  | Cloudflare                          | AWS CloudFront + WAF | Blocks scraping of map packs, per-tenant rate limit at the edge            |
| Edge            | API Gateway / ingress      | Envoy Gateway or Kong               | NGINX Ingress        | JWT auth, quotas, request ID, internal mTLS                                |
| Identity        | IdP                        | Keycloak                            | Auth0, Zitadel       | OIDC, mandatory MFA for owner, SSO in the enterprise phase                 |
| Identity        | Authorization              | OpenFGA or Cerbos                   | Casbin               | Tenant → sub-dealer → project relations kept out of business code         |
| Application     | API                        | FastAPI (Python) or Kotlin + Spring | Go                   | Same language as the workers reduces friction in the data models           |
| Application     | Web editor                 | React + WebGL (regl or three.js)    | Svelte               | 16×16 to 32×32 map at 60 fps; local state with CRDT (Yjs) for offline      |
| Application     | Desktop (phase 2)          | Tauri                               | Electron             | Shops with poor internet; same bundle as the web                           |
| Async           | Queue                      | NATS JetStream                      | RabbitMQ, SQS        | Streams per job type, dedupe by key, replay for reprocessing               |
| Async           | Workflow orchestration     | Temporal                            | Argo Workflows       | analyze→detect→verify pipeline with retries and history                    |
| Async           | Scheduler                  | Kubernetes CronJob                  | Temporal schedules   | Cleanup, billing reports                                                   |
| Data            | Relational database        | PostgreSQL 16 (CloudNativePG)       | Aurora Postgres      | Per-tenant RLS, monthly partitioning of Event                              |
| Data            | Object store               | S3 (or self-hosted MinIO)           | GCS, R2              | Bucket per environment, prefix per tenant, Object Lock (WORM) on originals |
| Data            | Cache                      | Redis (Valkey)                      | Dragonfly            | Sessions, hot analysis results, edit locks                                 |
| Data            | Search                     | OpenSearch                          | Meilisearch          | Search definitions and map packs by family, version, map name              |
| Data            | Migrations                 | Alembic or Flyway                   | Atlas                | Always compatible with the previous version (expand/contract)              |
| Secrets         | Vault                      | Vault or External Secrets + KMS     | Infisical            | Per-tenant KMS key for envelope encryption                                 |
| Platform        | Cluster                    | EKS/GKE with Karpenter              | k3s on bare metal    | Separate node pool for high-CPU workers                                    |
| Platform        | GitOps                     | Argo CD                             | Flux                 | Every deploy is a commit; rollback is a revert                             |
| Platform        | IaC                        | Terraform + Terragrunt              | Pulumi               | Modules per environment; remote state with lock                            |
| Platform        | Service mesh               | Linkerd                             | Istio                | Automatic mTLS, retries and timeouts outside the code                      |
| Platform        | Policy                     | Kyverno or OPA Gatekeeper           | —                    | No unsigned image, no root pod, no public bucket                           |
| Delivery        | CI                         | GitHub Actions                      | GitLab CI            | Tests, SAST, build, cosign signing, SBOM with syft                         |
| Delivery        | Image registry             | GHCR or ECR                         | Harbor               | Trivy scan on push                                                         |
| Delivery        | Feature flags              | Unleash or OpenFeature + flagd      | LaunchDarkly         | Release an ECU family per tenant before GA                                 |
| Observability   | Metrics                    | Prometheus + Grafana                | Datadog              | SLOs per endpoint and per job type                                         |
| Observability   | Logs                       | Loki                                | OpenSearch           | Structured logs with tenant_id and request_id; never log binary bytes     |
| Observability   | Tracing                    | OpenTelemetry → Tempo               | Jaeger               | Trace spans API → queue → worker                                           |
| Observability   | Errors                     | Sentry                              | GlitchTip            | Front and back end, with tagged release                                    |
| Observability   | Alerts and on-call         | Alertmanager → PagerDuty            | Grafana OnCall       | Runbook per alert                                                          |
| Observability   | Status page                | Instatus                            | Statuspage           | Incident communication to the customer                                     |
| Business        | Billing                    | Stripe Billing + Lago               | Chargebee            | Credits per file, per-seat subscription, sub-dealer with revenue share     |
| Business        | Product analytics          | PostHog                             | Mixpanel             | Upload → analysis → export funnel, per family                              |
| Business        | Support                    | Intercom or Plain                   | Zendesk              | Project context attached to the ticket                                     |
| Business        | Documentation and public API | Docusaurus + Redocly              | Mintlify             | Developer portal for the plugin SDK                                        |

### Environments and promotion

- `dev` (ephemeral per PR, Argo CD ApplicationSet), `staging` (anonymized data copy), `prod`. Promotion by image tag, never by rebuild.
- Canary deploy per tenant: a feature flag releases a new plugin to 5% of tenants, and the manual-correction rate metric decides whether to advance.

### Resilience and continuity

- RPO 15 min for Postgres (continuous WAL to the object store), RPO 0 for binaries (versioning + cross-region replication).
- RTO 1 h: cluster restore via GitOps + database restore tested monthly in staging (game day).
- Queue with 7-day retention: reprocess jobs after an incident without loss.
- Backups with 35-day retention, immutable, in a separate account.

### Good practices that count as engineering rules

- Twelve-factor for services; configuration only via environment variables and secrets via vault.
- Versioned API contracts (`/v1`), incompatible changes only with a new version and 6 months of deprecation.
- Tests: unit tests in the plugins with golden files, contract (Schemathesis over the OpenAPI), load (k6) on every release, quarterly chaos (Litmus) in staging.
- ADRs in the repository for each choice in this table; this page is ADR-000.
- Error budget per SLO: if the export SLO (99.9% success) is exceeded, the release stops and the team works only on reliability.

## Security and compliance

The platform's most valuable asset is the customers' binaries and the accumulated map packs; the biggest regulatory risk is the emissions side. Security here has three fronts: protect the data, protect the product against piracy, and keep the product out of defeat-device territory.

### Protection of binaries and data

| Control                  | Implementation                                                                                                                                         |
|--------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
| Encryption at rest       | Envelope encryption: data key per artifact, wrapped by a per-tenant KMS key; revoking the tenant key erases everything of theirs                       |
| Encryption in transit    | TLS 1.3 at the edge, mTLS between services via the mesh                                                                                                |
| Isolation                | RLS in Postgres with tenant_id per session; bucket prefix per tenant with an IAM policy that denies cross-prefix; namespaces and NetworkPolicy per environment |
| Operator access          | No human access to binaries in production; break-glass with two-person approval and a trail in Event                                                   |
| Upload                   | Antivirus and size and type validation before accepting; the binary is never executed, only read                                                       |
| Retention                | Originals with Object Lock for the contract term; derivatives expire according to the plan; deletion on request within 30 days with a certificate of destruction |
| Logs                     | Never contain binary bytes, VIN or e-mail; masking in the logging SDK                                                                                  |

### Application security (AppSec)

- OWASP ASVS level 2 as baseline; SAST (Semgrep), SCA (Dependabot + Trivy), DAST (ZAP) in the pipeline, blocking merge on critical.
- Supply chain: signed images (cosign), SBOM per release, admission controller rejects unsigned images; third-party plugins run in a sandbox (gVisor) with CPU and memory limits and no network.
- Annual external pentest and private bug bounty from v1.
- Threat model every four months (STRIDE over the component diagram).

### Licensing and anti-piracy

- Per-seat license tied to the IdP; credits per file debited on export, never on upload.
- Map packs with metadata signed per tenant and, if necessary, decoy maps; perturbation of offsets and factors was cut (it breaks the map or induces wrong edits).
- Export of definitions in XDF/A2L only to the tenant itself, with signed metadata; daily limit per plan.
- Desktop client with online license check every 72 h and offline grace period; no heavy DRM, which the market hates and cracks within weeks.

### Regulatory compliance

- **Emissions and automotive regulation.** The product does not offer, document or conceal functions that disable DPF, EGR, SCR, catalytic converter, lambda or emissions DTC. Regions for those functions are `protected` in the `MemoryLayout` and the core refuses to patch them. Brazilian basis: CTB (Brazilian Traffic Code) arts. 98 and 230, VII (altering a vehicle characteristic may require authorization), Lei 8.723/1993 and CONAMA resolutions of PROCONVE (Brazilian vehicle emissions control program); a power increase changes emissions even without a delete and can fail an environmental inspection where one exists. The terms of use and the export report state this. Check the CONTRAN resolution in force. The COBB/EPA case in the US stands as a reference for market risk, not as a legal basis.
- **LGPD (Brazilian General Data Protection Law).** VIN is personal data (art. 5, I) when it can be linked to the owner via RENAVAM, invoice or work order; immobilizer and odometer in the dump too. Service provision: contract performance (art. 7, V), with the **shop as controller and the platform as processor**, under a processor contract (art. 39). Corpus: the platform is a controller with its own purpose; prefer verifiable anonymization (art. 12: remove VIN, ECU serial, immo and odometer, with a tested procedure, not just "optional VIN") and, where that is not possible, legitimate interest with a recorded balancing test (LIA), or consent collected directly from the data subject (the car owner), specific and highlighted (art. 8, §4). "Opt-out" is not an LGPD category. Appointed data protection officer (encarregado) or an equivalent public channel if classified as a small-scale agent (Res. CD/ANPD 2/2022); DPIA (RIPD) of the ingestion pipeline and corpus (art. 38); record of processing operations (art. 37). Retention defined for the Event log (it contains data of the shops' employees).
- **Deletion and retention.** There is no 30-day deadline in the LGPD. Deletion by destroying the artifact key, including backup copies and keys in custody; retention of the original while there is a legal obligation or ongoing litigation (art. 16, I and III), documented in the RIPD. Object Lock in governance mode, never compliance.
- **International transfer.** An object store or KMS outside Brazil is an international transfer (art. 33): only with the ANPD standard clauses (Res. CD/ANPD 19/2024) signed with the provider and listed in the privacy policy. In the MVP, Brazilian region. GDPR applies by offering to EU residents, not by the tenant's nationality.
- **SOC 2 Type II** as a v2 goal; the controls above are already designed for the mapping.
- **Intellectual property.** Firmware is a computer program (Lei 9.609): storing it to provide the service is defensible; copying it into a test corpus is reproduction not covered by art. 6, so the corpus holds only anonymized dumps, for internal testing use, with no redistribution, never in a public repository. Leaked A2L/DAMOS: hosting and processing them knowing their origin may constitute unfair competition (Lei 9.279, art. 195, XI), and "private to the tenant" does not neutralize that; definitions without verifiable licensing are not hosted, only referenced locally by the customer. Check with a lawyer the interoperability exception (Lei 9.609, art. 6, IV) for checksum reverse engineering. "DMCA" is a GitHub procedure, not Brazilian law.
- **Anti-circumvention (Lei 9.610, art. 107).** Targets devices that prevent copying; checksum is integrity, so recalculation is probably not circumvention. TPROT and RSA signature are technical measures: the plugin never disables them nor patches a verification routine. Verify.
- **Civil liability.** A car owner's acknowledgment form does not exclude strict liability (CDC arts. 12, 14, 25 and 51, I); it serves as proof of adequate information (art. 6, III). The platform is part of the supply chain (art. 7, sole paragraph) and the shop itself may invoke the CDC as end consumer (verify). Minimum package: information form for the car owner (risks, loss of warranty, emissions, administrative irregularity), B2B contract with the shop with indemnification and liability cap, and a quote for professional liability / E&O insurance before the pilot.

### Incident response

- Severities S1 to S4 with communication SLA (S1: customer notified within 1 h, status page within 30 min). A binary leak with VIN is a personal data incident: notification to the ANPD and data subjects within 3 business days when there is relevant risk (art. 48; Res. CD/ANPD 15/2024), with the shop as controller in the playbook.
- Playbooks for binary leak, credential compromise and checksum corruption in export.
- Blameless post-mortem within 5 business days; actions become items with an owner and a deadline.

## Roadmap by phases

Each phase only starts when the previous phase's gate is measured, not when the deadline arrives. The MVP is deliberately single-tenant and with one ECU family: the technical risk lies in exporting a file that starts the car, not in scaling.

*(diagram: see the ADR's HTML artifact)*
*roadmap · 3 phases, 3 gates*

The Phase 0 deadlines are for one person plus the reference tuner part-time; Phases 1 and 2 assume 3 to 5 people and are fiction until there is revenue. The gate decides advancement, not the month.

**On ML (Phase 2, not before).** Detection in the MVP and v1 is heuristics plus imported definitions. Each confirmation or correction by the tuner in the editor becomes a label; it is this use that creates the dataset, not the other way around. A model (gradient boosting over block features, then something larger if worthwhile) only enters when it beats the heuristic in precision per family on the validation set, with automatic rollback if the manual-correction rate rises. No GPU, feature store or model registry in the inventory until then.

## Risks and open decisions

The risk that kills the project is not technical: it is not having a corpus of labeled dumps and not having anyone who knows the ECUs from the inside. The architecture mitigates this but does not solve it.

| Risk                                                                                 | Probability         | Impact             | Mitigation                                                                                                      |
|--------------------------------------------------------------------------------------|---------------------|--------------------|-----------------------------------------------------------------------------------------------------------------|
| No dataset to validate plugins                                                       | High                | High               | Partnership with 5 pilot shops in exchange for a lifetime license; each correction in the editor becomes a label |
| No ECU specialist on the team                                                        | High                | High               | Hire an experienced tuner part-time from month 1; official courses from the tool manufacturers                  |
| Wrong checksum bricks a customer's car                                               | Medium              | Critical           | Golden files per family, verify before and after export, export blocked without a green verify                  |
| Market dominated by closed ecosystems (Alientech, Magicmotorsport, EVC)              | High                | Medium             | Differentiate on domestic families and on workflow, not on total coverage; do not compete on hardware           |
| Customer pressure for delete functions                                               | High                | High (regulatory)  | Closed and public product decision; protected region in the layout; terms of use                                |
| Map pack leak                                                                        | Medium              | Medium             | Watermark per tenant, export limit, revocation                                                                  |
| Virtual bench gives false safety                                                     | Medium              | High               | Verdict always shows what the level tested and what it did not; level 1 is never sold as "tested on an engine"  |
| New cars with signed ECU (RSA, encrypted boot)                                       | High in the long term | High             | Focus on the 2008 to 2020 fleet in the MVP; track what the hardware manufacturers unlock                        |
| File service blocks or copies: it is the shop's supplier and holds the relationship  | High                | High               | Sell auditing to the file service as a quality seal before selling against it                                   |
| Competitor adds native diff (StageX with "compare with original" in a release)       | High                | Critical           | Registry of stock hashes, independent verify and PDF for the work order are defensible; diff alone is not       |
| Flex container changes (format, encryption, terms of use)                            | Medium              | High               | Accept raw `.bin` as the main path; container adapters are peripheral                                           |
| Founder part-time, with two active contracts and zero budget                         | High                | High               | Milestones by declared available hours, not by calendar weeks                                                   |

### Open decisions

- API language: Python (same as the workers) or Kotlin. Initial recommendation: Python, to share data models with the plugins.
- Temporal from the MVP or a simple queue first. Recommendation: simple queue in the MVP, Temporal when the pipeline has more than 5 stages.
- Managed cloud or bare metal with k3s to control storage cost. Depends on the average volume of dumps per tenant (measure in the pilot).
- Pricing model: credit per export, per-seat subscription, or hybrid. Validate with the pilot shops.
- Initial target market: Brazil only (domestic Fiat/VW/GM families) or already LATAM.

## Comparison with market leaders

Five analysts, each on one topic, confronted the ADR with WinOLS (EVC), ECM Titanium and KESS3 (Alientech), StageX and Flex (Magicmotorsport), Autotuner, Swiftec and HP Tuners, searching official and reseller pages in October 2026. Central finding: **no leader audits a third-party file, none blocks an implausible file before writing, and none links a datalog to the hash of the written file**. The gate, the independent verify and the provenance have no equivalent. The ADR's gaps are product gaps around this, not in the core.

### Where the ADR is ahead (consensus of the five)

- **Independent verify with honest semantics** (`bypassed`, `signature_unverifiable`, `not_applicable`): HP Tuners only says "invalid checksum, go back to stock"; WinOLS and ECM correct; StageX does not even correct. Nobody tells the customer that the third-party file's verification routine was patched.
- **Cryptographic and reproducible provenance**: hash per patch, event chain verifiable outside the database, plugin version and build in the export. The leaders are black boxes; WinOLS offers the opposite (hiding the owner in the export).
- **Mandatory gate, fail-closed, with honest disclaimer**: the market corrects the checksum and stops; the text "does not verify the combination between maps nor the actual engine" is more honest than any official material read.
- **Datalog linked to the version and the hash**: in KESS3 the log goes to the cloud with a free-form name; in HP Tuners it is a loose file.
- **Corpus with label states** (`proposed → reviewed → golden`) and ML only with a precision gate: StageX sells "AI" with no verifiable criterion.
- **Explicit regulatory position**: Swiftec sells DPF/EGR/AdBlue as a core feature and StageX sells DTC removal for coins; the ADR is defensible where the leaders carry liability.

### Gaps and adopted improvements, by topic

| Topic                                     | What the leader does                                                                                                                                                                                                                                             | Gap in the ADR                                                                           | Adopted improvement (enters in the indicated phase)                                                                                                                                                                                                                                           |
|-------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Detection: potential map                  | WinOLS searches in the background seconds after the project is created and lists "potential maps" with 3D preview and synchronized hexdump; "Bosch Recognition" by default via header pattern                                                                    | A heuristic candidate is not an editor state; no detector by manufacturer header         | Candidates are born as `MapDef{state: potential}` listed separately; pluggable `BoschHeaderDetector` detector before any ML; editor with synchronized hexdump and highlighting of `potential` (Phase 0 to 1)                                                                                  |
| Detection: one pack, several versions     | StageX: "a single map pack works on any software version of the same ECU"                                                                                                                                                                                        | Applying to a "close sibling" by offset does not describe realignment                    | `Identify` queries a global `sw_id → Definition` index and returns `definition_match: exact | sibling | none`; for `sibling`, each `MapDef` is realigned by searching for the known axes in a ±N KB window; only identical axes become `proposed` (Phase 1)                                        |
| Detection: curated import                 | WinOLS OLS521 (DAMOS/A2L, €785) with filters for 2,000 to 10,000 maps                                                                                                                                                                                            | Importing 5,000 maps without triage replicates the problem; DAMOS outside the endpoint   | Import accepts DAMOS; generates `MapDef{state: imported}` and a curated view by category is what the editor shows by default (Phase 1)                                                                                                                                                        |
| Checksum: discovering coverage            | WinOLS tests all modules online against the project and says which one applies; sells by "points" (2 = €300, 50 = €4,990, reseller, verify)                                                                                                                       | No "which plugin covers this file"                                                       | `probe` endpoint: runs `identify` of all plugins and reports whether the variant is covered; charging per family or variant, not per seat (Phase 1)                                                                                                                                           |
| Checksum: missing strategies              | WinOLS on EDC16/17 adjusts a compensation value at the end of the map area instead of recalculating; synchronizes mirrored blocks on Bosch truck                                                                                                                 | The declarative descriptor does not cover compensation or mirrored block                 | `strategy: compensate` and `mirror_block` in the descriptor; both in a `checksum` region, invariant 9 still holds (Phase 0)                                                                                                                                                                   |
| Checksum: signed ECU                      | Flex, Autotuner and KESS3 write MG1/MD1 on the bench; the tool resolves the signature (how, not published; verify)                                                                                                                                               | The ADR declares `signed` correctly but gives the customer no path                       | "Unsigned" export with a recorded confirmation that the tool signs; the write result goes into `oracle:` (Phase 2)                                                                                                                                                                            |
| Tools: slave files                        | Autotuner slave: encrypted file, 24 h time lock, master API to decrypt; KESS3 slave tied to a master; file-service.com integrates via API                                                                                                                        | The ADR assumes raw `.bin`; a slave file never enters                                    | Ingestion layer with per-tool adapters (Autotuner Master API, file service zip, FRF/VBF); slave is out of scope and becomes a documented prerequisite; `origin = file_service` stores the container metadata (Phase 1)                                                                        |
| Tools: compatibility manifest             | Accessport only lists maps for the identified vehicle; KESS3 identifies before writing; explicit blocking of an incompatible file not documented (verify)                                                                                                        | Export carries no manifest that the tool can check                                       | Export with a manifest (family, `sw_id`, hash) that a hardware plugin checks before writing (Phase 2)                                                                                                                                                                                         |
| Workflow: project as container            | WinOLS stores original, customer, plate, searchable list, exports xlsx                                                                                                                                                                                           | `Project` has no customer, plate, work order or search                                   | `customer_ref`, plate and `work_order` in `Project`; `GET /projects?q=`; CSV export (Phase 1)                                                                                                                                                                                                 |
| Workflow: commented versions              | WinOLS: versions with comment, "version overview" with touched maps, combine versions                                                                                                                                                                            | `Version` has no note or summary of touched maps                                         | Mandatory `note` in `Version`; `GET /versions/{vid}/summary` via the patches' `map_id`; merge = union of patches with conflict by `before` (Phase 1)                                                                                                                                          |
| Workflow: diff between projects           | ECM Titanium 3.0 compares files from different vehicles aligning offsets; HP Tuners compares different OS IDs; WinOLS "accept changes" finds a shifted map                                                                                                        | Diff only within the same project, per map                                               | Diff between any two artifacts of the tenant, aligned by `MapDef` (name and axes) and by layout region when there is no definition; "import patches from another version" action (Phase 0, this is the audit product)                                                                         |
| Workflow: report for the end customer     | No leader delivers an audit report; file-service.com generates an invoice PDF                                                                                                                                                                                    | One-page report planned, format not specified                                            | PDF + JSON with hash and QR; public page `verify/{report_hash}` that recalculates the chain; lay language: "what changed", "integrity", "what was not verified" (Phase 0)                                                                                                                     |
| Workflow: per-project rights              | WinOLS Reseller: per-project rights (view vs export binary/maps), file and key on separate servers; StageX slave applies the master's solutions                                                                                                                  | Sub-dealer only as a child tenant                                                        | Permissions per `Artifact`/`Version` (`view_diff`, `export_bin`); `sealed` deliverable signed per tenant, no proprietary encryption (Phase 1)                                                                                                                                                 |
| Workflow: visible SLA                     | File services publish response time (e.g. 60 min); file-service.com shows hours and ETA                                                                                                                                                                          | Analysis \< 30 s, but no ETA or exposed SLA                                              | Job ETA in the SSE and SLA in the report (Phase 1)                                                                                                                                                                                                                                            |
| License: model                            | WinOLS €1,034 perpetual + €98/year premium; ECM Titanium Full €2,390 or Credit €890; StageX Plus ≈ €1,900; KESS3 and Flex with annual renewal and loss of protocols (and, on Flex, of warranty) without subscription; HP Tuners US\$ 49.99/credit tied to VIN + serial + OS | No numeric anchor; perpetual + annual not considered                                     | Cheap perpetual audit package + annual subscription for definitions, corpus and stock hashes; credit per `(sw_id, VIN hash)` with free re-export of the same car; automatic refund when `verify` fails; local CLI without license check, the paid value stays on the server (Phase 1)        |
| License: training and channel             | EVC charges €2,975 to €4,760 per WinOLS course; Alientech €585 to €2,926; all sell through a reseller network                                                                                                                                                    | Training treated as an expense; no channel                                               | "File audit" course with the partner shop as paid instructor (solves the counterpart); file service as reseller with margin on referred audits (Phase 1)                                                                                                                                      |
| Validation: closing the datalog loop      | HP Tuners: 2D/3D histograms per bin, math parameters, "Paste Special" copies the error histogram into the table; MegaLogViewer HD as universal viewer                                                                                                            | Before/after datalog is informational only                                               | "Suggest patch from the bin" (λ error becomes a factor in the cell), always as a `Patch` with `before`; parsers per source (KESS3, Autotuner, HPT, COBB, MegaLogViewer) for canonical signals; export to MegaLogViewer (Phase 1)                                                               |
| Validation: ranges as open data           | No leader has per-map plausibility; KESS3 only min/max per signal in the datalogger                                                                                                                                                                              | Category coverage still incomplete                                                       | Prioritize categories by the corpus's real edit volume; publish the range table as open, versioned data (Phase 0 to 1)                                                                                                                                                                        |
| Validation: accessible HIL                | MetSim Pro (≈ €5,445) runs the ECU on the desk and reads DTC; no editor integration                                                                                                                                                                              | Level 3 cut                                                                              | When it returns, use a market simulator as the script executor, not an in-house HIL (Phase 2+)                                                                                                                                                                                                |

### What the market solved and the ADR accepts

Checksum was solved in the writing hardware, and the leaders sell coverage, not algorithm. The value of this product lies in verify, auditing and provenance; own recalculation is an add-on for bench, boot and families without tool support. This conclusion was already in the StageX section and the five comparators confirmed it.

### Comparison sources

- EVC/WinOLS: [software](https://s-web.evc.de/en/product/ols/software), [DAMOS](https://www.evc.de/en/product/ols/damos.asp), [Reseller](https://evc.de/en/product/ols/reseller/info.asp), [what's new](https://www.evc.de/en/download/down_winols_whatsnew.asp), [courses](https://www.evc.de/it/service/official_training_courses.asp), [checksum FAQ](https://www.evc.de/en/service/q1307.asp)
- Magicmotorsport: [StageX](https://www.magicmotorsport.com/stagex/), [Flex](https://magicmotorsport.com/?p=48384), [Flex renewal](https://viezu.com/shop/magic-motorsport-flex-subscription-renewal)
- Alientech: [KESS3](https://www.alientech-tools.com/en/kess3/), [ECM Titanium Full](https://tuning-shop.com/alientech/ecm-titanium-full-version), [ECM Titanium 3.0](https://viezu.com/?p=49990), [Alientech Suite](https://viezu.com/user-guide-for-alientech-suite-and-kess3-obd), [KESS3 prices](https://paramount-performance.com/alientech-kess-3-price-where-to-buy/), [KESS3 datalog](https://olsx.lu/en/faq/how-to-use-the-datalog-function-with-your-kess3)
- Autotuner: [tool](https://www.autotuner.com/products/autotuner-tool), [slave files](https://help.autotuner.com/en/articles/2984977-how-to-decrypt-slave-files-and-backup), [file-service.com integration](https://file-service.com/knowledge-base/features/autotuner-integration), [common mistakes](https://tuning-shop.com/blogs/autotuner-mistakes/)
- HP Tuners: [licenses](https://docs.hptuners.com/VCM_Editor/Introduction/Licensing_Vehicles/), [invalid checksum](https://support.hptuners.com/support/solutions/articles/153000064357-reader-upload-invalid-checksum), [math parameters](https://www.hptuners.com/articles/getting-started-with-math-parameters-in-vcm-scanner/), [histograms](https://www.hpacademy.com/previous-webinars/215-how-to-use-histograms-in-hp-tuners/)
- Others: [Swiftec](https://viezu.com/blog/swiftec-tuning-software-explained/), [Swiftec price](https://bds.lt/en/swiftec-full-pack-car-programming-software), [file-service.com](https://file-service.com/the-platform), [COBB datalog](https://cobbtuning.atlassian.net/wiki/spaces/PRS/pages/571899907/How+To+Datalog), [MetSim Pro](https://bds.lt/en/engine-control-module-diagnostic-and-repair-equipment-metsim-pro), [HP Academy checksum](https://www.hpacademy.com/blog/check-sum-correction-what-how-why/)

Marked "verify" by the analysts: unit price of a WinOLS module (only bundles at resellers); how KESS3, Autotuner and Flex handle RSA signature; explicit blocking of an incompatible file in the tools; format of the KESS3 and Autotuner datalog CSVs; Swiftec's license model; ECM Titanium's "project history"; StageX map pack prices in coins.

### Sources

- [MagicMotorSport StageX, product description](https://automechanika.messefrankfurt.com/frankfurt/de/ausstellersuche.detail.html/magicmotorsport-srl/mf_1_0015025589_3774404_10000007202401.html)
- [StageX Plus, reference price (BDS)](https://bds.lt/en/vehicle-remapping-software-stagex-plus-magicmotorsport)
- [Viezu: ECM Titanium vs WinOLS](https://viezu.com/blog/alientech-ecm-titanium-vs-evc-winols-car-tuning-software/)
- [DOJ: agreement with COBB Tuning over defeat devices](https://www.justice.gov/archives/opa/pr/united-states-reaches-agreement-cobb-tuning-products-clean-air-act-violations)
