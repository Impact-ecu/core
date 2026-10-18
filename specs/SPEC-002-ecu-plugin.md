# SPEC-002 · EcuPlugin contract

Status: proposed
Date: 2026-10-18
Governs: `src/core/plugins/` (`_contract.py` and the checksum descriptor interpreter), `src/core/conformance/`, and every `ecu-plugin-<family>` repository.
Derives from: SPEC-000 §Plugin SDK per ECU family, §ECU plugin contract and conformance suite, §Golden files, §Verification gate, §Standards written before the code, §Gaps and adopted improvements (checksum rows); SPEC-001; ADR-001.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Every numbered rule (`R<n>`) is normative and MUST be cited by at least one test (`# SPEC-002 R<n>`). Rule numbers are local to this spec; a rule of SPEC-001 is always written `SPEC-001 R<n>`.

## 1. Problem

A plugin is code written by someone who knows an ECU family, often from outside the team, and the core does not trust it (SPEC-000 §ECU plugin contract). Its outputs decide which bytes a tuner may edit and which checksum bytes get written to a customer's car. This spec fixes the protocol, the shapes it exchanges, the declarative checksum descriptor and its interpretation, the limits, the emissions boundary, the conformance suite and the publication rules, precisely enough that two independent interpreters produce identical patches and identical verify reports, and that a plugin that lies is caught by the core or by the suite.

Out of scope: kernel shapes and hashes (SPEC-001, reused here), definitions and map categories (SPEC-003), gate verdicts and what is exported with `warn` (SPEC-004), the provenance record (SPEC-005). No family-specific constant appears in this spec: per ADR-001 decisions 1–2, variant descriptors live in the private plugin repositories and nothing is copied from third-party tools.

## 2. Types

- **R1.** `Dump`, `Memory`, `MemoryId`, `DumpKind`, `Region`, `RegionKind`, `MemoryLayout` and `Patch` are the SPEC-001 §2 types, unchanged. The plugin contract MUST NOT redefine, extend or subclass them. All offsets are relative to the start of a memory's `data` (SPEC-001 R2). (SPEC-001 §2)

### 2.1 Identification
```
PresentMemory  = { memory_id: MemoryId, base_address: int | null, size: int }
PiiLocation    = { memory_id: MemoryId, start: int, end: int, kind: "vin" | "serial" }      # [start, end)
ProtectionFlag = "tprot"
Identification = {
  family: string,                       # equals EcuPlugin.family
  hw_id: string | null,
  sw_id: string | null,
  mcu: string | null,
  checksum_variant_id: string | null,   # null = unknown_variant
  memories_present: list[PresentMemory],
  memories_absent: list[MemoryId],
  pii_locations: list[PiiLocation],
  protection_flags: list[ProtectionFlag],
  confidence: int                       # thousandths, 0..1000
}
```
- **R2.** `family` matches `^[a-z][a-z0-9]*(\.[a-z0-9][a-z0-9_]*)+$` (e.g. `bosch.med17`). `checksum_variant_id`, when not null, matches `^[a-z0-9][a-z0-9._-]{0,63}$` and is opaque to the core; it names one checksum variant, that is hardware plus checksum method, never a family or a `sw_id`. (SPEC-000 §Golden files; ADR-001 decision 8)
- **R3.** `confidence` is an integer number of thousandths in `[0, 1000]`. SPEC-000's "confidence 0 to 1" and "< 0.5" are realized as `confidence` and `< 500`. No float appears in any contract object, so every contract object is hashable under SPEC-001 R60. (SPEC-000 §ECU plugin contract; SPEC-001 R60, R70)
- **R4.** `memories_present` lists every memory of the dump, sorted by `memory_id`, each with its `size`. `base_address` MUST equal the dump's value when the dump's value is not null; when it is null, it is the address the plugin identified, or null if unknown. SPEC-000's single `base_address?` is realized per memory here. A memory the family does not recognize is still listed. (SPEC-000 §Plugin SDK; SPEC-001 R2, R5)
- **R5.** `memories_absent` lists, sorted, the memories the family has but the dump lacks (e.g. DFlash missing from an OBD read). They appear in no layout; they are the "unknown" memories of SPEC-000 and SPEC-001 R5. (SPEC-000 §Plugin SDK; SPEC-001 R5)
- **R6.** `pii_locations` carries locations only, never values: a contract object never contains a VIN or serial. The anonymization pipeline reads the bytes itself. Locations of the same `kind` are sorted by `(memory_id, start)`. (SPEC-000 §Plugin SDK, §Golden files)

### 2.2 ChecksumRegion
```
Range          = { start: int, end: int }                                   # [start, end)
ChecksumRegion = {
  name: string,                         # ^[a-z][a-z0-9_]{0,63}$, unique per variant
  memory_id: MemoryId,
  kind: "recalculable" | "signed",
  descriptor: Descriptor | null,        # §4; null = implemented in plugin Python, or signed
  descriptor_hash: hex | null,          # R78; null iff descriptor is null
  covered: list[Range] | null,          # static coverage; required iff descriptor is null and kind is recalculable
  fields: list[Range] | null,           # static output fields; required iff descriptor is null and kind is recalculable
  reference: Reference                  # R33; required, no default
}
Reference      = { kind: "interpreter" | "independent" | "none", id: string | null, source: string | null }
```
- **R7.** A `signed` region has `descriptor`, `covered` and `fields` all null. A `recalculable` region has either a descriptor (and `covered`, `fields` null, since the interpreter derives them) or, for the exotic cases the descriptor cannot express, `descriptor: null` with static `covered` and `fields`. Every region also declares its `reference` (R33). A region with a descriptor has the descriptor's `name` and `memory_id`; otherwise `PluginContractError`, reason `r7`. (SPEC-000 §Plugin SDK: "Python plugin only for the exotic"; ADR-001 decision 6)
### 2.3 VerifyReport
```
VerifyStatus = "ok" | "fail" | "bypassed" | "signature_unverifiable" | "not_applicable"
RegionResult = {
  name: string, memory_id: MemoryId, kind: "recalculable" | "signed",
  status: "ok" | "fail" | "bypassed" | "signature_unverifiable",
  stored: hex | null,                   # R77
  computed: hex | null,                 # R77
  reason: string | null,                # resolution failure reason (R66) or null
  bypass: { memory_id: MemoryId, start: int, end: int } | null
}
VerifyReport = { status: VerifyStatus, reason: string | null, regions: list[RegionResult] }
```
- **R8.** When `status` is `not_applicable`, `regions` is `[]` and `reason` is one of the report-level reasons of §9 (R41, R42, R43). Otherwise `reason` is null and `regions` holds exactly one entry per `ChecksumRegion` returned by `checksums(ident)` (R30), sorted by `(memory_id, name)`. (SPEC-000 §Plugin SDK)

### 2.4 MapHint
```
MapHint = { memory_id: MemoryId, start: int, end: int, name: string, category: Category | null }
```
`Category` is the SPEC-003 vocabulary (SPEC-003 R18); `null` when the plugin does not know it.

- **R9.** Every contract object (`Identification`, `ChecksumRegion`, `VerifyReport`, `MapHint`, descriptors, the conformance report) is serializable to JCS per SPEC-001 R60, with byte strings as lowercase hex. Rejections raised by the core while checking a plugin are `PluginContractError` (plugin output breaks this spec) or `DescriptorError` (R79); a disagreement between the interpreter's two engines (R81) is `InterpreterDivergence`, reason `engine_divergence`, an internal error. Each carries a stable machine `reason`; none is a subclass of `KernelError`. (SPEC-001 R60, R72)

## 3. Protocol

```python
class EcuPlugin(Protocol):
    family: str                 # R2
    version: str                # semver (R134)
    contract_version: int       # major of this spec the plugin implements; 1 here
    pii_in_flash: bool          # family declaration (SPEC-000 §Plugin SDK; open question 4)

    def identify(self, dump: Dump) -> Identification | None: ...
    def layout(self, ident: Identification, dump_kind: DumpKind) -> MemoryLayout: ...
    def checksums(self, ident: Identification) -> list[ChecksumRegion]: ...
    def verify(self, dump: Dump, ident: Identification) -> VerifyReport: ...
    def checksum_patches(self, dump: Dump, ident: Identification) -> list[Patch]: ...
    def hints(self, ident: Identification) -> list[MapHint]: ...
```
- **R10.** The protocol is exactly the one above (SPEC-000 §Plugin SDK). `fix_checksums(bytearray)` does not exist: a plugin never receives a mutable buffer. The core calls `verify` and `checksum_patches` with a `Dump`; during release the gate obtains it with `core.kernel._internal.view` (SPEC-001 R8), so the plugin never touches an `UnverifiedImage`. (SPEC-000 §Plugin SDK; SPEC-001 R7–R9, §5)
- **R11.** The core validates every plugin output it consumes before using it (R12–R59), and a violation is a `PluginContractError`, never a silent repair. A `PluginContractError`, any exception raised by any plugin method (including `identify`, in breach of R12), or a violated limit (R103–R105) makes the plugin unavailable for that job, except a hints error (R58), which never does: the gate fails closed (SPEC-004 R21, R25, R26; `plugin_disagreement` is mapped to `G-DUAL-DIVERGENCE`, SPEC-004 R27). (SPEC-000 §ECU plugin contract: "the core does not trust it"; §Verification gate, Fail-closed)

### 3.1 identify
- **R12.** `identify` is a function of the `Dump` only and MUST NOT raise for any input, including dumps of other families and random bytes. It returns `None` when the dump is not of its family. (SPEC-000 §Plugin SDK, §ECU plugin contract)
- **R13.** `identify` MUST discriminate dumps with the same `sw_id` and a different checksum variant (e.g. same `sw_id` on TC1766 vs TC1797): their `checksum_variant_id`s differ. When the family is recognized but the variant is not, it returns `checksum_variant_id: null`; that dump is `unknown_variant` (R42). (SPEC-000 §Plugin SDK; ADR-001 decision 7)
- **R14.** `protection_flags` contains `"tprot"` when the plugin detects TPROT. The flag is informational only; no contract method disables or alters it (R91). (SPEC-000 §Plugin SDK)

### 3.2 layout
- **R20.** `layout(ident, dump_kind)` returns a `MemoryLayout` with exactly the memories of `ident.memories_present`, the same `base_address` and `size` per memory, valid under SPEC-001 R4 and R5; otherwise `PluginContractError`, reason `bad_layout`. (SPEC-000 §ECU plugin contract, layout row; SPEC-001 R4, R5)
- **R21.** Everything not explicitly `calibration` or `checksum` is `protected` (SPEC-001 R6). A memory the plugin does not recognize is one `protected` region named `unrecognized` covering the whole memory. When in doubt, a byte is `protected`. (SPEC-000 §Plugin SDK; §Critical points, ECU identification)
- **R22.** Protected regions that hold VIN, immobilizer data, coding, flash counters or emission-control calibration MUST be named, with a name starting `vin`, `immo`, `coding`, `counter` or `emissions` respectively (e.g. `emissions_egr`). (SPEC-000 §Plugin SDK: "VIN, immo, coding and flash counters are protected and named"; §ECU plugin contract, layout row)
- **R23.** `layout` MAY be called for `dump_kind: virtual`; the result describes the file as received and is used only for diff and audit (R41). (SPEC-000 §Plugin SDK)

### 3.3 checksums
- **R30.** `checksums(ident)` returns the variant's `ChecksumRegion`s whose `memory_id` is in `ident.memories_present`, sorted by `(memory_id, name)`, names unique. A region of an absent memory (e.g. DFlash missing from an `obd_partial` read) is not returned, so nothing is verified or recalculated for it. For `checksum_variant_id: null` it returns `[]`. (SPEC-000 §Plugin SDK: "`layout` … describes only the memories present")
- **R31.** Static validation (R79) of the regions returned by `checksums(ident)` runs against `layout(ident, dump.dump_kind)` of the dump being processed, at every use; the suite runs it against the layout of every corpus dump of the variant (R125). Coverage that depends on dump content (`ranges_from_table`) is resolved per dump by the interpreter (§4.4); `checksums` itself never sees the dump. At release the gate runs this static validation once, in its binding step, after it has computed the layout itself; a static `DescriptorError` there is `G-PLUGIN-ERROR` (SPEC-004 R23). (SPEC-000 §Plugin SDK; SPEC-000 signature `checksums(ident)`)
- **R32.** Regions without a descriptor MUST NOT have dependency edges (R75) with descriptor regions: no static `covered` range of one intersects the output fields of the other. A variant that needs such an edge is implemented entirely in Python. (Design consequence of R45, R55)
- **R33. Reference declaration.** Every `ChecksumRegion` declares the second implementation its results are compared with; there is no default. A descriptor region has `reference: {kind: "interpreter", id: null, source: null}`: the core descriptor interpreter (§4.5). A `signed` region has `{kind: "none", id: null, source: null}`: there is nothing to compare (R46). A Python region (`descriptor: null`, `recalculable`) has either `{kind: "independent", id, source}`, where `id` matches `^[a-z0-9][a-z0-9._-]{0,63}$` and names a `RegionReference` (R34), and `source` is a non-empty string naming its origin (author, repository, commit), which MUST differ from the plugin's; or `{kind: "none", id: null, source: null}`. Any other pairing → `PluginContractError`, reason `bad_reference`. A variant with any recalculable region whose reference is `none` is never `admitted` (R131), so it is `unknown_variant` (R42). (SPEC-000 §Verification gate: "export only with both agreeing"; "Fail-closed: if … the dual implementation … is unavailable, export is blocked"; §Golden files: "When a second codebase exists, it comes from a different source")
- **R34. RegionReference.** An independent reference is an object supplied to the gate by the consumer, loaded by entry point, with its `id` and `version` recorded in the job's provenance like a plugin's (SPEC-005 §3 `versions.references`; SPEC-004 §6, output `subject.references`): `RegionReference { id: str, version: str, verify_region(dump, ident, region) -> RegionResult, patches_region(dump, ident, region) -> list[Patch] }`. It obeys §6 like a plugin. (SPEC-000 §Plugin SDK; SPEC-004 R27)

### 3.4 verify
- **R40.** `verify` reads only; it never changes the dump. Its result MUST satisfy R8. (SPEC-000 §Plugin SDK)
- **R41.** For `dump.dump_kind == "virtual"` the status is `not_applicable`, reason `virtual_dump`, `regions: []`; it is never green. (SPEC-000 §Plugin SDK)
- **R42.** For a variant that is `unknown_variant`, either because `checksum_variant_id` is null or because the variant is not admitted (R132), the core does not call `verify` or `checksum_patches` and reports `not_applicable`, reason `unknown_variant`, `regions: []`. The core verifies and recalculates nothing for it. (ADR-001 decision 7; SPEC-000 §Principles, zero-cost paragraph; §Phase −1 fallback)
- **R43.** Otherwise the report status is the aggregation of the region statuses: `not_applicable` with reason `no_checksum_regions` if there are none; else `fail` if any region is `fail`; else `bypassed` if any is `bypassed`; else `signature_unverifiable` if any is `signature_unverifiable`; else `ok`. The core recomputes this aggregation; a different plugin status is `PluginContractError`, reason `r43`: a shape violation of the plugin's own output, not a divergence from a reference, which SPEC-004 R13 and R26 map to `G-PLUGIN-ERROR`, while the gate uses the recomputed status. (SPEC-000 §Plugin SDK)
- **R44.** A region is `bypassed` when the plugin detects that the routine verifying it was patched ("checksum off"), whatever its stored and computed values. A `bypassed` result MUST carry `bypass`, a non-empty range locating the patched routine, which lies inside one `protected` region of the layout. A file whose routine was patched is never reported `fail` for that region. `bypassed` is a plugin claim: the core checks only R44's location rule, and R116 and R119 constrain it on the corpus; an audit report presents it as detected by the plugin. (SPEC-000 §ECU plugin contract, verify row; §Plugin SDK)
- **R45.** For every region with `reference.kind = interpreter`, the core evaluates the descriptor with its interpreter (§4, both engines, R81) and compares with the plugin's `RegionResult`; for `reference.kind = independent`, it compares with `verify_region` of that `RegionReference` (R34), which returns only `ok` or `fail`; any other status, or an exception, makes the reference unavailable for the job (SPEC-004 `G-UNAVAILABLE-DUAL`). `stored`, `computed` and `reason` MUST be equal, and `status` MUST equal the reference's `ok`/`fail` or be `bypassed` per R44. Any difference raises `PluginContractError`, reason `plugin_disagreement`, naming the regions; the core never turns a disagreement into a report status. At release this comparison is made once, in the gate's dual step, which emits at most one `G-DUAL-DIVERGENCE`, block, S1 (SPEC-004 R27); the verify step maps only the status (SPEC-004 R26). (SPEC-000 §Plugin SDK: "dual implementation is done once, in the interpreter"; §Verification gate: "Divergence is a plugin bug and becomes S1")
- **R46.** A `signed` region is always `signature_unverifiable`, with `stored`, `computed` and `bypass` null. No signature is checked or computed. Because R43 lets `fail` or `bypassed` dominate the report status, the presence of a signed region is read from `regions`, not from the status: the gate records it in each subject's `signed_regions` (SPEC-004 §6), from which SPEC-005 R63 derives its `signature_unverifiable` code. (SPEC-000 §Plugin SDK; ADR-001 decision 6)
- **R47. Plugin independence.** A plugin MUST NOT build a `RegionResult` or a patch by calling the core interpreter: plugin packages MUST NOT import `core.plugins.descriptor`. Each plugin repository enforces this with an import-linter contract, and the suite's import scan checks it (R100, R124). R47 forbids the import, not a copy: a plugin that copies the interpreter's code would make R45 and R55 compare that code with itself (open question 9). (SPEC-000 §Golden files, dual implementation)

### 3.5 checksum_patches
- **R50.** `checksum_patches(dump, ident)` returns `list[Patch]` (SPEC-001 §2.3), sorted by `(memory_id, offset)`. It returns `[]` for `virtual` dumps and contributes nothing for `signed` regions. (SPEC-000 §Plugin SDK)
- **R51.** Each patch covers exactly one output field (R73) of one recalculable region, whole, and lies inside one `checksum` region of the layout; patches are pairwise disjoint. The kernel enforces containment and disjointness on the whole set (SPEC-001 R40, R41). (SPEC-000 invariant 9)
- **R52.** Each patch's `before` equals the dump's bytes at its range, and `before != after` (SPEC-001 R12, R21). A field whose value does not change produces no patch. (SPEC-001 R12, R21)
- **R53.** After `apply_checksum_patches(u, q, layout)` (SPEC-001 §5), `verify` of the result reports every recalculable region `ok`, unless the plugin reports it `bypassed`. (SPEC-000 §ECU plugin contract, checksum_patches row)
- **R54.** Fixed point: `checksum_patches` of that result returns `[]`. In particular it returns `[]` on an unmodified original that verifies `ok`. (Consequence of R52, R53)
- **R55.** For every descriptor region, the core derives the patches itself (R76); for every region with an independent reference, it takes `patches_region` (R34). The plugin's patches for those regions MUST be byte-identical, otherwise `PluginContractError`, reason `plugin_disagreement` (R45). (SPEC-000 §Plugin SDK; §Verification gate, dual implementation)

### 3.6 hints
- **R58.** `hints` is optional (`[]` is valid). Each hint lies inside one `calibration` region of the layout of the dump being analyzed. If any hint does not conform, the core rejects the whole `hints` result with `PluginContractError`, reason `r58`, records it, and uses `[]` for that job; it never drops single hints. Hints do not reach the gate, so this does not make the plugin unavailable. The suite fails on any such hint. (SPEC-000 §ECU plugin contract, hints row)
- **R59.** No hint points into a `protected` or `checksum` region. (SPEC-000 §ECU plugin contract, hints row; skill `emissions-boundary`)

## 4. Declarative checksum descriptor

For the bulk of variants the checksum is a descriptor interpreted by the core, not code (SPEC-000 §Plugin SDK; §High-value improvements #4). This section is complete: an interpreter written from it alone MUST reproduce `specs/vectors/spec-002/vectors.json`.

### 4.1 Schema
```
Field      = { offset: int, size: 2 | 4 | 1, endianness: "little" | "big" }
Algorithm  = { name: "crc32", poly: int, init: int, xor_out: int, reflect_in: bool, reflect_out: bool }
           | { name: "sum16" | "sum32" | "xor", word_size: 1 | 2 | 4, endianness: "little" | "big", init: int, xor_out: int }
TableField = { at: int, size: 1 | 2 | 4, endianness: "little" | "big" }
Table      = { offset: int, count: int, entry_size: int, start: TableField, end: TableField,
               end_is: "exclusive" | "inclusive" | "length", addressing: "offset" | "absolute" }
ChecksumDescriptor = {
  descriptor_version: 1, name: string, memory_id: MemoryId, algorithm: Algorithm,
  ranges: list[Range] | null, ranges_from_table: Table | null, chain: list[string] | null,
  skip_self: bool, store: Field | null, target: int | null,
  strategy: "recalculate" | "compensate", compensate: { offset: int } | null
}
MirrorDescriptor = {
  descriptor_version: 1, name: string, memory_id: MemoryId,
  mirror_block: { source: Range, dest_offset: int }
}
Descriptor = ChecksumDescriptor | MirrorDescriptor
```
- **R60.** A descriptor's key set is exactly that of its form, at every level: no extra key, no omitted key, no default. Unused keys are present with `null`. `descriptor_version` is `1`. `name` matches `^[a-z][a-z0-9_]{0,63}$` and is unique in the variant. Every integer is in `[0, 2³² − 1]`, and `poly`, `init`, `xor_out` and `target` fit the algorithm width. A value outside the types of §4.1 (e.g. `word_size: 3`, `size: 8`) is a schema violation. Violation: `DescriptorError`, reason `schema`. (SPEC-000 §Plugin SDK; SPEC-001 R60)
- **R61.** Width `W` is 32 for `crc32` and `sum32`, 16 for `sum16`, and `8 × word_size` for `xor`. For `sum16`/`sum32`, `8 × word_size ≤ W`. `store.size` MUST equal `W / 8`. Otherwise `DescriptorError`, reason `bad_width`. (SPEC-000 §Plugin SDK: "with endianness and word size", §Gaps checksum row)

### 4.2 Message
- **R63.** The message of a checksum descriptor is an ordered list of pieces (byte ranges of `memory_id`). Exactly one of `ranges`, `ranges_from_table`, `chain` is non-null (`DescriptorError`, reason `message_source`). Pieces are taken in list order (for a table, entry order), never sorted; for CRC the order is part of the definition. (SPEC-000 §Plugin SDK)
- **R64.** Static `ranges`: each has `start < end ≤ size` (`bad_range`); ranges are pairwise non-overlapping (`overlapping_ranges`). (SPEC-001 R4 conventions)
- **R65.** `ranges_from_table`: entry `i` starts at `offset + i × entry_size`, for `i` in `[0, count)`. Each `TableField` reads an unsigned integer of `size` bytes at `entry + at` with its endianness, giving `s` and `e`. If `addressing` is `absolute`, the memory's `base_address` is subtracted from `s`, and from `e` unless `end_is` is `length`; a null `base_address` is resolution failure `unknown_base_address`. Then the range is `[s, e)` for `exclusive`, `[s, e + 1)` for `inclusive`, `[s, s + e)` for `length`. A negative `s`, `e < s`, or an end beyond the memory size is `table_out_of_bounds`; an empty range is `empty_range`; overlapping resolved ranges are `overlapping_ranges`. Statically, the table bytes `[offset, offset + count × entry_size)` lie inside the memory (`bad_range`) and entirely inside one `protected` region of the layout (`table_not_protected`). Since neither an edit (calibration) nor recalculation (checksum fields) can change a protected byte, the table is the same on the dump, the unverified image and every intermediate copy of R76: it is resolved once, on the dump, and an edit can never move a checksum's coverage. The table bytes are still input bytes of the descriptor (R75, R118); they never lie in an output field, so they create no dependency edge. (SPEC-000 §Plugin SDK: "ranges_from_table (block pointers inside the file)")
- **R66.** A resolution failure on a dump is not an exception in `verify`: that region is `fail`, `reason` set to the failure, `computed: null`, `stored` as read (R77). In `checksum_patches` a resolution failure raises `DescriptorError` with that reason and no patch is returned; a plugin's own `checksum_patches` MUST raise `DescriptorError` with the same reason in the same case. The gate runs the core derivation first, whatever the plugin does, and reports a core resolution failure as `G-CHECKSUM-RESOLUTION`, block, without S1, taking precedence over any plugin outcome (SPEC-004 R25), since it is a property of the file, not a plugin or kernel bug. (SPEC-000 §Verification gate, Fail-closed; SPEC-001 R72)
- **R67.** For `sum16`, `sum32` and `xor`, every piece length (after R68 excision) is a multiple of `word_size`; words never straddle pieces. Otherwise `misaligned_piece` (statically for static ranges and chains, at resolution for tables). (Precision requirement of §1)
- **R68.** `skip_self: true` excises the store field from the message: the field MUST lie entirely inside one range (`partial_self` if it only intersects one, `skip_self_without_self` if it intersects none or if `store` is null), and that range becomes its non-empty parts before and after the field, in that order. With `skip_self: false` and `strategy: recalculate`, the store field MUST NOT intersect any range (`self_reference`), since a value cannot cover itself. (SPEC-000 §Plugin SDK: "skip_self (excludes the word itself)")
- **R69.** `chain` lists other checksum descriptors of the same variant and memory, each with a non-null `store`; the message is their store fields, in list order, as bytes in the dump. A missing name, a mirror descriptor, a descriptor without `store`, another memory, or the descriptor itself is `unknown_chain_target`. `skip_self` is `false` with `chain` (`schema`). (SPEC-000 §Plugin SDK: "chain (checksum of checksums)")

### 4.3 Algorithms and strategies
- **R62.** Algorithms over the message bytes `m` (pieces concatenated) or words (each piece split into `word_size` unsigned integers with the given endianness):
  - `crc32` follows the Rocksoft parameter model as used by the reveng CRC catalogue (`init` is the value of the unreflected register before the first byte). Reference loop:
    ```
    reg = init
    for b in m:
        if reflect_in: b = bitreverse8(b)
        reg ^= b << 24
        repeat 8: reg = ((reg << 1) ^ poly) & 0xFFFFFFFF if reg & 0x80000000 else (reg << 1) & 0xFFFFFFFF
    if reflect_out: reg = bitreverse32(reg)
    value = reg ^ xor_out
    ```
  - `sum16`/`sum32`: `acc = init`; for each word `w`, `acc = (acc + w) mod 2^W`; `value = acc ^ xor_out`.
  - `xor`: `acc = init`; for each word, `acc ^= w`; `value = acc ^ xor_out`.
  
  `value` is an integer in `[0, 2^W)`. (SPEC-000 §Plugin SDK: "algorithm (CRC32, sum16/32, XOR, polynomial) … init, xor_out"; §Gaps checksum row)
- **R70.** `strategy: recalculate` writes `value` into `store`, encoded in `store.size` bytes with `store.endianness`. It requires `store` non-null and `target`, `compensate` null (`strategy_fields`). (SPEC-000 §Plugin SDK)
- **R71.** `strategy: compensate` leaves the stored or target value alone and rewrites a compensation word inside the message so that `value` equals the goal `t`: the integer at `store` if `store` is non-null, else `target` (exactly one is non-null; `compensate` is non-null; else `strategy_fields`). It is supported for `sum16`, `sum32` with `8 × word_size == W`, and for `xor`; otherwise `compensate_not_supported`, checked first (so `crc32`, which has no `word_size`, never reaches the next rule). The compensation field is `[compensate.offset, compensate.offset + word_size)`; it lies inside one piece, at a word boundary of that piece (`compensate_outside_message`). With `g = t ^ xor_out`, `acc` the accumulator over the current message and `w` the current compensation word: for sums `w' = (g − acc + w) mod 2^W`; for `xor` `w' = g ^ acc ^ w`. `w'` is written with the algorithm's endianness. With `compensate`, the store field MAY lie inside the message with `skip_self: false`. (SPEC-000 §Gaps, checksum: missing strategies)
- **R72.** `mirror_block` declares that `[dest_offset, dest_offset + (source.end − source.start))` is a byte copy of `source`. Recalculation copies source to destination; verification compares them. `source.start < source.end ≤ size` and `dest_offset + (source.end − source.start) ≤ size` (`bad_range`); source and destination MUST NOT intersect (`self_reference`). (SPEC-000 §Gaps, checksum: missing strategies)

### 4.4 Output fields, dependencies and patches
- **R73.** The output fields of a descriptor are: its `store` (strategy `recalculate`), its compensation field (strategy `compensate`), or its mirror destination. Each output field lies inside one single `checksum` region of the layout (`field_out_of_checksum_region`), and output fields of a variant are pairwise disjoint (`field_overlap`). Input bytes (message, mirror source, the store of a compensate descriptor) MAY lie in any region kind. (SPEC-000 §Gaps: "both in a checksum region, invariant 9 still holds"; SPEC-001 R40)
- **R74.** In every memory, the union of the `checksum` regions of the layout is exactly the union of the output fields of the variant's recalculable regions (descriptor fields, plus static `fields` of Python regions); otherwise `unaccounted_checksum_bytes`. A plugin therefore cannot declare a broad `checksum` region over code. (SPEC-000 §Plugin SDK: locality enforced by the kernel; skill `emissions-boundary`)
- **R75.** Descriptor `D` depends on `E ≠ D` when an input byte of `D` (message pieces, table bytes per R65, mirror source, the store of a compensate descriptor) lies in an output field of `E`. Recalculation runs in topological order of this relation, choosing the smallest `name` (Unicode code point order) among ready descriptors (Kahn with a min-heap, as SPEC-001 R25). Because output fields are disjoint (R73), every topological order yields the same bytes; the min-heap order is the reference. A cycle is `dependency_cycle`: statically among descriptors whose inputs are static, at resolution otherwise. (SPEC-000 §Plugin SDK, chain; SPEC-001 R25)
- **R76.** `checksum_patches` for descriptor regions: copy the dump's memory, apply R70–R72 to the copy in R75 order (each descriptor reads the copy as left by its predecessors), then emit one `Patch` per output field whose bytes differ between the dump and the copy, covering the whole field, sorted by `(memory_id, offset)`. (SPEC-001 §2.3, R12, R40)
- **R77.** `verify` evaluates each descriptor on the dump as is, independently, with no recalculation. For a checksum descriptor, `stored` is the bytes of `store` (or, when `store` is null, `target` encoded big-endian in `W / 8` bytes) and `computed` is `value` encoded the same way; the region is `ok` iff they are equal. For a mirror descriptor, `stored` is the SHA-256 hex of the destination bytes and `computed` that of the source bytes. (SPEC-000 §ECU plugin contract, checksums and verify row)
- **R78.** `descriptor_hash = sha256(JCS(descriptor))`, per SPEC-001 R60 and R65. Because R60 forbids defaults, two descriptors with the same text have the same hash; equivalent descriptors written differently do not. (SPEC-001 R60, R65)
- **R79.** Static validation of a variant (descriptor set plus layout) reports every violation it finds as `DescriptorError` with the reasons named in R60–R75 (also `duplicate_name` and `unknown_memory`). An interpreter MAY report any one reason when several apply; each test vector contains exactly one violation. Validation runs at plugin load, at every `checksums` call, and in the suite. (SPEC-001 R72)

### 4.5 The interpreter and its two engines
- **R80.** The interpreter is the module `core.plugins.descriptor`. It is the reference of every region with `reference.kind = interpreter` (R33) and is used by the core and the gate only (R47). (SPEC-000 §Plugin SDK: "Dual implementation is done once, in the interpreter")
- **R81. Two engines.** The interpreter returns a value only when two independent engines agree. Engine A is the R62 reference: the bitwise CRC register, and word-by-word accumulation for sums and `xor`. Engine B is table-driven CRC (a 256-entry table computed from `poly` for the MSB-first register, with reflection done by bit reversal of input bytes and of the result) and byte-lane sums and `xor`: for a word of `k` bytes, lane `i` sums (or xors) the `i`-th least significant byte of every word, and the value is `Σ lane_sumᵢ · 256ⁱ mod 2^W` (for `xor`, the lanes concatenated). Every computed value (verify `computed`, a recalculated store, a compensation word, a mirror digest) is computed by both; a difference raises `InterpreterDivergence`, reason `engine_divergence`, never a `fail` status. The gate maps it to `G-DUAL-DIVERGENCE`, S1 (SPEC-004 R27). (SPEC-000 §Verification gate, dual implementation)
- **R82. What the dual check proves.** The two engines and the comparison with the plugin (R45, R55) catch implementation errors: arithmetic, byte order, table resolution, dependency order and patch derivation. They do not catch a wrong descriptor, since every party implements the same declared parameters. Whether a descriptor is true of a variant is established only by the oracle: `golden_field` records (R122, R131), as SPEC-000 §Golden files says ("the second implementation is the external oracle … not a second piece of code by the same author"). (SPEC-000 §Golden files; ADR-001 decisions 2, 4)

The descriptor does not express: compensation for CRC, two's-complement sums other than through `compensate` with `target`, complement-pair storage, checksums spanning several memories, tables with a terminator instead of `count`. Those go to Python (R7) until an extension is specified (open question 5).

## 5. Emissions boundary

- **R90.** Regions holding emission-control calibration (DPF, EGR, SCR/AdBlue, catalytic converter, lambda, emissions DTC) are `protected` and named per R22. No contract method creates, edits or proposes a patch for them. (SPEC-000 §Out of scope; §Critical points, Decision on emissions)
- **R91.** TPROT is a detected flag (R14), never a region the plugin writes. No contract method disables TPROT. (SPEC-000 §Plugin SDK; §Gaps, Anti-circumvention)
- **R92.** A plugin never patches a verification routine. Routine bytes are code and therefore `protected`; with R51 and R74, no checksum patch can reach them, provided the layout does not declare a `checksum` region over routine bytes. A plugin could still declare a narrow `checksum` region over code as a mirror destination or compensation field, which R74 accepts; the guarantee therefore rests on the human review of the layout by the reference tuner (R115, R131). Recalculation is the only correction. (SPEC-000 §Gaps, Anti-circumvention: "Written in SPEC-002"; §Phase −1)
- **R93.** Detection is in scope: reporting `bypassed` (R44) and reporting, through SPEC-001 R32, that a third-party file changed bytes in a protected `emissions*` region. Reporting a delete is an audit finding, never an offer to perform it. (SPEC-000 §Plugin SDK; §First wins; skill `emissions-boundary`)
- **R94.** For a `signed` region no correction is attempted; signature bytes are `protected`, never part of a `checksum` region, so the kernel rejects any patch to them. (ADR-001 decisions 3, 6; SPEC-000 §Plugin SDK)

## 6. Purity, limits and sandbox

- **R100.** Plugin packages import only from an allowlist: the public API of `core` (never `core.kernel._internal` or `core.plugins.descriptor`, R47), other modules of the same plugin package, and the standard-library modules `__future__`, `abc`, `binascii`, `bisect`, `collections`, `collections.abc`, `dataclasses`, `enum`, `functools`, `hashlib`, `heapq`, `itertools`, `operator`, `re`, `struct`, `typing` and `zlib`. Every other import is forbidden (including `os`, `io`, `pathlib`, `sys`, `importlib`, `builtins`, `shutil`, `pickle`, `socket`, `subprocess`, `threading`, `multiprocessing`, `ctypes`), as are calls to `open`, `exec`, `eval`, `compile`, `getattr` on modules and `__import__`. Each plugin repository enforces this with import-linter and an AST scan in the suite. Forbidding imports is not a sandbox (R106). (SPEC-000 §ECU plugin contract, general behavior row; SPEC-001 R8)
- **R101.** Contract methods are pure: no I/O, network, clock, randomness, environment reads, threads or mutable module state. The same inputs give JCS-identical outputs whatever the call order and however often they are called. (SPEC-000 §ECU plugin contract; SPEC-001 R71)
- **R102.** SPEC-001 R70 applies to plugins: explicit byte order, no native `struct` formats, no floats in outputs. (SPEC-000 invariant 1; SPEC-001 R70)
- **R103.** Each call has a wall-time budget. Provisional defaults, derived from the SPEC-000 budgets (export gate < 5 s; identification plus detection < 30 s for a 4 MB dump), not from measurement: `identify`, `layout`, `checksums`, `hints` 1 s each; `verify` and `checksum_patches` 2 s each. They are replaced by measured values (open question 2). (SPEC-000 §Non-functional requirements)
- **R104.** Each call has a peak memory budget. Until open question 2 is resolved the suite measures and reports peak memory per method without failing on it. (SPEC-000 §ECU plugin contract: "maximum memory")
- **R105.** A call over its time budget is aborted; in the suite it is a failure, at runtime the plugin is unavailable for the job (R11). Timing, aborting and memory measurement need a clock and process control, so they are done by the consumer that hosts the plugin (CLI, workers) or the suite runner, outside `src/core`; the core receives the outcome (result, timeout or exception) as data. (SPEC-000 §Verification gate, Fail-closed; §Four layers, layer 4)
- **R106.** In the MVP no third-party plugin exists and plugins run in process. Before the first third-party plugin is accepted, the consumer that hosts the plugin (CLI, workers; R105) MUST run it in a subprocess with a seccomp filter, no network, no credentials in the environment, exchanging JCS messages (SPEC-001 R60) over stdin/stdout; the framing is open question 3. (SPEC-000 §ECU plugin contract; §Application security)

## 7. Conformance suite

The suite is part of this spec and is the same for internal and external plugins (SPEC-000 §ECU plugin contract; §CI pipeline). Its checks live in `core.conformance` as pure functions over `Dump`s, plugin outputs and recorded measurements. The runner, which reads the private corpus, generates fuzz inputs, times and aborts calls, measures memory, and later hosts the subprocess sandbox (R106), lives outside `src/core` and is exposed as the reusable workflow `plugin-conformance` (SPEC-000 §Four layers, layer 4: "`core` does not import I/O, network, subprocess").

- **R110.** A plugin repository runs the suite of a core release pinned by git SHA. The runner reads the private corpus (dumps, metadata, oracle records); it never runs in public CI. (SPEC-000 §CI pipeline; ADR-001 Consequences)
- **R111.** identify, positive: every corpus dump of the family is identified with the corpus metadata's `family`, `hw_id`, `sw_id` and `checksum_variant_id`, and `confidence ≥ 500`. (SPEC-000 §ECU plugin contract, identify row)
- **R112.** identify, discrimination: 100% of corpus pairs with the same `sw_id` and different checksum variants get different `checksum_variant_id`s. (SPEC-000 §ECU plugin contract, identify row)
- **R113.** identify, negative: for every corpus dump of other families and for random dumps, `identify` returns `None` or `confidence < 500`. (SPEC-000 §ECU plugin contract, identify row)
- **R114.** identify, fuzz: at least 100,000 inputs per run, both random `Dump`s (random memory count, ids, sizes, `dump_kind`, `base_address`) and mutations of corpus dumps; any exception or R105 timeout fails. The Atheris time budgets of SPEC-000 §Core engineering practices apply on top. (SPEC-000 §ECU plugin contract: "10⁵ random and mutated inputs")
- **R115.** layout: R20–R22 for every corpus dump; for every dump with a human-reviewed reference layout, `layout_hash` (SPEC-001 R63) equals the reference. For every corpus dump of a variant, the set of its `checksum` regions (`checksum_region_set = sha256(JCS(sorted list of {memory_id, start, end, name}))`) MUST equal the set of a human-reviewed reference layout of that variant; a set never reviewed fails. (SPEC-000 §ECU plugin contract, layout row)
- **R116.** verify on originals: on every unmodified corpus original, every recalculable region is `ok` and every signed region `signature_unverifiable`. (SPEC-000 §ECU plugin contract, checksums and verify row)
- **R117.** Mutation inside: for each recalculable region and each original, the suite changes one byte at a time (XOR with a non-zero value from the seeded generator) at: 1,000 positions uniform over the region's covered bytes (resolved pieces, or static `covered`); the first and last 64 covered bytes of each piece; the first and last byte of each piece; and every byte of each output field. Each mutation MUST turn that region to `fail`. In PR runs detection is 100% on this sample; the nightly covers every covered byte. (SPEC-000 §ECU plugin contract: "1,000 uniform positions + 64 bytes at each edge + the edges of each block")
- **R118.** Mutation outside: 1,000 positions uniform over bytes that are neither covered nor an output field of any region of the variant, and are not table bytes (R65); each single-byte change MUST leave `stored`, `computed` and `reason` of every `RegionResult` unchanged, and its `status` unchanged or turned to `bypassed` with an R44 location (a plugin may detect "checksum off" by probing routine bytes, which are outside every coverage). (SPEC-000 §ECU plugin contract: "detects a wrongly declared region")
- **R119.** Checksum off: every corpus file labeled "checksum off" verifies `bypassed` with R44 locations; none is `fail`. (SPEC-000 §ECU plugin contract, verify row)
- **R120.** Every `virtual` corpus dump verifies `not_applicable` (R41). (SPEC-000 §Plugin SDK)
- **R121.** checksum_patches golden: for every golden case of the variant (original `image_hash`, version, expected output SHA-256), the released image's SHA-256 equals the golden one, R51–R55 hold, and R54's fixed point holds. (SPEC-000 §ECU plugin contract, checksum_patches row; §Golden files)
- **R122.** Golden records follow SPEC-000 §Golden files: per checksum variant, with `oracle:` (level, tool and version, date), never produced by Impact code. `golden_concordant` and `candidate` count for development runs only; admission needs `golden_field` (R131). (SPEC-000 §Golden files; ADR-001 decisions 2, 4)
- **R123.** hints: R58 and R59 for every corpus dump. (SPEC-000 §ECU plugin contract, hints row)
- **R124.** Purity: the R100 scan; R101 checked by calling every method twice per dump in two different dump orders and comparing JCS hashes; R103 timings and R104 peaks recorded per method. (SPEC-000 §ECU plugin contract, general behavior row)
- **R125.** Descriptors and references: R33 and R79 for every variant against the layout of every corpus dump; R45, R55 and R81 agreement on every corpus dump, on every R117 mutation and on every R121 golden case. (SPEC-000 §Plugin SDK)
- **R126.** The report is a JSON object:
  ```
  { report_version: 1,
    core: { version, git_sha }, plugin: { family, version, contract_version, wheel_sha256 },
    corpus: { revision, dumps }, run: { kind: "pr" | "nightly" | "release", seed },
    variants: [{ checksum_variant_id, originals, checksum_off, virtual, golden_field, golden_concordant,
                 descriptor_hashes, signed_regions, references: [{ region, kind, id, source }],
                 checksum_region_sets, review_fields: [{ region, kind: "mirror_destination" | "compensation", memory_id, start, end }],
                 admitted }],
    checks: [{ rule, passed, cases, failures }],
    mutation: [{ checksum_variant_id, region, mode: "sample" | "full", inside_sampled, inside_detected,
                 outside_sampled, outside_unchanged }],
    fuzz: { inputs, exceptions, timeouts },
    limits: [{ method, budget_ms, max_ms, peak_bytes }],
    layout_review: { reviewer, date } | null,
    failures: [{ rule, image_hash, reason }],
    verdict: "conformant" | "nonconformant" }
  ```
  Integers only, no floats. Lists are sorted by these keys, compared as tuples, with code-point string order: `variants` by `checksum_variant_id`; `descriptor_hashes`, `signed_regions` and `checksum_region_sets` ascending; `references` by `region`; `review_fields` by `(memory_id, start)`; `checks` by `rule`; `mutation` by `(checksum_variant_id, region, mode)`; `limits` by `method`; `failures` by `(rule, image_hash, reason)`, duplicates removed. Each key is unique in its list, so the order is total. It contains no dump bytes, no VIN, no file names: dumps are referenced by `image_hash` only. `rule` is the cited rule, e.g. `"SPEC-002 R117"`. (SPEC-000 §ECU plugin contract: "result is published alongside the plugin (how many dumps, which checksum variants, which mutations)"; §Golden files)
- **R127.** `report_hash = sha256(JCS(report))` (SPEC-001 R60, R65). The PR seed is fixed and recorded; the nightly seed is random and recorded, so every run is reproducible. (SPEC-000 §CI pipeline)

## 8. Publication, admission and versioning

- **R130.** A plugin version is published only from a `release` run with `verdict: conformant`, for the exact wheel whose SHA-256 is in the report; the report and its `report_hash` are published with the release, and the last nightly for that commit is green. (SPEC-000 §ECU plugin contract; §CI pipeline, `plugin-conformance`, `nightly`)
- **R131.** A checksum variant is `admitted` only if the release run shows: ≥ 5 unmodified originals of it, ≥ 1 `golden_field` record, every check passing for it, no recalculable region with reference `none` (R33), every `checksum_region_sets` entry of the variant matching a human-reviewed reference layout (R115), and `layout_review` filled by the reference tuner, who is not the person requesting the finished file, after reviewing every `review_fields` entry (a mirror destination or compensation field over code is how R92's guarantee could be bypassed). (SPEC-000 §"Done" criteria, first plugin; §Golden files; ADR-001 decision 4)
- **R132.** The core loads a plugin with its published report and treats every variant not `admitted` there as `unknown_variant` (R42). The gate receives that report as data, computes and records its `report_hash` (R127), requires its `plugin.family` and `plugin.version` to equal the plugin's, and takes the admitted set from its `variants` entries with `admitted: true`; without a matching report the plugin is unavailable (SPEC-004 R15, R21). The report is caller-supplied, with the same trust as the plugin object itself (the accepted limitation of SPEC-001 R8); nothing in this version anchors it to the published release (open question 10). Verification of originals is admitted before recalculation only through this same rule: there is no partial admission in this version (open question 6). (ADR-001 decisions 5, 7)
- **R133.** A family enters the catalog only with ≥ 20 distinct corpus dumps, verified checksum golden files (R121, R122) for every variant it offers, and a reference tuner who validated the initial definition; until then it is `beta` behind a feature flag. (SPEC-000 §Market coverage)
- **R134.** Plugins use semver. Running the corpus on the published and the candidate version, any difference in the JCS of `layout`, `checksums` (including `descriptor_hash` and `reference`), `verify` or `checksum_patches` output for any corpus dump, for any R117 mutated input, or for the unverified image of any R121 golden case requires a **major** bump (`checksum_patches` is `[]` on an unmodified original, R54, so only the last two inputs exercise recalculation); differences only in `identify` or `hints` output require at least a minor. The release fails otherwise. (SPEC-000 §Core engineering practices, Versioning; §CI pipeline, automated semver rule)
- **R135.** The core refuses a plugin whose `contract_version` it does not implement (`PluginContractError`, reason `contract_version`). Plugins are discovered by Python entry point; every job records plugin `family`, `version` and the conformance `report_hash` in its provenance as `versions.plugins: [{family, version, conformance_report_hash}]` (SPEC-005 §3), and every `RegionReference` used (R34) with its `id` and `version`, as `versions.references: [{id, version}]` sorted by `id` (SPEC-005 §3) and in the gate report's output `subject.references` (SPEC-004 §6). (SPEC-000 §Plugin SDK: "loads plugins by entry point and pins the version used in each job"; invariant 12)

## 9. Errors

`PluginContractError` reasons: `bad_layout`, `bad_reference`, `plugin_disagreement`, `contract_version`, plus a failed R7 or R12–R59 check named after the rule (`r<n>`; `r43` is a wrong report-level aggregation, R43). `InterpreterDivergence` reason: `engine_divergence`. `DescriptorError` reasons: `schema`, `bad_width`, `message_source`, `bad_range`, `overlapping_ranges`, `table_not_protected`, `misaligned_piece`, `partial_self`, `skip_self_without_self`, `self_reference`, `unknown_chain_target`, `strategy_fields`, `compensate_outside_message`, `compensate_not_supported`, `field_out_of_checksum_region`, `field_overlap`, `unaccounted_checksum_bytes`, `dependency_cycle`, `duplicate_name`, `unknown_memory`; resolution failures (R66): `unknown_base_address`, `table_out_of_bounds`, `empty_range`, plus the dynamic forms of the R67–R68, R71, R75 reasons. Report-level `reason` values (only with `not_applicable`, R8): `virtual_dump`, `unknown_variant`, `no_checksum_regions`. Each reason MUST have at least one test.

## 10. Test vectors

`specs/vectors/spec-002/vectors.json` is produced by `generate.py` in the same directory. Neither script uses the core. All data is synthetic; no parameter is a claim about any ECU (ADR-001 decision 2).
- **JCS:** the third-party `rfc8785` package, pinned in `requirements.txt`; the version used is in the `generator` block. **SHA-256:** `hashlib`.
- **CRC:** for polynomial `0x04C11DB7`, Python `zlib.crc32`, mapped to arbitrary `init`, `xor_out` and reflection by bit-reversal identities; for other polynomials, a table-driven reflected engine that `generate.py` first checks against zlib. Catalogue check values (CRC of `"123456789"`) for CRC-32/ISO-HDLC, /BZIP2, /MPEG-2, /CKSUM and /ISCSI are from the reveng CRC catalogue (Greg Cook, https://reveng.sourceforge.io/crc-catalogue/17plus.htm, retrieved 2026-10-18; numeric facts only, no code taken) and are asserted in both scripts.
- **Fixture:** one synthetic 512-byte memory with six descriptors covering every feature (static ranges, `skip_self`, a pointer table with absolute addresses, `chain`, `compensate` with `target`, `mirror_block`) and dependency edges among them. Names and list order are chosen so that neither is a topological order of R75 (`a_comp` depends on every other store, `b_chain` on `e_crc` and `f_table`, `c_sum16` on `e_crc`): an interpreter that ignores dependency order fails the edit cases. `generate.py` computes each field by hand with literal offsets in a hand-written topological order that differs from the R75 min-heap order.
- **Engines:** `generate.py` uses zlib and a table engine for CRC and `int.from_bytes` loops for words; `crosscheck.py` uses the R62 bitwise loop and `struct`. Together they stand for the two engines of R81; byte-lane sums are exercised by dedicated tests.
- **Cross-check:** `crosscheck.py` is a second, independent, stdlib-only implementation: the bitwise loop of R62, `struct`-based words, a generic interpreter with static validation, table resolution, Kahn min-heap order and patch derivation. It recomputes every expected value and exits non-zero on any disagreement.

| Vector | Rules | Checks |
|---|---|---|
| `algorithms` (18) | R62 | CRC (5 catalogue models, 3 custom init/reflection), sum16/sum32 (7 word sizes and endiannesses), xor (3) |
| `fixture` | R60, R63–R65, R69–R74, R77, R78 | `layout_hash`, `descriptor_hash` ×6, static validation passes, original verifies `ok`, `checksum_patches` is `[]` |
| `cases` edit_a, edit_b | R43, R51–R54, R63, R70–R72, R75–R77 | verify before fix (some regions `fail`, some still `ok`), patch list and `patch_hash`es, released `image_hash`, verify after fix, fixed point |
| `resolution_failures` | R43, R65, R66 | pointer table out of bounds → region `fail` with reason, others unaffected |
| `invalid_descriptor_sets` (13) | R60, R61, R65, R67–R69, R71, R73–R75, R79 | one reason each: `schema`, `bad_width`, `self_reference`, `partial_self`, `misaligned_piece`, `table_not_protected` (table in calibration, table in a checksum region), `unknown_chain_target`, `compensate_not_supported`, `field_out_of_checksum_region`, `field_overlap`, `unaccounted_checksum_bytes`, `dependency_cycle` |
| `aggregation` (5) | R43 | status precedence, `no_checksum_regions` |

Not covered by vectors, so they need dedicated tests: R1–R14 and R20–R23 (shapes, plugin-specific), R30–R34, R40–R42, R44–R47, R50, R55, R58–R59, R80–R82 (engine agreement and `engine_divergence`, by property tests over random descriptors and messages), R90–R94, R100–R106, R110–R135 (suite behavior, run on the corpus), and the remaining reasons of §9.

Implementations MUST pass every vector. Vectors are test data, not golden files: no value in them is a checksum of a real image.

## 11. Compatibility

Changing anything in §2, §3, §4 semantics, §5, the limits' enforcement in §6, §7 checks or §9 reasons is breaking: it requires a SPEC-002 revision in a `foundation-change` PR, a **major** version of `core` and a new `contract_version`. Adding a descriptor algorithm, a `ProtectionFlag` value, a report field or an error reason is minor; a plugin using an addition declares the minimum core version. Changing a time or memory default is minor and recorded in the core changelog. Vectors change only together with the rule they test. (SPEC-000 §Core engineering practices, Versioning; SPEC-001 §10)

## 12. Open questions

1. **Gate meaning of non-`ok` statuses (pending author decision).** Open until Luiz confirms: this change applies SPEC-000 §Plugin SDK ('the gate exports only with `warn`') and aligns invariant 10 and SPEC-001 R42 to it; the fail-closed alternative is `G-VERIFY-SIGNED` as block. Under it, a green `verify` is status `ok` or `signature_unverifiable` (at least one region, none `fail` or `bypassed`); `signature_unverifiable` exports only with `warn` (SPEC-004 R26); `bypassed` and `not_applicable` always block.
2. **Limits.** Measured time budgets per method and a memory budget, after the first corpus measurement (SPEC-001 open question 2 is the kernel counterpart). Also whether the nightly "every covered byte" mutation (R117) is affordable on 4 MB dumps, or needs an analytic shortcut for descriptor regions.
3. **Sandbox framing and runtime.** Message framing over stdin/stdout, and whether seccomp alone (SPEC-000 §ECU plugin contract) or gVisor (SPEC-000 §Application security) is the third-party boundary.
4. **`pii_in_flash` granularity.** SPEC-000 declares it per family; whether it should be per memory id.
5. **Descriptor extensions** listed at the end of §4 (CRC compensation, complement pairs, multi-memory checksums, terminator-ended tables, empty table entries), each to be added only with a source and vectors.
6. **Partial admission.** ADR-001 decision 5 puts `verify` before recalculation; whether a variant may be admitted for verification with weaker evidence than for recalculation. R131 currently requires `golden_field` for both, per ADR-001 decision 4.
7. **Identify threshold at the gate.** Whether the gate's input threshold (SPEC-004 `identify_min_confidence`, integer thousandths like R3) equals the suite's 500.
8. **`definition_match`** (SPEC-000 §Gaps, detection, Phase 1) is not in `Identification` yet.
9. **Independence of the dual check.** R81 puts both engines in the core and R47 makes the plugin a third, separate implementation, but all three may be written by the same people. R82 states the limit. Nothing checks that an independent `source` (R33) really differs from the plugin's, and R47 does not prevent copying the interpreter into a plugin; whether this satisfies SPEC-000 §"Done" criteria ("dual implementation active in the first family") given §Golden files ("not a second piece of code by the same author") is for Luiz to decide.
10. **Anchor for the conformance report.** The gate trusts the report it is given (R132). Whether a hash of the published report should be pinned in the plugin package metadata, read through `plugin`, so that a consumer cannot substitute a report that admits more variants. Decision for Luiz.
