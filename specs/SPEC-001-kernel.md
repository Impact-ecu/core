# SPEC-001 · Binary kernel

Status: accepted
Date: 2026-10-18
Governs: `src/core/kernel/`, the kernel side of `release`, and the hash definitions used by provenance.
Derives from: SPEC-000 §Two stages, §Binary kernel invariants, §Data model, §Plugin SDK per ECU family.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Every numbered rule (`R<n>`) is normative and MUST be cited by at least one test (`# SPEC-001 R<n>`).

## 1. Problem

Every consumer of Impact (export, editor, audit, bench, partners, corpus) depends on one operation being exactly right: turning an original ECU image plus a set of edits into a new image. A wrong byte bricks a car; a wrong diff makes an audit lie. This spec fixes the data shapes, the algorithms and the hashes of that operation precisely enough that two independent implementations produce identical bytes and identical hashes.

Out of scope: plugin behavior (SPEC-002), definitions (SPEC-003), gate rules and verdicts (SPEC-004), the provenance report format (SPEC-005). This spec defines only the hashes those documents reuse.

## 2. Data shapes

All byte strings are immutable (`bytes`). All integers are non-negative and ≤ 2⁵³ − 1. Field order below is descriptive; canonical order is defined by JCS (§7).

### 2.1 Memory and Dump
```
DumpKind  = "bench_full" | "boot_full" | "obd_full" | "obd_partial" | "virtual"
MemoryId  = string matching ^[a-z][a-z0-9_]{0,31}$          e.g. "pflash", "dflash", "eeprom"
Memory    = { memory_id: MemoryId, base_address: int | null, data: bytes }
Dump      = { dump_kind: DumpKind, memories: list[Memory] }
```
- **R1.** A `Dump` MUST have at least one memory; `memory_id`s MUST be unique; every `data` MUST be non-empty.
- **R2.** `base_address` is metadata for display and hashing only. All offsets in this spec are relative to the start of `data`. It MAY be `null` when it is not yet known (an `obd_partial` read before `identify`, SPEC-000 §Plugin SDK). Such a dump can be hashed (`null` is hashed as JSON `null`) and passed to `identify`, but `apply`, `diff` and `migrate` reject it (`ShapeError`, reason `unknown_base_address`). Once `identify` provides the address, the ingestion builds a new `Dump` with it, which has a different `image_hash`. The file's own `sha256` as received is unchanged and stays the artifact's identity.
- **R3.** `DumpKind` values are the ones above. They supersede the `full | partial | maps_only` values in SPEC-000 §Data model (Artifact), which this PR aligns.

### 2.2 Regions and MemoryLayout
```
RegionKind   = "calibration" | "checksum" | "protected"
Region       = { kind: RegionKind, start: int, end: int, name: string }      # [start, end), name may be ""
MemoryLayout = { memories: list[{ memory_id, base_address, size: int, regions: list[Region] }] }
```
- **R4.** For each memory, regions MUST be sorted by `start`, MUST NOT overlap, and MUST cover `[0, size)` exactly. A layout violating this is rejected (`LayoutError`, reason `bad_cover`).
- **R5.** The layout MUST describe exactly the memories of the dump it is used with: same `memory_id` set, same `base_address`, same `size`. Otherwise `LayoutError`, reason `shape_mismatch`. Memories absent from a dump are absent from its layout (the plugin reports them as unknown; the kernel never sees them).
- **R6.** Anything not explicitly `calibration` or `checksum` is `protected`. `calibration` and `checksum` regions are therefore disjoint by R4.

### 2.3 Patch
```
Patch = { memory_id: MemoryId, offset: int, length: int, before: bytes, after: bytes }
```
Metadata such as author, timestamp, `map_id` and `created_in_version` lives outside the patch and outside its hash (R61).

- **R10.** `length > 0` and `len(before) == len(after) == length`. Otherwise `ShapeError`, reason `bad_length`.
- **R11.** A patch is immutable and identified by `patch_hash` (R61). Two patches with the same hash are the same patch.
- **R12.** `before != after`. A no-op patch is rejected (`ShapeError`, reason `noop_patch`). Individual bytes MAY be equal; the patch as a whole MUST change something.
- **R13.** A patch never resizes a memory. There is no insert or delete operation.

### 2.4 Version
```
Version = {
  base_image_hash: hex,                 # image_hash of the original it applies to
  layout_hash: hex,                     # layout it was validated against
  patches: list[Patch],                 # the complete set; materializing never walks a parent version
  overlaps: list[[patch_hash, patch_hash]]   # ordered pairs: first applies before second
}
```
Application metadata (`version_id`, `project_id`, `parent_version`, `plugin_versions`, label, note) is outside the kernel.

### 2.5 Images
- **R7.** `UnverifiedImage` is the result of `apply`. It carries `dump_kind`, memory ids, base addresses, sizes and `image_hash`. It MUST NOT expose its bytes through any public attribute or method, and it MUST NOT be serializable: pickle, JSON encoding, `bytes()`, `memoryview()` and buffer-protocol access all fail.
- **R8.** The only read-only `Dump` view of an `UnverifiedImage` is `core.kernel._internal.view(u)`. In `core`, an import-linter contract allows only `core.gate` to import `core.kernel._internal`. Every consumer repository (CLI, workers, API, plugins) MUST carry an import-linter contract that forbids importing `core.kernel._internal` (skill `bootstrap-repo`). Python cannot make this a hard barrier: a determined caller can always reach private modules. The real guarantee is twofold. Every function that writes an output binary in any consumer accepts only `ReleasedImage`, which has the only public `to_dump()`. And the architecture test walks every export path (SPEC-000 §Four layers, layer 4). This limitation is accepted and recorded here.
- **R9.** `core.kernel` and `core.plugins` MUST NOT import `core.gate`, so no code below the gate can construct a `ReleasedImage`. `ReleasedImage` is constructed only by `core.gate` (SPEC-004), using the checksum step in §5.

## 3. apply

`apply(o: Dump, v: Version, layout: MemoryLayout) -> UnverifiedImage`

- **R20.** `apply` MUST first check `image_hash(o) == v.base_image_hash` and `layout_hash(layout) == v.layout_hash`; mismatch → `ShapeError`, reason `wrong_base` / `wrong_layout`. It then validates every patch (R10–R12, R23), computes the canonical order (R25), and applies patches one by one in that order to a copy of `o`. The input `o` is never mutated.
- **R21. Precondition.** Before writing patch `P[i]`, the bytes at its range in `apply(o, P[:i])` (not in `o`) MUST equal `P[i].before`. Otherwise `PreconditionConflict`, reason `before_mismatch`, carrying `i` and the `patch_hash`. Nothing is ever overwritten silently.
- **R22. Overlaps.** Two patches overlap if they have the same `memory_id` and their ranges intersect. Every overlapping pair MUST appear exactly once in `v.overlaps`, in either order. Missing pair → `OverlapError`, reason `missing_order`. A pair that does not overlap, references an unknown patch, or appears twice → `OverlapError`, reason `spurious_order`. A cycle → `OverlapError`, reason `cycle`.
- **R23. Containment.** Every patch range `[offset, offset + length)` MUST lie entirely inside one single `calibration` region of its memory. Crossing into another region, even an adjacent `calibration` one, is rejected before any write: `ContainmentError`, reason `out_of_region`. An unknown `memory_id` → `ContainmentError`, reason `unknown_memory`.
- **R24. Locality.** Bytes outside the union of patch ranges are identical between `o` and the result, in every memory.
- **R25. Canonical order.** The application order is the lexicographically smallest topological order of the `overlaps` constraints under the key `(memory_id, offset, patch_hash)`. That is Kahn's algorithm with a min-heap on that key: start with every patch that has no predecessor; repeatedly pop the smallest key, emit it, and push each successor whose predecessors have all been emitted. With no overlaps this is plain `(memory_id, offset)` order. An overlap pair MAY put a later offset first (vector V5c). Input order never matters: permuting `v.patches` changes neither the result nor `version_hash` (vectors V4, V4b).
- **R26. Preserved shape.** The result has the same `dump_kind`, the same memories, and the same `base_address` and size per memory as `o`. Applying to a partial dump yields a partial image.
- **R27. Composition.** For the canonical order `P` and every `k`, `apply(o, P) == apply(apply(o, P[:k]), P[k:])` byte for byte. The second application uses a version whose `base_image_hash` is `image_hash(apply(o, P[:k]))`, whose `layout_hash` is unchanged, and whose overlap pairs are those of `v` between remaining patches. Pairs between an applied and a remaining patch are already satisfied by the order. Reapplying an already applied patch fails R21.

## 4. invert and diff

- **R30. invert.** `invert(o, v)` returns a version whose patches are those of `v` with `before` and `after` swapped. Swapping changes each `patch_hash`, so every overlap pair `[a, b]` of `v` becomes `[b', a']`, where `a'` and `b'` are the hashes of the swapped patches. Its `base_image_hash` is `image_hash(apply(o, v))` and its `layout_hash` is unchanged. `apply(apply(o, v), invert(v)) == o` byte for byte.
- **R31. diff.** `diff(o: Dump, x: Dump, layout) -> DiffResult` requires `o` and `x` to have the same shape (R26 fields; else `ShapeError`, reason `shape_mismatch`). Within `calibration` regions it returns one patch per maximal run of consecutive differing bytes, split at region boundaries, in `(memory_id, offset)` order. These patches are pairwise disjoint and need no overlaps, and `apply(o, diff(o, x).as_version(), layout)` reproduces `x` in every `calibration` byte. For `x = apply(o, v)`, the result reproduces `x` exactly.
- **R32. Foreign changes.** Differing bytes outside `calibration` regions are never turned into patches. `diff` reports them in `DiffResult.foreign` as maximal runs `{memory_id, offset, length, region_kind, region_name}`, split at region boundaries, sorted by `(memory_id, offset)`. This is what lets an audit show a third-party file that touched a protected or checksum region (vector V8).

## 5. Checksum step of release

`apply_checksum_patches(u: UnverifiedImage, q: list[Patch], layout) -> UnverifiedImage` is the only kernel operation the gate uses to build a release candidate. Plugins return `q` from `checksum_patches` (SPEC-002); they never receive a mutable buffer.

- **R40.** Every patch in `q` MUST lie inside one single `checksum` region. If any one does not, the whole set is rejected: `ContainmentError`, reason `checksum_out_of_region`. Patches in `q` follow R10–R13, R21 and R22, with an empty overlap list (checksum patches MUST be disjoint).
- **R41.** The result differs from `u` only in bytes of `checksum` regions.
- **R42.** `release` returns a `ReleasedImage` only with a green `verify` and a gate verdict of `no findings` or `warn`; `block` raises; the verdict is immutable; an export with `warn` requires an `Event{alert_ack}` that references `sha256` of the released image. The gate owns this behavior (SPEC-004); the kernel owns R40–R41.

## 6. Migration

`migrate(o: Dump, v: Version, new_layout) -> MigrationResult{ version, conflicts }`

- **R50.** Migration creates a new version against `new_layout`. It keeps only patches that still satisfy R21 against `o` in canonical order and R23 under `new_layout`. Every other patch becomes a conflict with reason `before_mismatch` or `out_of_region`, plus its `patch_hash`. Overlap pairs that reference dropped patches are dropped too. Nothing is migrated silently.

## 7. Canonical JSON and hashes

- **R60.** Canonical JSON is RFC 8785 (JCS), UTF-8. Byte strings are encoded as **lowercase hexadecimal**, with no prefix and no separators. Integers are JSON numbers (R1 bounds keep them exact). No floats appear in any hashed object.
- **R61.** `patch_hash = sha256(JCS({memory_id, offset, length, before, after}))`, with the bytes hex-encoded per R60.
- **R62.** `image_hash = sha256(JCS({dump_kind, memories: [{memory_id, base_address, size, sha256}]}))`, where `sha256` is the lowercase hex SHA-256 of the memory's bytes and memories are sorted by `memory_id`.
- **R63.** `layout_hash = sha256(JCS({memories: [{memory_id, base_address, size, regions: [{kind, start, end, name}]}]}))`, with memories sorted by `memory_id` and regions by `start`.
- **R64.** `version_hash = sha256(JCS({base_image_hash, layout_hash, patches: [patch_hash in canonical order], overlaps: [[patch_hash, patch_hash] sorted lexicographically]}))`.
- **R65.** All hashes are lowercase hex SHA-256 strings. A hash is never computed over Python `repr`, plain `json.dumps`, dict iteration order, or locale-dependent text.

These definitions realize SPEC-000 invariant 12. The rest of the provenance record (kernel, plugin and gate-rule versions, `gate_report` hash, verdict, Python version, `build`) is specified in SPEC-005.

## 8. Determinism, purity and errors

- **R70.** The kernel contains no floating-point arithmetic. Byte decoding uses explicit byte order (`<` or `>`); native-order `struct` formats (`@`, `=`) and `numpy.frombuffer` without an explicit dtype byte order are forbidden by lint.
- **R71.** `apply`, `invert`, `diff`, `apply_checksum_patches` and `migrate` are pure: no I/O, network, clock, randomness, environment reads, threads or global state. The same inputs produce the same bytes and hashes on x86-64 and arm64.
- **R72.** Every rejection raises a subclass of `KernelError` carrying a stable machine `reason` string (the reasons named in this spec). It never returns a partial result. Each reason MUST have at least one test.
- **R73.** Each rule above that implements a SPEC-000 invariant is also a runtime assertion in the owning function. In production a failed assertion aborts the job and opens an S1.

| SPEC-000 invariant | Rules |
|---|---|
| 1 Determinism | R70, R71 |
| 2 Composition | R27 |
| 3 Containment | R10, R23 |
| 4 Precondition | R21 |
| 5 Locality | R24 |
| 6 Invertibility | R30, R31 |
| 7 Canonical order | R22, R25 |
| 8 Preserved shape | R13, R26 |
| 9 Contained checksum | R6, R40, R41 |
| 10 Verified release | R42 (gate, SPEC-004) |
| 11 Patch migration | R50 |
| 12 Provenance | R60–R65 (+ SPEC-005) |

## 9. Test vectors

`specs/vectors/spec-001/vectors.json` is produced by `generate.py` in the same directory. Neither script uses the core.
- **JCS:** the third-party `rfc8785` package, pinned in `requirements.txt`. The version actually used is recorded in the file's `generator` block.
- **SHA-256:** Python `hashlib`.
- **Expected images:** built by hand with explicit byte edits per case, never by a generic apply.
- **Cross-check:** `crosscheck.py` recomputes every hashed object with a second, stdlib-only canonicalization and exits non-zero on any disagreement. Both agree at the time of writing (12 objects, 0 disagreements).

Every entry carries a `rules` list; the table below matches those lists.

Fixture: a `bench_full` dump with two memories:
- `pflash`: base `0x80000000`, 64 bytes `00..3f`. Base layout: `boot` protected, then the adjacent calibration regions `maps_a` and `maps_b`, an unnamed protected region, and the `block_crc` checksum region. A `migrated` layout shrinks `maps_a` and adds a protected `reserved` region.
- `dflash`: base `0xAF000000`, 16 bytes `ff`, one protected region `vin_immo`.

| Vector | Rules | Checks |
|---|---|---|
| patches P1–P5, Q1, CA–CC | R60, R61 | `patch_hash` |
| original | R60, R62 | `image_hash` |
| layouts base, migrated | R60, R63 | `layout_hash` |
| layouts gap, missing_memory | R4, R5 | `bad_cover`, `shape_mismatch` |
| V4, V4b | R20, R21, R24, R25, R26, R64 | apply of disjoint patches; order independence of the result and of `version_hash` |
| V5, V5c | R22, R25, R64 | ordered overlaps, including an order that contradicts offset order |
| V5b, V5d, V5e | R22 | `missing_order`, `spurious_order`, `cycle` |
| V6 | R30 | invert with overlaps: inverted base hash, reversed pairs, round-trip |
| V6b, V6c, V7, V8b | R31 | diff of apply; overlapping edits merge into one run; split at region boundary; `shape_mismatch` |
| V8 | R32 | foreign changes in protected and checksum regions |
| V9, V9b | R40, R41 | checksum patch inside the checksum region; `checksum_out_of_region` |
| V10 | R50, R64 | migration keeps P1, reports P2 as `out_of_region` |
| V11, V11b | R20 | `wrong_base`, `wrong_layout` |
| R-* | R10, R12, R21, R23 | `bad_length`, `noop_patch`, `before_mismatch`, `out_of_region`, `unknown_memory` |

Not covered by vectors, so they need dedicated tests: R1–R3, R7–R9 and R13 (structural), R27 (property test over random k), R42 (gate, SPEC-004), R70–R73 (lint, architecture and cross-architecture CI), and `unknown_base_address` (R2).

Implementations MUST pass every vector. Vectors are test data, not golden files: they do not need an `oracle:` record, because no hash is a checksum result.

## 10. Compatibility

Changing anything in §2, §3–§6 semantics, §7 hash definitions or §8 error reasons is breaking: it requires a SPEC-001 revision in a `foundation-change` PR and a **major** version of `core` (SPEC-000 §Core engineering practices, Versioning). Adding a new error `reason` or a new optional API is minor. Vectors change only together with the rule they test.

## 11. Open questions

1. `Event` hash chain (SPEC-000 §Data model) reuses R60, but its fields belong to SPEC-005.
2. Maximum memory size and patch count limits (performance criterion: `apply` + `release` of the whole corpus in < 1 s per dump, SPEC-000 §"Done" criteria) to be set after the first corpus measurement.
3. Whether `diff` needs a "minimum gap" option to merge runs separated by a few unchanged bytes for readability. If added, it is a presentation concern outside the kernel; the kernel diff stays maximal-run.
