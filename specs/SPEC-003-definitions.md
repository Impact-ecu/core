# SPEC-003 · Definitions

Status: draft
Date: 2026-10-18
Governs: `src/core/definitions/`: the `MapDef`, `AxisDef` and `Definition` shapes, raw↔physical conversion, canonical units and categories, `definition_hash`, edits turned into patches, and the XDF and A2L converters.
Derives from: SPEC-000 §Principles (definition format axis), §Data model (Definition, MapDef, MapPack) and §Modeling decisions, §Standards written before the code (SPEC-003), §Verification gate (keyed ranges, reviewed category), §Non-functional requirements (definition portability, unit accuracy), §Ingestion and analysis pipeline (step 4), §Gaps that still require a decision (firmware copyright and A2L), §Gaps and adopted improvements (detection rows), §Licensing and anti-piracy, §Regulatory compliance (intellectual property); SPEC-001 §2.1, R2, R10–R12, R31, R60–R65, R70–R72; SPEC-004 R30–R35; SPEC-005 R1–R4.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Every numbered rule (`R<n>`) is normative and MUST be cited by at least one test (`# SPEC-003 R<n>`). Source tags in brackets (`[X1]`, `[A1]`, …) point to §13; every external format fact carries one. A fact marked **UNVERIFIED** was not confirmed by two independent sources or by the standard body, and is listed in §12.

## 1. Problem

The kernel patches bytes (SPEC-001). People edit physical quantities: degrees of advance, λ, kPa. A `MapDef` is the bridge: it says where a map lives in a memory, how its bytes decode to raw values, and how raw values map to physical ones. If the bridge is wrong by one byte, one byte order or one rounding step, the tuner sees wrong numbers and writes wrong bytes. The gate also reads maps through this bridge (SPEC-004 R31), so a wrong decode becomes a wrong verdict. Definitions also come from formats Impact does not control (XDF, A2L, later DAMOS), of uncertain legal origin (SPEC-000 §Gaps, firmware copyright and A2L).

This spec makes the bridge exact: no floating-point arithmetic anywhere, rational scaling, an explicit list of supported format constructs, and a round-trip that is checked by hash.

Out of scope: kernel shapes and hashes (SPEC-001, reused here), plugin `hints` (SPEC-002), range tables and verdicts (SPEC-004), events that record imports and label transitions (SPEC-005), the definition library service and MapPack storage (outside `core`), heuristic detection, DAMOS (R110).

## 2. Common rules

- **R1. Shape discipline.** Every listed key is required. An absent value is JSON `null`, never an omitted key. An unknown key, a missing key or a value of the wrong type → `DefinitionError`, reason `bad_shape`. Each object therefore has exactly one canonical form. (SPEC-005 R3, SPEC-001 R65)
- **R2. Integers.** Every JSON integer in this spec is non-negative and ≤ 2⁵³ − 1. Negative and fractional quantities are rationals (R3), never JSON numbers. No float appears in any object of this spec. (SPEC-001 R60, SPEC-005 R1)
- **R3. Rational.** A rational is a JSON string in the canonical text form of SPEC-004 R30: `^-?(0|[1-9][0-9]*)(/[1-9][0-9]*)?$`, reduced (gcd of numerator and denominator is 1), denominator ≥ 2 when present, no `-0`. In a stored `MapDef`, `AxisDef` or `Definition`, numerator and denominator have at most 40 decimal digits each (reason `rational_too_large`). Values computed during conversion (R13, R15) are unbounded and are never stored in a definition. Any other text → `DefinitionError`, reason `bad_rational`. (SPEC-004 R30)
- **R4. Text fields.** `name`, `unit_text` and every other free-text field are Unicode strings in NFC, with no code point in U+0000–U+001F, U+007F–U+009F, and no lone surrogate. `name` has 1 to 256 code points; `unit_text` has 0 to 64. Violation → reason `bad_text`. Text is rejected, never normalized: the hash is over the string as given. (SPEC-005 R4)
- **R5. Identifiers.** `map_id` and `axis_id` match `^[a-z0-9][a-z0-9_.-]{0,63}$`. `family_id` matches the plugin `family` form of SPEC-002 R2, `^[a-z][a-z0-9]*(\.[a-z0-9][a-z0-9_]*)+$` (e.g. `bosch.med17`). `memory_id` is SPEC-001 `MemoryId`. Violation → reason `bad_identifier`. (SPEC-001 §2.1)

## 3. Data shapes

Field order below is descriptive; canonical order is JCS (§4).

### 3.1 Cell type
```
Dtype = { kind: "uint" | "int" | "float", bits: 8 | 16 | 32, byte_order: "le" | "be" | "none" }
```
- **R6.** `byte_order` is `"none"` if and only if `bits == 8`. `kind: "float"` requires `bits == 32` (IEEE 754 binary32). `"int"` is two's complement. Anything else → reason `bad_dtype`. This covers SPEC-000 §Modeling decisions "int8/16/32, uint, float32, LE/BE, signed". 64-bit and 16-bit float cells are not supported in this version.
- **R7. Decoding.** A cell of `bits/8` bytes decodes to a raw value: `uint` and `int` by explicit byte order (`le`: first byte least significant; `be`: first byte most significant; never native order, SPEC-001 R70), `int` by two's complement; `float` to the exact rational value of the binary32, computed with integer arithmetic from sign, exponent and fraction fields (subnormals included, `-0` decodes to `0`). A binary32 with all exponent bits set (infinity or NaN) is not a value: the cell decodes to `non_finite`, which the gate turns into `G-NONFINITE` (SPEC-004 R30). No floating-point operation is used at any step.
- **R8. Cell order.** A map of `rows × cols` cells occupies `rows · cols · bits/8` contiguous bytes from its `offset`. `cell_order: "x_fastest"` puts cell `(row r, col c)` at index `r · cols + c`; `"y_fastest"` at `c · rows + r`. Columns run along the x axis and rows along the y axis. When `rows == 1` or `cols == 1` the two orders coincide and `cell_order` MUST be `"x_fastest"` (reason `non_canonical`), so one layout has one encoding. Strided or interleaved layouts are not representable in this version.

### 3.2 Scaling
```
Scaling = { factor: Rational, addend: Rational }       # physical = factor · raw + addend
```
- **R10.** `factor != "0"` (reason `zero_factor`). Scaling is a rational affine map from raw to physical. SPEC-000 §Modeling decisions ("factor and offset") is realized as `factor` and `addend`; the word `offset` is kept for memory positions.
- **R11. Why rationals.** Floats outside the kernel would be allowed only if exactly reproducible; this spec uses none: decimal factors written in XDF and A2L text (`0.000123`, `64.000000`) are exact decimals, which binary64 cannot represent, so any float pipeline would round twice and produce platform-visible differences in rounding at ties. Rationals parsed from that text are exact, hash identically everywhere, and match the gate's own exact arithmetic (SPEC-004 R30). The cost is that a factor such as 1/3 cannot be written back to XDF exactly; R76 rejects that export instead of rounding.
- **R12. Raw → physical.** `physical = factor · raw + addend`, exact. For `float` cells `raw` is the rational of R7.
- **R13. Physical → raw.** For a target physical value `p` (a rational), `q = (p − addend) / factor`, exact.
  - `uint`, `int`: `raw = round_half_even(q)`. If `raw` lies outside `[0, 2^bits − 1]` (`uint`) or `[−2^(bits−1), 2^(bits−1) − 1]` (`int`) → `DefinitionError`, reason `out_of_range`. Values are never clamped.
  - `float`: `raw` is the binary32 nearest to `q`, ties to the one with an even fraction field (IEEE 754 roundTiesToEven), computed exactly from `q`. If the magnitude of `q` is ≥ 2^128 − 2^103 (the rounding boundary above the largest finite binary32) → reason `out_of_range`. Zero encodes as `+0`.
- **R14. Accuracy.** For every raw value `r` of a dtype, `phys_to_raw(raw_to_phys(r)) == r` exactly (zero error). For every `p` that encodes, `|raw_to_phys(phys_to_raw(p)) − p| ≤ |factor| / 2` for integer kinds and ≤ half a binary32 unit in the last place of the result, times `|factor|`, for `float`. This meets and replaces the SPEC-000 §Non-functional requirements target "error ≤ 0.5 LSB in round trip"; property tests per `dtype` and factor check both directions. (SPEC-000 §Non-functional requirements, unit accuracy)
- **R15. Unchanged cells keep their bytes.** When an edit (R57) targets a cell whose current bytes already decode to the target physical value, the encoded bytes are the current bytes. This keeps `-0`, non-canonical encodings and untouched cells byte-identical and keeps no-op patches out (SPEC-001 R12).

### 3.3 Units and categories
```
Unit     = "deg_crank" | "lambda" | "kPa_abs" | "kPa_rel" | "mg_per_stroke" | "percent"
         | "rpm" | "degC" | "ms" | "Nm" | "one"
Category = "ignition" | "lambda" | "boost" | "injection_quantity" | "injector_duty"
         | "injector_dead_time" | "injector_flow" | "rail_pressure" | "torque_limit"
         | "speed_limit" | "egt_target" | "vvt" | "wastegate_duty" | "fuel_trim_limit"
MapType  = "base" | "correction" | "limit" | "flag"
```
- **R16. Canonical units.** The list is minimal: each unit exists because a SPEC-000 gate category needs it.

| Unit | Meaning | Needed by (SPEC-000) | Export text and identity alias | Other exact aliases (factor) |
|---|---|---|---|---|
| `deg_crank` | crank-angle degrees; positive = before TDC | ignition −10° to 45° (§Verification gate), VVT | `deg_crank` | none |
| `lambda` | air-fuel equivalence ratio | λ 0.75 to 1.15, CI λ ≥ 1.15 (§Verification gate); measured and target λ (§Virtual test bench 1b) | `lambda` | `λ` (1) |
| `kPa_abs` | absolute pressure | MAP sensor limit (§Virtual test bench 1), rail pressure, "absolute vs relative boost" | `kPa_abs` | none |
| `kPa_rel` | pressure relative to ambient | "above 50 kPa relative boost" (§Verification gate) | `kPa_rel` | none |
| `mg_per_stroke` | injected mass per stroke | injector flow, CI maps (§Verification gate, "still missing") | `mg/stroke` | none |
| `percent` | percent | injector duty above 100%, wastegate duty, STFT/LTFT (§Verification gate) | `%` | none |
| `rpm` | engine speed | rpm × load bins (§Virtual test bench 1b), speed limiters | `rpm` | `1/min` (1) |
| `degC` | degrees Celsius | target EGT; IAT and ECT (§Virtual test bench 1b) | `degC` | `°C` (1) |
| `ms` | milliseconds | injector dead time (§Verification gate, "still missing") | `ms` | `s` (1000), `us` (1/1000), `µs` (1/1000) |
| `Nm` | torque | torque limiters (§Verification gate, "still missing") | `Nm` | none |
| `one` | dimensionless: flags, counts, factors | flags and correction maps (§Verification gate) | `1` | none |

Pressure has no automatic alias: `kPa`, `hPa`, `mbar` and `bar` do not say whether the value is absolute or relative, and guessing would change which range applies (SPEC-004 R32). A vehicle-speed unit is left out until a limiter rule needs it.
- **R17. Unit mapping.** Unit text from a source format maps to a canonical unit only by exact, case-sensitive string match against the "export text" and "aliases" columns. A match with factor `k ≠ 1` multiplies `factor` and `addend` of the scaling (and every `fixed` axis value) by `k`, exactly. No match → `unit: null` and `unit_text` keeps the source text. An importer applies an alias with `k ≠ 1` only when the multiplied scaling (and every multiplied `fixed` value) stays exportable by the exporter of the same format (XDF: R76, a factor that is a finite decimal or `1/D`, finite-decimal addend and labels); otherwise the alias is not applied, `unit` is null and `unit_text` keeps the source text (vector U7: `X/3` in `s` stays `unit: null`). This keeps every importer result exportable (R64). The A2L exporter (R99) represents any rational, so A2L imports always apply the alias. When `unit` is not null, `unit_text` MUST be null; when `unit` is null, `unit_text` MUST be a string, and `""` is the only form of "no unit text" (reason `non_canonical` for either violation). A unit therefore has exactly one encoding (R1) and survives round-trip (R64).
- **R18. Categories.** `Category` names the quantity a map holds; `MapType` is SPEC-000's "map type: base, correction, limit, or flag" (§Verification gate). Both are null while unknown; converters always produce null (R63). SPEC-004 keys ranges on `(category, map_type, unit)` plus engine data (SPEC-004 R32). Adding a category or unit is minor (§11). SPEC-004's seed table uses these identifiers (SPEC-004 R70).

### 3.4 Axes
```
AxisRef = { axis_source: "inline",  memory_id, offset: int, count: int, dtype: Dtype,
            scaling: Scaling, unit: Unit | null, unit_text: string | null }
        | { axis_source: "pointer", memory_id, pointer_offset: int, pointer_dtype: Dtype,
            target_memory_id: MemoryId, count: int, dtype: Dtype,
            scaling: Scaling, unit: Unit | null, unit_text: string | null }
        | { axis_source: "shared",  axis_id }
        | { axis_source: "fixed",   values: list[Rational], unit: Unit | null, unit_text: string | null }
AxisDef = { axis_id, name, axis: AxisRef }                 # axis.axis_source != "shared"
```
- **R20. Sources.** SPEC-000 §Modeling decisions names `axis_source (inline, pointer, shared)`. This spec reads them as: `inline`, the breakpoints are raw cells stored in a memory at a fixed `offset`, contiguous, `count` cells of `dtype`; `pointer`, the memory holds at `pointer_offset` an unsigned pointer (`pointer_dtype.kind == "uint"`, 16 or 32 bits) to the breakpoints, which live in `target_memory_id` at `pointer − base_address(target)` (for Siemens/Continental, SPEC-000; address translation outside the kernel, as SPEC-001 R2 allows); `shared`, the axis is the `AxisDef` with that `axis_id` in the same `Definition`. It adds `fixed`: breakpoints are physical values written in the definition and not stored in any memory (XDF labels, A2L `FIX_AXIS`, R73, R96).
- **R21. Count.** An axis on x has `count == cols`; on y, `count == rows` (`fixed`: `len(values)`). Mismatch → reason `dims_mismatch`. `count ≥ 1`.
- **R22. Pointer resolution.** Resolving a `pointer` axis reads the pointer per R7, requires a non-null `base_address` for `target_memory_id` (else reason `unknown_base_address`, as SPEC-001 R2), and requires the whole breakpoint span inside that memory (else `out_of_memory`). Inside the gate these errors, and those of R55, are the block finding `G-DEFINITION` (SPEC-004 §9), never a kernel incident. No converter in this version produces `pointer`; it exists for Impact-native and plugin-assisted definitions.
- **R23. Shared axes.** A `shared` reference MUST name an `AxisDef` of the same `Definition` (reason `unknown_axis`). An `AxisDef` MUST NOT itself be `shared` (reason `bad_shape`), so there are no chains or cycles. Every `AxisDef` MUST be referenced by at least one `MapDef` (reason `orphan_axis`).
- **R24. Monotonicity is not a shape rule.** An axis whose decoded breakpoints are not strictly monotonic is still a valid definition: whether that blocks an export is SPEC-004 R39. Decoding never sorts or repairs breakpoints.

### 3.5 MapDef
```
MapDef = {
  map_id: string,
  name: string,
  category: Category | null,
  map_type: MapType | null,
  state: "potential" | "imported" | "proposed" | "reviewed" | "golden",
  memory_id: MemoryId,
  offset: int,                       # relative to the start of the memory's data (SPEC-001 R2)
  dims: { rows: int, cols: int },
  cell_order: "x_fastest" | "y_fastest",
  dtype: Dtype,
  scaling: Scaling,
  unit: Unit | null,
  unit_text: string | null,
  axes: { x: AxisRef | null, y: AxisRef | null }
}
```
- **R26.** `1 ≤ rows ≤ 65535`, `1 ≤ cols ≤ 65535` (reason `bad_dims`). Each axis is optional; a present axis follows R21. A scalar is `1 × 1` with both axes null; an A2L `VAL_BLK` has cells and no axis.
- **R27. Offsets.** Every `offset` in this spec is relative to the start of the memory's `data`, never an absolute address, exactly as SPEC-001 R2. Absolute addresses from source formats are translated at import (R79, R97) and translated back at export.
- **R28. map_id.** `map_id` is unique within a `Definition` (reason `duplicate_map_id`). It is what the patch metadata field `map_id` references (SPEC-001 §2.3, SPEC-000 §Data model, Patch). Converters derive it as `"m_" + sha256(JCS({memory_id, name, offset}))[0:24]`, so the same map at the same place gets the same id on every import. SPEC-000 §Data model calls the database key `mapdef_id`; that key is outside `core`.
- **R29. Content is immutable.** A `MapDef` is a value: any change produces a new `MapDef` with a new `mapdef_hash` (R51). A change to any field other than `state` sets `state` to `proposed` (the person who changed it marked it), so a reviewed label never survives an edit of its location, type, scaling or axes.
- **R30. Span.** `span(m, definition, dump) -> list[{memory_id, start, end}]` is every byte the meaning of `m` depends on: the cell bytes `[offset, offset + rows · cols · bits/8)` in `memory_id`, plus, for each axis however it is reached: `inline`, its breakpoint bytes `[offset, offset + count · bits/8)`; `pointer`, the pointer cell `[pointer_offset, pointer_offset + pointer_dtype.bits/8)` in the axis `memory_id` and the breakpoint bytes in `target_memory_id` resolved against `dump` (R22); `shared`, the span of the referenced `AxisDef`'s axis, resolved in `definition` (R23); `fixed`, nothing. The result is sorted by `(memory_id, start)` (code point order of `memory_id`), with overlapping or touching ranges merged. Errors are those of R22 and R55. The gate uses `span` to decide which maps an edit touches and which patch bytes are unmapped (SPEC-004 R31), so an edit to a shared axis or to a pointer or its target counts as an edit of every map that reads it. (SPEC-000 §Modeling decisions, `axis_source`; §Verification gate, "non-monotonic axis" blocks)

### 3.6 Definition
```
Definition = {
  spec: "SPEC-003/1",
  family_id: string,
  software_version: { match: "exact" | "prefix", values: list[string] },
  axes: list[AxisDef],
  mapdefs: list[MapDef],
  origin: { kind: "platform" | "xdf_import" | "a2l_import" | "damos_import" | "heuristic" | "sibling_realignment",
            derived_from: list[hex] },
  license: { kind: "platform_created" | "verifiable_license" | "unverified", reference: string | null },
  confidence_permille: int
}
```
- **R34.** `software_version.values` is non-empty, sorted by code point, without duplicates; each value is 1 to 64 printable ASCII characters. `exact` matches a `sw_id` equal to a value; `prefix` matches a `sw_id` that starts with a value. Regular expressions are not used, so matching is identical everywhere and has no pathological inputs. Whether a match is `exact`, `sibling` or `none` for a given dump (SPEC-000 §Gaps and adopted improvements, "one pack, several versions") is decided outside `core` (Phase 1).
- **R35.** `axes` is sorted by `axis_id` and `mapdefs` by `map_id`, both without duplicates (reasons `duplicate_axis_id`, `duplicate_map_id`). A constructor MAY receive them in any order and MUST sort before hashing, so input order never changes `definition_hash` (vector D2).
- **R36.** `confidence_permille` is in `[0, 1000]` and stands for SPEC-000 §Data model "confidence" without a float (SPEC-001 R60).
- **R37.** `origin.derived_from` lists the `definition_hash` of every definition this one copied a `MapDef` or `AxisDef` from, sorted and unique. A converter sets `kind` to its format and `derived_from` to `[]`. The hash of the source file is not part of the definition; it belongs to the import event (SPEC-005), so that importing an exported file reproduces the same `definition_hash` (R64).
- **R38.** `spec` is the literal `"SPEC-003/1"`. A future incompatible shape changes it (§11).

### 3.7 Label states
- **R40. States.** `potential`: a heuristic candidate, listed separately and never shown as an editor map by default (SPEC-000 §Gaps and adopted improvements, "Detection: potential map"); `imported`: produced by a converter (SPEC-000 same table, "curated import"); `proposed`: a tuner marked it; `reviewed`: the reference tuner checked it; `golden`: validated on the bench (SPEC-000 §Modeling decisions).
- **R41. Transitions.** Allowed: `potential → proposed`, `imported → proposed`, `proposed → reviewed`, `reviewed → golden`, and `reviewed → proposed`, `golden → proposed` (re-review after a dispute). Anything else → `DefinitionError`, reason `bad_transition`. Who may perform a transition and the evidence it needs (the reference tuner is not the requester, SPEC-000 §"Done" criteria; the bench or shop oracle for `golden`) are recorded by the transition event (SPEC-005), not by `core`.
- **R42. Gate contract.** A `MapDef` counts as having a reviewed category if and only if `state ∈ {reviewed, golden}`, `category` and `map_type` are not null, and `unit` is not null. Otherwise the gate tests only monotonicity and smoothness and emits the fixed warning (SPEC-000 §Verification gate, "physical range only with a reviewed category"; SPEC-004 R35).
- **R43. Sibling realignment (Phase 1).** When a `MapDef` is moved to a sibling software version by searching for its known axes (SPEC-000 §Gaps and adopted improvements, "one pack, several versions"), the result is a new `MapDef` in a new `Definition` with `origin.kind = sibling_realignment` and `derived_from` naming the source; it is not an edit of the source `MapDef` under R29 and needs no R41 transition, because a new `MapDef` may start in any state the producing rule allows. It is `proposed` only if every inline axis at the new place has bytes identical to the source; otherwise it is `potential`. The search itself is specified when Phase 1 starts.

### 3.8 License and distribution
- **R44.** Converters (XDF, A2L, DAMOS) always set `license.kind = "unverified"` and `reference = null`, unless the caller passes `verifiable_license` with a non-empty `reference` (a contract id, SPDX expression or URL). `core` cannot verify a license; it records who claimed one. `platform_created` is reserved for definitions authored on the platform with `origin.kind ∈ {platform, heuristic, sibling_realignment}`.
- **R45. Distribution.** `distribution(d)` is `"shareable"` only if `license.kind != "unverified"` and every definition in `origin.derived_from` is `"shareable"` (the caller resolves them; `core` holds no store). Otherwise it is `"local_only"`: the definition is not hosted by the platform, neither in the shared library nor in tenant storage, and is only referenced locally by the customer (CLI). This is the stricter of the two SPEC-000 readings (§Regulatory compliance, intellectual property: "definitions without verifiable licensing are not hosted, only referenced locally"; §Gaps that still require a decision, "Firmware copyright and A2L", keeps them "private to the tenant"), chosen fail-closed until Luiz and a lawyer decide (§12, question 5). Taint propagates: copying one `MapDef` from a `local_only` definition makes the copy `local_only`.
- **R46. Exports.** XDF and A2L export of a definition is for the tenant that owns it (SPEC-000 §Licensing and anti-piracy). `core` exports bytes; the consumer enforces who receives them and signs the metadata (SPEC-005).
- **R47. No third-party definitions in this repository.** Test vectors and fixtures contain only synthetic definitions written for Impact: no name, address, factor or layout copied from a real XDF, A2L or DAMOS (SPEC-000 §Gaps, firmware copyright; the public `core`).

## 4. Hashes

- **R50.** Canonical JSON, hex encoding and the prohibitions are exactly SPEC-001 R60 and R65. This spec adds no float and no byte string to hashed objects.
- **R51.** `mapdef_hash = sha256(JCS(MapDef))`; `axisdef_hash = sha256(JCS(AxisDef))`.
- **R52.** `definition_hash = sha256(JCS(Definition))`, with `axes` and `mapdefs` sorted per R35. It identifies exactly what a project used: a project pins a `definition_hash`, and updating a map pack creates a new definition instead of altering old projects (SPEC-000 §Modeling decisions, "Definition is decoupled from Project").
- **R53.** All hashes are lowercase hex SHA-256 (SPEC-001 R65).

## 5. Binding to a dump and edits

- **R55. Bind.** Decoding a `MapDef` against a `Dump` (SPEC-001 §2.1) requires its `memory_id`, and the `memory_id` and `target_memory_id` of every inline or pointer axis it reaches (directly or through `shared`), to exist (reason `unknown_memory`) and every byte span (cells, inline axes, pointers, pointer targets) to lie inside its memory (reason `out_of_memory`). A definition never stores memory sizes; binding is checked at use. `base_address` is needed only by `pointer` axes (R22). The gate reports a binding failure as `G-DEFINITION` with the `map_id` (SPEC-004 §9).
- **R56. Decode.** `decode(m, definition, dump) -> {cells: list[list[Rational | non_finite]], x: list[Rational | non_finite] | null, y: list[Rational | non_finite] | null}`, rows outer, in physical units; a `shared` axis is resolved in `definition` (R23). A float32 inline or pointer axis can hold infinity or NaN (R7); such a breakpoint decodes to `non_finite`, which the gate turns into `G-NONFINITE` (SPEC-004 R30). The gate decodes from the release candidate (SPEC-004 R31).
- **R57. Edits become patches.** `encode(m, dump, targets: {(row, col): Rational}) -> list[Patch]` encodes each target per R13 and R15, compares the resulting bytes of the whole cell span with the current ones, and returns one SPEC-001 `Patch{memory_id, offset, length, before, after}` per maximal run of differing bytes, in offset order, exactly like SPEC-001 R31. An empty result means nothing changed. `map_id` goes into patch metadata, never into the patch (SPEC-001 R61). Containment in a `calibration` region is the kernel's check (SPEC-001 R23), not repeated here.
- **R58.** Axis edits follow R57 on the axis span. Editing a `shared` axis edits every map that references it, because the axis bytes are in each map's span (R30); `encode` for a shared axis is called once per `AxisDef`, not per map.
- **R59. Reading unverified images.** `decode` takes a `Dump`. Its only callers on an `UnverifiedImage` are the gate (through SPEC-001 R8 `view`) and tests. How the editor shows decoded values of an applied but unreleased version is open (§12, question 9).

## 6. Converters: common rules

- **R60. Pure.** Importers take the file as `bytes` plus parameters; exporters return `bytes`. No file system, network, environment, clock or randomness (SPEC-001 R71). An A2L `/include` directive → reason `unsupported_include`, because resolving it needs I/O [A2].
- **R61. Nothing silent.** An importer returns `ImportResult{definition, rejected: list[{path, reason}], ignored: list[path]}`. Each source element is either mapped, *ignored* (presentation-only, listed in `ignored`), or *rejected* (listed with a reason; the map it belongs to is not imported). An element or attribute not named in the converter's tables (§7, §8) rejects the map it belongs to, or the whole file when it is at file level (reason `unknown_element` / `unknown_attribute`). The lists are sorted by `path`. Paths are `/`-joined element names, each followed by `[i]`, the 0-based index among siblings with the same name, and an attribute is `@name` (e.g. `XDFFORMAT[0]/XDFTABLE[0]/XDFAXIS[2]/decimalpl[0]`). `ignored` lists only items of imported maps and of the file level; a rejected map contributes one `rejected` entry with its own path. A required element or attribute that is missing → `missing_element`. Numeric text and attributes are read with surrounding ASCII whitespace (U+0020, U+0009, U+000D, U+000A only) removed; any other leading or trailing character, such as U+00A0, makes the value malformed (`bad_number` for numbers, vector X14); `title` and `units` text is taken verbatim (R4 then applies).
- **R62. Determinism.** The same bytes and parameters produce the same `ImportResult`; the same definition produces the same export bytes.
- **R63. Imported state.** Every imported `MapDef` has `state: "imported"`, `category: null`, `map_type: null`; `origin.kind` is the format; `license` per R44.
- **R64. Round-trip (mandatory).** For every definition `d` returned by an importer with parameters `P`, `import(export(d), P).definition` has the same `definition_hash` as `d`, with empty `rejected`. For any other exportable definition `e`, `import(export(e), P)` equals `normalize(e, P)`: `e` with every `state` set to `imported`, `category` and `map_type` null, every `map_id` (and `axis_id`) re-derived by R28 (R98), units re-derived by R17 from the export text, and `family_id`, `software_version`, `confidence_permille`, `origin` and `license` taken from `P`. R74's integer divisor and R17's exportability condition make every importer result exportable. An export that cannot satisfy this rejects instead of writing a lossy file (reason `unrepresentable`, with the field). Property tests check both statements over generated definitions; vectors X1 (importer result), XE1 (import-normal form) and XN1 (platform form, `normalize`) check them on fixed inputs.
- **R65. Fuzzing.** Each importer is a parser of untrusted input and is fuzzed as SPEC-000 §Core engineering practices requires (Atheris, 10 min per PR). A crash or an exception other than `DefinitionError` is a bug.
- **R66. Provisional mappings.** A table row marked **P** (§7, §8) rests on one community source and is **UNVERIFIED** against the format's owner. The converter implements it so that vectors and tests can run, but a `core` release whose converter accepts an input that depends on a **P** row MUST NOT be published until a SPEC-003 revision confirms the row (§12, questions 1 and 4). Rows marked **C** are confirmed by at least two independent sources or by the standard body.

## 7. XDF (TunerPro)

TunerPro publishes no XDF schema. Its online help is user documentation [X4] and the help pages on tunerpro.net returned HTTP 403 to automated fetches on 2026-10-18. Every fact below comes from three independent open-source XDF readers [X1] [X2] [X3]; each row says which ones agree.

### 7.1 Supported subset
An XDF file is XML with root `XDFFORMAT` containing an optional `XDFHEADER` and any number of `XDFCONSTANT` and `XDFTABLE` elements [X1] [X2] [X3].

| Construct | Impact mapping | Sources | Level |
|---|---|---|---|
| `XDFCONSTANT` | a `1 × 1` `MapDef`, axes null | [X1] [X2] | C |
| `XDFTABLE` | a `MapDef`; its `XDFAXIS id="z"` holds the cells, `id="x"` and `id="y"` the axes | [X1] [X2] [X3] | C |
| `title` (child of constant or table) | `name` | [X1] [X2] [X3] | C |
| `EMBEDDEDDATA@mmedaddress` | `offset` (R79), hex with `0x` prefix or decimal | [X1] [X2] [X3] | C |
| `EMBEDDEDDATA@mmedelementsizebits` | `dtype.bits` (8, 16, 32; other values `bad_dtype`) | [X1] [X2] [X3] | C |
| `EMBEDDEDDATA@mmedrowcount`, `@mmedcolcount` on z | `dims.rows`, `dims.cols`; absent = 1 | [X1] [X2] [X3] | C |
| cell storage | rows stored one after another, each row's columns contiguous: `cell_order: "x_fastest"`; rows pair with the y axis, columns with the x axis | [X1] (doc comment on `EmbeddedData`), [X2] (`TableLayout.cell_address`, `table_layout`) | C |
| `EMBEDDEDDATA@mmedtypeflags` bit `0x01` | `kind: "int"` (signed); clear = `uint` | [X2] only | **P** |
| `mmedtypeflags` bit `0x02` | `byte_order: "le"` (LSB first); clear = `"be"` | [X2] only; consistent with [X1]'s 16-bit example using `0x02` | **P** |
| `mmedtypeflags` bit `0x10000` | `kind: "float"`, requires 32 bits | [X2] only | **P** |
| `mmedtypeflags` absent | treated as `0x00` | [X2] default | **P** |
| `@mmedmajorstridebits`, `@mmedminorstridebits` | accepted only when absent or `0` (contiguous) | [X1] [X2] [X3] name them; meaning of `0` as "element size" from [X2] only | **P** |
| `MATH@equation` with exactly one `VAR id="X"` | `scaling` per R74 | [X1] [X2] [X3] | C |
| `units` | unit text, mapped by R17 | [X1] only | **P** |
| `indexcount` on x / y | axis `count` | [X1] [X2] | C |
| x / y `EMBEDDEDDATA` with `mmedaddress` | `inline` axis at that offset, its own dtype, `MATH`, `units` | [X1] [X2] | C |
| x / y `LABEL@index`, `@value`, no `mmedaddress` | `fixed` axis | [X1] [X2] | C |
| `XDFHEADER/BASEOFFSET@offset`, `@subtract` (or text form `baseoffset`) | accepted only when the offset is `0` | [X2] [X3] name both attributes; meaning of `subtract` from [X2] only | **P** for non-zero |
| `XDFHEADER/DEFAULTS@signed`, `@lsbfirst`, `@float` | accepted only when each is absent or `0` | [X1] [X2] [X3] | C (names); precedence over `mmedtypeflags` unknown |

- **R70. Rejected constructs.** These reject the element they occur in, with the reason in brackets: `XDFFLAG`, `XDFPATCH`, `XDFCHECKSUM` (`unsupported_element`; any other element not in the tables is `unknown_element`, R61; a checksum belongs to plugins, SPEC-002, and a code patch is never applied by Impact, SPEC-000 §Gaps, anti-circumvention); `embedinfo` (`unsupported_linked_axis`, its link semantics are undocumented [X1]); a `MATH` with a `VAR` other than one `X` (`unsupported_equation`, linked variables read other addresses [X2]); stride ≠ 0 (`unsupported_stride`); unknown `mmedtypeflags` bits, the float bit without 32 bits, or float with the signed bit (`unsupported_typeflags`); `BASEOFFSET` ≠ 0 (`unsupported_baseoffset`, file level); a `DEFAULTS` attribute `signed`, `lsbfirst` or `float` ≠ 0 (`unverified_defaults`, file level); `XDFTABLE@flags` or `XDFHEADER/flags` other than absent or 0 (`unsupported_flags`).
- **R71. Ignored constructs.** Listed in `ignored` (R61), never used: `XDFHEADER/deftitle`, `description`, `author`, `fileversion`, `CATEGORY`, `REGION`, `DEFAULTS@datasizeinbits`, `@sigdigits`, `@outputtype`; on constants, tables and axes: `description`, `CATEGORYMEM`, `DALINK`, `datatype`, `unittype`, `outputtype`, `decimalpl`, `min`, `max`, and the attributes `uniqueid`, `XDFFORMAT@version`. On an x / y axis without `mmedaddress`, the remaining `EMBEDDEDDATA` attributes are ignored [X1] (the "TVUB" example carries `mmedelementsizebits` and a stride on a label axis). [X1] marks `datatype`, `unittype` and `DALINK` as "purpose unknown"; they are ignored and listed, so a reviewer sees them.
- **R72. Dimensions.** z `mmedrowcount`/`mmedcolcount` give `dims`. An x axis is required iff `cols > 1` and a y axis iff `rows > 1`, with `indexcount == cols` (x) and `== rows` (y) (reason `dims_mismatch`). An x or y axis present on a dimension of size 1 is kept (its `count` is 1, R21), so the file round-trips. A table with `1 × 1` cells and no axes becomes the same `MapDef` as a constant.
- **R73. Fixed axes.** `LABEL` elements MUST have indices `0 … count − 1`, each once (reason `bad_labels`), and values in the signed decimal form `-?D` of R74, after R61 whitespace removal (reason `non_numeric_label`, e.g. `+1` or free text; [X1] notes labels may be free text). A label axis is accepted only when its `MATH` is absent or exactly `X` (reason `ambiguous_label_scaling`): whether labels are raw or physical when an equation is present is not documented.
- **R74. Equation grammar.** After removing ASCII spaces, `equation` MUST match one of these forms, where `F` is `-?D` and `A` is `D`, with `D = [0-9]+(\.[0-9]+)?`, and the divisor `N` is an integer, `N = [0-9]+`:
  `X` · `X*F` · `F*X` · `X/N` · each of the four followed by `+A` or `-A` · `A+X*F` · `A-X*F` · `A+X/N`.
  The value is the exact rational of the decimal text; `X/N` has factor `1/N`. `X/N` with `N = 0` → `zero_factor`. A decimal divisor (`X/3.5`) → `unsupported_equation`, so every imported factor is a finite decimal or `1/N` and is exportable under R76 (vector X15). `A-X*F` means factor `−F`. Anything else (`X*X`, parentheses, functions, exponents, other variables) → `unsupported_equation`. The forms are those seen in [X1]'s examples (an addend-first product `A+X*F` with a zero addend, a division by an integer, the bare variable), closed under sign and order; TunerPro accepts richer expressions [X2], which Impact rejects.
- **R75. Name and unit.** `title` → `name` (R4). Missing `units` → unit text `""`. The unit and scaling of a table come from its z axis.
- **R76. Export.** `export_xdf(d, memory_id)` writes every `MapDef` of `d`, in `map_id` order; it never filters. It rejects the whole export (`unrepresentable`) at the first violation, maps in `map_id` order, and names the field: `memory_id`; `cell_order`; `axes.x` / `axes.y` (missing axis); then for the x and then the y axis `axes.<k>.axis_source`, `axes.<k>.memory_id`, `axes.<k>.scaling.factor`, `axes.<k>.scaling.addend`, `axes.<k>.values`; then `scaling.factor`, `scaling.addend` (vectors XU1–XU7). The violations are: any `MapDef` or axis span lies in a memory other than `memory_id`; `cell_order: "y_fastest"` with `rows, cols > 1`; `cols > 1` with a null x axis (field `axes.x`) or `rows > 1` with a null y axis (field `axes.y`), since R72 would reject the re-import (vectors XU1, XU2); `shared` or `pointer` axes (shared axes are expanded only by an importer that produced them, which XDF never does); a factor that is neither a finite decimal nor `1/N` for a positive integer `N`; an addend or label that is not a finite decimal.
- **R77. Export bytes.** UTF-8, LF line ends, two-space indentation, no BOM, `&`, `<`, `>`, `"` escaped as entities, other characters literal. Structure, in this order:
  ```
  <?xml version="1.0" encoding="UTF-8"?>
  <XDFFORMAT>
    <XDFCONSTANT>                                  # or <XDFTABLE> with XDFAXIS x, y, z
      <title>NAME</title>
      <EMBEDDEDDATA mmedtypeflags="0xHH" mmedaddress="0xADDR" mmedelementsizebits="N" />
      <units>TEXT</units>                          # omitted when the text is ""
      <MATH equation="EQ">
        <VAR id="X" />
      </MATH>
    </XDFCONSTANT>
  </XDFFORMAT>
  ```
  A `MapDef` is written as `XDFCONSTANT` if and only if it is `1 × 1` with both axes null; every other `MapDef` (including a `1 × 1` map with an axis) is an `XDFTABLE`. In a table, `XDFAXIS id="x"` then `id="y"` (each only when not null) then `id="z"`. An inline axis writes `EMBEDDEDDATA` (flags, address, bits), `indexcount`, `units`, `MATH`; a fixed axis writes `indexcount`, `units`, then `LABEL index="i" value="V"` for each value, and no `MATH`; z writes `EMBEDDEDDATA` with `mmedrowcount` and `mmedcolcount` after `mmedelementsizebits`, then `units`, `MATH`. `mmedtypeflags` is `0x` plus uppercase hex of `(int ? 0x01 : 0) | (le ? 0x02 : 0) | (float ? 0x10000 : 0)`, at least two digits; addresses are `0x` plus uppercase hex without padding. `EQ` starts with `X` when the factor is 1, else `X*F` when the factor is a finite decimal, else `X/N`; it is followed by `+A` / `-A` when the addend is non-zero (factor 1 with addend −40 is `X-40`; vector XE1). Decimals are written exactly, without exponent, without trailing fractional zeros, with `0` before the point. Unit text is the canonical export text (R16) or `unit_text`. Whether TunerPro opens these files unchanged is checked by question 1 (§12).
- **R79. Addresses.** XDF addresses are offsets from the start of the edited file [X1] [X2]. The import parameter `memory_id` names the memory that file is; `offset = mmedaddress`. The file is one memory; multi-memory XDF does not exist in the sources.
- **R80. XML safety.** The input MUST be UTF-8 (XML declaration absent, or encoding `UTF-8` / `utf-8`; else `unsupported_encoding`). A document type declaration, an entity declaration or an external reference → `xml_forbidden`, file level. Entities other than the five predefined ones and numeric character references are rejected. Malformed XML → `bad_xml`. This closes entity expansion and external fetches in any XML library the implementation uses.

## 8. A2L (ASAM MCD-2 MC)

The ASAM MCD-2 MC standard is sold by ASAM and was not read for this spec. The facts below come from the ASAM public wiki page [A1], a specification-derived open-source parser [A2], a second independent parser [A3] and a vendor introduction [A4]. Until the standard text confirms the **P** rows, R66 applies.

### 8.1 Supported subset
| Construct | Impact mapping | Sources | Level |
|---|---|---|---|
| `/begin NAME … /end NAME` blocks, `/* */` and `//` comments, strings in `"` with `\"`, `""` and `\\` escapes | tokenizer | [A2] (tokenizer) | P |
| `ASAP2_VERSION`, `PROJECT`, `MODULE` | containers | [A2] | P |
| `CHARACTERISTIC` type `VALUE` | `1 × 1` `MapDef` | [A1] [A2] | C |
| `CHARACTERISTIC` type `CURVE` | `1 × n` `MapDef` with x axis | [A1] [A2] | C |
| `CHARACTERISTIC` type `VAL_BLK` with one-dimensional `NUMBER` or `MATRIX_DIM` | `1 × n`, no axis | [A1] [A2] | C |
| `CHARACTERISTIC` fields `name`, `characteristic_type`, `address`, `deposit` (record layout), `conversion` | `name`, type, `offset` (R97), dtype via layout, scaling via `COMPU_METHOD` | [A2] | P |
| `RECORD_LAYOUT` with only `FNC_VALUES position datatype index_mode DIRECT` | the cells start at `address`, contiguous | [A2] | P |
| `RECORD_LAYOUT` with only `AXIS_PTS_X position datatype INDEX_INCR DIRECT` | the breakpoints of an `AXIS_PTS` start at its `address` | [A2] | P |
| data types `UBYTE SBYTE UWORD SWORD ULONG SLONG FLOAT32_IEEE` | `uint`/`int` 8/16/32, `float` 32 | [A2] [A3] | C |
| `BYTE_ORDER MSB_FIRST` | `"be"` | [A2] (enum), [A3] (default value) | C |
| `BYTE_ORDER MSB_LAST` | `"le"` | [A2] (enum) | P |
| `COMPU_METHOD … IDENTICAL` | factor 1, addend 0 | [A1] [A2] [A4] | C |
| `COMPU_METHOD … LINEAR` with `COEFFS_LINEAR a b` | `physical = a · raw + b` → factor `a`, addend `b` | [A1] [A2] [A3] [A4] | C |
| `COMPU_METHOD … RAT_FUNC` with `COEFFS a b c d e f` | `COEFFS` maps **physical to internal**: `internal = (a·p² + b·p + c) / (d·p² + e·p + f)` | [A1] ("RAT_FUNC, which describes the conversion from the physical format to the internal format"), [A3] (`INT = f(PHYS)`), [A4] | C |
| `COMPU_METHOD` unit string, `PHYS_UNIT` | unit text (R17) | [A2] | P |
| `AXIS_DESCR COM_AXIS` with `AXIS_PTS_REF` | `shared` axis: an `AxisDef` from the `AXIS_PTS` | [A1] [A2] | C |
| `AXIS_DESCR FIX_AXIS` with `FIX_AXIS_PAR offset shift n` | values `offset + i · 2^shift`, `i = 0 … n−1` | [A2] (doc: `X_i = Offset + (i - 1)*2^shift`, 1-based) | P |
| `FIX_AXIS_PAR_DIST offset distance n` | values `offset + i · distance` | [A2] | P |
| `FIX_AXIS_PAR_LIST v…` | values as listed | [A2] | P |
| `ECU_ADDRESS_EXTENSION` | accepted only when `0` | [A2] | P |

- **R90. RAT_FUNC inversion.** Only `a = d = e = 0`, `b ≠ 0`, `f ≠ 0` is accepted: then `physical = (f · raw − c) / b`, so factor `f/b` and addend `−c/b`, exact. Any other coefficients → `unsupported_conversion` (a quadratic or a non-constant denominator has no affine inverse; [A3] also refuses to invert them). `LINEAR` with `a = 0` → `zero_factor`.
- **R91. Numbers.** COEFFS, limits and fixed-axis parameters are decimal literals with optional sign, fraction and exponent (`[+-]?[0-9]+(\.[0-9]*)?([eE][+-]?[0-9]+)?`, or `.5` style when [A2]'s tokenizer accepts it, which is P); they convert to exact rationals. Addresses are decimal or `0x` hexadecimal integers [A2]. A literal outside these forms → `bad_number`.
- **R92. Byte order resolution.** The object's own `BYTE_ORDER`, else `MOD_COMMON`'s. If neither exists → `missing_byte_order`: the default when both are absent is not confirmed ([A3] assumes `MSB_FIRST`). `LITTLE_ENDIAN` and `BIG_ENDIAN` (deprecated after 1.51 per [A2]), `MSB_FIRST_MSW_LAST` and `MSB_LAST_MSW_FIRST` → `unsupported_byte_order`.
- **R93. Rejected constructs.** `MAP`, `CUBOID`, `CUBE_4`, `CUBE_5` (`unverified_index_mode`: the pairing of `ROW_DIR`/`COLUMN_DIR` with x and y is not confirmed; [A3] maps `ROW_DIR` to NumPy C order over a shape `(x_points, y_points)`, which makes y the fastest index, the opposite of what the name suggests to a reader of XDF); `ASCII`; `STD_AXIS`, `RES_AXIS`, `CURVE_AXIS` (`unsupported_axis`: breakpoints inside the characteristic's record need `NO_AXIS_PTS_X`, positions and alignment rules not confirmed); record layouts with any other entry, `INDEX_DECR`, or an address type other than `DIRECT` (`unsupported_record_layout`); `DEPOSIT DIFFERENCE` (`unsupported_deposit`); `BIT_MASK`, `VIRTUAL_CHARACTERISTIC`, `DEPENDENT_CHARACTERISTIC` (`unsupported_characteristic`); `TAB_INTP`, `TAB_NOINTP`, `TAB_VERB`, `FORM` (`unsupported_conversion`); data types `A_UINT64`, `A_INT64`, `FLOAT16_IEEE`, `FLOAT64_IEEE` (`unsupported_dtype`); a conversion name not defined as a `COMPU_METHOD` in the module, including `NO_COMPU_METHOD` (`unresolved_conversion`, its meaning is not confirmed); a non-zero `ECU_ADDRESS_EXTENSION` (`unsupported_address_extension`); `/include` (R60).
- **R94. Ignored constructs.** `MEASUREMENT`, `FUNCTION`, `GROUP`, `IF_DATA`, `A2ML`, `MOD_PAR`, `UNIT`, `COMPU_VTAB`, `COMPU_VTAB_RANGE`, `FRAME`, `HEADER`; on characteristics and axis points: `long_identifier`, `max_diff`, limits, `EXTENDED_LIMITS`, `FORMAT`, `DISPLAY_IDENTIFIER`, `FUNCTION_LIST`, `ANNOTATION`, `CALIBRATION_ACCESS`, `READ_ONLY`, `MONOTONY`, `GUARD_RAILS`, `STEP_SIZE`, `MAX_REFRESH`, `SYMBOL_LINK`, `MODEL_LINK`, `REF_MEMORY_SEGMENT`, `input_quantity`; `ALIGNMENT_*` in `MOD_COMMON` and record layouts (single-entry layouts have no internal padding). Listed per R61.
- **R95. Units.** If the `COMPU_METHOD` unit and `PHYS_UNIT` are both non-empty and differ → `ambiguous_unit`; otherwise the non-empty one (or `""`) is the unit text. An `AXIS_DESCR` `PHYS_UNIT` applies to that axis the same way.
- **R96. Fixed axes.** A `FIX_AXIS` is accepted only when the `AXIS_DESCR` conversion is `IDENTICAL` or a `LINEAR`/`RAT_FUNC` equal to factor 1, addend 0 (reason `ambiguous_fixed_axis`): whether the parameters are internal or physical is not confirmed, and with an identity conversion both readings agree. `max_axis_points` MUST equal the computed count (`dims_mismatch`). Shift MUST be an integer (`bad_number`).
- **R97. Addresses.** A2L `address` is an absolute ECU address. The import parameter `memories: list[{memory_id, base_address, size}]` (from the plugin layout, SPEC-002) maps it: the span `[address, address + bytes)` MUST lie in exactly one memory (`address_unmapped`), and `offset = address − base_address` (address translation outside the kernel, SPEC-001 R2). Export adds `base_address` back.
- **R98. Shared axes.** Each `AXIS_PTS` referenced by an accepted `COM_AXIS` becomes one `AxisDef` with `axis_id = "a_" + sha256(JCS({memory_id, name, offset}))[0:24]` and an `inline` axis. The `AXIS_DESCR` conversion MUST equal the `AXIS_PTS` conversion (`conflicting_axis_conversion`) and its `max_axis_points` MUST equal the `AXIS_PTS` `max_axis_points` (`dims_mismatch`). `DEPOSIT` absent is read as `ABSOLUTE` (P).
- **R99. Export.** `export_a2l(d, memories)` writes, for each map, one `CHARACTERISTIC` with an explicit `BYTE_ORDER` (never relying on a default), a single-entry `RECORD_LAYOUT`, and a `COMPU_METHOD` of type `RAT_FUNC` with integer coefficients: for factor `p/q` and addend `r/s`, `COEFFS 0 b c 0 0 f` with `f = p·s`, `c = −r·q`, `b = q·s`, all three divided by `gcd(b, |c|, |f|)` (vector A2). `physical = (f·raw − c)/b` then equals `factor·raw + addend` exactly, so any rational scaling round-trips without decimals. `shared` axes become `AXIS_PTS` with `COM_AXIS`; `fixed` axes `FIX_AXIS_PAR_LIST`, rejecting (`unrepresentable`) a fixed value that is not a finite decimal (R91 has no fraction form); `pointer` axes, `y_fastest` maps and maps with two axes → `unrepresentable` in this version. The complete text template (identifiers, `ASAP2_VERSION`, format strings) is fixed together with question 4 (§12); until then the A2L converter is specified but not implemented.

## 9. DAMOS and other formats

- **R110.** DAMOS import is Phase 1 (SPEC-000 §Gaps and adopted improvements, "Detection: curated import"). It will produce `MapDef{state: imported}` with `origin.kind = "damos_import"` and `license.kind = "unverified"` (R44, R45), and needs a SPEC-003 revision with its own sourced mapping table. Map CSV (SPEC-000 §Non-functional requirements) likewise. No converter for an unspecified format may be added to `core`.

## 10. Purity, errors and test vectors

- **R120.** `core.definitions` is pure (SPEC-001 R71) and has no floating-point arithmetic (SPEC-001 R70 extended to definitions, as SPEC-004 R30 extends it to the gate). Integer decoding uses explicit byte order only.
- **R121.** Every rejection raises `DefinitionError` (a subclass per area MAY exist) with a stable machine `reason`, the ones named in this spec, and never returns a partial object. Converter rejections of single elements are entries in `ImportResult.rejected`, not exceptions; file-level rejections raise. Each reason MUST have at least one test.
- **R122.** R7, R13, R14, R15, R35 and R64 are also runtime assertions in their owning functions (SPEC-001 R73).

`specs/vectors/spec-003/vectors.json` is produced by `generate.py` in the same directory. Neither script uses the core.
- **JCS:** the third-party `rfc8785` package, pinned in `requirements.txt`; the version used is in the file's `generator` block. SHA-256 from `hashlib`.
- **Expected definitions** (including the XDF one) are written by hand as JSON literals in `generate.py`, never produced by an importer. Conversion results use `fractions.Fraction` and `struct` with explicit byte order, plus hand-asserted spot values.
- **Cross-check:** `crosscheck.py` is a second, stdlib-only implementation with a different method: its own JCS serializer (keys sorted by UTF-16 code units, ES6 string escaping), its own rational type, bit-level float decoding, float encoding by binary search over binary32 bit patterns, its own XDF parser (`xml.parsers.expat`) implementing §7, the XDF exporter of R77, and its own `span` (R30) with pointer resolution. It recomputes every expected value and exits non-zero on any disagreement.
- **Run:** `python -I generate.py > vectors.json`, then `python -I crosscheck.py vectors.json`. A tamper test edits one expected value and requires `crosscheck.py` to exit 1.
- Vectors are test data, not spec objects: a vector field that is not a SPEC-003 object (for example the A2L `COEFFS` integers of A2a–A2d) MAY hold negative JSON integers; R2 applies only to the objects of §3.

| Vector | Rules | Checks |
|---|---|---|
| Q1–Q16 | R3, R74, R91 | XDF decimal, A2L number and canonical rational text; `bad_number`, `bad_rational` |
| C1–C16 | R6, R7, R12 | raw decoding per dtype and byte order, two's complement, binary32 incl. subnormal, `-0`, infinity and NaN → `non_finite` |
| E1–E19 | R13, R14, R15 | physical → raw, ties to even (integer, binary32 normal and subnormal), negative factor, `out_of_range`, binary32 overflow boundary, negative value rounding to `+0`, unchanged cell keeps `-0` (identity scaling, E13, and non-identity scaling compared in physical units, E19); R14 raw → physical → raw identity on each integer result |
| U1–U7 | R16, R17 | unit aliases with factor; pressure without alias; case-sensitive match; alias not applied when the result would not be XDF-exportable (U7) |
| A1a–A1j, A2a–A2d | R90, R99 | A2L `COMPU_METHOD` → scaling, including `RAT_FUNC` direction; rejections; export coefficients and their re-import |
| M1, M2 | R26–R28, R51 | `mapdef_hash`, derived `map_id` |
| D1–D3 | R20, R21, R23, R34–R38, R51, R52 | `definition_hash` and `axisdef_hash` with inline, pointer, shared and fixed axes, `y_fastest` and a non-ASCII name; input order independence; a state change changes the hash |
| S2 | R30, R55 | a pointer axis whose `target_memory_id` is absent from the dump → `unknown_memory` |
| S1 | R22, R30 | `span` of each D1 map against a synthetic two-memory dump: cells, inline, shared and fixed axes, pointer cell and resolved pointer target, sorted and merged |
| X1 | R61–R64, R70–R77, R79 | synthetic XDF → `ImportResult` (definition, rejected, ignored), `definition_hash`; exported bytes; re-import hash |
| XE1 | R64, R76, R77 | export of a definition already in import-normal form: `XDFCONSTANT` for a `1 × 1` map without axes, `XDFTABLE` for a `1 × 1` map with an axis, factor 1 with a non-zero addend (`X-40`, `X+0.5`); re-import gives the same `definition_hash` |
| XN1 | R64, R75–R77 | export of a platform-form definition (non-derived `map_id`, `reviewed`/`golden`, categories, its own family and origin); re-import equals the hand-written `normalize(e, P)` |
| XU1–XU7 | R76 | export rejected, `unrepresentable`, with fields `axes.x` / `axes.y` (missing axis on a dimension > 1), `memory_id`, `scaling.factor`, `scaling.addend`, `axes.x.values`, `axes.x.axis_source` |
| X2–X15 | R61, R70, R72–R74, R80 | XDF rejections (`xml_forbidden`, `unsupported_stride`, `unsupported_equation`, `unsupported_baseoffset`, `unverified_defaults`, `dims_mismatch`, `ambiguous_label_scaling`, `unsupported_typeflags`, `unsupported_equation` for a decimal divisor (X15), `missing_element` for a `MATH` without `equation` and an axis without `indexcount`, `non_numeric_label` for `+1`, `bad_number` for an address padded with U+00A0); X12 accepts a label value with surrounding whitespace |

Not covered by vectors, so they need dedicated tests: R1, R2, R4, R5 (shape errors, including the R17 `non_canonical` unit encodings), R8 `y_fastest` decoding, R14 beyond the E spot checks (property tests), R22 errors (`unknown_base_address`, `out_of_memory`), R29, R41 (transition table), R42 (gate contract, SPEC-004), R43, R45 (taint), R55–R59 (bind and encode against a `Dump`), R60, R65 (fuzz), R92–R98 (A2L files, after question 4), R120–R122. Vectors are test data, not golden files; they need no `oracle:` record.

## 11. Compatibility

Changing a shape of §3, a conversion rule (R7, R12–R15), the unit factors of R16, the hash definitions (§4), the converter mappings of §7 and §8, or an error reason is breaking: it changes decoded values or hashes, so it requires a SPEC-003 revision in a `foundation-change` PR, a new `spec` value (R38) when the shape changes, and a **major** version of `core` (SPEC-000 §Core engineering practices, Versioning). Adding a unit, a category, an alias, an error reason, a newly supported format construct (moving it out of "rejected") or confirming a **P** row is minor. Vectors change only together with the rule they test.

## 12. Open questions

1. **XDF oracle (blocks R66 for XDF).** Confirm every **P** row of §7 with TunerPro itself (free, Windows): author a synthetic bin and XDF with each combination of signed, LSB-first and float, strides and `BASEOFFSET`, and record the `mmedtypeflags` and values TunerPro writes and shows; open R77 exports and check they load unchanged. This is a Phase −1-sized task and needs no ECU.
2. **XDF encodings.** Whether real XDF files use encodings other than UTF-8 (`°` in units suggests Latin-1 or Windows-1252 may occur). R80 rejects them for now.
3. **`DEFAULTS` precedence.** Whether `XDFHEADER/DEFAULTS` applies when `EMBEDDEDDATA` omits `mmedtypeflags` or `mmedelementsizebits`. R70 sidesteps it by requiring zero defaults.
4. **A2L standard text (blocks R66 for A2L and the A2L implementation).** Obtain ASAM MCD-2 MC 1.7.x to confirm: tokenizer rules, `ROW_DIR`/`COLUMN_DIR` versus x/y, `STD_AXIS` record layouts and alignment, the default byte order and deposit, `FIX_AXIS_PAR*` internal-vs-physical semantics, `NO_COMPU_METHOD`, and a complete export template (R99). Buying the standard has a cost (SPEC-000 zero-cost MVP); A2L is Phase 1 (SPEC-000 §Gaps and adopted improvements), so this can wait.
5. **Copyright policy conflict (decision for Luiz).** SPEC-000 §Gaps (line 352, "Decided") keeps unlicensed definitions private to the importing tenant; SPEC-000 §Regulatory compliance (line 665) says definitions without verifiable licensing "are not hosted, only referenced locally by the customer". R45 implements the stricter line 665 (`local_only`), fail-closed. If Luiz and a lawyer settle on line 352, R45 gains a `tenant_private` value (a minor change); the shapes do not change. SPEC-000 should be aligned to whichever reading wins.
6. **Axis source vocabulary.** R20's reading of `inline`, `pointer`, `shared` and the added `fixed` is an interpretation of SPEC-000 §Modeling decisions, which gives only the three words.
7. **Layering (resolved in the same foundation change).** SPEC-000 §Four layers now orders `kernel → provenance → definitions → plugins → gate → conformance`: `definitions` imports `kernel` (Patch, Dump) and the JCS helper, and the gate imports `definitions` (SPEC-004 R81). The import-linter contracts follow that order.
8. **Sign convention of `deg_crank` (blocks publication of the SPEC-004 seed table).** "Positive = before TDC" (R16) is a convention chosen here; SPEC-000 does not state it. The SPEC-004 seed ignition rules (−10 to 45, cap 30) are keyed on `deg_crank` and depend on this sign, so the seed table MUST NOT be published until a source confirms the convention or Luiz decides it.
9. **Decoded values of an unreleased version.** The editor needs the physical values of `apply(o, v)`, but SPEC-001 R7 hides the bytes of an `UnverifiedImage` and R8 lets only the gate call `view`. Options: `decode` overlays patch `after` bytes on the original `Dump` itself (pure, but duplicates part of `apply`), or SPEC-001 grants `core.definitions` access to `view`. Either is a SPEC-001 or SPEC-000 decision.
10. **Limits.** Maximum input size for importers, maximum maps per definition and the 65535 dimension bound (R26) are provisional until measured on real XDF/A2L files in the private corpus.

## 13. Sources

Fetched 2026-10-18. Commit hashes pin the exact code read.
- [X1] willemml/xdftuneparser-rs, commit `3b0e76a966a4d7e55f26a4bbda8470d6a3836d41`, `src/data_types.rs`, `src/parser.rs`: https://github.com/willemml/xdftuneparser-rs
- [X2] KingAiCodeForge/TunerPro-XDF-BIN-Universal-Exporter, commit `85a02600a288c1861cda8e772bdd6e7a081be955`, `tunerpro_exporter.py` (`_parse_embedded_data`, BASEOFFSET handling), `tunerpro_xdf/xdf_values.py` (`FLOAT_FLAG = 0x10000`), `tunerpro_xdf/xdf_addressing.py`: https://github.com/KingAiCodeForge/TunerPro-XDF-BIN-Universal-Exporter
- [X3] whalenlg/xdf_parser, commit `e6e770baf1fa51eb8c9a6bfa1d6e9c0ac76deb2a`, `xdf_merge.py` (`_extract_embedded`, `_extract_base_offset`, `_extract_defaults`): https://github.com/whalenlg/xdf_parser
- [X4] TunerPro help, "Editing Tables" (V1.2, 2009), Wayback snapshot 20251104141041 of https://www.tunerpro.net/WebHelp/source/Tables.htm. User documentation only; https://www.tunerpro.net/WebHelp/source/XDFHeader.htm returned HTTP 403.
- [A1] ASAM e.V., ASAM MCD-2 MC wiki: https://www.asam.net/standards/detail/mcd-2-mc/wiki/
- [A2] DanielT/a2lfile, commit `3fd5ed62e69412169e4c2d2422447a3008189b37`, `a2lfile/src/specification_orig.rs` (block and enum definitions), `a2lfile/src/tokenizer.rs`: https://github.com/DanielT/a2lfile
- [A3] christoph2/pyA2L, commit `bb5613485244b2c30408b57db6a9a7792f1f3745`, `pya2l/functions.py` (`RatFunc`, `Linear`), `pya2l/api/inspect.py` (`NoModCommon`, `fnc_np_order`, `fnc_np_shape`): https://github.com/christoph2/pyA2L
- [A4] CSS Electronics, "A2L File Explained (XCP on CAN)": https://www.csselectronics.com/pages/a2l-file-asap2-intro-xcp-on-can-bus
