# Impact · core

Trusted core of the Impact ECU verification and recalibration platform: binary kernel (`apply`/`release`, immutable patches, diff), per-ECU-family plugin contract, verification gate and provenance. Pure Python library: no I/O, no network, no framework.

- Architecture and decisions: [`specs/SPEC-000-adr.md`](specs/SPEC-000-adr.md)
- License: AGPL-3.0
- Status: Phase −1 (discovery) in parallel with the family-agnostic core. SPEC-001 to SPEC-005 are written; kernel code is in progress. Family plugins and golden files wait for the Phase −1 exit criteria.

