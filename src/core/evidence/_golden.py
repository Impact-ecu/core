"""Golden records and the `golden_field` evaluation (SPEC-006 §7.1, §7.2, R70-R80).

The level is never stored: it is computed against the registry it is given, so a revocation cannot leave a stale
level behind (decision D12). Classification outcomes are data; only preconditions raise (R80).
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from core.evidence._attestation import parse_attestation, verify_attestation
from core.evidence._errors import EvidenceError, ensure
from core.evidence._json import (
    DAY,
    FAMILY,
    HEX32,
    TOOL_NAME,
    VARIANT,
    digest,
    exact,
    increasing,
    listing,
    matches,
    sha256_hex,
    strings,
    text,
    try_jcs,
)
from core.evidence._published import PUBLISHED_DTC_SETS, E, K, N
from core.evidence._registry import AttesterRegistry
from core.provenance import Raw, Verifier

RECORD_SCHEMA = "impact.golden-record.v1"
EVALUATION_SCHEMA = "impact.golden-evaluation.v1"
RECORD_KEYS = frozenset(
    {"schema", "family", "checksum_variant_id", "base_image_hash", "version_hash", "expected_image_hash", "oracle"}
)
ORACLE_KEYS = frozenset({"tools", "attestations"})
TOOL_KEYS = frozenset({"name", "version", "image_hash", "date"})
# R73 stage 3: the reasons that make an entry negative (R74).
OUTCOME_REASONS = frozenset({"no_communication", "disqualifying_dtc", "tool_checksum_mismatch", "readback_mismatch"})
FIELD_BLOCKERS = frozenset({"below_attestations", "below_attesters", "below_units", "negative_field_evidence"})

Level = Literal["golden_field", "golden_concordant", "candidate", "none"]


@dataclass(frozen=True, slots=True)
class OracleTool:
    name: str
    version: str
    image_hash: str
    date: str


@dataclass(frozen=True, slots=True)
class GoldenRecord:
    """R70, built only by `parse_golden_record`."""

    family: str
    checksum_variant_id: str
    base_image_hash: str
    version_hash: str
    expected_image_hash: str
    tools: tuple[OracleTool, ...]
    attestations: tuple[str, ...]

    def to_json(self) -> Mapping[str, Raw]:
        tools = [{"name": t.name, "version": t.version, "image_hash": t.image_hash, "date": t.date} for t in self.tools]
        return {
            "schema": RECORD_SCHEMA,
            "family": self.family,
            "checksum_variant_id": self.checksum_variant_id,
            "base_image_hash": self.base_image_hash,
            "version_hash": self.version_hash,
            "expected_image_hash": self.expected_image_hash,
            "oracle": {"tools": tools, "attestations": list(self.attestations)},
        }

    @property
    def golden_record_hash(self) -> str:
        return digest(self.to_json())

    @property
    def key(self) -> tuple[str, str, str, str]:
        """R70: one record per `(family, checksum_variant_id, base_image_hash, version_hash)`."""
        return self.family, self.checksum_variant_id, self.base_image_hash, self.version_hash


def _tool_ok(value: Raw) -> bool:
    return (
        exact(value, TOOL_KEYS)
        and matches(value["name"], TOOL_NAME)
        and text(value["version"])
        and matches(value["image_hash"], HEX32)
        and matches(value["date"], DAY)
    )


def _tools(value: Raw) -> tuple[OracleTool, ...] | None:
    if not listing(value) or not all(_tool_ok(tool) for tool in value):
        return None
    tools = tuple(
        OracleTool(
            str(_get(tool, "name")), str(_get(tool, "version")), str(_get(tool, "image_hash")), str(_get(tool, "date"))
        )
        for tool in value
    )
    return tools if increasing([(tool.name, tool.version) for tool in tools]) else None


def _get(value: Raw, key: str) -> Raw:
    return value.get(key) if isinstance(value, Mapping) else None


def parse_golden_record(value: Raw) -> GoldenRecord:
    """R70: `bad_shape` for any other shape; `impact_oracle` for a tool named after this project."""
    oracle = _get(value, "oracle")
    tools = _tools(_get(oracle, "tools"))
    attestations = _get(oracle, "attestations")
    if not (
        exact(value, RECORD_KEYS)
        and value["schema"] == RECORD_SCHEMA
        and matches(value["family"], FAMILY)
        and matches(value["checksum_variant_id"], VARIANT)
        and all(matches(value[key], HEX32) for key in ("base_image_hash", "version_hash", "expected_image_hash"))
        and exact(oracle, ORACLE_KEYS)
        and tools is not None
        and strings(attestations, HEX32)
    ):
        raise EvidenceError("bad_shape", "not a GoldenRecord (SPEC-006 R70)")
    if any(_impact(tool.name) for tool in tools):
        raise EvidenceError("impact_oracle", "no golden hash comes from this project's code (SPEC-006 R70)")
    return GoldenRecord(
        family=str(value["family"]),
        checksum_variant_id=str(value["checksum_variant_id"]),
        base_image_hash=str(value["base_image_hash"]),
        version_hash=str(value["version_hash"]),
        expected_image_hash=str(value["expected_image_hash"]),
        tools=tools,
        attestations=tuple(attestations),
    )


def _impact(name: str) -> bool:
    # R70, R73, R87: "starts with `impact` in any letter case"; names are ASCII (R3).
    return name.lower().startswith("impact")


@dataclass(frozen=True, slots=True)
class AttestationEntry:
    attestation_hash: str
    qualifying: bool
    negative: bool
    reasons: tuple[str, ...]

    def to_json(self) -> Mapping[str, Raw]:
        return {
            "attestation_hash": self.attestation_hash,
            "qualifying": self.qualifying,
            "negative": self.negative,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True, slots=True)
class Counts:
    attestations: int
    attesters: int
    units: int


@dataclass(frozen=True, slots=True)
class GoldenEvaluation:
    """R78. Never a boolean."""

    golden_record_hash: str
    registry_hash: str
    dtc_set_hash: str
    commitment_epoch: str
    counts: Counts
    attestations: tuple[AttestationEntry, ...]
    reasons: tuple[str, ...]
    level: Level

    def to_json(self) -> Mapping[str, Raw]:
        return {
            "schema": EVALUATION_SCHEMA,
            "golden_record_hash": self.golden_record_hash,
            "registry_hash": self.registry_hash,
            "dtc_set_hash": self.dtc_set_hash,
            "commitment_epoch": self.commitment_epoch,
            "thresholds": {"attestations": N, "attesters": K, "units": E},
            "counts": {
                "attestations": self.counts.attestations,
                "attesters": self.counts.attesters,
                "units": self.counts.units,
            },
            "attestations": [entry.to_json() for entry in self.attestations],
            "reasons": list(self.reasons),
            "level": self.level,
        }

    @property
    def evaluation_hash(self) -> str:
        return digest(self.to_json())


@dataclass(frozen=True, slots=True)
class _Context:
    record: GoldenRecord
    registry: AttesterRegistry
    codes: frozenset[str]
    epoch: str
    verifier: Verifier


@dataclass(frozen=True, slots=True)
class _Classified:
    entry: AttestationEntry
    identity: str | None
    unit: str | None


def _order(candidate: Raw) -> tuple[int, bytes]:
    # R73 "first in code-point order of their JCS": UTF-8 byte order is code-point order. A candidate without a
    # JCS form is malformed, so whichever of those is chosen it fails as `bad_shape`.
    encoded = try_jcs(candidate)
    return (0, encoded) if encoded is not None else (1, b"")


def _choose(attestation_hash: str, supplied: Sequence[Raw]) -> Raw:
    """R73: collapse the supplied attestations claiming `attestation_hash` to one, independently of input order.

    Among several whose recomputed hash matches (one attestation, different signatures) the same JCS order decides.
    """
    candidates = [entry for entry in supplied if _get(entry, "attestation_hash") == attestation_hash]
    matching = [entry for entry in candidates if _recomputed(_get(entry, "attestation")) == attestation_hash]
    return min(matching or candidates, key=_order, default=None)


def _recomputed(attestation: Raw) -> str | None:
    encoded = try_jcs(attestation)
    return None if encoded is None else sha256_hex(encoded)


def _classify(attestation_hash: str, chosen: Raw, context: _Context) -> _Classified:
    """R73: the reasons of the first of the four stages that has any."""
    if chosen is None:
        return _Classified(AttestationEntry(attestation_hash, False, False, ("missing",)), None, None)
    authenticity = verify_attestation(chosen, context.registry, context.verifier)
    if authenticity:
        return _Classified(AttestationEntry(attestation_hash, False, False, tuple(authenticity)), None, None)
    attestation = parse_attestation(_get(chosen, "attestation"))
    record = context.record
    relevance = [
        reason
        for reason, applies in (
            (
                "wrong_variant",
                (attestation.family, attestation.checksum_variant_id) != (record.family, record.checksum_variant_id),
            ),
            ("wrong_subject", attestation.subject_image_hash != record.expected_image_hash),
            (
                "foreign_epoch",
                attestation.ecu_commitment_epoch is not None and attestation.ecu_commitment_epoch != context.epoch,
            ),
            ("impact_write_tool", _impact(attestation.write_tool_name)),
        )
        if applies
    ]
    if relevance:
        return _Classified(AttestationEntry(attestation_hash, False, False, tuple(sorted(relevance))), None, None)
    outcome = [
        reason
        for reason, applies in (
            ("no_communication", not attestation.communicates),
            ("disqualifying_dtc", any(code[:5] in context.codes for code in attestation.dtcs_after_clear_and_reread)),
            ("tool_checksum_mismatch", attestation.tool_checksum_status == "mismatch"),
            (
                "readback_mismatch",
                attestation.readback_image_hash is not None
                and attestation.readback_image_hash != attestation.subject_image_hash,
            ),
        )
        if applies
    ]
    if outcome:
        return _Classified(AttestationEntry(attestation_hash, False, True, tuple(sorted(outcome))), None, None)
    if attestation.ecu_commitment is None:
        return _Classified(AttestationEntry(attestation_hash, False, False, ("no_unit_commitment",)), None, None)
    entry = context.registry.attester(attestation.attester_key_id)
    identity = None if entry is None else entry.identity
    return _Classified(AttestationEntry(attestation_hash, True, False, ()), identity, attestation.ecu_commitment)


def _level(reasons: set[str], record: GoldenRecord) -> Level:
    """R76: tools never raise a level to `golden_field` and never lower it from there."""
    matching = {tool.name for tool in record.tools if tool.image_hash == record.expected_image_hash}
    if not reasons & FIELD_BLOCKERS:
        return "golden_field"
    if len(matching) >= 2 and "tool_disagreement" not in reasons:
        return "golden_concordant"
    if matching:
        return "candidate"
    return "none"


def _published_codes(dtc_set: Raw) -> tuple[str, frozenset[str]]:
    """R57: the hash and codes of a published set, else `unpublished_dtc_set`."""
    encoded = try_jcs(dtc_set)
    dtc_set_hash = None if encoded is None else sha256_hex(encoded)
    if dtc_set_hash is None or dtc_set_hash not in PUBLISHED_DTC_SETS:
        raise EvidenceError("unpublished_dtc_set", "the evaluation refuses any set it does not publish")
    codes = _get(dtc_set, "codes")
    return dtc_set_hash, frozenset(code for code in codes if isinstance(code, str)) if listing(codes) else frozenset()


def evaluate(
    record: GoldenRecord,
    attestations: Sequence[Raw],
    registry: AttesterRegistry,
    dtc_set: Raw,
    epoch: str,
    verifier: Verifier,
) -> GoldenEvaluation:
    """R72-R78 for a parsed record."""
    if not listing(attestations) or not matches(epoch, HEX32):
        raise EvidenceError("bad_shape", "attestations is a list and commitment_epoch a Hex32 (SPEC-006 R72)")
    dtc_set_hash, codes = _published_codes(dtc_set)
    context = _Context(record, registry, codes, epoch, verifier)
    classified = [_classify(h, _choose(h, attestations), context) for h in record.attestations]
    entries = tuple(item.entry for item in classified)
    for entry in entries:
        ensure(entry.qualifying == (not entry.reasons), "SPEC-006 R73")
        ensure(not entry.negative or set(entry.reasons) <= OUTCOME_REASONS, "SPEC-006 R73")
    qualifying = [item for item in classified if item.entry.qualifying]
    counts = Counts(
        attestations=len(qualifying),
        attesters=len({item.identity for item in qualifying}),
        units=len({item.unit for item in qualifying}),
    )
    reasons = {
        reason
        for reason, applies in (
            ("below_attestations", counts.attestations < N),
            ("below_attesters", counts.attesters < K),
            ("below_units", counts.units < E),
            ("negative_field_evidence", any(entry.negative for entry in entries)),
            ("tool_disagreement", any(tool.image_hash != record.expected_image_hash for tool in record.tools)),
        )
        if applies
    }
    level = _level(reasons, record)
    # R75 with N = K = E = 2: two qualifying entries that differ in both identity and unit, and no negative (R74).
    distinct_pair = any(a.identity != b.identity and a.unit != b.unit for a in qualifying for b in qualifying)
    ensure(
        (level == "golden_field") == (distinct_pair and not any(entry.negative for entry in entries)), "SPEC-006 R75"
    )
    return GoldenEvaluation(
        golden_record_hash=record.golden_record_hash,
        registry_hash=registry.registry_hash,
        dtc_set_hash=dtc_set_hash,
        commitment_epoch=epoch,
        counts=counts,
        attestations=entries,
        reasons=tuple(sorted(reasons)),
        level=level,
    )


def evaluate_golden(
    record: Raw,
    attestations: Sequence[Raw],
    registry: AttesterRegistry,
    dtc_set: Raw,
    commitment_epoch: str,
    verifier: Verifier,
) -> GoldenEvaluation:
    """R72: pure and deterministic; input order and duplicates never change the output."""
    return evaluate(parse_golden_record(record), attestations, registry, dtc_set, commitment_epoch, verifier)
