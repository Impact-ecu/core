"""The customer report (SPEC-005 §8): sections derived only from named inputs (R62, R63), signed binding (R61)."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from core.kernel import KernelError, MemoryLayout, Patch, canonical_order, diff
from core.provenance._errors import RecordError, ReportBindingError, ShapeError
from core.provenance._events import Draft, Event, EventMeta, append, event_hash, parse_event
from core.provenance._json import (
    HEX32_CHECK,
    ID_CHECK,
    VERIFY_STATUSES,
    Json,
    Raw,
    anything,
    array,
    as_mapping,
    as_str,
    child,
    hash_json,
    items,
    member,
    nullable,
    obj,
    one_of,
    strings,
    text,
    to_json,
    try_hash,
    uint,
)
from core.provenance._records import (
    FOREIGN,
    AuditInputs,
    AuditRecord,
    ExportInputs,
    ExportProvenance,
    region_name,
)
from core.provenance._signing import REPORT_DOMAIN, Signer, Verifier, key_id_of, sign, verified

REPORT_SCHEMA = "impact.report.v1"
# R63: the fixed text of the gate disclaimer.
DISCLAIMER = (
    "This gate verifies file integrity and cell-by-cell plausibility. "
    "It does not verify the combination between maps, firmware behavior, or the real engine."
)
NOT_VERIFIED_CODES = (
    "best_effort_build",
    "firmware_behavior",
    "map_interaction",
    "physical_range_unreviewed",
    "real_engine",
    "signature_unverifiable",
)
NOTICE_CODES = ("emissions_and_regulation", "input_verify_failed_acknowledged", "origin_not_evidence")
NOT_EVIDENCE = frozenset({"virtual_read", "file_service"})
GREEN = frozenset({"ok", "signature_unverifiable"})

ReportKind = Literal["export", "audit"]


def _is_object(value: Raw) -> bool:
    return isinstance(value, Mapping)


PATCH_LINE = obj(
    {"memory_id": text, "offset": uint, "length": uint, "region_name": region_name, "map_id": nullable(text)}
)
REPORT_SHAPE = obj(
    {
        "schema": one_of(REPORT_SCHEMA),
        "kind": one_of("export", "audit"),
        "tenant_id": ID_CHECK,
        "genesis_hash": HEX32_CHECK,
        "record": _is_object,
        "record_hash": HEX32_CHECK,
        "signer": obj({"key_id": HEX32_CHECK, "public_key": HEX32_CHECK}),
        "sections": obj(
            {
                "what_changed": obj({"patches": array(PATCH_LINE), "foreign": array(FOREIGN)}),
                "integrity": obj(
                    {
                        "input_verify": one_of(*VERIFY_STATUSES),
                        "input_result": one_of("ok", "failed_acknowledged"),
                        "candidate_verify": nullable(one_of(*VERIFY_STATUSES)),
                        "verdict": nullable(one_of("no findings", "warn")),
                        "reproducibility": one_of("full", "best_effort"),
                        "checksum_patch_count": uint,
                    }
                ),
                "not_verified": array(one_of(*NOT_VERIFIED_CODES), sorted_unique=True),
            }
        ),
        "notices": array(one_of(*NOTICE_CODES), sorted_unique=True),
        "disclaimer": one_of(DISCLAIMER),
    }
)


@dataclass(frozen=True, slots=True)
class Report:
    """SPEC-005 §8 as validated, frozen JSON; the record is validated as its `kind` (R3)."""

    value: Mapping[str, Json]

    def __post_init__(self) -> None:
        if not REPORT_SHAPE(self.value):
            raise ShapeError("bad_shape", "Report")
        frozen = as_mapping(to_json(self.value))
        record = as_mapping(child(frozen, "record"))
        if child(frozen, "kind") == "export":
            ExportProvenance(record)
        else:
            AuditRecord(record)
        object.__setattr__(self, "value", frozen)

    @property
    def report_hash(self) -> str:
        """R60."""
        return hash_json(self.value)

    @property
    def kind(self) -> ReportKind:
        return "export" if child(self.value, "kind") == "export" else "audit"


@dataclass(frozen=True, slots=True)
class ReportContext:
    """Who issues the report: the tenant, the signer's chain (R32) and the signer's public key."""

    tenant_id: str
    genesis_hash: str
    signer_public_key: str


def _region_of(layout: MemoryLayout, patch: Patch) -> str:
    names = [
        region.name
        for memory in layout.memories
        if memory.memory_id == patch.memory_id
        for region in memory.regions
        if region.start <= patch.offset < region.end
    ]
    return names[0] if names else ""


def _patch_lines(patches: Sequence[Patch], layout: MemoryLayout, map_ids: Mapping[str, str | None]) -> list[Json]:
    """`what_changed.patches`: `region_name` and `map_id` are display metadata (SPEC-001 §2.3)."""
    return [
        {
            "memory_id": patch.memory_id,
            "offset": patch.offset,
            "length": patch.length,
            "region_name": _region_of(layout, patch),
            "map_id": map_ids.get(patch.patch_hash),
        }
        for patch in patches
    ]


def _not_verified(gate_report: Raw, reproducibility: Raw) -> list[str]:
    """R63 `not_verified`, from the gate report and the record only."""
    codes = {"map_interaction", "firmware_behavior", "real_engine"}
    if any(member(finding, "rule_id") == "G-UNREVIEWED" for finding in items(member(gate_report, "findings"))):
        codes.add("physical_range_unreviewed")
    if items(member(member(gate_report, "subject"), "signed_regions")):
        codes.add("signature_unverifiable")
    if reproducibility == "best_effort":
        codes.add("best_effort_build")
    return sorted(codes)


def _require(holds: bool, detail: str) -> None:
    if not holds:
        raise RecordError("inconsistent_record", detail)


def _report(
    context: ReportContext,
    record: ExportProvenance | AuditRecord,
    *,
    sections: Mapping[str, Json],
    notices: set[str],
) -> Report:
    if not HEX32_CHECK(context.signer_public_key):
        raise ShapeError("bad_shape", "signer public_key must be 32 bytes in lowercase hex")
    export = isinstance(record, ExportProvenance)
    return Report(
        {
            "schema": REPORT_SCHEMA,
            "kind": "export" if export else "audit",
            "tenant_id": context.tenant_id,
            "genesis_hash": context.genesis_hash,
            "record": record.value,
            "record_hash": hash_json(record.value),
            "signer": {"key_id": key_id_of(context.signer_public_key), "public_key": context.signer_public_key},
            "sections": sections,
            "notices": sorted(notices),
            "disclaimer": DISCLAIMER,
        }
    )


def export_report(
    context: ReportContext,
    inputs: ExportInputs,
    record: ExportProvenance,
    *,
    map_ids: Mapping[str, str | None],
    import_event: Event,
) -> Report:
    """R62, R63 for an export: from the record, the version and its metadata (`map_ids` by patch hash), the
    output gate report and the original's `import` event (its `origin`)."""
    value = record.value
    try:
        order = canonical_order(inputs.version)
    except KernelError as error:
        raise RecordError("inconsistent_record", error.reason) from error
    _require(strings(child(value, "patch_hashes")) == [p.patch_hash for p in order], "version is not the record's")
    _require(try_hash(inputs.gate_report) == child(value, "gate_report_hash"), "gate report is not the record's")
    _require(
        import_event.type == "import"
        and child(import_event.payload, "image_hash") == child(value, "image_hash_original"),
        "import event is not the original's",
    )
    input_verify = child(value, "input_verify")
    notices = {"emissions_and_regulation"}
    if child(input_verify, "result") == "failed_acknowledged":
        notices.add("input_verify_failed_acknowledged")
    if child(import_event.payload, "origin") in NOT_EVIDENCE:
        notices.add("origin_not_evidence")
    sections: dict[str, Json] = {
        "what_changed": {"patches": _patch_lines(order, inputs.layout, map_ids), "foreign": []},
        "integrity": {
            "input_verify": child(input_verify, "status"),
            "input_result": child(input_verify, "result"),
            "candidate_verify": None,
            "verdict": child(value, "verdict"),
            "reproducibility": child(value, "reproducibility"),
            "checksum_patch_count": len(items(child(value, "checksum_patch_hashes"))),
        },
        "not_verified": list[Json](_not_verified(inputs.gate_report, child(value, "reproducibility"))),
    }
    return _report(context, record, sections=sections, notices=notices)


def audit_report(
    context: ReportContext, inputs: AuditInputs, record: AuditRecord, *, map_ids: Mapping[str, str | None]
) -> Report:
    """R62, R63 for an audit: from the record, the diff it was built from and the input gate report on the
    candidate. `input_result` is `ok` for a green original verify (`ok`, `signature_unverifiable`), else
    `failed_acknowledged`: an audit has no ack event, and §8 derives it from `verify.original`."""
    value = record.value
    try:
        result = diff(inputs.original, inputs.candidate, inputs.layout)
    except KernelError as error:
        raise RecordError("inconsistent_record", error.reason) from error
    patches = list(result.patches)
    _require(strings(child(value, "diff_patch_hashes")) == [p.patch_hash for p in patches], "diff is not the record's")
    _require(try_hash(inputs.gate_report) == child(value, "gate_report_hash"), "gate report is not the record's")
    verify = child(value, "verify")
    notices = {"emissions_and_regulation"}
    if child(value, "candidate_origin") in NOT_EVIDENCE:
        notices.add("origin_not_evidence")
    sections: dict[str, Json] = {
        "what_changed": {
            "patches": _patch_lines(patches, inputs.layout, map_ids),
            "foreign": child(value, "foreign"),
        },
        "integrity": {
            "input_verify": child(verify, "original"),
            "input_result": "ok" if child(verify, "original") in GREEN else "failed_acknowledged",
            "candidate_verify": child(verify, "candidate"),
            "verdict": None,
            "reproducibility": child(value, "reproducibility"),
            "checksum_patch_count": 0,
        },
        "not_verified": list[Json](_not_verified(inputs.gate_report, child(value, "reproducibility"))),
    }
    return _report(context, record, sections=sections, notices=notices)


def _record_field(kind: ReportKind) -> str:
    return "provenance_hash" if kind == "export" else "audit_hash"


@dataclass(frozen=True, slots=True)
class ReportFile:
    """R60: the authoritative JSON report; `event` is the `export` or `audit` event that signs it."""

    report: Report
    report_hash: str
    event: Event

    def to_json(self) -> Mapping[str, Json]:
        return {"report": self.report.value, "report_hash": self.report_hash, "event": self.event.to_json()}


def issue_report(report: Report, *, head: Event, meta: EventMeta, signer: Signer) -> ReportFile:
    """Sign `report_hash` (R51) and append the `export` or `audit` event carrying the signature (R36, R60)."""
    if signer.key_id != child(child(report.value, "signer"), "key_id"):
        raise ReportBindingError(("key_id_mismatch",))
    if head.tenant_id != child(report.value, "tenant_id"):
        raise ReportBindingError(("event_mismatch",))
    report_hash = report.report_hash
    payload: dict[str, Json] = {
        _record_field(report.kind): child(report.value, "record_hash"),
        "report_hash": report_hash,
        "key_id": signer.key_id,
        "signature": sign(signer, REPORT_DOMAIN, report_hash),
    }
    return ReportFile(report, report_hash, append(head, Draft(meta, report.kind, payload)))


REPORT_FILE_SHAPE = obj({"report": _is_object, "report_hash": HEX32_CHECK, "event": anything})


def check_report_file(value: Raw, verifier: Verifier) -> ReportFile:
    """R61 integrity; every failed check is in `ReportBindingError.reasons`. Origin needs `verify_chain` (R61)."""
    if not REPORT_FILE_SHAPE(value):
        raise ShapeError("bad_shape", "ReportFile")
    report = Report(as_mapping(to_json(member(value, "report"))))
    event = parse_event(member(value, "event"))
    report_hash = as_str(member(value, "report_hash"))
    signer = child(report.value, "signer")
    public_key, key_id = as_str(child(signer, "public_key")), child(signer, "key_id")
    record_hash = child(report.value, "record_hash")
    payload = event.payload
    reasons: list[str] = []
    if report.report_hash != report_hash:
        reasons.append("report_hash_mismatch")
    if hash_json(child(report.value, "record")) != record_hash:
        reasons.append("record_hash_mismatch")
    if key_id_of(public_key) != key_id:
        reasons.append("key_id_mismatch")
    if (
        event_hash(event.to_json()) != event.hash
        or event.type != report.kind
        or event.tenant_id != child(report.value, "tenant_id")
        or child(payload, "report_hash") != report_hash
        or child(payload, _record_field(report.kind)) != record_hash
        or child(payload, "key_id") != key_id
    ):
        reasons.append("event_mismatch")
    signature = child(payload, "signature")
    if not verified(verifier, public_key, REPORT_DOMAIN, report_hash, as_str(signature)):
        reasons.append("bad_signature")
    if reasons:
        raise ReportBindingError(tuple(sorted(reasons)))
    return ReportFile(report, report_hash, event)
