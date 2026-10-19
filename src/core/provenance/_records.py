"""`ExportProvenance` (SPEC-005 §3) and `AuditRecord` (§4): built by the core, never from caller hashes (R10, R20)."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from itertools import pairwise
from typing import Literal

from core.kernel import (
    Dump,
    KernelError,
    MemoryLayout,
    Patch,
    Version,
    apply,
    apply_checksum_patches,
    canonical_order,
    diff,
    image_hash,
    layout_hash,
    version_hash,
)
from core.provenance._errors import RecordError, ShapeError
from core.provenance._events import Event, event_hash
from core.provenance._json import (
    DIGEST,
    DUMP_KINDS,
    EVENT_REF_CHECK,
    HEX32_CHECK,
    ORIGINS,
    VERIFY_STATUSES,
    Check,
    Json,
    Raw,
    array,
    as_mapping,
    as_str,
    encodable,
    hash_json,
    items,
    matches,
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
from core.provenance._runtime import python_info

EXPORT_SCHEMA = "impact.export-provenance.v1"
AUDIT_SCHEMA = "impact.audit-record.v1"

BuildKind = Literal["image", "lockfile"]


_HASHES = array(HEX32_CHECK)


def _pair(value: Raw) -> bool:
    return _HASHES(value) and len(items(value)) == 2


def _sorted_pairs(value: Raw) -> bool:
    """`overlaps`: pairs of hashes, sorted and unique as in SPEC-001 R64."""
    return array(_pair)(value) and all(a < b for a, b in pairwise(tuple(strings(p)) for p in items(value)))


def region_name(value: Raw) -> bool:
    """A region name: any string without lone surrogates, empty included (SPEC-001 §2.2)."""
    return isinstance(value, str) and encodable(value)


_VERSIONS = obj(
    {
        "core": text,
        "plugins": array(
            obj({"family": text, "version": text, "conformance_report_hash": HEX32_CHECK}), sort_key="family"
        ),
        "gate_rules": text,
        "references": array(obj({"id": text, "version": text}), sort_key="id"),
    }
)
_COMMON: dict[str, Check] = {
    "dump_kind": one_of(*DUMP_KINDS),
    "image_hash_original": HEX32_CHECK,
    "layout_hash": HEX32_CHECK,
    "gate_report_hash": HEX32_CHECK,
    "python": obj({"implementation": text, "version": text}),
    "build": obj(
        {
            "kind": one_of("image", "lockfile"),
            "value": matches(DIGEST),
            "platform": text,
            "attestation_id": nullable(text),
        }
    ),
    "reproducibility": one_of("full", "best_effort"),
}

EXPORT_SHAPE = obj(
    {
        **_COMMON,
        "schema": one_of(EXPORT_SCHEMA),
        "image_hash_apply": HEX32_CHECK,
        "image_hash_release": HEX32_CHECK,
        "version_hash": HEX32_CHECK,
        "definition_hash": HEX32_CHECK,
        "patch_hashes": _HASHES,
        "overlaps": _sorted_pairs,
        "checksum_patch_hashes": _HASHES,
        "versions": _VERSIONS,
        "verdict": one_of("no findings", "warn"),
        "alert_ack": nullable(EVENT_REF_CHECK),
        "input_verify": obj(
            {
                "status": one_of(*VERIFY_STATUSES),
                "result": one_of("ok", "failed_acknowledged"),
                "suspect_ack": nullable(EVENT_REF_CHECK),
            }
        ),
    }
)

FOREIGN = obj(
    {
        "memory_id": text,
        "offset": uint,
        "length": uint,
        "region_kind": one_of("checksum", "protected"),
        "region_name": region_name,
    }
)
AUDIT_SHAPE = obj(
    {
        **_COMMON,
        "schema": one_of(AUDIT_SCHEMA),
        "image_hash_candidate": HEX32_CHECK,
        "candidate_origin": one_of(*ORIGINS),
        "diff_patch_hashes": _HASHES,
        "foreign": array(FOREIGN),
        "verify": obj({"original": one_of(*VERIFY_STATUSES), "candidate": one_of(*VERIFY_STATUSES)}),
        "versions": _VERSIONS,
    }
)


def _reproducibility_matches(value: Raw) -> bool:
    """R16, R17: `best_effort` if and only if the build is a lockfile, which never has an attestation."""
    build = member(value, "build")
    lockfile = member(build, "kind") == "lockfile"
    if lockfile and member(build, "attestation_id") is not None:
        return False
    return (member(value, "reproducibility") == "best_effort") == lockfile


def _frozen(value: Raw, shape: Check, what: str) -> Mapping[str, Json]:
    """R3: exactly the listed keys and types (`bad_shape`); R16, R17 (`inconsistent_record`)."""
    if not shape(value):
        raise ShapeError("bad_shape", what)
    if not _reproducibility_matches(value):
        raise RecordError("inconsistent_record", f"{what}: reproducibility does not follow build (R16, R17)")
    return as_mapping(to_json(value))


@dataclass(frozen=True, slots=True)
class ExportProvenance:
    """SPEC-005 §3 as validated, frozen JSON. `provenance_hash` is R18."""

    value: Mapping[str, Json]

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _frozen(self.value, EXPORT_SHAPE, "ExportProvenance"))

    @property
    def provenance_hash(self) -> str:
        return hash_json(self.value)


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """SPEC-005 §4 as validated, frozen JSON. `audit_hash` is R21."""

    value: Mapping[str, Json]

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _frozen(self.value, AUDIT_SHAPE, "AuditRecord"))

    @property
    def audit_hash(self) -> str:
        return hash_json(self.value)


@dataclass(frozen=True, slots=True)
class PluginVersion:
    family: str
    version: str
    conformance_report_hash: str


@dataclass(frozen=True, slots=True)
class Reference:
    """A `RegionReference` the gate used for the dual step, with the version it declares (SPEC-002 R34)."""

    id: str
    version: str


def _family(plugin: PluginVersion) -> str:
    return plugin.family


def _reference_id(reference: Reference) -> str:
    return reference.id


@dataclass(frozen=True, slots=True)
class Versions:
    core: str
    plugins: tuple[PluginVersion, ...]
    gate_rules: str
    references: tuple[Reference, ...] = ()

    def to_json(self) -> dict[str, Json]:
        plugins: list[Json] = [
            {"family": p.family, "version": p.version, "conformance_report_hash": p.conformance_report_hash}
            for p in sorted(self.plugins, key=_family)
        ]
        references: list[Json] = [
            {"id": r.id, "version": r.version} for r in sorted(self.references, key=_reference_id)
        ]
        return {"core": self.core, "plugins": plugins, "gate_rules": self.gate_rules, "references": references}


@dataclass(frozen=True, slots=True)
class Build:
    """R16: supplied by the packaging that runs the core."""

    kind: BuildKind
    value: str
    platform: str
    attestation_id: str | None

    def to_json(self) -> dict[str, Json]:
        return {
            "kind": self.kind,
            "value": self.value,
            "platform": self.platform,
            "attestation_id": self.attestation_id,
        }

    @property
    def reproducibility(self) -> str:
        """R17."""
        return "best_effort" if self.kind == "lockfile" else "full"


@dataclass(frozen=True, slots=True)
class ExportInputs:
    """What the gate holds when it exports (R10). `definition_hash` is SPEC-003 R52 of the definition it
    evaluated, computed by the gate because provenance sits below `core.definitions`; R11 binds it to the
    output gate report's subject. `input_report` is the input gate report of the original (SPEC-004 §6)."""

    original: Dump
    version: Version
    layout: MemoryLayout
    checksum_patches: tuple[Patch, ...]
    definition_hash: str
    versions: Versions
    gate_report: Raw
    input_report: Raw
    build: Build


@dataclass(frozen=True, slots=True)
class AuditInputs:
    """What an audit of `candidate` against `original` holds (R20); `gate_report` is the input gate report on
    the candidate."""

    original: Dump
    candidate: Dump
    candidate_origin: str
    layout: MemoryLayout
    verify_original: str
    verify_candidate: str
    versions: Versions
    gate_report: Raw
    build: Build


def _gate_report_hash(report: Raw) -> str:
    digest = try_hash(report)
    if digest is None or not isinstance(report, Mapping):
        raise ShapeError("bad_shape", "a gate report is a canonical JSON object")
    return digest


def _checksum_order(patch: Patch) -> tuple[str, int]:
    return (patch.memory_id, patch.offset)


def _kernel_error(error: KernelError) -> RecordError:
    return RecordError("inconsistent_record", f"kernel rejected the inputs: {error.reason}")


def export_provenance(
    inputs: ExportInputs, *, alert_ack: Event | None, suspect_ack: Event | None, chain: Sequence[Event]
) -> ExportProvenance:
    """R10: every hash computed here from kernel objects; then R11, R13 and R14 are asserted.

    `chain` is the signer's chain the export event will be appended to (R13, R14).
    """
    try:
        applied = apply(inputs.original, inputs.version, inputs.layout)
        released = apply_checksum_patches(applied, inputs.checksum_patches, inputs.layout)
        order = canonical_order(inputs.version)
        digest = version_hash(inputs.version)
    except KernelError as error:
        raise _kernel_error(error) from error
    input_report = inputs.input_report
    record = ExportProvenance(
        {
            "schema": EXPORT_SCHEMA,
            "dump_kind": inputs.original.dump_kind,
            "image_hash_original": image_hash(inputs.original),
            "image_hash_apply": applied.image_hash,
            "image_hash_release": released.image_hash,
            "layout_hash": layout_hash(inputs.layout),
            "version_hash": digest,
            "definition_hash": inputs.definition_hash,
            "patch_hashes": [patch.patch_hash for patch in order],
            "overlaps": sorted([first, second] for first, second in inputs.version.overlaps),
            "checksum_patch_hashes": [p.patch_hash for p in sorted(inputs.checksum_patches, key=_checksum_order)],
            "versions": inputs.versions.to_json(),
            "gate_report_hash": _gate_report_hash(inputs.gate_report),
            "verdict": as_str(member(inputs.gate_report, "verdict")),
            "alert_ack": None if alert_ack is None else alert_ack.ref,
            "input_verify": {
                "status": as_str(member(member(input_report, "subject"), "verify_status")),
                "result": "failed_acknowledged" if member(input_report, "verdict") == "block" else "ok",
                "suspect_ack": None if suspect_ack is None else suspect_ack.ref,
            },
            "python": python_info(),
            "build": inputs.build.to_json(),
            "reproducibility": inputs.build.reproducibility,
        }
    )
    check_export_record(
        record, version=inputs.version, gate_report=inputs.gate_report, input_report=input_report, chain=chain
    )
    return record


def check_export_record(
    record: ExportProvenance, *, version: Version, gate_report: Raw, input_report: Raw, chain: Sequence[Event]
) -> None:
    """R11, R13, R14: the runtime assertions of the export path (R92). Raises `RecordError`."""
    check_kernel_fields(record, version)
    check_gate_subject(record, gate_report)
    check_alert_ack(record, gate_report, chain)
    check_suspect_ack(
        record,
        input_verdict=member(input_report, "verdict"),
        input_verify_status=member(member(input_report, "subject"), "verify_status"),
        chain=chain,
    )


def _require(checks: Mapping[str, bool]) -> None:
    failed = sorted(name for name, holds in checks.items() if not holds)
    if failed:
        raise RecordError("inconsistent_record", "; ".join(failed))


def check_kernel_fields(record: ExportProvenance, version: Version) -> None:
    """R11, the part that depends only on the version and the record."""
    value = record.value
    patch_hashes = strings(member(value, "patch_hashes"))
    overlaps: list[Json] = [strings(pair) for pair in items(member(value, "overlaps"))]
    try:
        canonical = [patch.patch_hash for patch in canonical_order(version)]
    except KernelError as error:
        raise _kernel_error(error) from error
    recomputed = hash_json(
        {
            "base_image_hash": as_str(member(value, "image_hash_original")),
            "layout_hash": as_str(member(value, "layout_hash")),
            "patches": patch_hashes,
            "overlaps": overlaps,
        }
    )
    known = set(patch_hashes)
    _require(
        {
            "image_hash_original == v.base_image_hash": member(value, "image_hash_original") == version.base_image_hash,
            "layout_hash == v.layout_hash": member(value, "layout_hash") == version.layout_hash,
            "SPEC-001 R64 recomputes version_hash": recomputed == member(value, "version_hash"),
            "patch_hashes is the SPEC-001 R25 order": patch_hashes == canonical,
            "overlaps reference patch_hashes": all(set(strings(pair)) <= known for pair in overlaps),
        }
    )


def check_gate_subject(record: ExportProvenance, gate_report: Raw) -> None:
    """R11, the part bound to the output gate report (SPEC-004 §6 subject)."""
    value = record.value
    subject = member(gate_report, "subject")
    references = member(member(value, "versions"), "references")
    _require(
        {
            "gate_report_hash is sha256(JCS(gate_report))": try_hash(gate_report) == member(value, "gate_report_hash"),
            "verdict is the gate report's": member(gate_report, "verdict") == member(value, "verdict"),
            "definition_hash is the subject's": member(subject, "definition_hash") == member(value, "definition_hash"),
            "layout_hash is the subject's": member(subject, "layout_hash") == member(value, "layout_hash"),
            "references are the subject's": _same_json(member(subject, "references"), references),
        }
    )


def warn_findings(gate_report: Raw) -> list[Json]:
    """`{finding_id, rule_id, text}` of every `warn` finding, in report order (SPEC-004 R43, R50)."""
    return [
        {"finding_id": try_hash(f), "rule_id": as_str(member(f, "rule_id")), "text": as_str(member(f, "text"))}
        for f in items(member(gate_report, "findings"))
        if member(f, "severity") == "warn"
    ]


def _chain_event(chain: Sequence[Event], ref: Raw, event_type: str) -> Event | None:
    """The event of `chain` that `ref` names, if its stored hash is its R31 hash and its type matches."""
    named = [
        event
        for event in chain
        if (event.seq, event.event_id, event.hash) == (member(ref, "seq"), member(ref, "event_id"), member(ref, "hash"))
        and event.type == event_type
        and event_hash(event.to_json()) == event.hash
    ]
    return named[0] if named else None


def check_alert_ack(record: ExportProvenance, gate_report: Raw, chain: Sequence[Event]) -> None:
    """R13: `warn` needs the `alert_ack` of exactly this release and these warnings; `no findings` needs none."""
    value = record.value
    ref = member(value, "alert_ack")
    if member(value, "verdict") == "no findings":
        if ref is not None:
            raise RecordError("alert_ack_mismatch", "a no findings export carries no alert_ack")
        return
    if ref is None:
        raise RecordError("missing_alert_ack", "a warn export needs an alert_ack event (R13)")
    event = _chain_event(chain, ref, "alert_ack")
    payload = None if event is None else event.payload
    holds = (
        event is not None
        and member(payload, "image_hash_release") == member(value, "image_hash_release")
        and member(payload, "gate_report_hash") == member(value, "gate_report_hash")
        and member(value, "gate_report_hash") == try_hash(gate_report)
        and _same_json(member(payload, "warnings"), warn_findings(gate_report))
    )
    if not holds:
        raise RecordError("alert_ack_mismatch", "the alert_ack does not confirm this release and its warnings")


def check_suspect_ack(
    record: ExportProvenance, *, input_verdict: Raw, input_verify_status: Raw, chain: Sequence[Event]
) -> None:
    """R14: a suspect original (input verdict `block`) needs its `suspect_ack`; any other needs none."""
    value = record.value
    input_verify = member(value, "input_verify")
    status = member(input_verify, "status")
    ref = member(input_verify, "suspect_ack")
    if input_verdict == "block":
        event = _chain_event(chain, ref, "suspect_ack")
        payload = None if event is None else event.payload
        holds = (
            member(input_verify, "result") == "failed_acknowledged"
            and event is not None
            and member(payload, "image_hash") == member(value, "image_hash_original")
            and member(payload, "verify_status") == status
        )
    else:
        holds = member(input_verify, "result") == "ok" and ref is None
    if not holds or status != input_verify_status:
        raise RecordError("missing_suspect_ack", f"input verdict {input_verdict!r}, input_verify {status!r}")


def audit_record(inputs: AuditInputs) -> AuditRecord:
    """R20: every hash and list comes from `diff(original, candidate, layout)` (SPEC-001 R31, R32)."""
    try:
        result = diff(inputs.original, inputs.candidate, inputs.layout)
    except KernelError as error:
        raise _kernel_error(error) from error
    return AuditRecord(
        {
            "schema": AUDIT_SCHEMA,
            "dump_kind": inputs.original.dump_kind,
            "image_hash_original": image_hash(inputs.original),
            "image_hash_candidate": image_hash(inputs.candidate),
            "candidate_origin": inputs.candidate_origin,
            "layout_hash": result.layout_hash,
            "diff_patch_hashes": [patch.patch_hash for patch in result.patches],
            "foreign": [
                {
                    "memory_id": run.memory_id,
                    "offset": run.offset,
                    "length": run.length,
                    "region_kind": run.region_kind,
                    "region_name": run.region_name,
                }
                for run in result.foreign
            ],
            "verify": {"original": inputs.verify_original, "candidate": inputs.verify_candidate},
            "versions": inputs.versions.to_json(),
            "gate_report_hash": _gate_report_hash(inputs.gate_report),
            "python": python_info(),
            "build": inputs.build.to_json(),
            "reproducibility": inputs.build.reproducibility,
        }
    )


def _same_json(a: Raw, b: Raw) -> bool:
    return try_hash(a) is not None and try_hash(a) == try_hash(b)
