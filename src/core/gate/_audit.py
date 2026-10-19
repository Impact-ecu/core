"""`audit` (SPEC-005 §4.1, R23-R28): the gate builds the `AuditRecord`, with the layout and both verify statuses
from its own plugin calls, never from the caller."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import TypedDict, Unpack

from core import __version__
from core.definitions import Definition, MapAttribution, map_attribution, report_map_ids
from core.evidence import FieldEvidence
from core.gate._calls import PluginFault, call
from core.gate._check import CheckInputArgs, run_check_input
from core.gate._evidence import EvidenceAdmissionFn, published_admission
from core.gate._model import GateError, child, present
from core.gate._result import InputResult
from core.kernel import Dump, KernelError, MemoryLayout, diff, layout_hash
from core.plugins import ContractJson, EcuPlugin, PluginContractError, check_layout
from core.provenance import (
    AuditInputs,
    AuditRecord,
    Build,
    Event,
    Json,
    PluginVersion,
    Report,
    ReportContext,
    Verifier,
    Versions,
    audit_record,
    audit_report,
)


class AuditRefused(GateError):
    """SPEC-005 R25: the audit was not built; `reason` says why."""


@dataclass(frozen=True, slots=True)
class AuditFile:
    """One side of an audit: the dump and what `check_input` needs about that file (SPEC-004 §3)."""

    dump: Dump
    declared_sha256: str
    received_sha256: str
    confirmation: Event | None


class AuditArgs(TypedDict):
    """The keyword arguments of `audit` shared by both input gate runs (SPEC-005 §4.1)."""

    candidate_origin: str
    project_id: str
    plugin: EcuPlugin | None
    conformance_report: ContractJson | None
    evidence: FieldEvidence | None
    as_of: str
    verifier: Verifier | None
    rule_table: Json | None
    definition: Definition | None
    build: Build


@dataclass(frozen=True, slots=True)
class Audit:
    """SPEC-005 R23-R28. `report` builds the R62 report with the core's `map_id`s (R27)."""

    record: AuditRecord
    original_input: InputResult
    candidate_input: InputResult
    inputs: AuditInputs
    attribution: MapAttribution | None
    map_ids: Mapping[str, str | None]

    def report(self, context: ReportContext) -> Report:
        return audit_report(context, self.inputs, self.record, map_ids=self.map_ids)


def _input(file: AuditFile, args: AuditArgs, admit: EvidenceAdmissionFn, core_version: str) -> InputResult:
    checked: CheckInputArgs = {
        "declared_sha256": file.declared_sha256,
        "received_sha256": file.received_sha256,
        "project_id": args["project_id"],
        "plugin": args["plugin"],
        "conformance_report": args["conformance_report"],
        "evidence": args["evidence"],
        "as_of": args["as_of"],
        "verifier": args["verifier"],
        "confirmation": file.confirmation,
        "rule_table": args["rule_table"],
    }
    return run_check_input(file.dump, checked, admit, core_version)


def _text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _verify_status(result: InputResult) -> str | None:
    return _text(child(child(result.report, "subject"), "verify_status"))


def _layout(result: InputResult, dump: Dump, plugin: EcuPlugin | None, side: str) -> MemoryLayout:
    """R24: the layout of the identification the input gate accepted, checked per SPEC-002 R20-R22."""
    ident = result.identification
    if _verify_status(result) is None or ident is None:
        raise AuditRefused(f"{side}_not_identified", "the input gate stopped before verify (SPEC-005 R24)")
    accepted = present(plugin, "SPEC-005 R24")
    try:
        return check_layout(call(lambda: accepted.layout(ident, dump.dump_kind)), ident)
    except (PluginFault, PluginContractError) as error:
        raise AuditRefused("plugin_error", str(error)) from error


def _versions(result: InputResult, core_version: str) -> Versions:
    """R26: from the candidate's input report, which the gate wrote. A report that reached `verify` names its
    plugin, conformance report and rule table (SPEC-004 R45), so a missing one is a gate bug."""
    report = result.report
    subject = child(report, "subject")
    plugin = child(subject, "plugin")
    family = present(_text(child(plugin, "family")), "SPEC-004 R45")
    version = present(_text(child(plugin, "version")), "SPEC-004 R45")
    conformance = present(_text(child(subject, "conformance_report_hash")), "SPEC-004 R45")
    table_version = present(_text(child(child(child(report, "gate"), "rule_table"), "version")), "SPEC-004 R45")
    return Versions(core_version, (PluginVersion(family, version, conformance),), table_version, ())


def _valid(original: AuditFile, candidate: AuditFile, args: AuditArgs) -> bool:
    definition = args["definition"]
    return (
        all(isinstance(f, AuditFile) and isinstance(f.dump, Dump) for f in (original, candidate))
        and isinstance(args["build"], Build)
        and (definition is None or isinstance(definition, Definition))
    )


def run_audit(
    original: AuditFile, candidate: AuditFile, args: AuditArgs, admit: EvidenceAdmissionFn, core_version: str
) -> Audit:
    """`audit` with the evidence seam and the core version as parameters (tests; SPEC-004 R16)."""
    if not _valid(original, candidate, args):
        raise AuditRefused("bad_type", "audit takes two AuditFiles, a Build and a Definition or None")
    original_input = _input(original, args, admit, core_version)
    candidate_input = _input(candidate, args, admit, core_version)
    plugin = args["plugin"]
    layout = _layout(original_input, original.dump, plugin, "original")
    if layout_hash(_layout(candidate_input, candidate.dump, plugin, "candidate")) != layout_hash(layout):
        raise AuditRefused("layout_mismatch", "the candidate's layout is not the original's (SPEC-005 R24)")
    try:
        changes = diff(original.dump, candidate.dump, layout)
    except KernelError as error:
        raise AuditRefused(error.reason, str(error)) from error
    inputs = AuditInputs(
        original=original.dump,
        candidate=candidate.dump,
        candidate_origin=args["candidate_origin"],
        layout=layout,
        verify_original=present(_verify_status(original_input), "SPEC-005 R24"),
        verify_candidate=present(_verify_status(candidate_input), "SPEC-005 R24"),
        versions=_versions(candidate_input, core_version),
        gate_report=candidate_input.report,
        build=args["build"],
    )
    definition = args["definition"]
    attribution = (
        None if definition is None else map_attribution(changes.patches, definition, (original.dump, candidate.dump))
    )
    map_ids = {} if attribution is None else report_map_ids(attribution)
    return Audit(audit_record(inputs), original_input, candidate_input, inputs, attribution, map_ids)


def audit(original: AuditFile, candidate: AuditFile, **args: Unpack[AuditArgs]) -> Audit:
    """SPEC-005 §4.1: the input gate on both files, the layout and the diff, all computed by the core."""
    return run_audit(original, candidate, args, published_admission, __version__)
