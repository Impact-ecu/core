"""`check_input` (SPEC-004 §3): the input gate on a real plugin."""

from typing import TypedDict, Unpack

from core import __version__
from core.evidence import FieldEvidence
from core.gate._calls import PluginFault, admitted_variants, call, conformance_admission, plugin_ref
from core.gate._evidence import EvidenceAdmissionFn, published_admission
from core.gate._input import IdentView, InputAvailability, InputFacts, InputVerifyOutcome, input_report
from core.gate._model import GateError, present, shielded
from core.gate._report import SignedRegion
from core.gate._result import InputResult, seal
from core.gate._rules import parse_rule_table
from core.kernel import Dump, image_hash
from core.plugins import (
    ContractJson,
    DescriptorError,
    EcuPlugin,
    Identification,
    InterpreterDivergence,
    PluginContractError,
    check_identification,
    check_layout,
    check_verify_report,
    identification_hash,
)
from core.plugins.descriptor import check_checksums, compare_verify
from core.provenance import Event, Json, Verifier


class CheckInputArgs(TypedDict):
    """The keyword arguments of `check_input` (SPEC-004 §3)."""

    declared_sha256: str
    received_sha256: str
    project_id: str
    plugin: EcuPlugin | None
    conformance_report: ContractJson | None
    evidence: FieldEvidence | None
    as_of: str
    verifier: Verifier | None
    confirmation: Event | None
    rule_table: Json | None


class _InputSteps:
    def __init__(self, dump: Dump, args: CheckInputArgs, admit: EvidenceAdmissionFn) -> None:
        self.dump = dump
        self.args = args
        self.admit = admit
        self.ident: Identification | None = None

    def availability(self) -> InputAvailability:
        return shielded(self._availability)

    def verify(self) -> InputVerifyOutcome:
        return shielded(self._verify)

    def _availability(self) -> InputAvailability:
        """R10, R12, R15, R16."""
        table = parse_rule_table(self.args["rule_table"])
        plugin = self.args["plugin"]
        ref = plugin_ref(plugin)
        if plugin is None or ref is None:
            return InputAvailability(table, None, "unavailable", None, frozenset(), None)
        conformance = conformance_admission(self.args["conformance_report"], plugin)
        if conformance is None:
            return InputAvailability(table, ref, "unavailable", None, frozenset(), None)
        try:
            raw = call(lambda: plugin.identify(self.dump))
        except PluginFault:
            return InputAvailability(table, ref, "unavailable", None, frozenset(), None)
        try:
            ident = check_identification(raw, self.dump, ref.family)
        except PluginContractError:
            return InputAvailability(table, ref, "error", conformance.report_hash, frozenset(), None)
        self.ident = ident
        args = self.args
        admitted = admitted_variants(conformance, ref, self.admit, args["evidence"], args["as_of"], args["verifier"])
        view = (
            None
            if ident is None
            else IdentView(
                identification_hash(ident), ident.confidence, ident.checksum_variant_id, ident.hw_id, ident.sw_id
            )
        )
        return InputAvailability(table, ref, "ok", conformance.report_hash, admitted, view)

    def _verify(self) -> InputVerifyOutcome:
        """R13. Only reached for an identified, admitted variant."""
        plugin, ident, dump = present(self.args["plugin"], "R13"), present(self.ident, "R13"), self.dump
        try:
            layout = check_layout(call(lambda: plugin.layout(ident, dump.dump_kind)), ident)
            regions = check_checksums(call(lambda: plugin.checksums(ident)), ident, layout)
            report = check_verify_report(call(lambda: plugin.verify(dump, ident)), dump, regions, layout)
        except (PluginFault, PluginContractError, DescriptorError):
            return InputVerifyOutcome(None, (), divergence=False)
        signed = tuple(SignedRegion(r.memory_id, r.name) for r in report.regions if r.kind == "signed")
        # `check_input` receives no `RegionReference`s (§3): independent regions are compared at release (R27); here
        # they stand for themselves, so the input comparison covers the interpreter regions.
        independent = {region.name for region in regions if region.reference.kind == "independent"}
        themselves = {result.name: result for result in report.regions if result.name in independent}
        try:
            compare_verify(regions, report, dump, layout, themselves)
        except (PluginContractError, InterpreterDivergence):
            return InputVerifyOutcome(report.status, signed, divergence=True)
        return InputVerifyOutcome(report.status, signed, divergence=False)


def run_check_input(dump: Dump, args: CheckInputArgs, admit: EvidenceAdmissionFn, core_version: str) -> InputResult:
    """`check_input` with the evidence seam and the core version as parameters (tests; SPEC-004 R16)."""
    declared, received, project_id = args["declared_sha256"], args["received_sha256"], args["project_id"]
    if not (isinstance(dump, Dump) and all(isinstance(v, str) for v in (declared, received, project_id))):
        raise GateError("bad_type", "check_input takes a Dump and string hashes and project id")
    steps = _InputSteps(dump, args, admit)
    facts = InputFacts(declared, received, image_hash(dump), project_id)
    outcome = input_report(steps, facts, args["confirmation"], core_version)
    return InputResult(seal(), outcome.report, outcome.artifact_state, steps.ident)


def check_input(dump: Dump, **args: Unpack[CheckInputArgs]) -> InputResult:
    """SPEC-004 §3: the input gate. The identification is the gate's own `identify` (R12), the admitted set the
    conformance report intersected with field evidence the gate evaluates itself (R15, R16)."""
    return run_check_input(dump, args, published_admission, __version__)
