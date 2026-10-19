"""`release` (SPEC-004 §4): the only constructor of `ReleasedImage` (SPEC-001 R9), on a real plugin."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import TypedDict, Unpack, cast

from core import __version__
from core.definitions import ByteRange, Definition, DefinitionError, decode, definition_hash, span
from core.evidence import FieldEvidence
from core.gate._calls import PluginFault, admitted_variants, call, conformance_admission, plugin_ref
from core.gate._evidence import EvidenceAdmissionFn, published_admission
from core.gate._integrity import (
    edited,
    kernel_check,
    map_view,
    outside_calibration,
    outside_checksum_unchanged,
    patch_run,
    uncovered,
)
from core.gate._maps import Engine, MapView, UnboundMap
from core.gate._model import GateError, GateEvent, Stop, child, event_of, json_hash, present, shielded
from core.gate._output import (
    BindingOutcome,
    ChecksumOutcome,
    DualOutcome,
    InputState,
    KernelOutcome,
    MapsOutcome,
    OutputAvailability,
    PluginState,
    Sources,
    VerifyOutcome,
    output_report,
)
from core.gate._report import PluginRef, ReferenceRef, SignedRegion, silences_of
from core.gate._result import ExportBasis, GateBlocked, InputResult, ReleasedImage, seal
from core.gate._rules import Table, parse_rule_table
from core.kernel import (
    ContainmentError,
    Dump,
    KernelError,
    MemoryLayout,
    Patch,
    UnverifiedImage,
    Version,
    apply,
    apply_checksum_patches,
    image_hash,
    layout_hash,
    version_hash,
)
from core.kernel._internal import view
from core.plugins import (
    ChecksumRegion,
    ContractJson,
    DescriptorError,
    EcuPlugin,
    Identification,
    InterpreterDivergence,
    PluginContractError,
    RegionReference,
    RegionResult,
    VerifyReport,
    check_checksum_patches,
    check_identification,
    check_layout,
    check_regions,
    check_verify_report,
    identification_hash,
)
from core.plugins.descriptor import (
    check_checksums,
    compare_patches,
    compare_verify,
    interpret_patches,
    reference_result_usable,
)
from core.provenance import Event, Json, Verifier


class ReleaseArgs(TypedDict):
    """The keyword arguments of `release` (SPEC-004 §4)."""

    original: Dump
    version: Version
    plugin: EcuPlugin | None
    conformance_report: ContractJson | None
    evidence: FieldEvidence | None
    as_of: str
    verifier: Verifier | None
    references: Mapping[str, RegionReference]
    definition: Definition
    engine: Engine
    rule_table: Json | None
    project_id: str
    input: InputResult
    suspect_ack: Event | None
    silences: Sequence[Event]


@dataclass(frozen=True, slots=True)
class _Bound:
    """What the binding step computed, for every later step (R23: nothing else is trusted)."""

    plugin: EcuPlugin
    ident: Identification
    layout: MemoryLayout


def _patches(value: object, outcome: str) -> tuple[Patch, ...]:
    """A list of `Patch` (SPEC-002 R50 type), or the step stops with `outcome`."""
    if not (isinstance(value, list | tuple) and all(isinstance(p, Patch) for p in cast("Sequence[object]", value))):
        raise Stop(outcome)
    return tuple(cast("Sequence[Patch]", value))


def _guard[T](outcome: str, step: Callable[[], T], *errors: type[Exception]) -> T:
    """Run `step`; a `PluginFault` or one of `errors` stops the step with `outcome`."""
    caught: tuple[type[Exception], ...] = (PluginFault, *errors)
    try:
        return step()
    except caught as error:
        raise Stop(outcome) from error


def _reference_patches(reference: RegionReference, dump: Dump, ident: Identification, region: ChecksumRegion) -> object:
    return call(lambda: reference.patches_region(dump, ident, region))


def _reference_verify(reference: RegionReference, dump: Dump, ident: Identification, region: ChecksumRegion) -> object:
    return call(lambda: reference.verify_region(dump, ident, region))


def acknowledgement(event: GateEvent | None, project_id: str) -> Mapping[str, Json] | None:
    """R22, R53: the payload of a `suspect_ack` of this project, or None."""
    return event_of(event, "suspect_ack", project_id)


class _ReleaseSteps:
    """The real steps of R20 for one `release` call. Each public method is shielded (R28)."""

    def __init__(self, u: UnverifiedImage, args: ReleaseArgs, admit: EvidenceAdmissionFn) -> None:
        self.u = u
        self.args = args
        self.admit = admit
        self.ref: PluginRef | None = None
        self.ident: Identification | None = None
        self.conformance_hash: str | None = None
        self.regions: tuple[ChecksumRegion, ...] = ()
        self.bound: _Bound | None = None
        self.candidate: UnverifiedImage | None = None
        self.checksum_patches: tuple[Patch, ...] = ()
        self.report: VerifyReport | None = None

    def availability(self) -> OutputAvailability:
        return shielded(self._availability)

    def binding(self) -> BindingOutcome:
        return shielded(self._binding)

    def input_state(self) -> InputState:
        return shielded(self._input_state)

    def kernel(self) -> KernelOutcome:
        return shielded(self._kernel)

    def checksum(self) -> ChecksumOutcome:
        return shielded(self._checksum)

    def verify(self) -> VerifyOutcome:
        return shielded(self._verify)

    def dual(self) -> DualOutcome:
        return shielded(self._dual)

    def maps(self) -> MapsOutcome:
        return shielded(self._maps)

    # Step 1 - R21.

    def _availability(self) -> OutputAvailability:
        table = parse_rule_table(self.args["rule_table"])
        self.ref = plugin_ref(self.args["plugin"])
        try:
            return self._available(table)
        except Stop as stop:
            state = cast("PluginState", stop.outcome)
            variant = None if self.ident is None else self.ident.checksum_variant_id
            return OutputAvailability(table, self.ref, state, self.conformance_hash, variant, False, True, False)

    def _available(self, table: Table | None) -> OutputAvailability:
        plugin, original, ref = self.args["plugin"], self.args["original"], self.ref
        conformance = None if plugin is None else conformance_admission(self.args["conformance_report"], plugin)
        if plugin is None or ref is None or conformance is None:
            raise Stop("unavailable")
        raw = _guard("unavailable", lambda: call(lambda: plugin.identify(original)))
        self.conformance_hash = conformance.report_hash
        ident = _guard("error", lambda: check_identification(raw, original, ref.family), PluginContractError)
        self.ident = ident
        variant = None if ident is None else ident.checksum_variant_id
        args = self.args
        admitted = admitted_variants(conformance, ref, self.admit, args["evidence"], args["as_of"], args["verifier"])
        if ident is None or variant not in admitted:
            return OutputAvailability(table, ref, "ok", conformance.report_hash, variant, False, True, False)
        self.regions = _guard(
            "error", lambda: check_regions(call(lambda: plugin.checksums(ident))), PluginContractError
        )
        dual = all(self._reference_available(region) for region in self.regions if region.kind == "recalculable")
        signed_only = bool(self.regions) and all(region.kind == "signed" for region in self.regions)
        return OutputAvailability(table, ref, "ok", conformance.report_hash, variant, True, dual, signed_only)

    def _reference_available(self, region: ChecksumRegion) -> bool:
        """R21: an interpreter region always has its reference; an independent one needs a usable entry."""
        declared = region.reference
        if declared.kind == "interpreter":
            return True
        reference = self.args["references"].get(declared.id or "")
        if declared.kind != "independent" or reference is None:
            return False
        try:
            identity = call(lambda: (reference.id, reference.version))
        except PluginFault:
            return False
        return identity[0] == declared.id and isinstance(identity[1], str)

    # Step 2 - R23.

    def _binding(self) -> BindingOutcome:
        ident, original = self.ident, self.args["original"]
        if ident is None:
            return BindingOutcome(None, mismatch=True, plugin_error=False, protected=())
        plugin = present(self.args["plugin"], "SPEC-004 R23")
        try:
            layout = check_layout(call(lambda: plugin.layout(ident, original.dump_kind)), ident)
        except (PluginFault, PluginContractError):
            return BindingOutcome(None, mismatch=False, plugin_error=True, protected=())
        digest = layout_hash(layout)
        try:
            self.regions = check_checksums(self.regions, ident, layout) if self.regions else ()
        except (PluginContractError, DescriptorError):
            return BindingOutcome(digest, mismatch=False, plugin_error=True, protected=())
        self.bound = _Bound(plugin, ident, layout)
        version = self.args["version"]
        bound = (
            image_hash(original) == version.base_image_hash
            and digest == version.layout_hash
            and self._input_bound(ident)
        )
        try:
            applied = apply(original, version, layout)
        except ContainmentError:
            runs = tuple(patch_run(p) for p in outside_calibration(version.patches, layout))
            return BindingOutcome(digest, mismatch=not bound, plugin_error=False, protected=runs)
        except KernelError:
            return BindingOutcome(digest, mismatch=True, plugin_error=False, protected=())
        mismatch = not bound or applied.image_hash != self.u.image_hash
        return BindingOutcome(digest, mismatch=mismatch, plugin_error=False, protected=())

    def _input_bound(self, ident: Identification) -> bool:
        """R23: the input result is the one of this original, plugin, conformance report and identification."""
        result = self.args["input"]
        report = result.report
        subject = child(report, "subject")
        return (
            result.report_hash == json_hash(report)
            and child(report, "stage") == "input"
            and child(subject, "image_hash") == image_hash(self.args["original"])
            and child(subject, "plugin") == present(self.ref, "SPEC-004 R23").to_json()
            and child(subject, "conformance_report_hash") == self.conformance_hash
            and child(subject, "identification_hash") == identification_hash(ident)
        )

    # Step 3 - R22.

    def _input_state(self) -> InputState:
        result = self.args["input"]
        report = result.report
        if child(report, "verdict") != "block":
            return "ok"
        findings = child(report, "findings")
        listed = cast("Sequence[object]", findings) if isinstance(findings, tuple) else ()
        only_verify = all(child(f, "rule_id") == "G-INPUT-VERIFY" for f in listed if child(f, "severity") == "block")
        ack = acknowledgement(self.args["suspect_ack"], self.args["project_id"])
        subject = child(report, "subject")
        expected: dict[str, object] = {
            "input_report_hash": result.report_hash,
            "image_hash": image_hash(self.args["original"]),
            "artifact_sha256": child(subject, "received_sha256"),
            "verify_status": child(subject, "verify_status"),
        }
        matches = ack is not None and all(ack.get(key) == value for key, value in expected.items())
        return "acknowledged" if only_verify and matches else "unacknowledged"

    # Step 4 - R24.

    def _kernel(self) -> KernelOutcome:
        bound = present(self.bound, "SPEC-004 R24")
        return kernel_check(self.args["original"], view(self.u), bound.layout, self.args["version"].patches)

    # Step 5 - R25.

    def _checksum(self) -> ChecksumOutcome:
        bound = present(self.bound, "SPEC-004 R25")
        used = self._used_references()
        try:
            candidate, q = self._recalculate(bound, view(self.u))
        except Stop as stop:
            return ChecksumOutcome(stop.outcome, None, used)
        self.candidate, self.checksum_patches = candidate, q
        return ChecksumOutcome(None, candidate.image_hash, used)

    def _recalculate(self, bound: _Bound, dump: Dump) -> tuple[UnverifiedImage, tuple[Patch, ...]]:
        """R25: the core derivation first (its resolution failure takes precedence), then the plugin's patches
        compared with it (SPEC-002 R55), then the kernel checksum step and the R41 re-assertion."""
        try:
            interpret_patches(self.regions, dump, bound.layout)
        except DescriptorError as error:
            raise Stop("G-CHECKSUM-RESOLUTION") from error
        except InterpreterDivergence as error:
            raise Stop("G-DUAL-DIVERGENCE") from error
        independent = {region.name: self._independent_patches(region, dump, bound) for region in self._independent()}
        raw = _guard("G-PLUGIN-ERROR", lambda: call(lambda: bound.plugin.checksum_patches(dump, bound.ident)))
        q = _patches(raw, "G-PLUGIN-ERROR")
        _guard(
            "G-DUAL-DIVERGENCE",
            lambda: compare_patches(self.regions, q, dump, bound.layout, independent),
            PluginContractError,
        )
        try:
            candidate = apply_checksum_patches(self.u, q, bound.layout)
        except ContainmentError as error:
            raise Stop("G-CHECKSUM-CONTAINMENT") from error
        except KernelError as error:
            raise Stop("G-PLUGIN-ERROR") from error
        _guard(
            "G-PLUGIN-ERROR", lambda: check_checksum_patches(q, dump, bound.layout, self.regions), PluginContractError
        )
        if not outside_checksum_unchanged(dump, view(candidate), bound.layout):
            raise Stop("G-INVARIANT")
        return candidate, q

    def _independent_patches(self, region: ChecksumRegion, dump: Dump, bound: _Bound) -> tuple[Patch, ...]:
        """R25, SPEC-002 R45: a reference that raises or returns no patch list is unavailable."""
        reference = self.args["references"][region.reference.id or ""]
        raw = _guard("G-UNAVAILABLE-DUAL", lambda: _reference_patches(reference, dump, bound.ident, region))
        return _patches(raw, "G-UNAVAILABLE-DUAL")

    def _independent(self) -> list[ChecksumRegion]:
        return [region for region in self.regions if region.reference.kind == "independent"]

    def _used_references(self) -> tuple[ReferenceRef, ...]:
        references = self.args["references"]
        used = [references[region.reference.id or ""] for region in self._independent()]
        return tuple(ReferenceRef(reference.id, reference.version) for reference in used)

    # Step 6 - R26.

    def _verify(self) -> VerifyOutcome:
        bound, candidate = present(self.bound, "SPEC-004 R26"), present(self.candidate, "SPEC-004 R26")
        dump = view(candidate)
        try:
            raw = call(lambda: bound.plugin.verify(dump, bound.ident))
            report = check_verify_report(raw, dump, self.regions, bound.layout)
        except (PluginFault, PluginContractError):
            return VerifyOutcome(None, ())
        self.report = report
        signed = tuple(SignedRegion(r.memory_id, r.name) for r in report.regions if r.kind == "signed")
        return VerifyOutcome(report.status, signed)

    # Step 7 - R27.

    def _dual(self) -> DualOutcome:
        bound, candidate = present(self.bound, "SPEC-004 R27"), present(self.candidate, "SPEC-004 R27")
        report = present(self.report, "SPEC-004 R27")
        dump = view(candidate)
        used = self._used_references()
        try:
            results = {region.name: self._independent_result(region, dump, bound) for region in self._independent()}
        except Stop as stop:
            return DualOutcome(stop.outcome, used)
        try:
            compare_verify(self.regions, report, dump, bound.layout, results)
        except (PluginContractError, InterpreterDivergence):
            return DualOutcome("G-DUAL-DIVERGENCE", used)
        return DualOutcome(None, used)

    def _independent_result(self, region: ChecksumRegion, dump: Dump, bound: _Bound) -> RegionResult:
        """SPEC-002 R45: only `ok` or `fail` for this region; anything else makes the reference unavailable."""
        reference = self.args["references"][region.reference.id or ""]
        result = _guard("G-UNAVAILABLE-DUAL", lambda: _reference_verify(reference, dump, bound.ident, region))
        if not reference_result_usable(region, result):
            raise Stop("G-UNAVAILABLE-DUAL")
        return cast("RegionResult", result)

    # Step 8 - R31.

    def _maps(self) -> MapsOutcome:
        definition, original = self.args["definition"], self.args["original"]
        # Without a release candidate (an unknown variant, R25) the maps are read from `u`; the checksum step
        # changes only checksum regions, so the decoded cells are the same.
        target = view(self.u if self.candidate is None else self.candidate)
        patches = self.args["version"].patches
        maps: list[MapView | UnboundMap] = []
        covered: list[ByteRange] = []
        for mapdef in definition.mapdefs:
            try:
                ranges = span(mapdef, definition, original) + span(mapdef, definition, target)
                decoded = decode(mapdef, definition, target)
            except DefinitionError:
                maps.append(UnboundMap(mapdef.map_id))
                continue
            covered.extend(ranges)
            maps.append(map_view(mapdef, definition, decoded, edited(ranges, patches)))
        return MapsOutcome(tuple(maps), uncovered(patches, covered))


def _version_hash(version: Version) -> str | None:
    try:
        return version_hash(version)
    except KernelError:
        return None


def _valid(u: UnverifiedImage, args: ReleaseArgs) -> bool:
    return (
        isinstance(u, UnverifiedImage)
        and isinstance(args["original"], Dump)
        and isinstance(args["version"], Version)
        and isinstance(args["definition"], Definition)
        and isinstance(args["engine"], Engine)
        and type(args["input"]) is InputResult
        and isinstance(args["project_id"], str)
    )


def run_release(u: UnverifiedImage, args: ReleaseArgs, admit: EvidenceAdmissionFn, core_version: str) -> ReleasedImage:
    """`release` with the evidence seam and the core version as parameters (tests; SPEC-004 R16)."""
    if not _valid(u, args):
        raise GateError("bad_type", "release takes the kernel, definition and gate objects of SPEC-004 §4")
    steps = _ReleaseSteps(u, args, admit)
    sources = Sources(
        definition_hash=definition_hash(args["definition"]),
        engine=args["engine"],
        input_report_hash=args["input"].report_hash,
        original_image_hash=image_hash(args["original"]),
        unverified_image_hash=u.image_hash,
        version_hash=_version_hash(args["version"]),
    )
    silences = silences_of(args["silences"], args["project_id"])
    report = output_report(steps, sources, silences, core_version)
    candidate = steps.candidate
    if report.verdict == "block" or candidate is None:
        raise GateBlocked(report.report, report.report_hash)
    # SPEC-005 R100: the layout of R23 and the patches of R25 that produced `candidate`, kept for `export_inputs`.
    layout = present(steps.bound, "SPEC-004 R29").layout
    basis = ExportBasis(args["original"], args["version"], layout, steps.checksum_patches, args["input"].report)
    return ReleasedImage(seal(), candidate, report, args["project_id"], basis)


def release(u: UnverifiedImage, **args: Unpack[ReleaseArgs]) -> ReleasedImage:
    """SPEC-004 §4. Raises `GateBlocked(report, report_hash)` for a `block` verdict and constructs nothing."""
    return run_release(u, args, published_admission, __version__)
