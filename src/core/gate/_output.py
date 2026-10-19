"""The output gate's step order and report (SPEC-004 R20-R28, R45), independent of how each step is computed.

`release` drives a real plugin through `OutputSteps`; the vector tests drive the same order with the integrity
outcomes `specs/vectors/spec-004` gives as inputs. The driver asks for a step only when R20 says it runs, so a
plugin is never called after a block that stops the run.
"""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, Protocol

from core.gate._maps import Engine, Entries, MapView, UnboundMap, evaluate_maps
from core.gate._model import Finding, GateFault, NotTested, Run, Tested, blocks, builtin
from core.gate._report import (
    Collected,
    GateReport,
    PluginRef,
    ReferenceRef,
    SignedRegion,
    assemble,
    reference_key,
    signed_json,
)
from core.gate._rules import Table
from core.provenance import Json

PluginState = Literal["ok", "unavailable", "error"]
InputState = Literal["ok", "acknowledged", "unacknowledged"]
# R20 steps 2-8, by the R41 kind each one is reported under.
KINDS = ("binding", "input_state", "kernel_invariants", "checksum_step", "verify", "dual_checksum", "map_rules")


@dataclass(frozen=True, slots=True)
class OutputAvailability:
    """Step 1 (R21). `dual_available` and `signed_only` are meaningful only for an admitted variant."""

    table: Table | None
    plugin: PluginRef | None
    plugin_state: PluginState
    conformance_report_hash: str | None
    checksum_variant_id: str | None
    admitted: bool
    dual_available: bool
    signed_only: bool


@dataclass(frozen=True, slots=True)
class BindingOutcome:
    """Step 2 (R23). `protected` holds the runs of a `ContainmentError` of the re-apply."""

    layout_hash: str | None
    mismatch: bool
    plugin_error: bool
    protected: tuple[Run, ...]


@dataclass(frozen=True, slots=True)
class KernelOutcome:
    """Step 4 (R24)."""

    protected: tuple[Run, ...]
    invariant: bool


@dataclass(frozen=True, slots=True)
class ChecksumOutcome:
    """Step 5 (R25): the built-in rule id of the failure, if any, and the release candidate."""

    finding: str | None
    release_candidate_hash: str | None
    references: tuple[ReferenceRef, ...]


@dataclass(frozen=True, slots=True)
class VerifyOutcome:
    """Step 6 (R26). `status` is None when the plugin call or its contract check failed."""

    status: str | None
    signed_regions: tuple[SignedRegion, ...]


@dataclass(frozen=True, slots=True)
class DualOutcome:
    """Step 7 (R27)."""

    finding: str | None
    references: tuple[ReferenceRef, ...]


@dataclass(frozen=True, slots=True)
class MapsOutcome:
    """Step 8 input (R31): every `MapDef` decoded from the release candidate, and the unmapped patch runs."""

    maps: tuple[MapView | UnboundMap, ...]
    unmapped: tuple[Run, ...]


@dataclass(frozen=True, slots=True)
class Sources:
    """Subject fields that describe caller inputs and are always set (R45). `version_hash` is None only for a
    version whose overlaps cannot be ordered, which binding reports."""

    definition_hash: str
    engine: Engine
    input_report_hash: str
    original_image_hash: str
    unverified_image_hash: str
    version_hash: str | None


class OutputSteps(Protocol):
    def availability(self) -> OutputAvailability: ...
    def binding(self) -> BindingOutcome: ...
    def input_state(self) -> InputState: ...
    def kernel(self) -> KernelOutcome: ...
    def checksum(self) -> ChecksumOutcome: ...
    def verify(self) -> VerifyOutcome: ...
    def dual(self) -> DualOutcome: ...
    def maps(self) -> MapsOutcome: ...


class _Run:
    """One output run: entries and subject fields collected step by step."""

    def __init__(self, sources: Sources) -> None:
        self.entries = Entries()
        self.table: Table | None = None
        self.admitted = False
        self.references: set[ReferenceRef] = set()
        self.subject: dict[str, Json] = {
            "checksum_variant_id": None,
            "conformance_report_hash": None,
            "definition_hash": sources.definition_hash,
            "engine": sources.engine.to_json(),
            "input_report_hash": sources.input_report_hash,
            "input_verify": None,
            "layout_hash": None,
            "original_image_hash": sources.original_image_hash,
            "plugin": None,
            "references": [],
            "release_candidate_hash": None,
            "signed_regions": [],
            "unverified_image_hash": sources.unverified_image_hash,
            "version_hash": sources.version_hash,
        }
        self.engine = sources.engine

    def add(self, findings: Sequence[Finding]) -> bool:
        """Record findings; True when the run continues."""
        self.entries.findings.extend(findings)
        return not blocks(findings)

    def skip_after(self, kind: str | None, reason: str) -> None:
        start = 0 if kind is None else KINDS.index(kind) + 1
        self.entries.not_tested.extend(NotTested(k, reason) for k in KINDS[start:])

    def call[T](self, kind: str | None, step: Callable[[], T]) -> T | None:
        """R28: a step that fails in a way it cannot attribute yields `G-INVARIANT`, S1, and stops the run."""
        try:
            return step()
        except GateFault:
            if kind is not None:
                self.entries.tested.append(Tested(kind))
            self.entries.findings.append(builtin("G-INVARIANT"))
            self.skip_after(kind, "earlier_block")
            return None

    def availability(self, av: OutputAvailability) -> bool:
        """R21; R45 nulls `conformance_report_hash` and `checksum_variant_id` with `G-UNAVAILABLE-PLUGIN`."""
        self.table = av.table
        self.admitted = av.plugin_state == "ok" and av.admitted
        self.subject["plugin"] = None if av.plugin is None else av.plugin.to_json()
        found: list[Finding] = []
        if av.table is None:
            found.append(builtin("G-UNAVAILABLE-RULES"))
        if av.plugin_state == "unavailable":
            found.append(builtin("G-UNAVAILABLE-PLUGIN"))
        else:
            self.subject["conformance_report_hash"] = av.conformance_report_hash
            self.subject["checksum_variant_id"] = av.checksum_variant_id
        if av.plugin_state == "error":
            found.append(builtin("G-PLUGIN-ERROR"))
        if self.admitted and not av.dual_available:
            found.append(builtin("G-UNAVAILABLE-DUAL"))
        self.entries.findings.extend(found)
        if found:
            self.skip_after(None, "gate_unavailable")
        return not found

    def binding(self, b: BindingOutcome) -> bool:
        self.entries.tested.append(Tested("binding"))
        self.subject["layout_hash"] = b.layout_hash
        found: list[Finding] = []
        if b.plugin_error:
            found.append(builtin("G-PLUGIN-ERROR"))
        if b.mismatch:
            found.append(builtin("G-BINDING"))
        if b.protected:
            found.append(builtin("G-PROTECTED", runs=b.protected))
        return self.stop_if_blocked("binding", found)

    def stop_if_blocked(self, kind: str, found: Sequence[Finding]) -> bool:
        """R20: a block in step 2, 4 or 5 stops the run; the remaining steps are `earlier_block`."""
        if self.add(found):
            return True
        self.skip_after(kind, "earlier_block")
        return False

    def input_state(self, state: InputState) -> None:
        self.entries.tested.append(Tested("input_state"))
        self.subject["input_verify"] = "failed_acknowledged" if state == "acknowledged" else "ok"
        if state == "unacknowledged":
            self.entries.findings.append(builtin("G-INPUT-SUSPECT"))

    def kernel(self, k: KernelOutcome) -> bool:
        self.entries.tested.append(Tested("kernel_invariants"))
        found = [builtin("G-PROTECTED", runs=k.protected)] if k.protected else []
        if k.invariant:
            found.append(builtin("G-INVARIANT"))
        return self.stop_if_blocked("kernel_invariants", found)

    def checksum(self, c: ChecksumOutcome) -> bool:
        self.entries.tested.append(Tested("checksum_step"))
        self.references.update(c.references)
        self.subject["release_candidate_hash"] = c.release_candidate_hash
        return self.stop_if_blocked("checksum_step", [] if c.finding is None else [builtin(c.finding)])

    def verify(self, v: VerifyOutcome) -> None:
        self.entries.tested.append(Tested("verify"))
        self.subject["signed_regions"] = signed_json(v.signed_regions)
        self.entries.findings.extend(verify_findings(v.status))

    def dual(self, d: DualOutcome) -> None:
        self.entries.tested.append(Tested("dual_checksum"))
        self.references.update(d.references)
        if d.finding is not None:
            self.entries.findings.append(builtin(d.finding))

    def maps(self, m: MapsOutcome, table: Table) -> None:
        self.entries.extend(evaluate_maps(m.maps, table, self.engine))
        if m.unmapped:
            self.entries.findings.append(builtin("G-UNMAPPED", runs=m.unmapped))


def verify_findings(status: str | None) -> list[Finding]:
    """R26: only the status is mapped; `None` is a plugin call or contract failure."""
    if status is None:
        return [builtin("G-PLUGIN-ERROR")]
    if status == "signature_unverifiable":
        return [builtin("G-VERIFY-SIGNED")]
    if status != "ok":
        return [builtin("G-VERIFY", status=status)]
    return []


def _drive(run: _Run, steps: OutputSteps) -> None:
    """R20, in order."""
    av = run.call(None, steps.availability)
    if av is None or not run.availability(av):
        return
    b = run.call("binding", steps.binding)
    if b is None or not run.binding(b):
        return
    state = run.call("input_state", steps.input_state)
    if state is None:
        return
    run.input_state(state)
    k = run.call("kernel_invariants", steps.kernel)
    if k is None or not run.kernel(k):
        return
    if run.admitted:
        c = run.call("checksum_step", steps.checksum)
        if c is None or not run.checksum(c):
            return
    else:
        run.entries.not_tested.append(NotTested("checksum_step", "unknown_variant"))
    _verify_and_dual(run, steps, av)


def _verify_and_dual(run: _Run, steps: OutputSteps, av: OutputAvailability) -> None:
    """Steps 6 to 8. Findings of 6 and 7 do not stop the run (R20)."""
    if not run.admitted:
        # R26, R27: an unknown variant is `not_applicable` without calling the plugin; nothing to compare.
        run.verify(VerifyOutcome("not_applicable", ()))
        run.entries.not_tested.append(NotTested("dual_checksum", "unknown_variant"))
        _maps(run, steps)
        return
    v = run.call("verify", steps.verify)
    if v is None:
        return
    run.verify(v)
    if av.signed_only:
        run.entries.not_tested.append(NotTested("dual_checksum", "signed_only"))
    elif v.status is None:
        # Nothing the plugin returned can be compared; its G-PLUGIN-ERROR already blocks.
        run.entries.not_tested.append(NotTested("dual_checksum", "earlier_block"))
    else:
        d = run.call("dual_checksum", steps.dual)
        if d is None:
            return
        run.dual(d)
    _maps(run, steps)


def _maps(run: _Run, steps: OutputSteps) -> None:
    m = run.call("map_rules", steps.maps)
    # Availability passed, so the table is valid here.
    if m is not None and run.table is not None:
        run.maps(m, run.table)


def output_report(steps: OutputSteps, sources: Sources, silences: Mapping[str, str], core_version: str) -> GateReport:
    run = _Run(sources)
    _drive(run, steps)
    run.subject["references"] = [ref.to_json() for ref in sorted(run.references, key=reference_key)]
    return assemble(Collected("output", run.subject, run.entries, run.table), core_version, silences)
