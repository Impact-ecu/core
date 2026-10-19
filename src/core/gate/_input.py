"""The input gate's checks and report (SPEC-004 R10-R15, R45), independent of how the plugin is called.

`check_input` supplies the outcomes from a real plugin; the vector tests supply them as data. Threshold,
confirmation, admission and status mapping are decided here, once, for both.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, Protocol

from core.gate._maps import Entries
from core.gate._model import Finding, GateEvent, GateFault, NotTested, Tested, builtin, event_of
from core.gate._output import PluginState
from core.gate._report import Collected, GateReport, PluginRef, SignedRegion, assemble, signed_json
from core.gate._rules import Table
from core.provenance import Json

ArtifactState = Literal["accepted", "suspect"]
_SHA256 = re.compile(r"[0-9a-fA-F]{64}")


@dataclass(frozen=True, slots=True)
class IdentView:
    """What the input gate reads from `identify`'s result (R12); `hash` is `sha256(JCS(identification))`."""

    hash: str
    confidence: int
    checksum_variant_id: str | None
    hw_id: str | None
    sw_id: str | None


@dataclass(frozen=True, slots=True)
class InputAvailability:
    """R10, R12, R15, R16. `admitted` is the conformance report's set intersected with field evidence."""

    table: Table | None
    plugin: PluginRef | None
    plugin_state: PluginState
    conformance_report_hash: str | None
    admitted: frozenset[str]
    identification: IdentView | None


@dataclass(frozen=True, slots=True)
class InputVerifyOutcome:
    """R13. `status` is None when the plugin call or its contract check failed."""

    status: str | None
    signed_regions: tuple[SignedRegion, ...]
    divergence: bool


@dataclass(frozen=True, slots=True)
class InputFacts:
    declared_sha256: str
    received_sha256: str
    image_hash: str
    project_id: str


class InputSteps(Protocol):
    def availability(self) -> InputAvailability: ...
    def verify(self) -> InputVerifyOutcome: ...


@dataclass(frozen=True, slots=True)
class InputReport:
    report: GateReport
    artifact_state: ArtifactState


def hash_matches(declared: str, received: str) -> bool:
    """R11: compared as lowercase hex."""
    return all(_SHA256.fullmatch(value) for value in (declared, received)) and declared.lower() == received.lower()


def _confirmed(
    payload: Mapping[str, Json] | None, facts: InputFacts, plugin: PluginRef | None, ident: IdentView
) -> bool:
    """R12: the confirmation names exactly this file, image, plugin and identification."""
    expected: dict[str, Json] = {
        "artifact_sha256": facts.received_sha256,
        "image_hash": facts.image_hash,
        "family": None if plugin is None else plugin.family,
        "plugin_version": None if plugin is None else plugin.version,
        "hw_id": ident.hw_id,
        "sw_id": ident.sw_id,
        "checksum_variant_id": ident.checksum_variant_id,
    }
    return payload is not None and plugin is not None and all(payload.get(k) == v for k, v in expected.items())


class _Input:
    def __init__(self, facts: InputFacts) -> None:
        self.facts = facts
        self.entries = Entries()
        self.subject: dict[str, Json] = {
            "checksum_variant_id": None,
            "confidence": None,
            "conformance_report_hash": None,
            "declared_sha256": facts.declared_sha256,
            "identification_hash": None,
            "identify_confirmation_event_id": None,
            "image_hash": facts.image_hash,
            "plugin": None,
            "received_sha256": facts.received_sha256,
            "signed_regions": [],
            "verify_status": None,
        }

    def finding(self, finding: Finding) -> None:
        self.entries.findings.append(finding)

    def skip(self, reason: str, *kinds: str) -> None:
        self.entries.not_tested.extend(NotTested(kind, reason) for kind in kinds)

    def availability(self, av: InputAvailability) -> bool:
        """R10, R12, R15: True when identification can be evaluated."""
        self.subject["plugin"] = None if av.plugin is None else av.plugin.to_json()
        ident = av.identification
        if av.plugin_state != "unavailable":
            self.subject["conformance_report_hash"] = av.conformance_report_hash
        if ident is not None:
            self.subject["checksum_variant_id"] = ident.checksum_variant_id
            self.subject["confidence"] = ident.confidence
            self.subject["identification_hash"] = ident.hash
        unavailable = av.table is None or av.plugin_state == "unavailable"
        if av.table is None:
            self.finding(builtin("G-UNAVAILABLE-RULES"))
        if av.plugin_state == "unavailable":
            self.finding(builtin("G-UNAVAILABLE-PLUGIN"))
        if av.plugin_state == "error":
            self.finding(builtin("G-PLUGIN-ERROR"))
        if unavailable:
            self.skip("gate_unavailable", "identify", "input_verify")
            return False
        self.entries.tested.append(Tested("identify"))
        if av.plugin_state == "error":
            self.skip("identify_failed", "input_verify")
            return False
        return True

    def identified(self, av: InputAvailability, table: Table, confirmation: GateEvent | None) -> IdentView | None:
        """R12: above the threshold, or confirmed; the confirmation is recorded only when it was used."""
        ident = av.identification
        if ident is not None and ident.confidence > table.identify_min_confidence:
            return ident
        payload = event_of(confirmation, "identification_confirmed", self.facts.project_id)
        if ident is not None and confirmation is not None and _confirmed(payload, self.facts, av.plugin, ident):
            self.subject["identify_confirmation_event_id"] = confirmation.event_id
            return ident
        self.finding(builtin("G-INPUT-IDENTIFY"))
        self.skip("identify_failed", "input_verify")
        return None

    def verify(self, outcome: InputVerifyOutcome) -> None:
        """R13."""
        status = outcome.status
        self.subject["verify_status"] = status
        self.subject["signed_regions"] = signed_json(outcome.signed_regions)
        if status is None:
            self.finding(builtin("G-PLUGIN-ERROR"))
        elif status == "signature_unverifiable":
            self.finding(builtin("G-INPUT-SIGNED"))
        elif status != "ok":
            self.finding(builtin("G-INPUT-VERIFY", status=status))
        if outcome.divergence:
            self.finding(builtin("G-DUAL-DIVERGENCE"))


def _drive(run: _Input, steps: InputSteps, confirmation: GateEvent | None) -> Table | None:
    try:
        av = steps.availability()
    except GateFault:
        run.finding(builtin("G-INVARIANT"))
        run.skip("earlier_block", "identify", "input_verify")
        return None
    if not run.availability(av) or av.table is None:
        return av.table
    ident = run.identified(av, av.table, confirmation)
    if ident is None:
        return av.table
    run.entries.tested.append(Tested("input_verify"))
    if ident.checksum_variant_id not in av.admitted:
        # R13, R15, R16: an unknown variant is not verified; `not_applicable` blocks.
        run.verify(InputVerifyOutcome("not_applicable", (), divergence=False))
        return av.table
    try:
        outcome = steps.verify()
    except GateFault:
        run.finding(builtin("G-INVARIANT"))
        return av.table
    run.verify(outcome)
    return av.table


def input_report(
    steps: InputSteps, facts: InputFacts, confirmation: GateEvent | None, core_version: str
) -> InputReport:
    run = _Input(facts)
    run.entries.tested.append(Tested("input_hash"))
    if not hash_matches(facts.declared_sha256, facts.received_sha256):
        run.finding(builtin("G-INPUT-HASH"))
    table = _drive(run, steps, confirmation)
    report = assemble(Collected("input", run.subject, run.entries, table), core_version, {})
    # R14: a block verdict marks the artifact suspect.
    return InputReport(report, "suspect" if report.verdict == "block" else "accepted")
