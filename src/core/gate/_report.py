"""Report assembly: R3, R4, R8, R40-R43, R61; the shapes both stages record in their subjects (§6)."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from core.gate._maps import Entries
from core.gate._model import (
    BUILTIN,
    SPEC,
    Finding,
    GateEvent,
    Verdict,
    event_of,
    finding_key,
    freeze_object,
    json_hash,
    not_tested_key,
    tested_key,
    verdict_of,
)
from core.gate._rules import Table
from core.provenance import DISCLAIMER, Json


@dataclass(frozen=True, slots=True)
class PluginRef:
    family: str
    version: str

    def to_json(self) -> dict[str, Json]:
        return {"family": self.family, "version": self.version}


@dataclass(frozen=True, slots=True)
class SignedRegion:
    memory_id: str
    name: str

    def to_json(self) -> dict[str, Json]:
        return {"memory_id": self.memory_id, "name": self.name}


@dataclass(frozen=True, slots=True)
class ReferenceRef:
    """A `RegionReference` used in R25 or R27, as the output subject lists it (SPEC-002 R34)."""

    id: str
    version: str

    def to_json(self) -> dict[str, Json]:
        return {"id": self.id, "version": self.version}


def signed_json(regions: Sequence[SignedRegion]) -> list[Json]:
    """§6: sorted by `(memory_id, name)`."""
    return [region.to_json() for region in sorted(regions, key=_signed_key)]


def _signed_key(region: SignedRegion) -> tuple[str, str]:
    return (region.memory_id, region.name)


def reference_key(reference: ReferenceRef) -> tuple[str, str]:
    return (reference.id, reference.version)


@dataclass(frozen=True, slots=True)
class GateReport:
    """A report (§6) frozen as JSON, with `report_hash` (R43) and its verdict (R4)."""

    report: Mapping[str, Json]
    report_hash: str
    verdict: Verdict


def silences_of(events: Sequence[GateEvent], project_id: str) -> dict[str, str]:
    """R60, R61: `rule_id` -> the smallest `event_id` of a silence with a justification commitment."""
    effective: dict[str, str] = {}
    for event in events:
        payload = event_of(event, "rule_silence", project_id)
        rule_id = None if payload is None else payload.get("rule_id")
        commitment = None if payload is None else payload.get("justification_commitment")
        if isinstance(rule_id, str) and isinstance(commitment, str):
            current = effective.get(rule_id)
            effective[rule_id] = event.event_id if current is None else min(current, event.event_id)
    return effective


def _findings(items: Sequence[Finding]) -> list[Json]:
    return [finding.to_json() for finding in sorted(items, key=finding_key)]


@dataclass(frozen=True, slots=True)
class Collected:
    """What one run of either stage produced, before assembly."""

    stage: str
    subject: Mapping[str, Json]
    entries: Entries
    table: Table | None


def assemble(run: Collected, core_version: str, silences: Mapping[str, str]) -> GateReport:
    """The canonical report (R40). `info` findings go to `information` (R3); a silenced table `warn` goes to
    `silenced` (R61); the verdict comes from `findings` only (R4)."""
    kept: list[Finding] = []
    information: list[Finding] = []
    silenced: list[Finding] = []
    for finding in run.entries.findings:
        if finding.severity == "info":
            information.append(finding)
        elif finding.severity == "warn" and finding.rule_id not in BUILTIN and finding.rule_id in silences:
            silenced.append(finding)
        else:
            kept.append(finding)
    verdict = verdict_of(kept)
    table = run.table
    report: dict[str, Json] = {
        "disclaimer": DISCLAIMER,
        "findings": _findings(kept),
        "gate": {"core_version": core_version, "rule_table": None if table is None else table.ref(), "spec": SPEC},
        "information": _findings(information),
        "not_tested": [entry.to_json() for entry in sorted(run.entries.not_tested, key=not_tested_key)],
        "silenced": [
            {**finding.to_json(), "silence_event_id": silences[finding.rule_id]}
            for finding in sorted(silenced, key=finding_key)
        ],
        "stage": run.stage,
        "subject": run.subject,
        "tested": [entry.to_json() for entry in sorted(run.entries.tested, key=tested_key)],
        "verdict": verdict,
    }
    frozen = freeze_object(report)
    return GateReport(frozen, json_hash(frozen), verdict)
