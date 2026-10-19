"""Verdicts, findings, check entries and the built-in rules of SPEC-004 §2, §6 and §9."""

import hashlib
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal, Protocol, TypedDict, Unpack, cast

from core.kernel import canonical_json
from core.provenance import Json

Verdict = Literal["block", "warn", "no findings"]
Severity = Literal["block", "warn", "info"]
Axis = Literal["x", "y"]
Combustion = Literal["SI", "CI"]
Fuel = Literal["gasoline", "E27", "E100", "flex", "diesel"]

SPEC = "SPEC-004"
HEX64 = re.compile(r"[0-9a-f]{64}")
BUILTIN_VERSION = 1


class GateError(Exception):
    """Every gate rejection that is not a report: a stable machine `reason` (SPEC-004 R82)."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


class GateInvariantError(Exception):
    """A runtime assertion of SPEC-004 R82 failed: a gate bug, never a user error (SPEC-001 R73)."""

    def __init__(self, rule: str) -> None:
        super().__init__(f"invariant_violation: {rule}")
        self.rule = rule


def ensure(holds: bool, rule: str) -> None:
    # Not `assert`: it must stay active under `python -O` (SPEC-001 R73).
    if not holds:
        raise GateInvariantError(rule)


def present[T](value: T | None, rule: str) -> T:
    """`value`, which the step order guarantees is set; otherwise a gate bug (SPEC-001 R73)."""
    if value is None:
        raise GateInvariantError(rule)
    return value


class Stop(Exception):
    """Ends one step early with `outcome` (a built-in rule id or a plugin state); never leaves the step."""

    def __init__(self, outcome: str) -> None:
        super().__init__(outcome)
        self.outcome = outcome


class GateFault(Exception):
    """An error inside a step that the gate cannot attribute (SPEC-004 R28): becomes `G-INVARIANT`, S1."""


def shielded[T](step: Callable[[], T]) -> T:
    """Run `step`; any exception it raises becomes a `GateFault` the driver turns into a finding (R28)."""
    try:
        return step()
    except Exception as error:
        raise GateFault(type(error).__name__) from error


class GateEvent(Protocol):
    """The four fields the gate reads from an event (SPEC-004 R53)."""

    @property
    def event_id(self) -> str: ...

    @property
    def project_id(self) -> str | None: ...

    @property
    def type(self) -> str: ...

    @property
    def payload(self) -> Mapping[str, Json]: ...


def event_of(event: GateEvent | None, event_type: str, project_id: str) -> Mapping[str, Json] | None:
    """The payload of `event` when it is of `event_type` and of this project; otherwise it is ignored (R53)."""
    if event is None or event.type != event_type or event.project_id != project_id:
        return None
    return event.payload


@dataclass(frozen=True, slots=True)
class Run:
    """A byte run, SPEC-001 offsets."""

    memory_id: str
    offset: int
    length: int

    def to_json(self) -> dict[str, Json]:
        return {"memory_id": self.memory_id, "offset": self.offset, "length": self.length}


class Located(Protocol):
    @property
    def memory_id(self) -> str: ...

    @property
    def offset(self) -> int: ...


def run_key(item: Located) -> tuple[str, int]:
    """`(memory_id, offset)`: the order of runs and patches (R23, R31)."""
    return (item.memory_id, item.offset)


@dataclass(frozen=True, slots=True)
class Finding:
    """SPEC-004 §2. `text` never embeds a cell value (R2)."""

    rule_id: str
    rule_version: int
    severity: Severity
    text: str
    map_id: str | None = None
    cells: tuple[tuple[int, int], ...] = ()
    axis: Axis | None = None
    breakpoints: tuple[int, ...] = ()
    runs: tuple[Run, ...] = ()
    incident: Literal["S1"] | None = None

    def to_json(self) -> dict[str, Json]:
        return {
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "severity": self.severity,
            "text": self.text,
            "map_id": self.map_id,
            "cells": [[row, col] for row, col in sorted(self.cells)],
            "axis": self.axis,
            "breakpoints": sorted(self.breakpoints),
            "runs": [run.to_json() for run in sorted(self.runs, key=run_key)],
            "incident": self.incident,
        }


def finding_key(finding: Finding) -> tuple[str, str, str]:
    """R42: `(rule_id, map_id, axis)`, null as the empty string."""
    return (finding.rule_id, finding.map_id or "", finding.axis or "")


@dataclass(frozen=True, slots=True)
class Tested:
    kind: str
    map_id: str | None = None
    rule_id: str | None = None

    def to_json(self) -> dict[str, Json]:
        return {"kind": self.kind, "map_id": self.map_id, "rule_id": self.rule_id}


@dataclass(frozen=True, slots=True)
class NotTested:
    kind: str
    reason: str
    map_id: str | None = None
    rule_id: str | None = None

    def to_json(self) -> dict[str, Json]:
        return {"kind": self.kind, "map_id": self.map_id, "rule_id": self.rule_id, "reason": self.reason}


def tested_key(entry: Tested) -> tuple[str, str, str]:
    return (entry.kind, entry.map_id or "", entry.rule_id or "")


def not_tested_key(entry: NotTested) -> tuple[str, str, str, str]:
    return (entry.kind, entry.map_id or "", entry.rule_id or "", entry.reason)


# §9: built-in rules are code, `rule_version` 1, with fixed texts. `<status>` is the only substitution.
BUILTIN: Mapping[str, tuple[Severity, str]] = MappingProxyType(
    {
        "G-INPUT-HASH": ("block", "received file hash differs from the declared hash"),
        "G-INPUT-IDENTIFY": ("block", "identification below the confidence threshold and not confirmed"),
        "G-INPUT-VERIFY": ("block", "input verify returned <status>"),
        "G-INPUT-SIGNED": ("warn", "signed region: its signature cannot be verified"),
        "G-UNAVAILABLE-RULES": ("block", "rule table unavailable; export blocked"),
        "G-UNAVAILABLE-PLUGIN": ("block", "plugin unavailable; export blocked"),
        "G-UNAVAILABLE-DUAL": ("block", "reference checksum implementation unavailable; export blocked"),
        "G-PLUGIN-ERROR": ("block", "plugin call failed"),
        "G-BINDING": ("block", "image, version, layout, plugin or input check do not match"),
        "G-INPUT-SUSPECT": ("block", "input artifact is suspect and was not acknowledged"),
        "G-PROTECTED": ("block", "a patch touches a region that is not calibration"),
        "G-INVARIANT": ("block", "kernel invariant violated"),
        "G-CHECKSUM-CONTAINMENT": ("block", "checksum patches outside a checksum region"),
        "G-CHECKSUM-RESOLUTION": ("block", "checksum coverage could not be resolved on this file"),
        "G-VERIFY": ("block", "checksum verify returned <status> after the checksum step"),
        "G-VERIFY-SIGNED": ("warn", "signed region: its signature cannot be verified, and an edit may invalidate it"),
        "G-DUAL-DIVERGENCE": ("block", "checksum implementations disagree"),
        "G-DEFINITION": ("block", "a map of the definition does not fit this file"),
        "G-NONFINITE": ("block", "map value is not a finite number"),
        "G-AXIS-MONOTONIC": ("block", "axis is not strictly monotonic"),
        "G-INJECTOR-DUTY": ("block", "injector duty above 100%"),
        "G-UNREVIEWED": ("warn", "you edited a map whose meaning has not been confirmed"),
        "G-UNMAPPED": ("warn", "you edited bytes that belong to no known map"),
    }
)
# R2: `incident: "S1"` only where the spec says so (R24, R25, R27, R28 and R13 "as in R27").
S1_RULES = frozenset({"G-INVARIANT", "G-DUAL-DIVERGENCE"})


class Where(TypedDict, total=False):
    """Where a built-in finding applies (R2), and the `<status>` of its text."""

    status: str
    map_id: str
    cells: Sequence[tuple[int, int]]
    axis: Axis
    breakpoints: Sequence[int]
    runs: Sequence[Run]


def builtin(rule_id: str, **where: Unpack[Where]) -> Finding:
    severity, text = BUILTIN[rule_id]
    return Finding(
        rule_id=rule_id,
        rule_version=BUILTIN_VERSION,
        severity=severity,
        text=text.replace("<status>", where.get("status", "")),
        map_id=where.get("map_id"),
        cells=tuple(where.get("cells", ())),
        axis=where.get("axis"),
        breakpoints=tuple(where.get("breakpoints", ())),
        runs=tuple(where.get("runs", ())),
        incident="S1" if rule_id in S1_RULES else None,
    )


def blocks(findings: Sequence[Finding]) -> bool:
    return any(finding.severity == "block" for finding in findings)


def verdict_of(findings: Sequence[Finding]) -> Verdict:
    """R4: from `findings` only (information and silenced excluded by the caller)."""
    if blocks(findings):
        return "block"
    if any(finding.severity == "warn" for finding in findings):
        return "warn"
    return "no findings"


def json_hash(value: Json) -> str:
    """R43: lowercase hex `sha256(JCS(value))`."""
    return hashlib.sha256(canonical_json(value)).hexdigest()


def freeze_object(value: Mapping[str, Json]) -> Mapping[str, Json]:
    """An immutable copy of a JSON object: objects as read-only mappings, arrays as tuples."""
    return MappingProxyType({key: freeze(item) for key, item in value.items()})


def freeze(value: Json) -> Json:
    if isinstance(value, Mapping):
        return freeze_object(value)
    if isinstance(value, Sequence) and not isinstance(value, str):
        return tuple(freeze(item) for item in value)
    return value


def child(value: object, key: str) -> object:
    """`value[key]` of a mapping, or None."""
    return cast("Mapping[str, object]", value).get(key) if isinstance(value, Mapping) else None
