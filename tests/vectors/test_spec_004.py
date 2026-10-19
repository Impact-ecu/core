"""SPEC-004 §11: every value in specs/vectors/spec-004/vectors.json, against `core.gate`.

Expected reports are hand-written in generate.py and recomputed by crosscheck.py; nothing here is computed by the
core and then compared with itself. As §11 states, maps enter already decoded and the integrity outcomes of steps
2-7 are inputs: these tests drive the gate's own step order (`output_report`, `input_report`) with them, so the
threshold, admission, stopping, R45 nulls, map rules, silences, verdict and assembly are the gate's.
"""

import json
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import Any, cast

import pytest
import rfc8785

from core.definitions import NON_FINITE, Value
from core.gate import AlertRecord, fatigue, parse_rule_table
from core.gate._input import IdentView, InputAvailability, InputFacts, InputVerifyOutcome, input_report
from core.gate._maps import AxisView, Engine, MapView, UnboundMap
from core.gate._model import BUILTIN, Run, json_hash
from core.gate._output import (
    BindingOutcome,
    ChecksumOutcome,
    DualOutcome,
    InputState,
    KernelOutcome,
    MapsOutcome,
    OutputAvailability,
    Sources,
    VerifyOutcome,
    output_report,
)
from core.gate._report import GateReport, PluginRef, SignedRegion, silences_of
from core.gate._result import authorize
from core.kernel import canonical_json
from core.provenance import DISCLAIMER

ROOT = Path(__file__).resolve().parents[2]
VECTORS: dict[str, Any] = json.loads((ROOT / "specs" / "vectors" / "spec-004" / "vectors.json").read_text("utf-8"))
SPEC004 = (ROOT / "specs" / "SPEC-004-gate.md").read_text("utf-8")
CORE_VERSION = "0.0.0"  # the version generate.py records; the real gate records core.__version__
PROJECT = "proj-1"


@dataclass(frozen=True)
class Ev:
    """An event as the gate reads it (R53): `event_id`, `project_id`, `type`, `payload`."""

    event_id: str
    project_id: str | None
    type: str
    payload: dict[str, Any]


def value(text: str) -> Value:
    return NON_FINITE if text == "non_finite" else Fraction(text)


def axis_view(axis: dict[str, Any] | None) -> AxisView | None:
    return None if axis is None else AxisView(axis["unit"], tuple(value(v) for v in axis["values"]))


def map_view(m: dict[str, Any]) -> MapView | UnboundMap:
    if m["bind_error"]:
        return UnboundMap(m["map_id"])
    return MapView(
        map_id=m["map_id"],
        state=m["label_state"],
        category=m["category"],
        map_type=m["map_type"],
        unit=m["unit"],
        cells=tuple(tuple(value(v) for v in row) for row in m["values"]),
        x=axis_view(m["x_axis"]),
        y=axis_view(m["y_axis"]),
        edited=m["edited"],
    )


def table_of(name: str | None) -> object:
    return None if name is None else VECTORS["rule_tables"][name]["value"]


def runs_of(items: list[dict[str, Any]]) -> tuple[Run, ...]:
    return tuple(Run(r["memory_id"], r["offset"], r["length"]) for r in items)


def signed_of(items: list[dict[str, str]]) -> tuple[SignedRegion, ...]:
    return tuple(SignedRegion(r["memory_id"], r["name"]) for r in items)


@dataclass
class VectorSteps:
    """`OutputSteps` that answer with the integrity outcomes the vector gives (SPEC-004 §11)."""

    inp: dict[str, Any]

    @property
    def integrity(self) -> dict[str, Any]:
        return cast("dict[str, Any]", self.inp["integrity"])

    @property
    def sources(self) -> dict[str, Any]:
        return cast("dict[str, Any]", self.inp["sources"])

    def availability(self) -> OutputAvailability:
        available = self.integrity["plugin_available"]
        variant = self.sources["checksum_variant_id"]
        return OutputAvailability(
            table=parse_rule_table(table_of(self.inp["rule_table"])),
            plugin=PluginRef(**self.sources["plugin"]) if available else None,
            plugin_state="ok" if available else "unavailable",
            conformance_report_hash=self.sources["conformance_report_hash"],
            checksum_variant_id=variant,
            admitted=variant in self.inp["admitted_variants"],
            dual_available=self.integrity["dual"] not in ("unavailable", "reference_none"),
            signed_only=self.integrity["dual"] == "signed_only",
        )

    def binding(self) -> BindingOutcome:
        state = self.integrity["binding"]
        protected = runs_of(self.integrity.get("protected_runs", [])) if state == "containment" else ()
        return BindingOutcome(self.sources["layout_hash"], state == "mismatch", False, protected)

    def input_state(self) -> InputState:
        state: InputState = self.integrity["input_state"]
        return state

    def kernel(self) -> KernelOutcome:
        return KernelOutcome((), invariant=False)

    def checksum(self) -> ChecksumOutcome:
        if self.integrity["checksum_resolution"] != "ok":
            return ChecksumOutcome("G-CHECKSUM-RESOLUTION", None, ())
        return ChecksumOutcome(None, self.sources["release_candidate_hash"], ())

    def verify(self) -> VerifyOutcome:
        return VerifyOutcome(self.integrity["verify_status"], signed_of(self.sources["signed_regions"]))

    def dual(self) -> DualOutcome:
        return DualOutcome("G-DUAL-DIVERGENCE" if self.integrity["dual"] == "diverge" else None, ())

    def maps(self) -> MapsOutcome:
        return MapsOutcome(tuple(map_view(m) for m in self.inp["maps"]), runs_of(self.inp["unmapped_runs"]))


def run_output(case: dict[str, Any]) -> GateReport:
    inp = case["input"]
    sources = inp["sources"]
    silences = [
        Ev(s["event_id"], PROJECT, "rule_silence", {k: s[k] for k in ("rule_id", "justification_commitment")})
        for s in inp["silences"]
    ]
    return output_report(
        VectorSteps(inp),
        Sources(
            definition_hash=sources["definition_hash"],
            engine=Engine(sources["engine"]["combustion"], sources["engine"]["fuel"]),
            input_report_hash=sources["input_report_hash"],
            original_image_hash=sources["original_image_hash"],
            unverified_image_hash=sources["unverified_image_hash"],
            version_hash=sources["version_hash"],
        ),
        silences_of(silences, PROJECT),
        CORE_VERSION,
    )


OUTPUT = {case["name"]: case for case in VECTORS["output_cases"]}


def jcs(value: dict[str, Any]) -> bytes:
    return rfc8785.dumps(value)


# SPEC-004 R1-R8, R20-R45, R60, R61, R63, R70 (per case, as listed in its `rules`).
@pytest.mark.parametrize("name", sorted(OUTPUT))
def test_output_case(name: str) -> None:
    case = OUTPUT[name]
    expected = case["expected"]
    got = run_output(case)
    assert canonical_json(got.report) == jcs(expected["report"])
    assert got.report_hash == expected["report_hash"]
    assert got.verdict == expected["verdict"]
    findings: Any = got.report["findings"]
    assert [json_hash(f) for f in findings] == expected["finding_ids"]
    # SPEC-004 R8, R40: the disclaimer is the first canonical member.
    assert canonical_json(got.report).startswith(b'{"disclaimer":')


@dataclass
class VectorInputSteps:
    inp: dict[str, Any]

    def availability(self) -> InputAvailability:
        ident = self.inp["identification"]
        view = None
        if ident is not None:
            view = IdentView(
                hash=json_hash(ident),
                confidence=ident["confidence"],
                checksum_variant_id=ident["checksum_variant_id"],
                hw_id=ident["hw_id"],
                sw_id=ident["sw_id"],
            )
        return InputAvailability(
            table=parse_rule_table(table_of(self.inp["rule_table"])),
            plugin=PluginRef(**self.inp["plugin"]),
            plugin_state="ok",
            conformance_report_hash=self.inp["conformance_report_hash"],
            admitted=frozenset(self.inp["admitted_variants"]),
            identification=view,
        )

    def verify(self) -> InputVerifyOutcome:
        return InputVerifyOutcome(self.inp["verify_status"], signed_of(self.inp["signed_regions"]), divergence=False)


INPUT = {case["name"]: case for case in VECTORS["input_cases"]}


# SPEC-004 R4, R10-R15 (per case, as listed in its `rules`).
@pytest.mark.parametrize("name", sorted(INPUT))
def test_input_case(name: str) -> None:
    case = INPUT[name]
    inp, expected = case["input"], case["expected"]
    confirm = inp["confirmation"]
    event = (
        None if confirm is None else Ev(confirm["event_id"], confirm["project_id"], confirm["type"], confirm["payload"])
    )
    facts = InputFacts(inp["declared_sha256"], inp["received_sha256"], inp["image_hash"], inp["project_id"])
    got = input_report(VectorInputSteps(inp), facts, event, CORE_VERSION)
    assert canonical_json(got.report.report) == jcs(expected["report"])
    assert got.report.report_hash == expected["report_hash"]
    assert got.report.verdict == expected["verdict"]
    assert got.artifact_state == expected["artifact_state"]


# SPEC-004 R50, R51, R52 (and R61 for A9).
@pytest.mark.parametrize("ack_case", VECTORS["ack_cases"], ids=lambda a: a["name"])
def test_ack_case(ack_case: dict[str, Any]) -> None:
    report = run_output(OUTPUT[ack_case["case"]])
    subject: Any = report.report["subject"]
    ack = None if ack_case["ack"] is None else Ev("0" * 32, PROJECT, "alert_ack", ack_case["ack"])
    reason = authorize(report, subject["release_candidate_hash"], PROJECT, ack)
    assert {"authorized": reason is None, "reason": reason} == ack_case["expected"]


# SPEC-004 R62, R63.
@pytest.mark.parametrize("fatigue_case", VECTORS["fatigue_cases"], ids=lambda f: f["name"])
def test_fatigue_case(fatigue_case: dict[str, Any]) -> None:
    records = [
        AlertRecord(r["family"], r["rule_id"], r["latency_ms"], r["map_changed"]) for r in fatigue_case["records"]
    ]
    got = [
        {
            "alerts": f.alerts,
            "downgrade": f.downgrade,
            "family": f.family,
            "fraction": str(f.fraction),
            "quick_confirms": f.quick_confirms,
            "rule_id": f.rule_id,
        }
        for f in fatigue(records)
    ]
    assert got == fatigue_case["expected"]


# SPEC-004 R32, R33: every vector table is valid and hashes as the vectors say.
@pytest.mark.parametrize("name", sorted(VECTORS["rule_tables"]))
def test_rule_table(name: str) -> None:
    entry = VECTORS["rule_tables"][name]
    table = parse_rule_table(entry["value"])
    assert table is not None
    assert table.hash == entry["hash"]
    assert table.ref() == {
        "table_id": entry["value"]["table_id"],
        "version": entry["value"]["version"],
        "hash": entry["hash"],
    }


# SPEC-004 R8: the disclaimer is verbatim, and SPEC-000 states it.
def test_disclaimer() -> None:
    assert VECTORS["disclaimer"] == DISCLAIMER
    assert DISCLAIMER in (ROOT / "specs" / "SPEC-000-adr.md").read_text("utf-8")


# SPEC-004 §9: every built-in rule's severity and text equal the table of this spec.
def test_builtin_rules_match_the_spec_table() -> None:
    rows = {}
    for line in SPEC004.splitlines():
        cells = [cell.strip() for cell in line.split("|")]
        if len(cells) > 5 and cells[1].startswith("`G-"):
            rows[cells[1].strip("`")] = (cells[3].split(",")[0], cells[4].strip("`"))
    assert rows == dict(BUILTIN)
    assert len(rows) == 23


def test_vector_counts() -> None:
    assert len(OUTPUT) == 39
    assert len(INPUT) == 9
    assert len(VECTORS["ack_cases"]) == 9
    assert len(VECTORS["fatigue_cases"]) == 3
