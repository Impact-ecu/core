"""Synthetic SPEC-004 scenarios on the SPEC-002 512-byte fixture. Nothing here describes a real ECU.

The rule table copies the SPEC-004 R70 rows as test data only: the gate publishes no seed table (R70 forbids it
until SPEC-003 open question 8 is settled), so every caller supplies one.
"""

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from fractions import Fraction
from typing import Any, cast

from core.definitions import Definition, Dtype, InlineAxis, License, MapDef, Origin, Scaling, SoftwareVersion
from core.evidence import EvidenceAdmission, FieldEvidence, VariantAdmission
from core.gate import AuditFile, Engine, GateBlocked, InputResult, ReleasedImage
from core.gate._audit import AuditArgs
from core.gate._check import CheckInputArgs, run_check_input
from core.gate._evidence import EvidenceAdmissionFn
from core.gate._release import ReleaseArgs, run_release
from core.gate._result import ExportBasis
from core.kernel import Dump, DumpKind, MemoryLayout, Patch, UnverifiedImage, Version, apply, image_hash, layout_hash
from core.plugins import (
    ChecksumRegion,
    Identification,
    Range,
    Reference,
    RegionResult,
    RegionStatus,
    VerifyReport,
)
from core.provenance import Actor, Build, Event, Verifier
from tests.unit.plugin_fixtures import FAMILY, LAYOUT, ORIGINAL, VARIANT, FakePlugin, dump_of

PROJECT = "proj-1"
AS_OF = "2026-10-19T00:00:00Z"
CORE_VERSION = "9.9.9"
U8 = Dtype("uint", 8, "none")
IDENTITY = Scaling(Fraction(1), Fraction(0))

CONFORMANCE: dict[str, Any] = {
    "plugin": {"family": FAMILY, "version": "1.0.0"},
    "verdict": "conformant",
    "variants": [{"checksum_variant_id": VARIANT, "admitted": True}],
}


def key(category: str, map_type: str, combustion: str, fuel: str | None, unit: str) -> dict[str, Any]:
    return {"category": category, "map_type": map_type, "combustion": combustion, "fuel": fuel, "unit": unit}


def rule(rule_id: str, kind: str, k: dict[str, Any], params: dict[str, str], text: str) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "rule_version": 1,
        "kind": kind,
        "severity": "warn",
        "text": text,
        "params": dict(params),
        "key": dict(k),
    }


IGN = key("ignition", "base", "SI", "gasoline", "deg_crank")
RULES = [
    rule(
        "ign.si.gasoline.base.range",
        "range",
        IGN,
        {"min": "-10", "max": "45"},
        "ignition advance outside -10 to 45 deg",
    ),
    rule(
        "ign.si.gasoline.base.boost_cap",
        "conditional_cap",
        IGN,
        {"max": "30", "above": "50", "axis_unit": "kPa_rel"},
        "ignition advance above 30 deg in a cell above 50 kPa relative boost",
    ),
    rule(
        "lambda.si.gasoline.base.range",
        "range",
        key("lambda", "base", "SI", "gasoline", "lambda"),
        {"min": "3/4", "max": "23/20"},
        "lambda outside 0.75 to 1.15",
    ),
    rule(
        "lambda.ci.diesel.base.range",
        "range",
        key("lambda", "base", "CI", "diesel", "lambda"),
        {"min": "23/20"},
        "lambda below 1.15",
    ),
]
TABLE: dict[str, Any] = {"table_id": "gate-tests", "version": "1.0.0", "identify_min_confidence": 800, "rules": RULES}

MAP = MapDef(
    map_id="syn.ign",
    name="SYN_IGN",
    category="ignition",
    map_type="base",
    state="reviewed",
    memory_id="pflash",
    offset=64,
    rows=2,
    cols=2,
    cell_order="x_fastest",
    dtype=U8,
    scaling=IDENTITY,
    unit="deg_crank",
    unit_text=None,
    x=InlineAxis("pflash", 96, 2, U8, IDENTITY, "rpm", None),
    y=InlineAxis("pflash", 100, 2, U8, IDENTITY, "kPa_rel", None),
)


def definition(*mapdefs: MapDef) -> Definition:
    return Definition(
        "synthetic.fixture",
        SoftwareVersion("exact", ("SYN0001",)),
        (),
        mapdefs or (MAP,),
        Origin("platform", ()),
        License("platform_created", None),
        500,
    )


def admit_all(evidence: FieldEvidence | None, as_of: str, verifier: Verifier | None) -> EvidenceAdmission:
    """A `current` field-evidence admission listing the fixture variant as `golden_field` (SPEC-006 R83)."""
    del evidence, as_of, verifier
    return EvidenceAdmission("current", (), "e" * 64, (VariantAdmission(FAMILY, VARIANT, True, (), ()),))


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write(data: bytes, offset: int, after: bytes) -> bytes:
    return data[:offset] + after + data[offset + len(after) :]


def patches_for(data: bytes, edits: Mapping[int, bytes]) -> tuple[Patch, ...]:
    """One patch per edit, `before` read from `data`; edits that change nothing are skipped (SPEC-001 R12)."""
    return tuple(
        Patch("pflash", offset, len(after), data[offset : offset + len(after)], after)
        for offset, after in sorted(edits.items())
        if data[offset : offset + len(after)] != after
    )


# The map edited to cells [[10, 20], [25, 30]], x = [10, 20] rpm, y = [0, 60] kPa_rel: inside every seed range.
GOOD_EDITS: dict[int, bytes] = {64: bytes([10, 20, 25, 30]), 96: bytes([10, 20]), 100: bytes([0, 60])}


def event(event_type: str, payload: Mapping[str, Any], *, event_id: str = "0" * 32, project_id: str = PROJECT) -> Event:
    return Event(
        tenant_id="tenant-1",
        seq=1,
        event_id=event_id,
        project_id=project_id,
        type=event_type,
        payload=dict(payload),
        actor=Actor("user", "user-1"),
        ts=AS_OF,
        prev_hash="0" * 64,
        hash="1" * 64,
    )


def input_args(original: Dump, **overrides: object) -> CheckInputArgs:
    data = b"".join(memory.data for memory in original.memories)
    args: dict[str, object] = {
        "declared_sha256": sha(data),
        "received_sha256": sha(data),
        "project_id": PROJECT,
        "plugin": FakePlugin(),
        "conformance_report": CONFORMANCE,
        "evidence": None,
        "as_of": AS_OF,
        "verifier": None,
        "confirmation": None,
        "rule_table": TABLE,
    }
    return cast("CheckInputArgs", {**args, **overrides})


def check(original: Dump, admit: EvidenceAdmissionFn = admit_all, **overrides: object) -> InputResult:
    return run_check_input(original, input_args(original, **overrides), admit, CORE_VERSION)


@dataclass
class Scenario:
    """A release of the version `edits` makes on `original`, with everything `release` takes."""

    original: Dump = field(default_factory=lambda: dump_of(ORIGINAL))
    edits: Mapping[int, bytes] = field(default_factory=lambda: dict(GOOD_EDITS))
    plugin: object = field(default_factory=FakePlugin)
    overrides: dict[str, object] = field(default_factory=dict[str, object])
    layout: MemoryLayout = LAYOUT

    @property
    def version(self) -> Version:
        data = self.original.memories[0].data
        return Version(image_hash(self.original), layout_hash(self.layout), patches_for(data, self.edits))

    def unverified(self) -> UnverifiedImage:
        return apply(self.original, self.version, self.layout)

    def input(self, **overrides: object) -> InputResult:
        return run_check_input(
            self.original, input_args(self.original, plugin=self.plugin, **overrides), admit_all, CORE_VERSION
        )

    def args(self, **overrides: object) -> ReleaseArgs:
        args: dict[str, object] = {
            "original": self.original,
            "version": self.version,
            "plugin": self.plugin,
            "conformance_report": CONFORMANCE,
            "evidence": None,
            "as_of": AS_OF,
            "verifier": None,
            "references": {},
            "definition": definition(),
            "engine": Engine("SI", "gasoline"),
            "rule_table": TABLE,
            "project_id": PROJECT,
            "suspect_ack": None,
            "silences": (),
        }
        merged = {**args, **self.overrides, **overrides}
        if "input" not in merged:
            merged["input"] = self.input()
        return cast("ReleaseArgs", merged)

    def release(
        self, u: UnverifiedImage | None = None, admit: EvidenceAdmissionFn = admit_all, **overrides: object
    ) -> ReleasedImage:
        return run_release(self.unverified() if u is None else u, self.args(**overrides), admit, CORE_VERSION)

    def blocked(
        self, u: UnverifiedImage | None = None, admit: EvidenceAdmissionFn = admit_all, **overrides: object
    ) -> Mapping[str, Any]:
        """The report of a release that must block (R29)."""
        try:
            self.release(u, admit, **overrides)
        except GateBlocked as error:
            return error.report
        raise AssertionError("the gate did not block")


def export_basis(s: Scenario) -> ExportBasis:
    """What a release of `s` keeps for SPEC-005 R100, with no checksum patches; for sealed-construction tests."""
    return ExportBasis(s.original, s.version, LAYOUT, (), s.input().report)


def doc(value: object) -> dict[str, Any]:
    """A report as plain test data (reports are frozen `Json` in `core`)."""
    return cast("dict[str, Any]", value)


def rule_ids(report: Mapping[str, Any], member: str = "findings") -> list[str]:
    return [f["rule_id"] for f in report[member]]


def skipped_of(report: Mapping[str, Any]) -> list[tuple[str, str | None, str | None, str]]:
    return [(e["kind"], e["map_id"], e["rule_id"], e["reason"]) for e in report["not_tested"]]


def ran_of(report: Mapping[str, Any]) -> list[tuple[str, str | None, str | None]]:
    return [(e["kind"], e["map_id"], e["rule_id"]) for e in report["tested"]]


@dataclass
class SignedPlugin(FakePlugin):
    """The fixture plugin plus one `signed` region (SPEC-002 R46)."""

    def checksums(self, ident: Identification) -> list[ChecksumRegion]:
        signed = ChecksumRegion("z_sig", "pflash", "signed", None, None, None, Reference("none", None, None))
        return [*super().checksums(ident), signed]

    def verify(self, dump: Dump, ident: Identification) -> VerifyReport:
        report = super().verify(dump, ident)
        signed = RegionResult("z_sig", "pflash", "signed", "signature_unverifiable", None, None, None, None)
        status = report.status if report.status in ("fail", "bypassed") else "signature_unverifiable"
        return VerifyReport(status, None, (*report.regions, signed))


@dataclass
class Overridden(FakePlugin):
    """The fixture plugin with any method replaced by a callable."""

    replaced: dict[str, Callable[..., object]] = field(default_factory=dict[str, Callable[..., object]])

    def identify(self, dump: Dump) -> Identification | None:
        if "identify" in self.replaced:
            return cast("Identification | None", self.replaced["identify"](dump))
        return super().identify(dump)

    def layout(self, ident: Identification, dump_kind: DumpKind) -> MemoryLayout:
        if "layout" in self.replaced:
            return cast("MemoryLayout", self.replaced["layout"](ident, dump_kind))
        return super().layout(ident, dump_kind)

    def checksums(self, ident: Identification) -> list[ChecksumRegion]:
        if "checksums" in self.replaced:
            return cast("list[ChecksumRegion]", self.replaced["checksums"](ident))
        return super().checksums(ident)

    def verify(self, dump: Dump, ident: Identification) -> VerifyReport:
        if "verify" in self.replaced:
            return cast("VerifyReport", self.replaced["verify"](dump, ident))
        return super().verify(dump, ident)

    def checksum_patches(self, dump: Dump, ident: Identification) -> list[Patch]:
        if "checksum_patches" in self.replaced:
            return cast("list[Patch]", self.replaced["checksum_patches"](dump, ident))
        return super().checksum_patches(dump, ident)


def raises(*_args: object) -> object:
    raise RuntimeError("plugin failure")


INDEPENDENT = Reference("independent", "ref-sha", "a second implementation from another source")
PYTHON_REGION = ChecksumRegion(
    "p_sha", "pflash", "recalculable", None, (Range(32, 256),), (Range(256, 288),), INDEPENDENT
)


def _sha_result(dump: Dump) -> RegionResult:
    data = dump.memories[0].data
    stored, computed = data[256:288].hex(), sha(data[32:256])
    status: RegionStatus = "ok" if stored == computed else "fail"
    return RegionResult("p_sha", "pflash", "recalculable", status, stored, computed, None, None)


def _sha_patches(dump: Dump) -> list[Patch]:
    data = dump.memories[0].data
    after = bytes.fromhex(sha(data[32:256]))
    return [] if data[256:288] == after else [Patch("pflash", 256, 32, data[256:288], after)]


@dataclass
class PythonPlugin(FakePlugin):
    """One Python region whose checksum is SHA-256 of the calibration area, compared with an independent reference."""

    regions: tuple[ChecksumRegion, ...] = (PYTHON_REGION,)

    def verify(self, dump: Dump, ident: Identification) -> VerifyReport:
        del ident
        result = _sha_result(dump)
        return VerifyReport(result.status, None, (result,))

    def checksum_patches(self, dump: Dump, ident: Identification) -> list[Patch]:
        del ident
        return _sha_patches(dump)


@dataclass
class ShaReference:
    """The `RegionReference` of `PythonPlugin` (SPEC-002 R34)."""

    id: str = "ref-sha"
    version: str = "1.0.0"
    replaced: dict[str, Callable[..., object]] = field(default_factory=dict[str, Callable[..., object]])

    def verify_region(self, dump: Dump, ident: Identification, region: ChecksumRegion) -> RegionResult:
        del ident, region
        if "verify_region" in self.replaced:
            return cast("RegionResult", self.replaced["verify_region"](dump))
        return _sha_result(dump)

    def patches_region(self, dump: Dump, ident: Identification, region: ChecksumRegion) -> list[Patch]:
        del ident, region
        if "patches_region" in self.replaced:
            return cast("list[Patch]", self.replaced["patches_region"](dump))
        return _sha_patches(dump)


SHA_ORIGINAL = write(ORIGINAL, 256, bytes.fromhex(sha(ORIGINAL[32:256])))


BUILD = Build("lockfile", "sha256:" + "44" * 32, "linux/amd64", None)


def file_of(dump: Dump, *, confirmation: Event | None = None) -> AuditFile:
    received = sha(b"".join(memory.data for memory in dump.memories))
    return AuditFile(dump, received, received, confirmation)


def arguments(**overrides: object) -> AuditArgs:
    """The keyword arguments of an audit of the fixture (SPEC-005 §4.1)."""
    args: dict[str, object] = {
        "candidate_origin": "file_service",
        "project_id": PROJECT,
        "plugin": FakePlugin(),
        "conformance_report": CONFORMANCE,
        "evidence": None,
        "as_of": "2026-10-19T00:00:00Z",
        "verifier": None,
        "rule_table": TABLE,
        "definition": None,
        "build": BUILD,
    }
    return cast("AuditArgs", {**args, **overrides})
