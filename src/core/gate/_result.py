"""The sealed results of the gate: `InputResult` (SPEC-004 R9), `ReleasedImage` (R29, R51, SPEC-001 R9), the
export authorization of R50-R54 and the export inputs of SPEC-005 R100-R102.

Both classes refuse construction without the module-private seal, every attribute assignment, and pickling or
copying. Python cannot make this a hard barrier (the accepted limitation of SPEC-001 R8); `release` re-checks an
`InputResult`'s binding (R22, R23) and every consumer writes bytes only through `ReleasedImage.to_dump`.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, NoReturn, SupportsIndex, cast, final

from core.gate._model import HEX64, GateError, GateEvent, Verdict, child, ensure, event_of, json_hash, present
from core.gate._report import GateReport
from core.kernel import Dump, DumpKind, MemoryLayout, MemoryShape, Patch, UnverifiedImage, Version
from core.kernel._internal import view
from core.plugins import Identification
from core.provenance import Build, Event, ExportInputs, Json, PluginVersion, Reference, Versions

_SEAL = object()
_ACK_KEYS = frozenset({"image_hash_release", "gate_report_hash", "warnings", "presented_ms", "confirmed_ms"})
_WARNING_KEYS = frozenset({"finding_id", "rule_id", "text"})
_MAX_SAFE_INTEGER = 2**53 - 1

ArtifactState = Literal["accepted", "suspect"]


class GateBlocked(Exception):
    """R29: the verdict is `block`; nothing was constructed. Carries the report (R82)."""

    def __init__(self, report: Mapping[str, Json], report_hash: str) -> None:
        super().__init__(f"gate verdict block (report {report_hash})")
        self.reason = "block"
        self.report = report
        self.report_hash = report_hash


class ExportRefused(GateError):
    """R51, R52: `to_dump` refused; `reason` is one of R52's."""


def _sealed(seal: object, what: str) -> None:
    if seal is not _SEAL:
        raise GateError("sealed", f"{what} is constructed only by core.gate (SPEC-004 R9, R29)")


class _Immutable:
    __slots__ = ()

    def __setattr__(self, name: str, value: object) -> NoReturn:
        raise AttributeError(f"{type(self).__name__} is immutable: cannot set {name!r}")

    def __delattr__(self, name: str) -> NoReturn:
        raise AttributeError(f"{type(self).__name__} is immutable: cannot delete {name!r}")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError(f"{type(self).__name__} cannot be copied or serialized")


@final
class InputResult(_Immutable):
    """R9: `{report, report_hash, artifact_state, identification}`; `identification` is the gate's own `identify`."""

    __slots__ = ("_artifact_state", "_identification", "_report")

    _report: GateReport
    _artifact_state: ArtifactState
    _identification: Identification | None

    def __init__(
        self, seal: object, report: GateReport, artifact_state: ArtifactState, identification: Identification | None
    ) -> None:
        _sealed(seal, "InputResult")
        object.__setattr__(self, "_report", report)
        object.__setattr__(self, "_artifact_state", artifact_state)
        object.__setattr__(self, "_identification", identification)

    @property
    def report(self) -> Mapping[str, Json]:
        return self._report.report

    @property
    def report_hash(self) -> str:
        return self._report.report_hash

    @property
    def artifact_state(self) -> ArtifactState:
        return self._artifact_state

    @property
    def identification(self) -> Identification | None:
        return self._identification

    def __repr__(self) -> str:
        return f"InputResult(artifact_state={self._artifact_state!r}, report_hash={self.report_hash!r})"


def _uint(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= _MAX_SAFE_INTEGER


def _hex(value: object) -> bool:
    return isinstance(value, str) and HEX64.fullmatch(value) is not None


def _text(value: object) -> bool:
    return isinstance(value, str) and value != ""


def _warning(value: object) -> bool:
    keys = set(cast("Mapping[object, object]", value)) if isinstance(value, Mapping) else set()
    return (
        keys == _WARNING_KEYS
        and _hex(child(value, "finding_id"))
        and _text(child(value, "rule_id"))
        and _text(child(value, "text"))
    )


def _sequence(value: object) -> Sequence[object]:
    return cast("Sequence[object]", value) if isinstance(value, Sequence) and not isinstance(value, str) else ()


def _ack_shape(payload: Mapping[str, Json]) -> bool:
    """SPEC-005 R36 `alert_ack`, including `presented_ms <= confirmed_ms` (R52 `bad_payload`)."""
    warnings = payload.get("warnings")
    presented, confirmed = payload.get("presented_ms"), payload.get("confirmed_ms")
    return (
        set(payload) == _ACK_KEYS
        and _hex(payload.get("image_hash_release"))
        and _hex(payload.get("gate_report_hash"))
        and isinstance(warnings, Sequence)
        and not isinstance(warnings, str)
        and all(_warning(item) for item in warnings)
        and _uint(presented)
        and _uint(confirmed)
        and cast("int", presented) <= cast("int", confirmed)
    )


@dataclass(frozen=True, slots=True)
class AlertWarning:
    """R54: one `warn` finding of an output report as an `alert_ack` lists it (R50, SPEC-005 R36)."""

    finding_id: str
    rule_id: str
    text: str

    def to_json(self) -> dict[str, Json]:
        return {"finding_id": self.finding_id, "rule_id": self.rule_id, "text": self.text}


def _gate_text(value: object, rule: str) -> str:
    """A string the gate wrote into its own report; anything else is a gate bug (SPEC-001 R73)."""
    return present(value if isinstance(value, str) else None, rule)


def _warnings(report: GateReport) -> tuple[AlertWarning, ...]:
    """R43, R50: every `warn` finding of `findings`, in report order; the one source R52 and R54 share."""
    return tuple(
        AlertWarning(
            json_hash(cast("Json", item)),
            _gate_text(child(item, "rule_id"), "SPEC-004 R2"),
            _gate_text(child(item, "text"), "SPEC-004 R2"),
        )
        for item in _sequence(report.report.get("findings"))
        if child(item, "severity") == "warn"
    )


def _mismatch(report: GateReport, image_hash: str, payload: Mapping[str, Json]) -> str | None:
    """R52 after `bad_payload`: the first of image, report, `(finding_id, rule_id)` list and text list."""
    warns = _warnings(report)
    acked = _sequence(payload.get("warnings"))
    checks = (
        ("image_mismatch", payload.get("image_hash_release") == image_hash),
        ("report_mismatch", payload.get("gate_report_hash") == report.report_hash),
        (
            "findings_mismatch",
            [(child(w, "finding_id"), child(w, "rule_id")) for w in acked]
            == [(warn.finding_id, warn.rule_id) for warn in warns],
        ),
        ("text_mismatch", [child(w, "text") for w in acked] == [warn.text for warn in warns]),
    )
    return next((reason for reason, holds in checks if not holds), None)


def authorize(report: GateReport, image_hash: str, project_id: str, ack: GateEvent | None) -> str | None:
    """R52, in its order; None when authorized. An ack of another project is ignored (R53)."""
    if ack is not None and ack.project_id != project_id:
        ack = None
    if report.verdict == "no findings":
        return None if ack is None else "unexpected_ack"
    if ack is None:
        return "ack_required"
    payload = event_of(ack, "alert_ack", project_id)
    if payload is None or not _ack_shape(payload):
        return "bad_payload"
    return _mismatch(report, image_hash, payload)


@dataclass(frozen=True, slots=True)
class ExportBasis:
    """SPEC-005 R100: what the `release` call held that `ExportInputs` needs and the report does not carry."""

    original: Dump
    version: Version
    layout: MemoryLayout
    checksum_patches: tuple[Patch, ...]
    input_report: Mapping[str, Json]


@final
class ReleasedImage(_Immutable):
    """R29: an image the gate let out, with its verdict, report and `report_hash`; bytes only via `to_dump` (R51)."""

    __slots__ = ("_basis", "_candidate", "_project_id", "_report")

    _candidate: UnverifiedImage
    _report: GateReport
    _project_id: str
    _basis: ExportBasis

    def __init__(
        self, seal: object, candidate: UnverifiedImage, report: GateReport, project_id: str, basis: ExportBasis
    ) -> None:
        _sealed(seal, "ReleasedImage")
        # SPEC-000 invariant 10, SPEC-001 R42: never constructed with a block verdict, and the image is the
        # release candidate the report names.
        ensure(report.verdict != "block", "SPEC-004 R29")
        subject = child(report.report, "subject")
        ensure(child(subject, "release_candidate_hash") == candidate.image_hash, "SPEC-004 R29")
        object.__setattr__(self, "_candidate", candidate)
        object.__setattr__(self, "_report", report)
        object.__setattr__(self, "_project_id", project_id)
        object.__setattr__(self, "_basis", basis)

    @property
    def dump_kind(self) -> DumpKind:
        return self._candidate.dump_kind

    @property
    def memories(self) -> tuple[MemoryShape, ...]:
        return self._candidate.memories

    @property
    def image_hash(self) -> str:
        return self._candidate.image_hash

    @property
    def verdict(self) -> Verdict:
        return self._report.verdict

    @property
    def report(self) -> Mapping[str, Json]:
        return self._report.report

    @property
    def report_hash(self) -> str:
        return self._report.report_hash

    def to_dump(self, ack: Event | None) -> Dump:
        """R51: the `Dump` only when R52 authorizes it; otherwise `ExportRefused(reason)`."""
        reason = authorize(self._report, self.image_hash, self._project_id, ack)
        if reason is not None:
            raise ExportRefused(reason)
        return view(self._candidate)

    def __repr__(self) -> str:
        return f"ReleasedImage(verdict={self.verdict!r}, image_hash={self.image_hash!r})"


def _released(value: object, what: str) -> ReleasedImage:
    if not isinstance(value, ReleasedImage):
        raise GateError("bad_type", f"{what} takes a ReleasedImage")
    return value


def alert_warnings(released: ReleasedImage) -> tuple[AlertWarning, ...]:
    """R54: the warnings an `alert_ack` of this release lists, in report order; `()` for `no findings`."""
    return _warnings(_released(released, "alert_warnings")._report)


def alert_ack_payload(released: ReleasedImage, *, presented_ms: int, confirmed_ms: int) -> dict[str, Json]:
    """R54: the SPEC-005 R36 `alert_ack` payload that R52 authorizes for this release."""
    image = _released(released, "alert_ack_payload")
    if image.verdict == "no findings":
        raise GateError("unexpected_ack", "a no findings release takes no alert_ack (SPEC-004 R52)")
    if not (_uint(presented_ms) and _uint(confirmed_ms) and presented_ms <= confirmed_ms):
        raise GateError("bad_payload", "presented_ms and confirmed_ms are integers, presented_ms <= confirmed_ms")
    return {
        "image_hash_release": image.image_hash,
        "gate_report_hash": image.report_hash,
        "warnings": [warning.to_json() for warning in _warnings(image._report)],
        "presented_ms": presented_ms,
        "confirmed_ms": confirmed_ms,
    }


def export_inputs(released: ReleasedImage, *, build: Build) -> ExportInputs:
    """SPEC-005 R100-R102: the `ExportInputs` of this release, from what its `release` call held and its own
    report; only `build` (SPEC-005 R16) comes from the caller."""
    image = _released(released, "export_inputs")
    if not isinstance(build, Build):
        raise GateError("bad_type", "export_inputs takes a provenance Build")
    report = image.report
    gate, subject = child(report, "gate"), child(report, "subject")
    plugin = child(subject, "plugin")
    plugins = (
        PluginVersion(
            _gate_text(child(plugin, "family"), "SPEC-004 R45"),
            _gate_text(child(plugin, "version"), "SPEC-004 R45"),
            _gate_text(child(subject, "conformance_report_hash"), "SPEC-004 R45"),
        ),
    )
    references = tuple(
        Reference(_gate_text(child(r, "id"), "SPEC-004 R45"), _gate_text(child(r, "version"), "SPEC-004 R45"))
        for r in _sequence(child(subject, "references"))
    )
    versions = Versions(
        _gate_text(child(gate, "core_version"), "SPEC-004 R45"),
        plugins,
        _gate_text(child(child(gate, "rule_table"), "version"), "SPEC-004 R45"),
        references,
    )
    basis = image._basis
    return ExportInputs(
        original=basis.original,
        version=basis.version,
        layout=basis.layout,
        checksum_patches=basis.checksum_patches,
        definition_hash=_gate_text(child(subject, "definition_hash"), "SPEC-004 R45"),
        versions=versions,
        gate_report=report,
        input_report=basis.input_report,
        build=build,
    )


def seal() -> object:
    """The construction seal, for `core.gate` modules only."""
    return _SEAL
