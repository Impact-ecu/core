"""The importer contract of SPEC-006 §3: protocol, outcomes, `run_import` and `dispatch`."""

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal, Protocol

from core.importers._json import FrozenObject, JsonValue, NotJsonError, freeze_json, jcs, jcs_hash
from core.kernel import Dump, DumpKind, KernelError, Memory, image_hash

CONTRACT_VERSION = 1
MAX_INPUT_BYTES = 67108864
MAX_MEMORIES = 8
RAW_IMPORTER_ID = "impact.raw"
IMPORT_RECORD_SCHEMA = "impact.import-record.v1"

RejectReason = Literal[
    "unsupported_container",
    "encrypted_container",
    "malformed",
    "too_large",
    "limit_exceeded",
    "empty_input",
    "bad_params",
    "dump_kind_conflict",
    "ambiguous_container",
]
# `ambiguous_container` is produced by dispatch only (R25), never by an importer.
IMPORTER_REASONS: frozenset[str] = frozenset(
    {
        "unsupported_container",
        "encrypted_container",
        "malformed",
        "too_large",
        "limit_exceeded",
        "empty_input",
        "bad_params",
        "dump_kind_conflict",
    }
)
DUMP_KINDS: frozenset[str] = frozenset({"bench_full", "boot_full", "obd_full", "obd_partial", "virtual"})

IMPORTER_ID = re.compile(r"[a-z][a-z0-9]*(\.[a-z0-9][a-z0-9_]*)+")
CONTAINER_KIND = re.compile(r"[a-z][a-z0-9_]{0,31}")
TOOL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._+-]{0,63}")
MEMORY_ID = re.compile(r"[a-z][a-z0-9_]{0,31}")
# Semantic Versioning 2.0.0, the regular expression published with the specification.
SEMVER = re.compile(
    r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?",
    re.ASCII,
)


class ImporterContractError(Exception):
    """An importer broke the contract (SPEC-006 R12, R35, R111); the file is not imported.

    Not a `KernelError`: code that handles kernel rejections must not swallow it.
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True, slots=True)
class ImportParams:
    """SPEC-006 §3.1. Validated by `run_import`, never on construction, so a bad value is `bad_params`."""

    dump_kind: DumpKind
    source_tool: str | None
    options: Mapping[str, JsonValue]


@dataclass(frozen=True, slots=True)
class ImportRejected:
    """SPEC-006 R10: why a file was not imported, and the container recognized, if any."""

    reason: RejectReason
    container_kind: str | None


@dataclass(frozen=True, slots=True)
class ImportRecord:
    """SPEC-006 §3.2. Built only by `run_import` (R20); every hash in it is computed by the core."""

    importer_id: str
    importer_version: str
    source_tool: str | None
    container_kind: str
    input_sha256: str
    dump_kind: DumpKind
    options: Mapping[str, JsonValue]
    image_hash: str
    schema: str = field(default=IMPORT_RECORD_SCHEMA, init=False)

    def to_json(self) -> Mapping[str, JsonValue]:
        return {
            "schema": self.schema,
            "importer_id": self.importer_id,
            "importer_version": self.importer_version,
            "source_tool": self.source_tool,
            "container_kind": self.container_kind,
            "input_sha256": self.input_sha256,
            "dump_kind": self.dump_kind,
            "options": self.options,
            "image_hash": self.image_hash,
        }


@dataclass(frozen=True, slots=True)
class Imported:
    """SPEC-006 §3.2: the dump, its record and `import_record_hash` (R21)."""

    dump: Dump
    record: ImportRecord
    import_record_hash: str


class Importer(Protocol):
    """SPEC-006 R10. `import_file` never raises and never guesses (R12, R13)."""

    importer_id: str
    version: str
    contract_version: int
    container_kind: str

    def import_file(self, data: bytes, params: ImportParams) -> Dump | ImportRejected: ...


@dataclass(frozen=True, slots=True)
class _Identity:
    importer_id: str
    version: str
    container_kind: str


def import_record_jcs(record: ImportRecord) -> bytes:
    """UTF-8 JCS of the record (SPEC-006 R1, R21)."""
    return jcs(record.to_json())


def import_record_hash(record: ImportRecord) -> str:
    """SPEC-006 R21: `sha256(JCS(ImportRecord))`."""
    return jcs_hash(record.to_json())


def outcome_jcs(outcome: Imported | ImportRejected) -> bytes:
    """UTF-8 JCS of an outcome, the value R14, R33 and R36 compare across runs and versions."""
    if isinstance(outcome, Imported):
        return jcs(
            {
                "outcome": "imported",
                "record": outcome.record.to_json(),
                "import_record_hash": outcome.import_record_hash,
            }
        )
    return jcs(
        {
            "outcome": "rejected",
            "rejection": {"reason": outcome.reason, "container_kind": outcome.container_kind},
        }
    )


def _matches(pattern: re.Pattern[str], value: object) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _identity(importer: Importer) -> _Identity:
    try:
        importer_id = importer.importer_id
        version = importer.version
        contract_version = importer.contract_version
        container_kind = importer.container_kind
    except Exception as exc:
        raise ImporterContractError("importer_exception", type(exc).__name__) from exc
    # SPEC-006 R35: refuse a contract version this core does not implement.
    if isinstance(contract_version, bool) or contract_version != CONTRACT_VERSION:
        raise ImporterContractError("contract_version", repr(contract_version))
    if not (
        _matches(IMPORTER_ID, importer_id) and _matches(SEMVER, version) and _matches(CONTAINER_KIND, container_kind)
    ):
        raise ImporterContractError("bad_return", f"identity {importer_id!r} {version!r} {container_kind!r}")
    return _Identity(importer_id, version, container_kind)


def _checked_params(params: ImportParams) -> ImportParams | None:
    if not isinstance(params, ImportParams) or params.dump_kind not in DUMP_KINDS:
        return None
    if params.source_tool is not None and not _matches(TOOL_NAME, params.source_tool):
        return None
    try:
        options = freeze_json(params.options)
    except NotJsonError:
        return None
    if not isinstance(options, FrozenObject):
        return None
    return ImportParams(params.dump_kind, params.source_tool, options)


def _checked_rejection(rejection: ImportRejected, container_kind: str) -> ImportRejected:
    try:
        reason = rejection.reason
        recognized = rejection.container_kind
    except AttributeError as exc:
        raise ImporterContractError("bad_return", "uninitialized ImportRejected") from exc
    if reason not in IMPORTER_REASONS:
        raise ImporterContractError("bad_return", f"reason {reason!r}")
    # R10: one container kind per importer; `unsupported_container` means none was recognized.
    allowed: set[str | None] = {None} if reason == "unsupported_container" else {None, container_kind}
    if recognized not in allowed:
        raise ImporterContractError("bad_return", f"container_kind {recognized!r} with {reason}")
    return ImportRejected(reason, recognized)


def _checked_dump(dump: Dump, dump_kind: DumpKind) -> Dump:
    # A frozen Dump is validated on construction, but object.__setattr__ can bypass that: rebuild it.
    try:
        rebuilt = Dump(
            dump.dump_kind,
            tuple(Memory(memory.memory_id, memory.base_address, memory.data) for memory in dump.memories),
        )
    except (KernelError, AttributeError, TypeError) as exc:
        raise ImporterContractError("bad_dump", str(exc)) from exc
    # R11: the caller's dump_kind is never overridden by an importer.
    if rebuilt.dump_kind != dump_kind:
        raise ImporterContractError("bad_dump", f"dump_kind {rebuilt.dump_kind!r}, declared {dump_kind!r}")
    return rebuilt


def run_import(importer: Importer, data: bytes, params: ImportParams) -> Imported | ImportRejected:
    """SPEC-006 R20: the only entry point to an importer."""
    if not isinstance(data, bytes):
        raise TypeError("data must be the bytes of one file (SPEC-006 R17)")
    identity = _identity(importer)
    checked = _checked_params(params)
    if checked is None:
        return ImportRejected("bad_params", None)
    if len(data) > MAX_INPUT_BYTES:
        return ImportRejected("too_large", None)
    try:
        result = importer.import_file(data, checked)
    except Exception as exc:
        raise ImporterContractError("importer_exception", type(exc).__name__) from exc
    if isinstance(result, ImportRejected):
        return _checked_rejection(result, identity.container_kind)
    if not isinstance(result, Dump):
        raise ImporterContractError("bad_return", type(result).__name__)
    dump = _checked_dump(result, checked.dump_kind)
    if len(dump.memories) > MAX_MEMORIES or sum(len(memory.data) for memory in dump.memories) > MAX_INPUT_BYTES:
        return ImportRejected("limit_exceeded", identity.container_kind)
    record = ImportRecord(
        importer_id=identity.importer_id,
        importer_version=identity.version,
        source_tool=checked.source_tool,
        container_kind=identity.container_kind,
        input_sha256=hashlib.sha256(data).hexdigest(),
        dump_kind=checked.dump_kind,
        options=checked.options,
        image_hash=image_hash(dump),
    )
    return Imported(dump, record, import_record_hash(record))


def dispatch(importers: Sequence[Importer], data: bytes, params: ImportParams) -> Imported | ImportRejected:
    """SPEC-006 R25, R26: try every importer but the raw one; ambiguity is never resolved by priority."""
    identified = [(_identity(importer), importer) for importer in importers]
    ids = [identity.importer_id for identity, _ in identified]
    if len(set(ids)) != len(ids):
        raise ValueError("two importers share an importer_id (SPEC-006 R35)")
    recognized: list[Imported | ImportRejected] = []
    for identity, importer in sorted(identified, key=_by_importer_id):
        if identity.importer_id == RAW_IMPORTER_ID:
            continue
        outcome = run_import(importer, data, params)
        if isinstance(outcome, ImportRejected) and outcome.reason == "unsupported_container":
            continue
        recognized.append(outcome)
    if not recognized:
        return ImportRejected("unsupported_container", None)
    if len(recognized) > 1:
        return ImportRejected("ambiguous_container", None)
    return recognized[0]


def _by_importer_id(pair: tuple[_Identity, Importer]) -> str:
    return pair[0].importer_id
