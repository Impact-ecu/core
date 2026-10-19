"""`audit_generic` (SPEC-004 R17-R19, SPEC-005 §4.2): the audit without a family plugin. It never calls a plugin
or `release`, never builds a `ReleasedImage` and never says ok (R18)."""

from dataclasses import dataclass
from types import MappingProxyType
from typing import TypedDict

from core import __version__
from core.definitions import Definition, MapAttribution, definition_hash, map_attribution
from core.gate._model import GateError
from core.kernel import Dump
from core.provenance import (
    Build,
    ChangedRun,
    GenericAuditInputs,
    GenericAuditRecord,
    KnownMaps,
    PluginReason,
    RecordError,
    changed_ranges,
    generic_audit_record,
)


class AuditRefused(GateError):
    """SPEC-005 R25, SPEC-004 R17: the audit was not built; `reason` says why."""


class GenericArgs(TypedDict):
    """The keyword arguments of `audit_generic` (SPEC-004 R17); `AuditArgs` carries the same three."""

    definition: Definition | None
    candidate_origin: str
    build: Build


@dataclass(frozen=True, slots=True)
class GenericAudit:
    """SPEC-004 R17: the record and, with a definition, the SPEC-003 R100 attribution of its changes."""

    record: GenericAuditRecord
    attribution: MapAttribution | None


def valid_generic(original: object, candidate: object, definition: object, build: object) -> bool:
    """SPEC-004 R17 `bad_type`."""
    return (
        isinstance(original, Dump)
        and isinstance(candidate, Dump)
        and isinstance(build, Build)
        and (definition is None or isinstance(definition, Definition))
    )


def _known(definition: Definition, attribution: MapAttribution) -> KnownMaps:
    return KnownMaps(
        definition_hash(definition),
        MappingProxyType({line.patch_hash: line.map_ids for line in attribution.patches}),
        tuple(ChangedRun(run.memory_id, run.offset, run.length) for run in attribution.unmapped),
        attribution.unbound,
    )


def run_generic(
    original: Dump, candidate: Dump, args: GenericArgs, reason: PluginReason, core_version: str
) -> GenericAudit:
    """SPEC-005 R110-R115 on arguments already type-checked; `reason` is R113's for the plugin checks."""
    definition = args["definition"]
    try:
        patches = changed_ranges(original, candidate)
    except RecordError as error:
        raise AuditRefused(error.reason, str(error)) from error
    attribution: MapAttribution | None = None
    known: KnownMaps | None = None
    if definition is not None:
        attribution = map_attribution(patches, definition, (original, candidate))
        known = _known(definition, attribution)
    inputs = GenericAuditInputs(
        original, candidate, args["candidate_origin"], known, reason, core_version, args["build"]
    )
    return GenericAudit(generic_audit_record(inputs), attribution)


def audit_generic(
    original: Dump, candidate: Dump, *, definition: Definition | None, candidate_origin: str, build: Build
) -> GenericAudit:
    """SPEC-004 R17: changed ranges, attribution and record, all computed by the core, with no plugin."""
    if not valid_generic(original, candidate, definition, build):
        raise AuditRefused("bad_type", "audit_generic takes two Dumps, a Definition or None, and a Build")
    args: GenericArgs = {"definition": definition, "candidate_origin": candidate_origin, "build": build}
    return run_generic(original, candidate, args, "no_admitted_plugin", __version__)
