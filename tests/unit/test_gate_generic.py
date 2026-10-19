"""SPEC-004 R17-R19, SPEC-005 R110-R115: the gate's audit without a family plugin, on the SPEC-002 fixture bytes."""

import json
from dataclasses import fields, replace
from typing import Any, cast

import pytest

from core import __version__
from core.definitions import definition_hash
from core.gate import AuditRefused, GenericAudit, ReleasedImage, audit, audit_generic
from core.gate._audit import Audit, run_audit
from core.kernel import Dump, canonical_json, image_hash
from core.provenance import Json, ShapeError
from tests.unit.gate_support import (
    BUILD,
    CORE_VERSION,
    MAP,
    TABLE,
    Overridden,
    admit_all,
    arguments,
    definition,
    file_of,
    write,
)
from tests.unit.plugin_fixtures import ORIGINAL, dump_of

# A cell of syn.ign (64..68), a byte in its x axis (96) and two bytes outside every map (300, 301).
CANDIDATE = write(write(write(ORIGINAL, 65, b"\x7f"), 96, b"\x55"), 300, b"\x00\x01")
UNBOUND = replace(MAP, map_id="syn.unbound", memory_id="nowhere", x=None, y=None)


def plain(value: Json) -> dict[str, Any]:
    return cast("dict[str, Any]", json.loads(canonical_json(value)))


def generic(**overrides: object) -> GenericAudit:
    kwargs: dict[str, Any] = {"definition": None, "candidate_origin": "file_service", "build": BUILD, **overrides}
    original = cast("Dump", kwargs.pop("original", dump_of(ORIGINAL)))
    candidate = cast("Dump", kwargs.pop("candidate", dump_of(CANDIDATE)))
    return audit_generic(original, candidate, **kwargs)


# SPEC-004 R17, SPEC-005 R111, R112, R113: attribution from the definition the gate received.
def test_generic_audit_with_a_definition() -> None:
    chosen = definition(MAP, UNBOUND)
    result = generic(definition=chosen)
    value = plain(result.record.value)
    assert result.attribution is not None
    assert value["definition_hash"] == definition_hash(chosen)
    assert value["image_hash_original"] == image_hash(dump_of(ORIGINAL))
    assert value["image_hash_candidate"] == image_hash(dump_of(CANDIDATE))
    assert [(c["offset"], c["length"], c["map_ids"]) for c in value["changes"]] == [
        (65, 1, ["syn.ign"]),
        (96, 1, ["syn.ign"]),
        (300, 2, []),
    ]
    assert value["outside_known_maps"] == [{"memory_id": "pflash", "offset": 300, "length": 2}]
    assert value["unbound_maps"] == ["syn.unbound"]
    assert [(e["check"], e["reason"]) for e in value["not_evaluated"]] == [
        ("identification", "no_admitted_plugin"),
        ("layout", "no_admitted_plugin"),
        ("map_rules", "no_rule_table"),
        ("verify", "no_admitted_plugin"),
    ]
    assert value["versions"] == {"core": __version__}


# SPEC-005 R112, R113: without a definition every change is outside every known map.
def test_generic_audit_without_a_definition() -> None:
    result = generic()
    value = plain(result.record.value)
    assert result.attribution is None
    assert value["definition_hash"] is None
    assert len(value["outside_known_maps"]) == len(value["changes"]) == 3
    assert value["not_evaluated"][2] == {"check": "map_rules", "reason": "no_definition"}


# SPEC-004 R18, SPEC-005 R113: no release, no input result, no verdict, never "ok".
def test_never_a_release_and_never_ok() -> None:
    result = generic(definition=definition())
    assert [f.name for f in fields(result)] == ["record", "attribution"]
    assert not any(isinstance(getattr(result, f.name), ReleasedImage) for f in fields(result))
    text = canonical_json(result.record.value).decode()
    assert '"ok"' not in text
    assert "verdict" not in text
    assert plain(result.record.value)["checksum_status"] == "not_verified"


# SPEC-004 R17: arguments of the wrong type are `bad_type`.
@pytest.mark.parametrize(
    "overrides",
    [
        {"original": ORIGINAL},
        {"candidate": "file"},
        {"definition": "syn.ign"},
        {"build": "lockfile"},
    ],
)
def test_bad_type(overrides: dict[str, object]) -> None:
    with pytest.raises(AuditRefused) as raised:
        generic(**overrides)
    assert raised.value.reason == "bad_type"


# SPEC-004 R17, SPEC-005 R111: dumps of another shape are refused.
def test_shape_mismatch() -> None:
    with pytest.raises(AuditRefused) as raised:
        generic(candidate=dump_of(CANDIDATE, "obd_full"))
    assert raised.value.reason == "shape_mismatch"


# SPEC-004 R17, SPEC-005 R3: an origin outside SPEC-000 Artifact.origin is `bad_shape`.
def test_bad_origin() -> None:
    with pytest.raises(ShapeError) as raised:
        generic(candidate_origin="workshop")
    assert raised.value.reason == "bad_shape"


def degraded(**overrides: object) -> GenericAudit:
    result = run_audit(
        file_of(dump_of(ORIGINAL)), file_of(dump_of(CANDIDATE)), arguments(**overrides), admit_all, CORE_VERSION
    )
    assert isinstance(result, GenericAudit)
    return result


# SPEC-004 R19, SPEC-005 R115: without a rule table the audit is built, generic, with reason `no_rule_table`.
@pytest.mark.parametrize("table", [None, {**TABLE, "identify_min_confidence": 1001}])
def test_audit_without_a_rule_table(table: object) -> None:
    value = plain(degraded(rule_table=table, definition=definition()).record.value)
    assert [e["reason"] for e in value["not_evaluated"]] == ["no_rule_table"] * 4
    assert value["versions"] == {"core": CORE_VERSION}
    without = plain(degraded(rule_table=None).record.value)
    assert without["not_evaluated"][2]["reason"] == "no_definition"


def refuse(*_args: object) -> object:
    raise AssertionError("the degraded audit called the plugin")


# SPEC-005 R115: the degraded audit calls no plugin.
def test_degraded_audit_calls_no_plugin() -> None:
    silent = Overridden(replaced={"identify": refuse, "layout": refuse, "verify": refuse, "checksums": refuse})
    result = degraded(rule_table=None, plugin=silent)
    assert plain(result.record.value)["changes"]


# SPEC-005 R115, R25: the type checks still run first.
def test_degraded_audit_type_checks_first() -> None:
    with pytest.raises(AuditRefused) as raised:
        run_audit(
            file_of(dump_of(ORIGINAL)), file_of(dump_of(CANDIDATE)), arguments(rule_table=None, build=1), admit_all, "1"
        )
    assert raised.value.reason == "bad_type"


# SPEC-004 R19: with a valid table the plugin audit is unchanged; the public `audit` degrades the same way.
def test_audit_with_a_table_and_public_degradation() -> None:
    with_table = run_audit(file_of(dump_of(ORIGINAL)), file_of(dump_of(CANDIDATE)), arguments(), admit_all, "1")
    assert isinstance(with_table, Audit)
    public = audit(file_of(dump_of(ORIGINAL)), file_of(dump_of(CANDIDATE)), **arguments(rule_table=None))
    assert isinstance(public, GenericAudit)
    assert plain(public.record.value)["versions"] == {"core": __version__}
