"""SPEC-005 R23-R28: the gate builds the audit of a candidate against its original, on the SPEC-002 fixture."""

import json
from dataclasses import replace
from typing import cast

import pytest

from core.gate import AuditFile, AuditRefused, audit
from core.gate._audit import Audit, run_audit
from core.gate._evidence import EvidenceAdmissionFn, admission_with
from core.kernel import Dump, LayoutMemory, Memory, MemoryLayout, Region, canonical_json, diff, image_hash, layout_hash
from core.plugins import Identification, PresentMemory
from core.provenance import ReportContext, ShapeError
from tests.unit.gate_support import (
    CORE_VERSION,
    Overridden,
    admit_all,
    arguments,
    definition,
    doc,
    event,
    file_of,
    raises,
    sha,
    write,
)
from tests.unit.plugin_fixtures import LAYOUT, ORIGINAL, FakePlugin, dump_of

CONTEXT = ReportContext("tenant-1", "aa" * 32, "bb" * 32)
# A calibration edit inside the map at 64, a write in the checksum region and one in the protected `code` region.
CANDIDATE = write(write(write(ORIGINAL, 64, bytes([10, 20, 25, 30])), 260, b"\xee"), 300, b"\x00\x01")


def run(
    original: Dump | None = None,
    candidate: Dump | None = None,
    admit: EvidenceAdmissionFn = admit_all,
    **overrides: object,
) -> Audit:
    result = run_audit(
        file_of(dump_of(ORIGINAL) if original is None else original),
        file_of(dump_of(CANDIDATE) if candidate is None else candidate),
        arguments(**overrides),
        admit,
        CORE_VERSION,
    )
    assert isinstance(result, Audit)
    return result


def refusal(
    original: Dump | None = None,
    candidate: Dump | None = None,
    admit: EvidenceAdmissionFn = admit_all,
    **overrides: object,
) -> str:
    with pytest.raises(AuditRefused) as raised:
        run(original, candidate, admit, **overrides)
    return raised.value.reason


# SPEC-005 R23, R24, R26, R20: verify statuses, layout and versions come from the gate's own calls.
def test_record_from_the_gates_own_calls() -> None:
    result = run()
    record = doc(result.record.value)
    original_subject = doc(result.original_input.report)["subject"]
    candidate_report = doc(result.candidate_input.report)
    assert record["verify"] == {"original": "ok", "candidate": "fail"}
    assert original_subject["verify_status"] == "ok"
    assert candidate_report["subject"]["verify_status"] == "fail"
    assert record["layout_hash"] == layout_hash(LAYOUT)
    assert record["image_hash_original"] == image_hash(dump_of(ORIGINAL))
    assert record["image_hash_candidate"] == image_hash(dump_of(CANDIDATE))
    assert record["gate_report_hash"] == result.candidate_input.report_hash
    assert json.loads(canonical_json(record["versions"])) == {
        "core": CORE_VERSION,
        "plugins": [
            {
                "family": "synthetic.fixture",
                "version": "1.0.0",
                "conformance_report_hash": candidate_report["subject"]["conformance_report_hash"],
            }
        ],
        "gate_rules": "1.0.0",
        "references": [],
    }
    assert record["reproducibility"] == "best_effort"
    expected = diff(dump_of(ORIGINAL), dump_of(CANDIDATE), LAYOUT)
    assert list(record["diff_patch_hashes"]) == [p.patch_hash for p in expected.patches]
    assert [(f["region_kind"], f["region_name"], f["offset"]) for f in record["foreign"]] == [
        ("checksum", "checksums", 260),
        ("protected", "code", 300),
    ]


# SPEC-005 R27, SPEC-003 R102: with a definition, each patch line carries the core's map_id.
def test_report_lines_with_a_definition() -> None:
    result = run(definition=definition())
    assert result.attribution is not None
    lines = doc(result.report(CONTEXT).value)["sections"]["what_changed"]["patches"]
    assert [(line["offset"], line["map_id"]) for line in lines] == [(64, "syn.ign")]


# SPEC-005 R27: without a definition every map_id is null and there is no attribution.
def test_report_lines_without_a_definition() -> None:
    result = run()
    assert result.attribution is None
    lines = doc(result.report(CONTEXT).value)["sections"]["what_changed"]["patches"]
    assert [line["map_id"] for line in lines] == [None]


# SPEC-005 R24, SPEC-006 R82: a `not_applicable` status (unknown variant) is a status; the audit proceeds.
def test_unknown_variant_still_audits() -> None:
    result = run(admit=admission_with(None))
    assert doc(result.record.value)["verify"] == {"original": "not_applicable", "candidate": "not_applicable"}


# SPEC-005 R23: the public `audit` uses the published field evidence (none yet, so `not_applicable`).
def test_public_audit() -> None:
    result = audit(file_of(dump_of(ORIGINAL)), file_of(dump_of(CANDIDATE)), **arguments())
    assert isinstance(result, Audit)
    assert doc(result.record.value)["verify"] == {"original": "not_applicable", "candidate": "not_applicable"}
    assert doc(result.record.value)["versions"]["core"] != CORE_VERSION


# SPEC-005 R24: a plugin that is unavailable stops the input gate before verify, so no layout is taken. (Without a
# rule table the generic audit is built instead, SPEC-005 R115; tests/unit/test_gate_generic.py.)
def test_no_plugin_refuses() -> None:
    assert refusal(plugin=None) == "original_not_identified"


def low_confidence(dump: Dump) -> Identification | None:
    ident = FakePlugin().identify(dump)
    return None if ident is None else replace(ident, confidence=700)


# SPEC-005 R23, R24, SPEC-004 R12: each side uses its own confirmation; an unconfirmed side is refused.
def test_each_side_uses_its_own_confirmation() -> None:
    plugin = Overridden(replaced={"identify": low_confidence})
    original = dump_of(ORIGINAL)
    ident = low_confidence(original)
    assert ident is not None
    confirmation = event(
        "identification_confirmed",
        {
            "artifact_sha256": sha(ORIGINAL),
            "image_hash": image_hash(original),
            "family": ident.family,
            "plugin_version": "1.0.0",
            "hw_id": ident.hw_id,
            "sw_id": ident.sw_id,
            "checksum_variant_id": ident.checksum_variant_id,
        },
    )
    with pytest.raises(AuditRefused) as raised:
        run_audit(
            file_of(original, confirmation=confirmation),
            file_of(dump_of(CANDIDATE)),
            arguments(plugin=plugin),
            admit_all,
            CORE_VERSION,
        )
    assert raised.value.reason == "candidate_not_identified"
    with pytest.raises(AuditRefused) as raised:
        run_audit(file_of(original), file_of(dump_of(CANDIDATE)), arguments(plugin=plugin), admit_all, CORE_VERSION)
    assert raised.value.reason == "original_not_identified"


# SPEC-005 R25, SPEC-002 R11: a layout call that raises is `plugin_error`.
def test_layout_raising_refuses() -> None:
    # Only an unknown variant skips the input gate's own layout call (SPEC-004 R13), so only then can the audit's
    # call be the first to fail.
    plugin = Overridden(replaced={"layout": raises})
    assert refusal(plugin=plugin, admit=admission_with(None)) == "plugin_error"


def layout_by_sw(ident: Identification, dump_kind: object) -> MemoryLayout:
    del dump_kind
    if ident.sw_id == "sw-1":
        return LAYOUT
    memory = LAYOUT.memories[0]
    regions = (Region("calibration", 0, 256, "maps"), *memory.regions[2:])
    return MemoryLayout((LayoutMemory(memory.memory_id, memory.base_address, memory.size, regions),))


def sw_by_content(dump: Dump) -> Identification | None:
    ident = FakePlugin().identify(dump)
    if ident is None or dump.memories[0].data == ORIGINAL:
        return ident
    return replace(ident, sw_id="sw-2")


# SPEC-005 R24, R25: two layouts for one audit are refused.
def test_layout_mismatch_refuses() -> None:
    plugin = Overridden(replaced={"identify": sw_by_content, "layout": layout_by_sw})
    assert refusal(plugin=plugin) == "layout_mismatch"


# SPEC-005 R25, SPEC-001 R31: dumps of another shape cannot be diffed.
def test_shape_mismatch_refuses() -> None:
    assert refusal(candidate=dump_of(CANDIDATE, "obd_full")) == "shape_mismatch"


def unaddressed(dump: Dump) -> Identification | None:
    ident = FakePlugin().identify(dump)
    return None if ident is None else replace(ident, memories_present=(PresentMemory("pflash", None, 512),))


def null_layout(ident: Identification, dump_kind: object) -> MemoryLayout:
    del ident, dump_kind
    memory = LAYOUT.memories[0]
    return MemoryLayout((LayoutMemory(memory.memory_id, None, memory.size, memory.regions),))


# SPEC-005 R25, SPEC-001 R2: a dump without a base address is not diffed (rebase it first, SPEC-002 R18).
def test_unknown_base_address_refuses() -> None:
    raw = Dump("bench_full", (Memory("pflash", None, ORIGINAL),))
    raw_candidate = Dump("bench_full", (Memory("pflash", None, CANDIDATE),))
    plugin = Overridden(replaced={"identify": unaddressed, "layout": null_layout})
    reason = refusal(original=raw, candidate=raw_candidate, plugin=plugin, admit=admission_with(None))
    assert reason == "unknown_base_address"


# SPEC-005 R25: arguments of the wrong type are refused before any plugin call.
@pytest.mark.parametrize(("name", "value"), [("build", "lockfile"), ("definition", "syn.ign")])
def test_bad_type_refuses(name: str, value: str) -> None:
    assert refusal(None, None, admit_all, **{name: value}) == "bad_type"


def test_bad_file_refuses() -> None:
    with pytest.raises(AuditRefused) as raised:
        run_audit(cast("AuditFile", dump_of(ORIGINAL)), file_of(dump_of(CANDIDATE)), arguments(), admit_all, "1")
    assert raised.value.reason == "bad_type"


# SPEC-005 R3, R25: an origin outside SPEC-000 Artifact.origin is a record shape error.
def test_bad_origin_is_bad_shape() -> None:
    with pytest.raises(ShapeError) as raised:
        run(candidate_origin="workshop")
    assert raised.value.reason == "bad_shape"


# SPEC-005 R28: an audit has no verdict; the candidate's input verdict is what the consumer shows.
def test_audit_has_no_verdict_of_its_own() -> None:
    result = run()
    assert doc(result.candidate_input.report)["verdict"] == "block"
    assert "verdict" not in doc(result.record.value)
    assert doc(result.report(CONTEXT).value)["sections"]["integrity"]["verdict"] is None
