"""SPEC-005 §3.1 (R100-R102) and SPEC-004 R54 on the SPEC-002 fixture plugin: `export_inputs`, `alert_warnings`
and `alert_ack_payload`, built by the gate from what its `release` call held.

Expected hashes use the third-party `rfc8785` JCS, never the core's own canonicalization.
"""

import hashlib
from collections.abc import Callable, Mapping
from typing import Any, cast

import pytest
import rfc8785

from core.definitions import definition_hash
from core.gate import (
    AlertWarning,
    ExportRefused,
    GateError,
    GateInvariantError,
    ReleasedImage,
    alert_ack_payload,
    alert_warnings,
    export_inputs,
)
from core.gate._report import GateReport
from core.gate._result import seal
from core.kernel import apply_checksum_patches, image_hash
from core.kernel._internal import view
from core.provenance import Build, Draft, Event, EventMeta, PluginVersion, Reference, append, export_provenance
from tests.unit.gate_support import (
    CONFORMANCE,
    CORE_VERSION,
    GOOD_EDITS,
    PROJECT,
    SHA_ORIGINAL,
    TABLE,
    PythonPlugin,
    Scenario,
    ShaReference,
    definition,
    doc,
    export_basis,
)
from tests.unit.plugin_fixtures import FAMILY, IDENT, LAYOUT, FakePlugin, dump_of
from tests.unit.provenance_scenario import IMAGE_BUILD, LOCK_BUILD
from tests.unit.provenance_support import USER, event_id, start, ts

WARN_EDITS = {**GOOD_EDITS, 64: bytes([10, 20, 25, 40])}
BOOST_CAP = "ign.si.gasoline.base.boost_cap"


def jcs_sha(value: object) -> str:
    return hashlib.sha256(rfc8785.dumps(cast("dict[str, Any]", value))).hexdigest()


def plain(value: object) -> object:
    """A frozen report as `rfc8785` accepts it: tuples as lists, mappings as dicts."""
    if isinstance(value, tuple | list):
        return [plain(item) for item in value]
    if isinstance(value, Mapping):
        return {key: plain(item) for key, item in cast("Mapping[str, object]", value).items()}
    return value


def ack_event(chain: list[Event], payload: dict[str, Any], project_id: str = PROJECT) -> Event:
    head = chain[-1]
    meta = EventMeta(event_id(900 + head.seq), project_id, USER, ts(head.seq + 1))
    event = append(head, Draft(meta, "alert_ack", payload))
    chain.append(event)
    return event


# SPEC-005 R100, R101, SPEC-004 R25: the kept objects are the release call's, the patches are the plugin's.
def test_export_inputs_no_findings() -> None:
    s = Scenario()
    released = s.release()
    assert released.verdict == "no findings"
    inputs = export_inputs(released, build=IMAGE_BUILD)
    assert inputs.original is s.original
    assert inputs.version == s.version
    assert inputs.layout == LAYOUT
    expected_q = tuple(FakePlugin().checksum_patches(view(s.unverified()), IDENT))
    assert inputs.checksum_patches == expected_q
    assert apply_checksum_patches(s.unverified(), expected_q, LAYOUT).image_hash == released.image_hash
    assert inputs.definition_hash == definition_hash(definition())
    assert inputs.versions.core == CORE_VERSION
    assert inputs.versions.plugins == (PluginVersion(FAMILY, "1.0.0", jcs_sha(CONFORMANCE)),)
    assert inputs.versions.gate_rules == TABLE["version"]
    assert inputs.versions.references == ()
    assert inputs.gate_report is released.report
    assert doc(inputs.input_report)["stage"] == "input"
    assert jcs_sha(plain(inputs.input_report)) == doc(released.report)["subject"]["input_report_hash"]
    assert inputs.build is IMAGE_BUILD
    record = export_provenance(inputs, alert_ack=None, suspect_ack=None, chain=[start()]).value
    assert record["image_hash_release"] == released.image_hash
    assert record["image_hash_original"] == image_hash(s.original)
    assert record["gate_report_hash"] == released.report_hash == jcs_sha(plain(released.report))
    assert record["verdict"] == "no findings"
    by_place = sorted(expected_q, key=lambda p: (p.memory_id, p.offset))
    assert plain(record["checksum_patch_hashes"]) == [p.patch_hash for p in by_place]
    assert record["input_verify"] == {"status": "ok", "result": "ok", "suspect_ack": None}
    assert export_inputs(released, build=LOCK_BUILD).build is LOCK_BUILD


# SPEC-005 R101: an independent reference used by the gate is listed with the version it declares.
def test_export_inputs_lists_the_references() -> None:
    s = Scenario(original=dump_of(SHA_ORIGINAL), plugin=PythonPlugin())
    released = s.release(references={"ref-sha": ShaReference()})
    inputs = export_inputs(released, build=IMAGE_BUILD)
    assert inputs.versions.references == (Reference("ref-sha", "1.0.0"),)
    record = export_provenance(inputs, alert_ack=None, suspect_ack=None, chain=[start()]).value
    assert plain(doc(record)["versions"]["references"]) == [{"id": "ref-sha", "version": "1.0.0"}]
    assert record["image_hash_release"] == released.image_hash


# SPEC-005 R100, R101, R13; SPEC-004 R50-R52, R54: the gate's payload authorizes `to_dump` and binds the record.
def test_warn_export_end_to_end() -> None:
    released = Scenario(edits=WARN_EDITS).release()
    assert released.verdict == "warn"
    finding = doc(released.report)["findings"][0]
    warnings = alert_warnings(released)
    assert warnings == (AlertWarning(jcs_sha(plain(finding)), BOOST_CAP, finding["text"]),)
    payload = alert_ack_payload(released, presented_ms=1000, confirmed_ms=4000)
    assert payload == {
        "image_hash_release": released.image_hash,
        "gate_report_hash": jcs_sha(plain(released.report)),
        "warnings": [{"finding_id": jcs_sha(plain(finding)), "rule_id": BOOST_CAP, "text": finding["text"]}],
        "presented_ms": 1000,
        "confirmed_ms": 4000,
    }
    chain = [start()]
    ack = ack_event(chain, payload)
    dump = released.to_dump(ack)
    assert image_hash(dump) == released.image_hash
    record = export_provenance(
        export_inputs(released, build=IMAGE_BUILD), alert_ack=ack, suspect_ack=None, chain=chain
    ).value
    assert record["verdict"] == "warn"
    assert record["alert_ack"] == ack.ref
    assert record["image_hash_release"] == released.image_hash


# SPEC-004 R54, R61: no findings lists no warning; a silenced warning is not listed either.
def test_alert_warnings_empty() -> None:
    assert alert_warnings(Scenario().release()) == ()
    silence = {"rule_id": BOOST_CAP, "justification_commitment": "c" * 64}
    chain = [start()]
    meta = EventMeta(event_id(950), PROJECT, USER, ts(1))
    event = append(chain[-1], Draft(meta, "rule_silence", silence))
    quiet = Scenario(edits=WARN_EDITS).release(silences=(event,))
    assert quiet.verdict == "no findings"
    assert alert_warnings(quiet) == ()


# SPEC-004 R54: `unexpected_ack` for a no findings release.
def test_alert_ack_payload_unexpected_ack() -> None:
    with pytest.raises(GateError) as error:
        alert_ack_payload(Scenario().release(), presented_ms=0, confirmed_ms=0)
    assert error.value.reason == "unexpected_ack"


# SPEC-004 R52, R54: `bad_payload` for a time that is not a safe integer or out of order.
@pytest.mark.parametrize(
    ("presented", "confirmed"),
    [(2, 1), (-1, 5), (0, 2**53), (True, 5), (0, "5"), (0.0, 5)],
)
def test_alert_ack_payload_bad_payload(presented: object, confirmed: object) -> None:
    released = Scenario(edits=WARN_EDITS).release()
    with pytest.raises(GateError) as error:
        alert_ack_payload(released, presented_ms=cast("int", presented), confirmed_ms=cast("int", confirmed))
    assert error.value.reason == "bad_payload"


# SPEC-004 R54: the boundary times are accepted and authorized.
def test_alert_ack_payload_boundaries() -> None:
    released = Scenario(edits=WARN_EDITS).release()
    for presented, confirmed in [(0, 0), (2**53 - 1, 2**53 - 1)]:
        payload = alert_ack_payload(released, presented_ms=presented, confirmed_ms=confirmed)
        chain = [start()]
        assert image_hash(released.to_dump(ack_event(chain, payload))) == released.image_hash


# SPEC-004 R53, R54: the payload is bound to the release, not to an event of another project.
def test_alert_ack_payload_other_project() -> None:
    released = Scenario(edits=WARN_EDITS).release()
    chain = [start()]
    ack = ack_event(chain, alert_ack_payload(released, presented_ms=1, confirmed_ms=2), project_id="proj-2")
    with pytest.raises(ExportRefused) as refused:
        released.to_dump(ack)
    assert refused.value.reason == "ack_required"


# SPEC-005 R102, SPEC-004 R54: `bad_type` for anything but a `ReleasedImage` and a provenance `Build`.
def test_bad_type() -> None:
    released = Scenario().release()
    other = cast("ReleasedImage", object())
    calls: list[Callable[[], object]] = [
        lambda: export_inputs(other, build=IMAGE_BUILD),
        lambda: export_inputs(released, build=cast("Build", object())),
        lambda: alert_warnings(other),
        lambda: alert_ack_payload(other, presented_ms=0, confirmed_ms=0),
    ]
    for call in calls:
        with pytest.raises(GateError) as error:
            call()
        assert error.value.reason == "bad_type"


def _sealed_with(report: dict[str, Any]) -> ReleasedImage:
    s = Scenario()
    basis = export_basis(s)
    report["verdict"] = "warn"
    gate_report = GateReport(report, jcs_sha(plain(report)), "warn")
    return ReleasedImage(seal(), apply_checksum_patches(s.unverified(), (), LAYOUT), gate_report, PROJECT, basis)


# SPEC-005 R101, SPEC-004 R45, R82: a report the gate wrote without a required field is a gate bug.
@pytest.mark.parametrize(
    ("where", "value"),
    [("plugin", None), ("conformance_report_hash", None), ("definition_hash", 7), ("references", [{"id": 1}])],
)
def test_missing_subject_field_is_a_gate_bug(where: str, value: object) -> None:
    report = doc(plain(Scenario().release().report))
    report["subject"][where] = value
    report["subject"]["release_candidate_hash"] = Scenario().unverified().image_hash
    with pytest.raises(GateInvariantError, match="SPEC-004 R45"):
        export_inputs(_sealed_with(report), build=IMAGE_BUILD)


# SPEC-004 R2, R82: a warn finding without a string rule id is a gate bug, never an empty ack.
def test_malformed_warning_is_a_gate_bug() -> None:
    report = doc(plain(Scenario().release().report))
    report["subject"]["release_candidate_hash"] = Scenario().unverified().image_hash
    report["findings"] = [{"rule_id": None, "severity": "warn", "text": "t"}]
    with pytest.raises(GateInvariantError, match="SPEC-004 R2"):
        alert_warnings(_sealed_with(report))
