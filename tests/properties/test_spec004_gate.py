"""SPEC-004 properties: no path to a `ReleasedImage` except `release` with a passing gate (SPEC-000 invariant 10,
SPEC-001 R9, R42; SPEC-004 R4, R20-R29), and determinism of the report (R80)."""

import random
from collections.abc import Mapping
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from core.gate import GateBlocked, GateError, ReleasedImage
from core.gate._evidence import EvidenceAdmissionFn, published_admission
from core.gate._model import json_hash
from core.gate._report import GateReport
from core.kernel import Dump, UnverifiedImage, Version, canonical_json, image_hash
from core.plugins.descriptor import interpret_verify
from core.provenance import Event
from tests.unit.gate_support import (
    GOOD_EDITS,
    PROJECT,
    TABLE,
    Overridden,
    Scenario,
    admit_all,
    check,
    doc,
    event,
    export_basis,
    raises,
)
from tests.unit.plugin_fixtures import LAYOUT, ORIGINAL, REGIONS, FakePlugin, dump_of

CALIBRATION = range(48, 256)  # [32, 48) is mirrored by `d_mirror`; editing it is still calibration
ANYWHERE = range(512)
OCCUPIED = {offset + i for offset, after in GOOD_EDITS.items() for i in range(len(after))}

edits = st.dictionaries(
    st.one_of(st.sampled_from(CALIBRATION), st.sampled_from(ANYWHERE)), st.binary(min_size=1, max_size=1), max_size=6
)
faults = st.sampled_from(["none", "verify", "checksum_patches", "identify", "layout"])


def forged(original: Dump, version: Version) -> UnverifiedImage:
    """The image the patches describe, built without `apply`, so out-of-region edits reach the gate too."""
    data = bytearray(original.memories[0].data)
    for patch in version.patches:
        data[patch.offset : patch.end] = patch.after
    return UnverifiedImage(dump_of(bytes(data)))


def outside_calibration(version: Version) -> bool:
    return any(not p.offset >= 32 or p.end > 256 for p in version.patches)


@given(edits=edits, fault=faults, evidence=st.booleans(), table=st.booleans(), bound=st.booleans())
def test_no_path_to_a_released_image_but_a_passing_gate(
    edits: dict[int, bytes], fault: str, evidence: bool, table: bool, bound: bool
) -> None:
    plugin = FakePlugin() if fault == "none" else Overridden(replaced={fault: raises})
    s = Scenario(edits={**GOOD_EDITS, **edits}, plugin=plugin)
    version = s.version
    if not version.patches:
        return
    u = forged(s.original, version)
    other = check(dump_of(ORIGINAL[:-1] + b"\x00"))
    overrides: dict[str, object] = {"rule_table": TABLE if table else None, "input": s.input() if bound else other}
    admit = admit_all if evidence else published_admission
    outcome = _outcome(s, u, admit, overrides)
    if not isinstance(outcome, ReleasedImage):
        assert outcome["verdict"] == "block"
        assert any(f["severity"] == "block" for f in outcome["findings"])
        return
    released = outcome
    # Only a fully available, bound, admitted, calibration-only release passes.
    assert fault == "none"
    assert evidence
    assert table
    assert bound
    assert not outside_calibration(version)
    assert released.verdict in ("warn", "no findings")
    assert all(f["severity"] != "block" for f in doc(released.report)["findings"])
    assert doc(released.report)["subject"]["release_candidate_hash"] == released.image_hash
    ack = _ack(released) if released.verdict == "warn" else None
    dump = released.to_dump(ack)
    assert image_hash(dump) == released.image_hash
    results = interpret_verify(REGIONS, dump, LAYOUT)
    assert all(result.status == "ok" for result in results.values())
    before, after = s.original.memories[0].data, dump.memories[0].data
    changed = {i for i in range(512) if before[i] != after[i]}
    assert all(32 <= i < 288 for i in changed)


def _outcome(
    s: Scenario, u: UnverifiedImage, admit: EvidenceAdmissionFn, overrides: dict[str, object]
) -> ReleasedImage | Mapping[str, Any]:
    try:
        return s.release(u=u, admit=admit, **overrides)
    except GateBlocked as blocked:
        return blocked.report


def _ack(released: ReleasedImage) -> Event:
    warns = [f for f in doc(released.report)["findings"] if f["severity"] == "warn"]
    payload = {
        "image_hash_release": released.image_hash,
        "gate_report_hash": released.report_hash,
        "warnings": [{"finding_id": json_hash(f), "rule_id": f["rule_id"], "text": f["text"]} for f in warns],
        "presented_ms": 0,
        "confirmed_ms": 9000,
    }
    return event("alert_ack", payload, project_id=PROJECT)


# SPEC-004 R9, R29, SPEC-001 R9: nothing but the gate's seal constructs a `ReleasedImage`.
@given(st.one_of(st.none(), st.integers(), st.text(), st.builds(object)))
def test_released_image_needs_the_seal(seal: object) -> None:
    released = Scenario().release()
    report = GateReport(released.report, released.report_hash, released.verdict)
    with pytest.raises(GateError, match="sealed"):
        ReleasedImage(seal, Scenario().unverified(), report, PROJECT, export_basis(Scenario()))


# SPEC-004 R80: the same inputs give the same report bytes; patch and silence order never matter.
@given(edits=edits, seed=st.integers(0, 2**32 - 1))
def test_report_is_deterministic(edits: dict[int, bytes], seed: int) -> None:
    # Non-overlapping patches: overlapping ones without an order are rejected (SPEC-001 R22) whatever the order.
    kept = {k: v for k, v in edits.items() if k in CALIBRATION and k not in OCCUPIED}
    s = Scenario(edits={**GOOD_EDITS, **kept})
    version = s.version
    if not version.patches:
        return
    shuffled = list(version.patches)
    random.Random(seed).shuffle(shuffled)
    other = Version(version.base_image_hash, version.layout_hash, tuple(shuffled))
    silences = [
        event("rule_silence", {"rule_id": r, "justification_commitment": "c" * 64}, event_id=f"{i:032x}")
        for i, r in enumerate(["ign.si.gasoline.base.range", "ign.si.gasoline.base.boost_cap"])
    ]
    first = _report(s, version, silences)
    second = _report(s, other, list(reversed(silences)))
    assert canonical_json(first) == canonical_json(second)


def _report(s: Scenario, version: Version, silences: list[Event]) -> Mapping[str, Any]:
    try:
        return s.release(u=forged(s.original, version), version=version, silences=tuple(silences)).report
    except GateBlocked as blocked:
        return blocked.report
