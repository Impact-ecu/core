"""SPEC-005 R100-R102 and SPEC-004 R54 as properties: for every release the gate lets out, the inputs it builds
give a record of exactly that release, and the ack payload it builds is the one R52 authorizes.

Expected hashes use the third-party `rfc8785` JCS, never the core's own canonicalization.
"""

import hashlib
from collections.abc import Mapping
from typing import Any, cast

import pytest
import rfc8785
from hypothesis import given
from hypothesis import strategies as st

from core.gate import GateBlocked, GateError, alert_ack_payload, alert_warnings, export_inputs
from core.kernel import KernelError, image_hash
from core.provenance import Draft, EventMeta, append, export_provenance
from tests.unit.gate_support import GOOD_EDITS, PROJECT, Scenario, doc
from tests.unit.provenance_scenario import IMAGE_BUILD
from tests.unit.provenance_support import USER, event_id, start, ts

CALIBRATION = range(48, 256)
MAP_CELLS = range(64, 68)

edits = st.dictionaries(
    st.one_of(st.sampled_from(CALIBRATION), st.sampled_from(MAP_CELLS)), st.binary(min_size=1, max_size=1), max_size=6
)


def jcs_sha(value: object) -> str:
    return hashlib.sha256(rfc8785.dumps(cast("dict[str, Any]", value))).hexdigest()


def plain(value: object) -> object:
    if isinstance(value, tuple | list):
        return [plain(item) for item in value]
    if isinstance(value, Mapping):
        return {key: plain(item) for key, item in cast("Mapping[str, object]", value).items()}
    return value


# SPEC-005 R100, R101, SPEC-004 R43, R50, R52, R54, SPEC-000 invariants 10 and 12.
@given(edits=edits, presented=st.integers(0, 2**53 - 1), delay=st.integers(0, 10**6))
def test_export_inputs_and_ack_describe_the_release(edits: dict[int, bytes], presented: int, delay: int) -> None:
    s = Scenario(edits={**GOOD_EDITS, **edits})
    try:
        released = s.release()
    except (GateBlocked, KernelError):
        return
    report = doc(plain(released.report))
    warns = [f for f in report["findings"] if f["severity"] == "warn"]
    expected = [(jcs_sha(f), f["rule_id"], f["text"]) for f in warns]
    assert [(w.finding_id, w.rule_id, w.text) for w in alert_warnings(released)] == expected
    chain = [start()]
    ack = None
    if released.verdict == "warn":
        confirmed = min(presented + delay, 2**53 - 1)
        payload = alert_ack_payload(released, presented_ms=presented, confirmed_ms=confirmed)
        assert payload["warnings"] == [{"finding_id": h, "rule_id": r, "text": t} for h, r, t in expected]
        meta = EventMeta(event_id(7), PROJECT, USER, ts(1))
        ack = append(chain[-1], Draft(meta, "alert_ack", payload))
        chain.append(ack)
    else:
        assert expected == []
        with pytest.raises(GateError, match="unexpected_ack"):
            alert_ack_payload(released, presented_ms=presented, confirmed_ms=presented)
    assert image_hash(released.to_dump(ack)) == released.image_hash
    inputs = export_inputs(released, build=IMAGE_BUILD)
    record = export_provenance(inputs, alert_ack=ack, suspect_ack=None, chain=chain).value
    assert record["image_hash_release"] == released.image_hash
    assert record["image_hash_original"] == image_hash(s.original)
    assert record["gate_report_hash"] == jcs_sha(report)
    assert record["definition_hash"] == doc(released.report)["subject"]["definition_hash"]
    assert record["verdict"] == released.verdict
