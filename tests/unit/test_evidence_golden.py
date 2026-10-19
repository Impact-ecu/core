"""SPEC-006 §7.1, §7.2: golden records and `evaluate_golden` beyond the G01-G33 matrix."""

import copy
from collections.abc import Callable, Mapping, Sequence
from typing import Any

import pytest

from core.evidence import E, EvidenceError, GoldenEvaluation, GoldenRecord, K, N, evaluate_golden, parse_golden_record
from core.provenance import Raw
from tests.unit.evidence_support import (
    DTC_SET,
    EPOCH,
    OTHER,
    POOL,
    PRE,
    RECORD,
    B,
    attestation,
    record,
    sha,
    signed,
    tool,
)
from tests.unit.provenance_support import VERIFIER

AX, BY = POOL["AX"], POOL["BY"]
H_AX, H_BY = AX["attestation_hash"], BY["attestation_hash"]


def reason_of(call: Callable[[], object]) -> str:
    with pytest.raises(EvidenceError) as caught:
        call()
    return caught.value.reason


def evaluate(value: Raw, supplied: Sequence[Raw], *, dtc_set: Raw = DTC_SET, epoch: str = EPOCH) -> GoldenEvaluation:
    return evaluate_golden(value, supplied, PRE, dtc_set, epoch, VERIFIER)


# SPEC-006 R71: the thresholds are constants N = K = E = 2, reported in every evaluation.
def test_thresholds() -> None:
    assert (N, K, E) == (2, 2, 2)
    assert evaluate(record(H_AX, H_BY), [AX, BY]).to_json()["thresholds"] == {
        "attestations": 2,
        "attesters": 2,
        "units": 2,
    }


def _changed(path: tuple[str, ...], value: object) -> dict[str, Any]:
    changed = copy.deepcopy(RECORD)
    target = changed
    for key in path[:-1]:
        target = target[key]
    if value is KeyError:
        del target[path[-1]]
    else:
        target[path[-1]] = value
    return changed


BAD_RECORDS = [
    (("schema",), "impact.golden-record.v2"),
    (("extra",), 1),
    (("family",), KeyError),
    (("checksum_variant_id",), None),
    (("base_image_hash",), "00"),
    (("oracle",), None),
    (("oracle", "level"), "golden_field"),
    (("oracle", "tools"), [tool("B"), tool("A")]),
    (("oracle", "tools"), [tool("A"), tool("A")]),
    (("oracle", "tools"), [{**tool("A"), "date": "2026-10-18T00:00:00Z"}]),
    (("oracle", "tools"), [{**tool("A"), "version": 1}]),
    (("oracle", "tools"), [{**tool("A"), "extra": 1}]),
    (("oracle", "tools"), {"name": "A"}),
    (("oracle", "attestations"), ["22" * 32, "11" * 32]),
    (("oracle", "attestations"), ["11" * 32, "11" * 32]),
    (("oracle", "attestations"), ["XY" * 32]),
]


# SPEC-006 R70, R72, R80 `bad_shape`: a malformed record is a precondition failure, never a level.
@pytest.mark.parametrize(("path", "value"), BAD_RECORDS, ids=str)
def test_bad_record(path: tuple[str, ...], value: object) -> None:
    changed = _changed(path, value)
    assert reason_of(lambda: parse_golden_record(changed)) == "bad_shape"
    assert reason_of(lambda: evaluate(changed, [])) == "bad_shape"


# SPEC-006 R70, R80 `impact_oracle`: no tool named after this project, in any letter case.
@pytest.mark.parametrize("name", ["impact", "Impact CLI", "IMPACT-flash", "iMpAcTool 2"])
def test_impact_oracle(name: str) -> None:
    changed = record(H_AX, tools=[tool(name)])
    assert reason_of(lambda: parse_golden_record(changed)) == "impact_oracle"
    assert reason_of(lambda: evaluate(changed, [])) == "impact_oracle"
    assert isinstance(parse_golden_record(record(H_AX, tools=[tool("Flasher impact")])), GoldenRecord)


# SPEC-006 R70, R85: the hash, the key and a round trip of the record and its `oracle:` block.
def test_record_hash_and_key() -> None:
    value = record(H_AX, H_BY, tools=[tool("A", version="1"), tool("A", version="2")])
    parsed = parse_golden_record(value)
    assert parsed.golden_record_hash == sha(value)
    assert parsed.key == (
        value["family"],
        value["checksum_variant_id"],
        value["base_image_hash"],
        value["version_hash"],
    )
    assert sha(parsed.to_json()) == sha(value)


# SPEC-006 R72: `commitment_epoch` is a Hex32 and `attestations` a list (`bad_shape`).
def test_evaluation_preconditions() -> None:
    not_a_list: Any = {"AX": AX}
    assert reason_of(lambda: evaluate(record(H_AX), [AX], epoch="nope")) == "bad_shape"
    assert reason_of(lambda: evaluate(record(H_AX), not_a_list)) == "bad_shape"
    assert reason_of(lambda: evaluate(record(H_AX), "AX")) == "bad_shape"


# SPEC-006 R57, R80 `unpublished_dtc_set`: any set other than a published one is refused, even a superset.
@pytest.mark.parametrize(
    "dtc_set",
    [
        {**DTC_SET, "codes": [*DTC_SET["codes"], "P0610"]},
        {**DTC_SET, "version": 2},
        {**DTC_SET, "version": 1.0},
        [DTC_SET],
        "57c7c574aaf3d5c27c6d230071782c59553d9eb33daece04869a45d38361e0dc",
    ],
)
def test_unpublished_dtc_set(dtc_set: Raw) -> None:
    assert reason_of(lambda: evaluate(record(H_AX), [AX], dtc_set=dtc_set)) == "unpublished_dtc_set"


def _entry(evaluation: GoldenEvaluation, attestation_hash: str) -> Mapping[str, Raw]:
    return next(e.to_json() for e in evaluation.attestations if e.attestation_hash == attestation_hash)


# SPEC-006 R73 stage 2, R87 `impact_write_tool`, R100 replay into another record: every relevance reason, sorted.
def test_relevance_reasons() -> None:
    value = attestation(
        B,
        "Y",
        subject_image_hash=OTHER,
        identification={**AX["attestation"]["identification"], "checksum_variant_id": "synthetic.variant.2"},
        write_tool={"name": "IMPACT export", "version": "0.1.0"},
    )
    entry = signed(value)
    evaluation = evaluate(record(H_AX, entry["attestation_hash"]), [AX, entry])
    assert _entry(evaluation, entry["attestation_hash"]) == {
        "attestation_hash": entry["attestation_hash"],
        "qualifying": False,
        "negative": False,
        "reasons": ["impact_write_tool", "wrong_subject", "wrong_variant"],
    }
    assert evaluation.level == "none"


# SPEC-006 R73 stage 3, R74: every outcome reason that applies, sorted, makes the entry negative; R55: the failure
# type byte never hides a code; R44: a readback that differs is negative.
def test_outcome_reasons() -> None:
    value = attestation(
        B,
        "Y",
        communicates=False,
        dtcs_after_clear_and_reread=["P0120", "P062F-87"],
        tool_checksum_status="mismatch",
        readback_image_hash=OTHER,
    )
    entry = signed(value)
    evaluation = evaluate(record(H_AX, H_BY, entry["attestation_hash"]), [AX, BY, entry])
    assert _entry(evaluation, entry["attestation_hash"])["reasons"] == [
        "disqualifying_dtc",
        "no_communication",
        "readback_mismatch",
        "tool_checksum_mismatch",
    ]
    assert _entry(evaluation, entry["attestation_hash"])["negative"] is True
    assert evaluation.counts.attestations == 2
    assert evaluation.reasons == ("negative_field_evidence",)
    assert evaluation.level == "none"


# SPEC-006 R73: a relevance failure hides the outcome stage, so an attestation about another image is not negative.
def test_stages_stop_at_the_first_with_reasons() -> None:
    entry = signed(attestation(B, "Y", subject_image_hash=OTHER, communicates=False))
    evaluation = evaluate(record(H_AX, H_BY, entry["attestation_hash"]), [AX, BY, entry])
    assert _entry(evaluation, entry["attestation_hash"])["reasons"] == ["wrong_subject"]
    assert evaluation.level == "golden_field"


# SPEC-006 R73: a supplied attestation not listed is ignored; one listed but not supplied is `missing`.
def test_unlisted_and_missing() -> None:
    evaluation = evaluate(record(H_AX, H_BY), [AX, BY, POOL["EZ_NOCOMM"]])
    assert evaluation.level == "golden_field"
    missing = evaluate(record(H_AX, "ff" * 32), [AX])
    assert _entry(missing, "ff" * 32)["reasons"] == ["missing"]


# SPEC-006 R73: among copies claiming one hash, the one whose recomputed hash matches wins, whatever the order;
# among several such copies (one attestation, two signatures), the JCS order decides, so input order never does.
def test_collapse_of_copies() -> None:
    forged = {**BY, "attestation": {**BY["attestation"], "communicates": False}}
    resigned = {**BY, "signature": AX["signature"]}
    not_json = {**BY, "attestation": {**BY["attestation"], "created_at": 1.5}}
    for supplied in ([AX, forged, BY], [BY, forged, AX], [not_json, AX, BY], [AX, BY, not_json]):
        assert evaluate(record(H_AX, H_BY), supplied).level == "golden_field"
    first = evaluate(record(H_AX, H_BY), [AX, BY, resigned])
    second = evaluate(record(H_AX, H_BY), [resigned, AX, BY])
    assert first == second
    assert _entry(first, H_BY)["reasons"] == (["bad_signature"] if resigned["signature"] < BY["signature"] else [])
    alone = evaluate(record(H_AX, H_BY), [AX, forged])
    assert _entry(alone, H_BY)["reasons"] == ["attestation_hash_mismatch"]
    unhashable = evaluate(record(H_AX, H_BY), [AX, not_json])
    assert _entry(unhashable, H_BY)["reasons"] == ["bad_shape"]


# SPEC-006 R76: `golden_concordant` needs two matching tools with distinct names and no disagreement.
def test_tool_levels() -> None:
    same_name = record(H_AX, tools=[tool("A", version="1"), tool("A", version="2")])
    assert evaluate(same_name, [AX]).level == "candidate"
    two = record(H_AX, tools=[tool("A"), tool("B")])
    assert evaluate(two, [AX]).level == "golden_concordant"
    disagree = record(H_AX, tools=[tool("A"), tool("B"), tool("C", OTHER)])
    evaluation = evaluate(disagree, [AX])
    assert (evaluation.level, evaluation.reasons) == (
        "candidate",
        ("below_attestations", "below_attesters", "below_units", "tool_disagreement"),
    )
    only_other = record(H_AX, tools=[tool("C", OTHER)])
    assert evaluate(only_other, [AX]).level == "none"


# SPEC-006 R78: the evaluation is data with its hash, never a boolean.
def test_evaluation_object() -> None:
    evaluation = evaluate(record(H_AX, H_BY), [AX, BY])
    value = evaluation.to_json()
    assert value["schema"] == "impact.golden-evaluation.v1"
    assert evaluation.evaluation_hash == sha(value)


# SPEC-006 R86: a record only gains attestations, and gaining one is a golden change (a new `golden_record_hash`).
def test_adding_an_attestation_changes_the_record() -> None:
    before = parse_golden_record(record(H_AX))
    after = parse_golden_record(record(H_AX, H_BY))
    assert before.key == after.key
    assert before.golden_record_hash != after.golden_record_hash
    assert set(before.attestations) < set(after.attestations)
