"""SPEC-006 R72-R77 as properties: order independence, determinism and the classification matrix.

A pool of signed attestations covers every attester state (enrolled, rotated, revoked as compromised, reviewer-only,
unknown), every unit (three serials and one without) and every R73 stage. The expected reasons, counts and levels
come from the table in `expected`, written from SPEC-006 §7.2, not from `core.evidence`.
"""

import copy
import random
from dataclasses import dataclass
from itertools import product
from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from core.evidence import AttesterRegistry, FieldEvidence, GoldenEvaluation, evaluate_golden, evidence_admission
from tests.unit.evidence_support import (
    A2,
    DTC_SET,
    EPOCH,
    EPOCH2,
    GOLDEN,
    OTHER,
    POST,
    PRE,
    REVIEWED,
    TEMPLATE,
    A,
    B,
    C,
    D,
    E,
    F,
    V,
    attestation,
    record,
    signed,
    tool,
)
from tests.unit.provenance_support import VERIFIER, Ed25519Signer
from tests.unit.provenance_support import _plain as plain

KEYS: dict[str, Ed25519Signer] = {"A": A, "A2": A2, "B": B, "C": C, "D": D, "E": E, "F": F}
IDENTITY = {"A": "A", "A2": "A", "B": "B", "C": "C", "E": "E"}
UNITS = ("X", "Y", "Z", None)
KINDS: dict[str, dict[str, Any]] = {
    "ok": {},
    "not_reported": {"tool_checksum_status": "not_reported"},
    "benign_dtc": {"dtcs_after_clear_and_reread": ["P0120", "U0100-87"]},
    "no_communication": {"communicates": False},
    "disqualifying_dtc": {"dtcs_after_clear_and_reread": ["P0606-41"]},
    "tool_checksum_mismatch": {"tool_checksum_status": "mismatch"},
    "readback_mismatch": {"readback_image_hash": OTHER},
    "wrong_subject": {"subject_image_hash": OTHER, "readback_image_hash": OTHER},
    "wrong_variant": {"identification": {**TEMPLATE["identification"], "checksum_variant_id": "synthetic.variant.2"}},
    "foreign_epoch": {"ecu_commitment_epoch": EPOCH2},
    "impact_write_tool": {"write_tool": {"name": "impact", "version": "0.1.0"}},
}
OUTCOMES = {"no_communication", "disqualifying_dtc", "tool_checksum_mismatch", "readback_mismatch"}
RELEVANCE = {"wrong_subject", "wrong_variant", "foreign_epoch", "impact_write_tool"}


@dataclass(frozen=True)
class Item:
    key: str
    unit: str | None
    kind: str
    signed: dict[str, Any]

    @property
    def attestation_hash(self) -> str:
        return str(self.signed["attestation_hash"])


def _item(key: str, unit: str | None, kind: str) -> Item:
    value = attestation(KEYS[key], unit, **copy.deepcopy(KINDS[kind]))
    return Item(key, unit, kind, signed(value, KEYS[key]))


POOL = [
    _item(key, unit, kind)
    for key, unit, kind in product(KEYS, UNITS, KINDS)
    if not (unit is None and kind == "foreign_epoch")
]
REGISTRIES: dict[str, AttesterRegistry] = {"pre": PRE, "post": POST}


def expected(item: Item, registry: str) -> list[str]:
    """SPEC-006 R50, R73, R77 for one pool item, from the attester states of the vector chain."""
    if item.key == "D":
        return ["unknown_attester"]
    if item.key == "C" and registry == "post":
        return ["revoked_attester"]
    if item.key == "F":
        return ["not_attester"]
    if item.kind in RELEVANCE or item.kind in OUTCOMES:
        return [item.kind]
    return [] if item.unit is not None else ["no_unit_commitment"]


selection = st.lists(st.sampled_from(POOL), min_size=0, max_size=6, unique_by=lambda item: item.attestation_hash)
registry_names = st.sampled_from(sorted(REGISTRIES))


def _evaluate(
    listed: list[Item], supplied: list[dict[str, Any]], registry: str, tools: list[Any] | None = None
) -> GoldenEvaluation:
    golden = record(*(item.attestation_hash for item in listed), tools=tools)
    return evaluate_golden(golden, supplied, REGISTRIES[registry], DTC_SET, EPOCH, VERIFIER)


# SPEC-006 R72, R73, R100 (replay counts once), R110: order, duplicates and unlisted attestations change nothing.
@given(selection, registry_names, st.lists(st.sampled_from(POOL), max_size=3), st.randoms(use_true_random=False))
def test_order_and_duplicates(listed: list[Item], registry: str, extra: list[Item], rng: random.Random) -> None:
    supplied = [item.signed for item in listed]
    noisy = supplied + [item.signed for item in extra] + [rng.choice(supplied) for _ in supplied]
    rng.shuffle(noisy)
    first = _evaluate(listed, supplied, registry)
    assert _evaluate(listed, noisy, registry) == first
    assert _evaluate(listed, supplied, registry).evaluation_hash == first.evaluation_hash


# SPEC-006 R50, R52, R55, R73, R74, R77: every entry has exactly the expected reasons; negative iff stage 3.
@given(selection, registry_names, st.booleans())
def test_entry_matrix(listed: list[Item], registry: str, drop_one: bool) -> None:
    supplied = [item.signed for item in listed]
    if drop_one and supplied:
        supplied = supplied[1:]
    evaluation = _evaluate(listed, supplied, registry)
    entries = {entry.attestation_hash: entry for entry in evaluation.attestations}
    assert [entry.attestation_hash for entry in evaluation.attestations] == sorted(entries)
    for index, item in enumerate(listed):
        entry = entries[item.attestation_hash]
        reasons = ["missing"] if drop_one and index == 0 else expected(item, registry)
        assert list(entry.reasons) == reasons
        assert entry.qualifying == (not reasons)
        assert entry.negative == bool(reasons and set(reasons) <= OUTCOMES)


# SPEC-006 R71, R74-R76: with N = K = E = 2, `golden_field` iff no negative and two qualifying entries that differ
# in both identity and unit; counts are over qualifying entries, identities by rotation chain. R101: two enrolled
# identities meet K whoever holds them; enrollment is the only Sybil defense.
@given(selection, registry_names)
def test_field_level(listed: list[Item], registry: str) -> None:
    evaluation = _evaluate(listed, [item.signed for item in listed], registry)
    qualifying = [item for item in listed if not expected(item, registry)]
    negative = any(set(expected(item, registry)) <= OUTCOMES and expected(item, registry) for item in listed)
    pair = any(a.unit != b.unit and IDENTITY[a.key] != IDENTITY[b.key] for a in qualifying for b in qualifying)
    assert (evaluation.level == "golden_field") == (pair and not negative)
    assert evaluation.counts.attestations == len(qualifying)
    assert evaluation.counts.attesters == len({IDENTITY[item.key] for item in qualifying})
    assert evaluation.counts.units == len({item.unit for item in qualifying})
    assert ("negative_field_evidence" in evaluation.reasons) == negative


tools = st.lists(
    st.tuples(st.sampled_from(["Alpha", "Beta", "Gamma"]), st.sampled_from(["1", "2"]), st.booleans()),
    max_size=4,
    unique_by=lambda entry: (entry[0], entry[1]),
)


# SPEC-006 R76: tools never raise a level to `golden_field` nor lower it; below it, they decide the level.
@given(selection, registry_names, tools)
def test_tools_never_touch_the_field_level(listed: list[Item], registry: str, chosen: list[Any]) -> None:
    oracle_tools = sorted(
        (tool(name, GOLDEN if matches else OTHER, version) for name, version, matches in chosen),
        key=lambda entry: (entry["name"], entry["version"]),
    )
    supplied = [item.signed for item in listed]
    without = _evaluate(listed, supplied, registry)
    with_tools = _evaluate(listed, supplied, registry, oracle_tools)
    assert (without.level == "golden_field") == (with_tools.level == "golden_field")
    if with_tools.level != "golden_field":
        names = {name for name, _, matches in chosen if matches}
        disagree = any(not matches for _, _, matches in chosen)
        level = "golden_concordant" if len(names) >= 2 and not disagree else "candidate" if names else "none"
        assert with_tools.level == level
    assert ("tool_disagreement" in with_tools.reasons) == any(not matches for _, _, matches in chosen)


ADMISSIONS = {case["id"]: case for case in V["admissions"]}
ALL = list(V["attestations"].values())


# SPEC-006 R83, R110: the order of records and attestations in the evidence never changes the admission.
@given(
    st.sampled_from(["A7-negative-without-review", "A8-negative-with-approved-review"]),
    st.randoms(use_true_random=False),
)
def test_admission_order(case_id: str, rng: random.Random) -> None:
    case = ADMISSIONS[case_id]
    registry = REVIEWED if case["registry"] == "reviewed" else POST
    records, attestations = list(case["records"]), list(ALL)
    rng.shuffle(records)
    rng.shuffle(attestations)
    bundle = FieldEvidence(V["heads"]["values"][case["head"]], registry, records, attestations, DTC_SET, EPOCH)
    admission = evidence_admission(
        bundle, V["trust"], V["head_policy"]["value"], case["as_of"], VERIFIER, test_mode=True
    )
    assert plain(admission.to_json()) == case["expect"]
