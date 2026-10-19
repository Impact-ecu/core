"""Hypothesis fuzzing of the rule-table parser (SPEC-004 R30, R33) and of alert-ack authorization (R52).

A rule table is data the gate receives; any value either validates or is unavailable (None). Nothing raises.
"""

import copy
from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from core.gate import Table, parse_rule_table
from core.gate._report import GateReport
from core.gate._result import authorize
from tests.unit.gate_support import TABLE

json_values = st.recursive(
    st.none() | st.booleans() | st.integers(-(2**60), 2**60) | st.text(max_size=8) | st.floats(allow_nan=True),
    lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=12), children, max_size=6),
    max_leaves=20,
)
TABLE_KEYS = ["table_id", "version", "identify_min_confidence", "rules"]
RULE_KEYS = ["rule_id", "rule_version", "kind", "severity", "text", "params", "key"]


@st.composite
def near_tables(draw: st.DrawFn) -> dict[str, Any]:
    """The test table with one member of the table, of a rule, of its params or of its key replaced or dropped."""
    value = copy.deepcopy(TABLE)
    rule = value["rules"][draw(st.integers(0, len(value["rules"]) - 1))]
    target, keys = draw(
        st.sampled_from(
            [
                (value, TABLE_KEYS),
                (rule, RULE_KEYS),
                (rule["params"], ["min", "max", "above", "axis_unit", "neutral"]),
                (rule["key"], ["category", "map_type", "combustion", "fuel", "unit"]),
            ]
        )
    )
    key = draw(st.sampled_from(keys))
    if draw(st.booleans()):
        target.pop(key, None)
    else:
        target[key] = draw(json_values)
    return value


# SPEC-004 R33: the parser never raises; a table it accepts hashes and keeps every rule.
@given(st.one_of(json_values, near_tables()))
def test_parser_never_raises(value: object) -> None:
    table = parse_rule_table(value)
    assert table is None or isinstance(table, Table)
    if isinstance(table, Table) and isinstance(value, dict):
        assert len(table.rules) == len(value["rules"])


class Ack:
    """An event as the gate reads it (R53), with an arbitrary payload."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self.event_id = "0" * 32
        self.project_id = "proj-1"
        self.type = "alert_ack"
        self.payload = payload


# SPEC-004 R52: any payload yields an authorization reason, never an exception.
@given(
    st.dictionaries(
        st.sampled_from(["image_hash_release", "gate_report_hash", "warnings", "presented_ms", "confirmed_ms"]),
        json_values,
    )
)
def test_authorization_never_raises(payload: dict[str, Any]) -> None:
    report = GateReport({"findings": (), "verdict": "warn"}, "0" * 64, "warn")
    reason = authorize(report, "0" * 64, "proj-1", Ack(payload))
    assert reason in {"bad_payload", "image_mismatch", "report_mismatch", "findings_mismatch", "text_mismatch", None}
