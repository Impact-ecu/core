"""SPEC-004 §5: rule-table validation (R30, R32, R33) and the map rules (R30, R34-R39) on decoded maps."""

from fractions import Fraction
from typing import Any

import pytest

from core.definitions import NON_FINITE, Value
from core.gate import parse_rule_table
from core.gate._maps import AxisView, Engine, Entries, MapView, UnboundMap, evaluate_maps
from core.gate._rules import Table, parse_rational
from tests.unit.gate_support import TABLE, key, rule

SI_GASOLINE = Engine("SI", "gasoline")


def table(*rules: dict[str, Any], threshold: int = 800) -> dict[str, Any]:
    return {"table_id": "t", "version": "1.0.0", "identify_min_confidence": threshold, "rules": list(rules)}


SYN = key("syn", "base", "SI", "gasoline", "u")
AMP = {"neutral": "1", "max_deviation": "0"}
INFO = {"severity": "info"}


def valid_rules() -> list[dict[str, Any]]:
    return [
        rule("r.range", "range", SYN, {"min": "0"}, "range"),
        {**rule("r.sensor", "sensor_range", SYN, {"min": "0", "max": "9"}, "sensor"), "severity": "block"},
        rule("r.cap", "conditional_cap", SYN, {"max": "1", "above": "2", "axis_unit": "rpm"}, "cap"),
        rule("r.amp", "relative_amplitude", key("syn", "correction", "CI", None, "u"), AMP, "a"),
        {**rule("r.smooth", "smoothness", key("syn", "flag", "SI", "E100", "u"), {"max_step": "1/2"}, "s"), **INFO},
    ]


# SPEC-004 R32, R33: a valid table parses, keeps its rules and records `{table_id, version, hash}`.
def test_valid_table() -> None:
    parsed = parse_rule_table(table(*valid_rules()))
    assert isinstance(parsed, Table)
    assert [r.rule_id for r in parsed.rules] == ["r.range", "r.sensor", "r.cap", "r.amp", "r.smooth"]
    assert parsed.rules[2].axis_unit == "rpm"
    assert parsed.rules[2].params == {"max": Fraction(1), "above": Fraction(2)}
    assert parsed.rules[4].params == {"max_step": Fraction(1, 2)}
    assert set(parsed.ref()) == {"table_id", "version", "hash"}
    assert parse_rule_table(TABLE) is not None


def mutate(path: tuple[Any, ...], new: object) -> dict[str, Any]:
    value = table(*valid_rules())
    target: Any = value
    for step in path[:-1]:
        target = target[step]
    if new is DELETE:
        del target[path[-1]]
    else:
        target[path[-1]] = new
    return value


DELETE = object()

INVALID = [
    ("not an object", None, None),
    ("extra top-level key", ("extra",), 1),
    ("threshold above 1000", ("identify_min_confidence",), 1001),
    ("threshold boolean", ("identify_min_confidence",), True),
    ("empty table id", ("table_id",), ""),
    ("table id lone surrogate", ("table_id",), "\ud800"),
    ("version not semver", ("version",), "1.0"),
    ("rules not a list", ("rules",), "rules"),
    ("rules a mapping", ("rules",), {}),
    ("rule not an object", ("rules", 0), "rule"),
    ("rule id with G- prefix", ("rules", 0, "rule_id"), "G-X"),
    ("rule id not a string", ("rules", 0, "rule_id"), 1),
    ("unknown kind", ("rules", 0, "kind"), "diff"),
    ("empty text", ("rules", 0, "text"), ""),
    ("rule_version 0", ("rules", 0, "rule_version"), 0),
    ("key not an object", ("rules", 0, "key"), []),
    ("key missing unit", ("rules", 0, "key", "unit"), DELETE),
    ("bad map type", ("rules", 0, "key", "map_type"), "table"),
    ("bad combustion", ("rules", 0, "key", "combustion"), "EV"),
    ("bad fuel", ("rules", 0, "key", "fuel"), "kerosene"),
    ("empty category", ("rules", 0, "key", "category"), ""),
    ("params not an object", ("rules", 0, "params"), []),
    ("range without bounds", ("rules", 0, "params"), {}),
    ("unknown parameter", ("rules", 0, "params", "step"), "1"),
    ("non-canonical rational", ("rules", 0, "params", "min"), "0.5"),
    ("unreduced rational", ("rules", 0, "params", "min"), "2/4"),
    ("denominator one", ("rules", 0, "params", "min"), "1/1"),
    ("negative zero", ("rules", 0, "params", "min"), "-0"),
    ("rational not a string", ("rules", 0, "params", "min"), 0),
    ("sensor range missing max", ("rules", 1, "params", "max"), DELETE),
    ("sensor range warn", ("rules", 1, "severity"), "warn"),
    ("range block", ("rules", 0, "severity"), "block"),
    ("cap axis unit empty", ("rules", 2, "params", "axis_unit"), ""),
    ("cap on a correction map", ("rules", 2, "key", "map_type"), "correction"),
    ("amplitude on a base map", ("rules", 3, "key", "map_type"), "base"),
    ("negative max deviation", ("rules", 3, "params", "max_deviation"), "-1"),
    ("negative max step", ("rules", 4, "params", "max_step"), "-1/2"),
    ("duplicate rule id", ("rules", 1, "rule_id"), "r.range"),
]


# SPEC-004 R30, R33: every violation makes the table invalid, hence unavailable (R21).
@pytest.mark.parametrize(("what", "path", "new"), INVALID, ids=[case[0] for case in INVALID])
def test_invalid_tables(what: str, path: tuple[Any, ...] | None, new: object) -> None:
    del what
    value: object = None if path is None else mutate(path, new)
    assert parse_rule_table(value) is None


# SPEC-004 R30: the canonical text form, exactly.
@pytest.mark.parametrize(
    ("text", "expected"),
    [("0", Fraction(0)), ("-7", Fraction(-7)), ("3/4", Fraction(3, 4)), ("-23/20", Fraction(-23, 20))],
)
def test_parse_rational(text: str, expected: Fraction) -> None:
    assert parse_rational(text) == expected


@pytest.mark.parametrize("text", ["-0", "01", "1/0", "1/1", "2/4", "+1", "1.5", "", "1/-2", "-0/3"])
def test_parse_rational_rejects(text: str) -> None:
    assert parse_rational(text) is None


def grid(rows: list[list[int | str]]) -> tuple[tuple[Value, ...], ...]:
    return tuple(tuple(NON_FINITE if v == "nan" else Fraction(v) for v in row) for row in rows)


def view(
    cells: list[list[int | str]],
    *,
    x: tuple[str | None, list[int | str]] | None = None,
    y: tuple[str | None, list[int | str]] | None = None,
    **fields: object,
) -> MapView:
    base: dict[str, Any] = {
        "map_id": "m",
        "state": "reviewed",
        "category": "syn",
        "map_type": "base",
        "unit": "u",
        "edited": True,
    }
    base.update(fields)

    def axis(spec: tuple[str | None, list[int | str]] | None) -> AxisView | None:
        return None if spec is None else AxisView(spec[0], grid([spec[1]])[0])

    return MapView(cells=grid(cells), x=axis(x), y=axis(y), **base)


def run(m: MapView | UnboundMap, *rules: dict[str, Any], engine: Engine = SI_GASOLINE) -> Entries:
    parsed = parse_rule_table(table(*rules))
    assert parsed is not None
    return evaluate_maps((m,), parsed, engine)


def found(out: Entries) -> list[tuple[str, str | None, tuple[tuple[int, int], ...], str | None, tuple[int, ...]]]:
    return [(f.rule_id, f.map_id, f.cells, f.axis, f.breakpoints) for f in out.findings]


def skipped(out: Entries) -> list[tuple[str, str, str | None, str | None]]:
    return [(e.kind, e.reason, e.map_id, e.rule_id) for e in out.not_tested]


def ran(out: Entries) -> list[tuple[str, str | None, str | None]]:
    return [(e.kind, e.map_id, e.rule_id) for e in out.tested]


# SPEC-004 R39: strict monotonicity in either direction; breakpoints name every bad difference.
@pytest.mark.parametrize(
    ("points", "bad"),
    [([1, 2, 3], []), ([3, 2, 1], []), ([5], []), ([1, 3, 2, 4], [1]), ([3, 3, 3], [0, 1]), ([2, 1, 1, 3], [1, 2])],
)
def test_axis_monotonic(points: list[int | str], bad: list[int]) -> None:
    out = run(view([[1] * len(points)], x=("rpm", points)))
    assert ran(out)[0] == ("axis_monotonic", "m", "G-AXIS-MONOTONIC")
    expected = [("G-AXIS-MONOTONIC", "m", (), "x", tuple(bad))] if bad else []
    assert [f for f in found(out) if f[0] == "G-AXIS-MONOTONIC"] == expected


# SPEC-004 R30, R38 step 1: non-finite breakpoints and cells block; monotonicity is then not tested.
def test_non_finite() -> None:
    out = run(view([[1, "nan"], [2, 3]], x=("rpm", [1, "nan"]), y=("rpm", ["nan", 2])))
    assert found(out)[:3] == [
        ("G-NONFINITE", "m", (), "x", (1,)),
        ("G-NONFINITE", "m", (), "y", (0,)),
        ("G-NONFINITE", "m", ((0, 1),), None, ()),
    ]
    assert ("axis_monotonic", "non_finite", "m", None) in skipped(out)


# SPEC-004 R38 step 1: a map without axes.
def test_no_axis() -> None:
    assert ("axis_monotonic", "no_axis", "m", None) in skipped(run(view([[1]])))


# SPEC-004 R35, R38 steps 2 and 4: an unreviewed map warns and runs only monotonicity and smoothness.
@pytest.mark.parametrize(
    "fields",
    [{"state": "proposed"}, {"category": None}, {"map_type": None}, {"unit": None}, {"state": "imported"}],
)
def test_unreviewed(fields: dict[str, Any]) -> None:
    out = run(view([[90]], **fields), rule("r", "range", SYN, {"max": "1"}, "t"))
    assert found(out) == [("G-UNREVIEWED", "m", (), None, ())]
    assert ("physical_range", "category_not_reviewed", "m", None) in skipped(out)


def test_unreviewed_correction_lists_amplitude() -> None:
    out = run(view([[1]], state="proposed", map_type="correction"))
    assert ("relative_amplitude", "category_not_reviewed", "m", None) in skipped(out)


# SPEC-004 R38 step 3: smoothness reasons in order, then both cells of every pair above max_step.
def test_smoothness() -> None:
    smooth = rule("r.s", "smoothness", SYN, {"max_step": "10"}, "s")
    assert ("smoothness", "shape", "m", None) in skipped(run(view([[1, 50]]), smooth))
    assert ("smoothness", "binary", "m", None) in skipped(run(view([[0, 1], [1, 0]]), smooth))
    assert ("smoothness", "fuel_not_declared", "m", None) in skipped(
        run(view([[0, 1], [2, 3]]), smooth, engine=Engine("SI", None))
    )
    assert ("smoothness", "no_rule", "m", None) in skipped(run(view([[0, 1], [2, 3]])))
    out = run(view([[0, 5, 30], [5, 10, "nan"]]), smooth)
    assert ("r.s", "m", ((0, 1), (0, 2)), None, ()) in found(out)
    assert ("smoothness", "m", "r.s") in ran(out)


# SPEC-004 R34: context reasons; a rule without fuel is listed once and never matches.
def test_context() -> None:
    nofuel = rule("r.nofuel", "range", key("syn", "base", "SI", None, "u"), {"max": "0"}, "t")
    smooth = rule("r.amp", "relative_amplitude", key("syn", "correction", "SI", None, "u"), AMP, "a")
    out = run(view([[5]]), nofuel, smooth)
    assert ("physical_range", "rule_without_fuel", None, "r.nofuel") in skipped(out)
    assert ("relative_amplitude", "rule_without_fuel", None, "r.amp") in skipped(out)
    assert ("physical_range", "no_rule", "m", None) in skipped(out)
    out = run(view([[5]]), engine=Engine(None, "gasoline"))
    assert ("physical_range", "combustion_not_declared", "m", None) in skipped(out)


# SPEC-004 R36, R38 steps 5-6: correction runs only relative amplitude; limit and flag run no range.
def test_map_types() -> None:
    quarter = {"neutral": "1", "max_deviation": "1/4"}
    amp = rule("r.amp", "relative_amplitude", key("syn", "correction", "SI", "gasoline", "u"), quarter, "a")
    out = run(view([["3/4", "5/4"], [1, "13/10"]], map_type="correction"), amp)
    assert ("physical_range", "map_type_correction", "m", None) in skipped(out)
    assert ("r.amp", "m", ((1, 1),), None, ()) in found(out)
    assert ("relative_amplitude", "fuel_not_declared", "m", None) in skipped(
        run(view([[1]], map_type="correction"), amp, engine=Engine("SI", None))
    )
    assert ("relative_amplitude", "no_rule", "m", None) in skipped(run(view([[1]], map_type="correction")))
    for map_type in ("limit", "flag"):
        out = run(view([[900]], map_type=map_type), rule("r", "range", SYN, {"max": "1"}, "t"))
        assert found(out) == []
        assert ("physical_range", f"map_type_{map_type}", "m", None) in skipped(out)


# SPEC-004 R37: inclusive bounds; sensor range blocks; info goes with its severity.
def test_ranges() -> None:
    both = rule("r.range", "range", SYN, {"min": "-10", "max": "45"}, "t")
    out = run(view([[-10, 45], [-11, 46]]), both)
    assert found(out) == [("r.range", "m", ((1, 0), (1, 1)), None, ())]
    only_min = rule("r.min", "range", SYN, {"min": "23/20"}, "t")
    assert found(run(view([["23/20", 1]]), only_min)) == [("r.min", "m", ((0, 1),), None, ())]
    sensor = {**rule("r.sensor", "sensor_range", SYN, {"min": "0", "max": "250"}, "t"), "severity": "block"}
    out = run(view([[-1, 250]]), sensor)
    assert [f.severity for f in out.findings] == ["block"]
    info = {**both, "severity": "info"}
    assert [f.severity for f in run(view([[99]]), info).findings] == ["info"]


# SPEC-004 R37 conditional cap: strictly above on either matching axis; `axis_unit_absent` otherwise.
def test_conditional_cap() -> None:
    cap = rule("r.cap", "conditional_cap", SYN, {"max": "30", "above": "50", "axis_unit": "kPa_rel"}, "t")
    rows: list[list[int | str]] = [[31, 31], [31, 31]]
    out = run(view(rows, x=("rpm", [1, 2]), y=("kPa_rel", [50, 60])), cap)
    assert found(out) == [("r.cap", "m", ((1, 0), (1, 1)), None, ())]
    out = run(view(rows, x=("kPa_rel", [40, "nan"]), y=("rpm", [1, 2])), cap)
    assert [f for f in found(out) if f[0] == "r.cap"] == []
    out = run(view(rows, x=("rpm", [1, 2])), cap)
    assert ("physical_range", "axis_unit_absent", "m", "r.cap") in skipped(out)
    assert ("physical_range", "m", "r.cap") not in ran(out)


# SPEC-004 R39: injector duty above 100% blocks for a reviewed base map in percent, whatever the context.
def test_injector_duty() -> None:
    out = run(view([[100, "201/2"]], category="injector_duty", unit="percent"), engine=Engine(None, None))
    assert found(out) == [("G-INJECTOR-DUTY", "m", ((0, 1),), None, ())]
    assert ran(out) == [("physical_range", "m", "G-INJECTOR-DUTY")]
    assert ("physical_range", "combustion_not_declared", "m", None) in skipped(out)
    duty = run(view([[50]], category="injector_duty", unit="percent"))
    assert found(duty) == []
    assert ("physical_range", "no_rule", "m", None) not in skipped(duty)


# SPEC-004 R28, R31: a map that does not bind blocks; an unedited map is not tested.
def test_unbound_and_unedited() -> None:
    out = run(UnboundMap("stale"))
    assert found(out) == [("G-DEFINITION", "stale", (), None, ())]
    assert skipped(out) == [("map_rules", "definition_bind", "stale", None)]
    out = run(view([[900]], edited=False), rule("r", "range", SYN, {"max": "1"}, "t"))
    assert found(out) == []
    assert skipped(out) == [("map_rules", "not_edited", "m", None)]
