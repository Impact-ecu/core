"""Map rules on decoded maps: SPEC-004 R30, R34-R39.

Values are exact rationals (`Fraction`) or the token `non_finite` (SPEC-003 R7); nothing here uses floating
point (R30). The maps arrive already decoded from the release candidate (R31); this module never decodes.
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from fractions import Fraction
from itertools import pairwise

from core.definitions import Value
from core.gate._model import Axis, Combustion, Finding, Fuel, NotTested, Tested, builtin
from core.gate._rules import RANGE_KINDS, Rule, RuleKind, Table
from core.provenance import Json

_REVIEWED_STATES = frozenset({"reviewed", "golden"})
_HUNDRED = Fraction(100)


@dataclass(frozen=True, slots=True)
class Engine:
    """`{combustion, fuel}` of SPEC-004 §4; either may be undeclared (R34)."""

    combustion: Combustion | None
    fuel: Fuel | None

    def to_json(self) -> dict[str, Json]:
        return {"combustion": self.combustion, "fuel": self.fuel}


@dataclass(frozen=True, slots=True)
class AxisView:
    unit: str | None
    values: tuple[Value, ...]


@dataclass(frozen=True, slots=True)
class MapView:
    """One `MapDef` decoded from the release candidate, rows outer (SPEC-003 R56), and whether it was edited."""

    map_id: str
    state: str
    category: str | None
    map_type: str | None
    unit: str | None
    cells: tuple[tuple[Value, ...], ...]
    x: AxisView | None
    y: AxisView | None
    edited: bool


@dataclass(frozen=True, slots=True)
class UnboundMap:
    """A `MapDef` whose `span` or `decode` failed on the original or on the release candidate (R28, R31)."""

    map_id: str


@dataclass(slots=True)
class Entries:
    """What one run collects; sorted and split only when the report is assembled (R3, R42)."""

    findings: list[Finding] = field(default_factory=list[Finding])
    tested: list[Tested] = field(default_factory=list[Tested])
    not_tested: list[NotTested] = field(default_factory=list[NotTested])

    def extend(self, other: "Entries") -> None:
        self.findings.extend(other.findings)
        self.tested.extend(other.tested)
        self.not_tested.extend(other.not_tested)


def check_kind(kind: RuleKind) -> str:
    """The R41 kind a table rule is reported under."""
    return "physical_range" if kind in RANGE_KINDS else kind


def context_reason(engine: Engine) -> str | None:
    """R34: with a context reason no table rule matches any map."""
    if engine.combustion is None:
        return "combustion_not_declared"
    if engine.fuel is None:
        return "fuel_not_declared"
    return None


def reviewed(m: MapView) -> bool:
    """R35 via SPEC-003 R42: state `reviewed` or `golden`, and category, map type and unit set."""
    return m.state in _REVIEWED_STATES and None not in (m.category, m.map_type, m.unit)


def _matches(rule: Rule, m: MapView, engine: Engine) -> bool:
    """R32: the whole key."""
    key = rule.key
    return (key.category, key.map_type, key.unit, key.combustion, key.fuel) == (
        m.category,
        m.map_type,
        m.unit,
        engine.combustion,
        engine.fuel,
    )


def _cells(m: MapView, violates: Callable[[int, int, Fraction], bool]) -> list[tuple[int, int]]:
    """Every finite cell `(row, col)` for which `violates` holds. Non-finite cells are R30's alone."""
    return [
        (row, col)
        for row, values in enumerate(m.cells)
        for col, value in enumerate(values)
        if isinstance(value, Fraction) and violates(row, col, value)
    ]


def _emit(out: Entries, rule: Rule, m: MapView, cells: Sequence[tuple[int, int]]) -> None:
    """R37: one finding per rule listing every violating cell; every rule that runs is `tested`."""
    out.tested.append(Tested(check_kind(rule.kind), m.map_id, rule.rule_id))
    if cells:
        out.findings.append(Finding(rule.rule_id, rule.rule_version, rule.severity, rule.text, m.map_id, tuple(cells)))


def _axes(m: MapView, out: Entries) -> None:
    """R30 non-finite breakpoints and R39 strict monotonicity, in the order of R38 step 1."""
    named: tuple[tuple[Axis, AxisView | None], ...] = (("x", m.x), ("y", m.y))
    axes = [(name, view) for name, view in named if view is not None]
    non_finite = False
    for name, view in axes:
        indices = [i for i, v in enumerate(view.values) if not isinstance(v, Fraction)]
        if indices:
            non_finite = True
            out.findings.append(builtin("G-NONFINITE", map_id=m.map_id, axis=name, breakpoints=indices))
    if not axes:
        out.not_tested.append(NotTested("axis_monotonic", "no_axis", m.map_id))
        return
    if non_finite:
        out.not_tested.append(NotTested("axis_monotonic", "non_finite", m.map_id))
        return
    out.tested.append(Tested("axis_monotonic", m.map_id, "G-AXIS-MONOTONIC"))
    for name, view in axes:
        points = [v for v in view.values if isinstance(v, Fraction)]
        steps = [second - first for first, second in pairwise(points)]
        direction = next((step > 0 for step in steps if step != 0), None)
        bad = [i for i, step in enumerate(steps) if step == 0 or (step > 0) != direction]
        if bad:
            out.findings.append(builtin("G-AXIS-MONOTONIC", map_id=m.map_id, axis=name, breakpoints=bad))


def _smoothness(m: MapView, rules: Sequence[Rule], reason: str | None, out: Entries) -> None:
    """R38 step 3: both cells of every orthogonally adjacent pair differing by more than `max_step`."""
    rows, cols = len(m.cells), len(m.cells[0])
    if rows < 2 or cols < 2:
        out.not_tested.append(NotTested("smoothness", "shape", m.map_id))
        return
    if len({value for values in m.cells for value in values}) <= 2:
        out.not_tested.append(NotTested("smoothness", "binary", m.map_id))
        return
    if reason is not None:
        out.not_tested.append(NotTested("smoothness", reason, m.map_id))
        return
    matching = [rule for rule in rules if rule.kind == "smoothness"]
    if not matching:
        out.not_tested.append(NotTested("smoothness", "no_rule", m.map_id))
    for rule in matching:
        step = rule.params["max_step"]
        flagged: set[tuple[int, int]] = set()
        for row in range(rows):
            for col in range(cols):
                for other in ((row, col + 1), (row + 1, col)):
                    if other[0] < rows and other[1] < cols and _apart(m, (row, col), other, step):
                        flagged.update({(row, col), other})
        _emit(out, rule, m, sorted(flagged))


def _apart(m: MapView, a: tuple[int, int], b: tuple[int, int], step: Fraction) -> bool:
    x, y = m.cells[a[0]][a[1]], m.cells[b[0]][b[1]]
    return isinstance(x, Fraction) and isinstance(y, Fraction) and abs(x - y) > step


def _amplitude(m: MapView, rules: Sequence[Rule], reason: str | None, out: Entries) -> None:
    """R38 step 6, R37 `relative_amplitude`."""
    if reason is not None:
        out.not_tested.append(NotTested("relative_amplitude", reason, m.map_id))
        return
    matching = [rule for rule in rules if rule.kind == "relative_amplitude"]
    if not matching:
        out.not_tested.append(NotTested("relative_amplitude", "no_rule", m.map_id))
    for rule in matching:
        _emit(out, rule, m, _cells(m, _beyond(rule.params["neutral"], rule.params["max_deviation"])))


def _beyond(neutral: Fraction, deviation: Fraction) -> Callable[[int, int, Fraction], bool]:
    return lambda _row, _col, value: abs(value - neutral) > deviation


def _outside(low: Fraction | None, high: Fraction | None) -> Callable[[int, int, Fraction], bool]:
    return lambda _row, _col, value: (low is not None and value < low) or (high is not None and value > high)


def _hot(a: AxisView | None, unit: str, index: int, above: Fraction) -> bool:
    if a is None or a.unit != unit:
        return False
    coordinate = a.values[index]
    return isinstance(coordinate, Fraction) and coordinate > above


def _range_rule(m: MapView, rule: Rule, out: Entries) -> None:
    """R37 `range`, `sensor_range` and `conditional_cap`; bounds inclusive."""
    params = rule.params
    if rule.kind != "conditional_cap":
        _emit(out, rule, m, _cells(m, _outside(params.get("min"), params.get("max"))))
        return
    unit = rule.axis_unit or ""
    if not any(a is not None and a.unit == unit for a in (m.x, m.y)):
        out.not_tested.append(NotTested("physical_range", "axis_unit_absent", m.map_id, rule.rule_id))
        return
    cap, above = params["max"], params["above"]
    _emit(
        out,
        rule,
        m,
        _cells(m, lambda r, c, v: v > cap and (_hot(m.y, unit, r, above) or _hot(m.x, unit, c, above))),
    )


def _physical(m: MapView, rules: Sequence[Rule], reason: str | None, out: Entries) -> None:
    """R38 step 7: `G-INJECTOR-DUTY` regardless of context, then the range-kind table rules."""
    duty = m.category == "injector_duty" and m.unit == "percent"
    if duty:
        out.tested.append(Tested("physical_range", m.map_id, "G-INJECTOR-DUTY"))
        cells = _cells(m, lambda _r, _c, v: v > _HUNDRED)
        if cells:
            out.findings.append(builtin("G-INJECTOR-DUTY", map_id=m.map_id, cells=cells))
    if reason is not None:
        out.not_tested.append(NotTested("physical_range", reason, m.map_id))
        return
    matching = [rule for rule in rules if rule.kind in RANGE_KINDS]
    if not matching and not duty:
        out.not_tested.append(NotTested("physical_range", "no_rule", m.map_id))
    for rule in matching:
        _range_rule(m, rule, out)


def _evaluate(m: MapView, rules: Sequence[Rule], reason: str | None, out: Entries) -> None:
    """R38: the evaluation order and the precedence of not-tested reasons for one edited map."""
    _axes(m, out)
    non_finite = _cells_non_finite(m)
    if non_finite:
        out.findings.append(builtin("G-NONFINITE", map_id=m.map_id, cells=non_finite))
    is_reviewed = reviewed(m)
    if not is_reviewed:
        out.findings.append(builtin("G-UNREVIEWED", map_id=m.map_id))
    _smoothness(m, rules, reason, out)
    if not is_reviewed:
        out.not_tested.append(NotTested("physical_range", "category_not_reviewed", m.map_id))
        if m.map_type == "correction":
            out.not_tested.append(NotTested("relative_amplitude", "category_not_reviewed", m.map_id))
        return
    if m.map_type != "base":
        out.not_tested.append(NotTested("physical_range", f"map_type_{m.map_type}", m.map_id))
    if m.map_type == "correction":
        _amplitude(m, rules, reason, out)
    elif m.map_type == "base":
        _physical(m, rules, reason, out)


def _cells_non_finite(m: MapView) -> list[tuple[int, int]]:
    return [
        (row, col)
        for row, values in enumerate(m.cells)
        for col, value in enumerate(values)
        if not isinstance(value, Fraction)
    ]


def evaluate_maps(maps: Sequence[MapView | UnboundMap], table: Table, engine: Engine) -> Entries:
    """Step 8 of R20: R31 (which maps), R34 (rules without fuel, context) and R38 per edited map."""
    out = Entries()
    runnable: list[Rule] = []
    for rule in table.rules:
        if rule.key.fuel is None:
            out.not_tested.append(NotTested(check_kind(rule.kind), "rule_without_fuel", None, rule.rule_id))
        else:
            runnable.append(rule)
    reason = context_reason(engine)
    for m in maps:
        if isinstance(m, UnboundMap):
            out.findings.append(builtin("G-DEFINITION", map_id=m.map_id))
            out.not_tested.append(NotTested("map_rules", "definition_bind", m.map_id))
        elif not m.edited:
            out.not_tested.append(NotTested("map_rules", "not_edited", m.map_id))
        else:
            matched = [] if reason is not None else [rule for rule in runnable if _matches(rule, m, engine)]
            _evaluate(m, matched, reason, out)
    return out
