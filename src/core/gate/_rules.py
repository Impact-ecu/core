"""Rule tables: exact values (SPEC-004 R30), keys (R32) and validation (R33).

A table is data handed to the gate as JSON. An invalid table is unavailable (R21), never repaired, so
`parse_rule_table` returns None instead of raising.
"""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from fractions import Fraction
from typing import Literal, cast

from core.gate._model import Combustion, Fuel, Severity, json_hash
from core.provenance import Json

RuleKind = Literal["range", "conditional_cap", "sensor_range", "relative_amplitude", "smoothness"]
MapTypeKey = Literal["base", "correction", "limit", "flag"]

RULE_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_RATIONAL = re.compile(r"-?(?:0|[1-9][0-9]*)(?:/[1-9][0-9]*)?")
_SEMVER = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
_MAX_SAFE_INTEGER = 2**53 - 1

_TABLE_KEYS = frozenset({"table_id", "version", "identify_min_confidence", "rules"})
_RULE_KEYS = frozenset({"rule_id", "rule_version", "kind", "severity", "text", "params", "key"})
_KEY_KEYS = frozenset({"category", "map_type", "combustion", "fuel", "unit"})
_FUELS = frozenset({"gasoline", "E27", "E100", "flex", "diesel"})
_MAP_TYPES = frozenset({"base", "correction", "limit", "flag"})
_COMBUSTIONS = frozenset({"SI", "CI"})
# R33: required and allowed parameters per kind. A parameter no kind defines makes the table invalid.
_PARAMS: Mapping[str, tuple[frozenset[str], frozenset[str]]] = {
    "range": (frozenset(), frozenset({"min", "max"})),
    "sensor_range": (frozenset({"min", "max"}), frozenset({"min", "max"})),
    "conditional_cap": (frozenset({"max", "axis_unit", "above"}), frozenset({"max", "axis_unit", "above"})),
    "relative_amplitude": (frozenset({"neutral", "max_deviation"}), frozenset({"neutral", "max_deviation"})),
    "smoothness": (frozenset({"max_step"}), frozenset({"max_step"})),
}
_REQUIRED_MAP_TYPE: Mapping[str, str] = {
    "range": "base",
    "conditional_cap": "base",
    "sensor_range": "base",
    "relative_amplitude": "correction",
}
_KINDS = frozenset(_PARAMS)
RANGE_KINDS = frozenset({"range", "conditional_cap", "sensor_range"})


@dataclass(frozen=True, slots=True)
class RuleKey:
    category: str
    map_type: MapTypeKey
    combustion: Combustion
    fuel: Fuel | None
    unit: str


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    rule_version: int
    kind: RuleKind
    severity: Severity
    text: str
    key: RuleKey
    params: Mapping[str, Fraction]
    axis_unit: str | None


@dataclass(frozen=True, slots=True)
class Table:
    table_id: str
    version: str
    hash: str
    identify_min_confidence: int
    rules: tuple[Rule, ...]

    def ref(self) -> dict[str, Json]:
        """R32: how every report records the table."""
        return {"table_id": self.table_id, "version": self.version, "hash": self.hash}


def parse_rational(text: object) -> Fraction | None:
    """R30: `^-?(0|[1-9][0-9]*)(/[1-9][0-9]*)?$`, reduced, denominator >= 2 when present, no `-0`."""
    if not isinstance(text, str) or _RATIONAL.fullmatch(text) is None or text == "-0":
        return None
    numerator, _, denominator = text.partition("/")
    if not denominator:
        return Fraction(int(numerator))
    value = Fraction(int(numerator), int(denominator))
    return value if value.denominator == int(denominator) >= 2 else None


def _text(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _object(value: object, keys: frozenset[str]) -> Mapping[str, object] | None:
    if not isinstance(value, Mapping):
        return None
    members = cast("Mapping[object, object]", value)
    return cast("Mapping[str, object]", members) if set(members) == keys else None


def _one_of(value: object, allowed: frozenset[str]) -> bool:
    """Membership for untrusted values: an unhashable value is simply not a member."""
    return isinstance(value, str) and value in allowed


def _int(value: object, low: int, high: int) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and low <= value <= high else None


def _key(value: object) -> RuleKey | None:
    key = _object(value, _KEY_KEYS)
    if key is None:
        return None
    category, map_type, combustion, fuel, unit = (
        key["category"],
        key["map_type"],
        key["combustion"],
        key["fuel"],
        key["unit"],
    )
    if not (_text(category) and _text(unit) and _one_of(map_type, _MAP_TYPES) and _one_of(combustion, _COMBUSTIONS)):
        return None
    if fuel is not None and not _one_of(fuel, _FUELS):
        return None
    return RuleKey(
        cast("str", category),
        cast("MapTypeKey", map_type),
        cast("Combustion", combustion),
        cast("Fuel | None", fuel),
        cast("str", unit),
    )


def _params(kind: str, value: object) -> tuple[dict[str, Fraction], str | None] | None:
    if not isinstance(value, Mapping):
        return None
    params = cast("Mapping[object, object]", value)
    required, allowed = _PARAMS[kind]
    names = set(params)
    if not (required <= names <= allowed) or (kind == "range" and not names):
        return None
    numbers: dict[str, Fraction] = {}
    axis_unit: str | None = None
    for name in sorted(cast("set[str]", names)):
        item = params[name]
        if name == "axis_unit":
            if not _text(item):
                return None
            axis_unit = cast("str", item)
            continue
        number = parse_rational(item)
        if number is None or (name in ("max_deviation", "max_step") and number < 0):
            return None
        numbers[name] = number
    return numbers, axis_unit


def _rule(value: object) -> Rule | None:
    rule = _object(value, _RULE_KEYS)
    if rule is None:
        return None
    rule_id, kind, severity, text = rule["rule_id"], rule["kind"], rule["severity"], rule["text"]
    version = _int(rule["rule_version"], 1, _MAX_SAFE_INTEGER)
    if not (isinstance(rule_id, str) and RULE_ID.fullmatch(rule_id) and _one_of(kind, _KINDS) and _text(text)):
        return None
    key = _key(rule["key"])
    params = _params(cast("str", kind), rule["params"])
    allowed = frozenset({"block"} if kind == "sensor_range" else {"warn", "info"})
    required_type = _REQUIRED_MAP_TYPE.get(cast("str", kind))
    if version is None or key is None or params is None or not _one_of(severity, allowed):
        return None
    if required_type is not None and key.map_type != required_type:
        return None
    numbers, axis_unit = params
    return Rule(
        rule_id,
        version,
        cast("RuleKind", kind),
        cast("Severity", severity),
        cast("str", text),
        key,
        numbers,
        axis_unit,
    )


def parse_rule_table(value: object) -> Table | None:
    """R33. None when `value` is not a valid table: the rule table is then unavailable (R21)."""
    table = _object(value, _TABLE_KEYS)
    if table is None:
        return None
    table_id, version, rules = table["table_id"], table["version"], table["rules"]
    threshold = _int(table["identify_min_confidence"], 0, 1000)
    if threshold is None or not _text(table_id) or not (isinstance(version, str) and _SEMVER.fullmatch(version)):
        return None
    if not isinstance(rules, Sequence) or isinstance(rules, str):
        return None
    parsed = [_rule(item) for item in cast("Sequence[object]", rules)]
    checked = [rule for rule in parsed if rule is not None]
    ids = [rule.rule_id for rule in checked]
    if len(checked) != len(parsed) or len(set(ids)) != len(ids):
        return None
    # Every member was checked above to be a JSON value of the hashable domain.
    digest = json_hash(cast("Json", value))
    return Table(cast("str", table_id), version, digest, threshold, tuple(checked))
