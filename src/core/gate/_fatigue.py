"""Alert fatigue (SPEC-004 R62, R63): a pure metric over records built outside the core.

The gate never reads this (R64): a downgrade exists only as a new rule-table version.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from fractions import Fraction

QUICK_MS = 5000
_HALF = Fraction(1, 2)


@dataclass(frozen=True, slots=True)
class AlertRecord:
    """One `warn` finding shown. `latency_ms` is the ack's `confirmed_ms - presented_ms`, None if never acked."""

    family: str
    rule_id: str
    latency_ms: int | None
    map_changed: bool


@dataclass(frozen=True, slots=True)
class Fatigue:
    family: str
    rule_id: str
    alerts: int
    quick_confirms: int
    fraction: Fraction
    downgrade: bool


def _quick(record: AlertRecord) -> bool:
    return record.latency_ms is not None and record.latency_ms < QUICK_MS and not record.map_changed


def fatigue(records: Sequence[AlertRecord]) -> tuple[Fatigue, ...]:
    """R62 per `(family, rule_id)`, sorted by that pair; R63 `downgrade` when the fraction exceeds 1/2."""
    groups: dict[tuple[str, str], list[AlertRecord]] = {}
    for record in records:
        groups.setdefault((record.family, record.rule_id), []).append(record)
    result = []
    for (family, rule_id), group in sorted(groups.items()):
        quick = sum(1 for record in group if _quick(record))
        fraction = Fraction(quick, len(group))
        result.append(Fatigue(family, rule_id, len(group), quick, fraction, fraction > _HALF))
    return tuple(result)
