"""Verification gate (SPEC-004): the only way a binary leaves Impact, and the only constructor of
`ReleasedImage` (SPEC-001 R9).

The verdict is `block`, `warn` or `no findings`, always inside a report with its disclaimer (R1, R8); never
a boolean and never "pass". Pure (R80): no I/O, network, clock, randomness, environment reads or threads.
"""

from core.gate._check import CheckInputArgs, check_input
from core.gate._fatigue import AlertRecord, Fatigue, fatigue
from core.gate._maps import Engine
from core.gate._model import BUILTIN, Fuel, GateError, GateInvariantError, Severity, Verdict
from core.gate._release import ReleaseArgs, release
from core.gate._result import ExportRefused, GateBlocked, InputResult, ReleasedImage
from core.gate._rules import Rule, RuleKey, Table, parse_rule_table

__all__ = [
    "BUILTIN",
    "AlertRecord",
    "CheckInputArgs",
    "Engine",
    "ExportRefused",
    "Fatigue",
    "Fuel",
    "GateBlocked",
    "GateError",
    "GateInvariantError",
    "InputResult",
    "ReleaseArgs",
    "ReleasedImage",
    "Rule",
    "RuleKey",
    "Severity",
    "Table",
    "Verdict",
    "check_input",
    "fatigue",
    "parse_rule_table",
    "release",
]
