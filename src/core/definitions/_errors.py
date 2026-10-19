"""Definition errors (SPEC-003 R121) and the runtime invariant check (R122)."""


class DefinitionError(Exception):
    """Every rejection of SPEC-003. `reason` is a stable machine string named in the spec (R121).

    `field` names the offending field where the spec requires it (R64, R76: `unrepresentable`).
    """

    def __init__(self, reason: str, detail: str = "", *, field: str | None = None) -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail
        self.field = field


class DefinitionInvariantError(Exception):
    """A runtime assertion of SPEC-003 R122 failed: a bug in `core.definitions`, never a user error.

    Deliberately not a DefinitionError: code that handles rejections must not swallow it.
    """

    def __init__(self, rule: str) -> None:
        super().__init__(f"invariant_violation: {rule}")
        self.rule = rule


def ensure(holds: bool, rule: str) -> None:
    # Not `assert`: it must stay active under `python -O` (SPEC-003 R122, SPEC-001 R73).
    if not holds:
        raise DefinitionInvariantError(rule)
