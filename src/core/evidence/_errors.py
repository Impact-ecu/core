"""Evidence errors (SPEC-006 R80, R111) and the runtime assertions of R112."""

from core.kernel import KernelInvariantError


class EvidenceError(Exception):
    """A precondition failure with a stable `reason` (SPEC-006 R80). Never a `KernelError` (R111).

    Classification outcomes are data, never this exception (R73-R76, R83).
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


def ensure(holds: bool, rule: str) -> None:
    # R112: a failed assertion aborts the job and opens an S1; not `assert`, so it survives `python -O`.
    if not holds:
        raise KernelInvariantError(rule)
