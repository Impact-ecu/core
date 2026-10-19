"""Kernel errors (SPEC-001 R72) and the runtime invariant check (R73)."""


class KernelError(Exception):
    """Base of every kernel rejection. `reason` is a stable machine string (SPEC-001 R72)."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


class ShapeError(KernelError):
    """Malformed input or a mismatch between inputs (SPEC-001 R1, R2, R10, R12, R14, R20, R31)."""


class LayoutError(KernelError):
    """A layout that is malformed or does not describe the dump (SPEC-001 R4, R5)."""


class OverlapError(KernelError):
    """Overlap constraints of a version are missing, spurious or cyclic (SPEC-001 R22)."""


class ContainmentError(KernelError):
    """A patch outside the region kind it may touch (SPEC-001 R23, R40)."""


class PreconditionConflict(KernelError):
    """A patch's `before` does not match the bytes it would overwrite (SPEC-001 R21)."""

    def __init__(self, index: int, patch_hash: str) -> None:
        super().__init__("before_mismatch", f"patch {index} in canonical order ({patch_hash})")
        self.index = index
        self.patch_hash = patch_hash


class KernelInvariantError(Exception):
    """A runtime assertion of a SPEC-000 invariant failed: a kernel bug, never a user error (R73).

    Deliberately not a KernelError: code that handles rejections must not swallow it; it aborts the job.
    """

    def __init__(self, rule: str) -> None:
        super().__init__(f"invariant_violation: {rule}")
        self.rule = rule


def ensure(holds: bool, rule: str) -> None:
    # Not `assert`: it must stay active under `python -O` (SPEC-001 R73).
    if not holds:
        raise KernelInvariantError(rule)
