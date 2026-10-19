"""Verification gate (SPEC-004): the only constructor of `ReleasedImage` (SPEC-001 R9).

Not implemented yet. `release` is fail-closed: it raises for every input, so no image can leave
the kernel until SPEC-004 is implemented here.
"""

from typing import NoReturn


def release() -> NoReturn:
    raise NotImplementedError("core.gate.release is not implemented yet (SPEC-004); nothing can be released")
