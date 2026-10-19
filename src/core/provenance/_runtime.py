"""The interpreter identity of SPEC-005 R15: the only environment read in `core` (R90)."""

import platform
import sys

from core.provenance._json import Json


def python_info() -> dict[str, Json]:
    """`{implementation, version}` of the running interpreter, never passed in by a caller (R15)."""
    return {"implementation": sys.implementation.name, "version": platform.python_version()}
