"""Byte view of an `UnverifiedImage`, for `core.gate` and tests only (SPEC-001 R8).

import-linter allows only `core.gate` to import this module inside `core`; every consumer
repository forbids it. Output bytes leave the system only through `ReleasedImage.to_dump()`.
"""

from core.kernel._image import UnverifiedImage, as_dump
from core.kernel._model import Dump


def view(u: UnverifiedImage) -> Dump:
    """The read-only `Dump` behind `u`. `Dump` and `Memory` are frozen and hold `bytes`."""
    return as_dump(u)
