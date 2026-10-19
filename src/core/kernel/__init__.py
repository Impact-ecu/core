"""Binary kernel (SPEC-001): data shapes, apply, invert, diff, migrate, checksum step, hashes.

Pure: no I/O, network, clock, randomness, environment, threads or global state (SPEC-001 R71).
"""

from core.kernel._apply import Conflict, MigrationResult, apply, apply_checksum_patches, invert, migrate
from core.kernel._canonical import JcsValue, canonical_json, jcs
from core.kernel._diff import DiffResult, ForeignRun, diff
from core.kernel._errors import (
    ContainmentError,
    KernelError,
    KernelInvariantError,
    LayoutError,
    OverlapError,
    PreconditionConflict,
    ShapeError,
)
from core.kernel._image import MemoryShape, UnverifiedImage, image_hash
from core.kernel._model import (
    Dump,
    DumpKind,
    LayoutMemory,
    Memory,
    MemoryLayout,
    Patch,
    Region,
    RegionKind,
    Version,
    layout_hash,
)
from core.kernel._order import canonical_order, version_hash

__all__ = [
    "Conflict",
    "ContainmentError",
    "DiffResult",
    "Dump",
    "DumpKind",
    "ForeignRun",
    "JcsValue",
    "KernelError",
    "KernelInvariantError",
    "LayoutError",
    "LayoutMemory",
    "Memory",
    "MemoryLayout",
    "MemoryShape",
    "MigrationResult",
    "OverlapError",
    "Patch",
    "PreconditionConflict",
    "Region",
    "RegionKind",
    "ShapeError",
    "UnverifiedImage",
    "Version",
    "apply",
    "apply_checksum_patches",
    "canonical_json",
    "canonical_order",
    "diff",
    "image_hash",
    "invert",
    "jcs",
    "layout_hash",
    "migrate",
    "version_hash",
]
