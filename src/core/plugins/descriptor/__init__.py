"""The checksum descriptor interpreter (SPEC-002 §4.5, R80) and the checks that run it.

Used by the core and the gate only: plugin packages MUST NOT import this module (R47).
"""

from core.plugins.descriptor._dual import (
    check_checksums,
    compare_patches,
    compare_verify,
    reference_result_usable,
)
from core.plugins.descriptor._interpret import interpret_patches, interpret_verify, validate_variant

__all__ = [
    "check_checksums",
    "compare_patches",
    "compare_verify",
    "interpret_patches",
    "interpret_verify",
    "reference_result_usable",
    "validate_variant",
]
