"""The JSON domain and hash of contract objects (SPEC-002 R9, R78, R127).

Descriptors (`reflect_in`, `skip_self`) and the conformance report (`passed`, `admitted`) carry booleans,
so contract objects are encoded by the kernel's `jcs`, never by its boolean-free `canonical_json`. Floats are
never accepted (R3).
"""

import hashlib

from core.kernel import JcsValue, jcs

type ContractJson = JcsValue

MAX_SAFE_INTEGER = 2**53 - 1


def contract_hash(value: ContractJson) -> str:
    """Lowercase hex SHA-256 of `jcs(value)` (SPEC-001 R65)."""
    return hashlib.sha256(jcs(value)).hexdigest()
