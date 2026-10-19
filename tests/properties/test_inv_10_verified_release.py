"""SPEC-000 invariant 10 (Verified release): kernel side, SPEC-001 R7, R9, R42.

R42 is owned by the gate (SPEC-004), which is not implemented yet. What the kernel owns is that an
`UnverifiedImage` never leaks its bytes and that nothing below the gate releases one: the only
release path, `core.gate.release`, is fail-closed until SPEC-004 lands.
"""

import copy
import json
import pickle
from collections.abc import Callable
from typing import Any

import pytest
from hypothesis import given

import core.gate
from core.kernel import apply
from tests.properties.strategies import Scenario, scenarios

PUBLIC_ATTRIBUTES = {"dump_kind", "memories", "image_hash"}
# Typed as taking Any so the calls type-check: the point is that they fail at runtime.
BYTE_CONVERSIONS: tuple[Callable[[Any], object], ...] = (bytes, bytearray, memoryview)


# SPEC-001 R7
@given(scenarios())
def test_unverified_image_never_exposes_or_serializes_its_bytes(s: Scenario) -> None:
    u = apply(s.dump, s.version, s.layout)
    assert {name for name in dir(u) if not name.startswith("_")} == PUBLIC_ATTRIBUTES
    for name in PUBLIC_ATTRIBUTES:
        value = getattr(u, name)
        assert not isinstance(value, bytes | bytearray | memoryview)
    assert "data" not in repr(u)
    for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
        with pytest.raises(TypeError):
            pickle.dumps(u, protocol=protocol)
    with pytest.raises(TypeError):
        copy.copy(u)
    with pytest.raises(TypeError):
        copy.deepcopy(u)
    with pytest.raises(TypeError):
        json.dumps(u)
    with pytest.raises(TypeError):
        u.__getstate__()
    for convert in BYTE_CONVERSIONS:
        with pytest.raises(TypeError):
            convert(u)


# SPEC-001 R9, R42: no image leaves through the gate before SPEC-004 is implemented.
def test_release_is_fail_closed() -> None:
    with pytest.raises(NotImplementedError):
        core.gate.release()
