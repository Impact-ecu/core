"""SPEC-000 invariant 10 (Verified release): kernel side, SPEC-001 R7, R9, R42.

R42 is owned by the gate (SPEC-004). What the kernel owns is that an `UnverifiedImage` never leaks its
bytes and that nothing below the gate releases one.
"""

import copy
import json
import pickle
from collections.abc import Callable
from typing import Any

import pytest
from hypothesis import given

import core.gate
import core.kernel
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


# SPEC-001 R9, R42: the gate is the only constructor of `ReleasedImage`; its release property is in
# tests/properties/test_spec004_gate.py. Below the gate nothing names it.
def test_only_the_gate_constructs_a_released_image() -> None:
    assert not hasattr(core.kernel, "ReleasedImage")
    assert core.gate.ReleasedImage.__module__ == "core.gate._result"
