"""Hypothesis fuzzing of the descriptor parser and of static validation (SPEC-002 R60, R79).

Any input either parses / validates or raises `DescriptorError`; nothing else escapes.
"""

from hypothesis import given
from hypothesis import strategies as st

from core.plugins import ChecksumRegion, Descriptor, DescriptorError, Reference, descriptor_from_json, descriptor_json
from core.plugins.descriptor import validate_variant
from tests.properties.descriptor_strategies import descriptors
from tests.unit.plugin_fixtures import FIXTURE, LAYOUT

json_values = st.recursive(
    st.none() | st.booleans() | st.integers(-(2**40), 2**40) | st.text(max_size=8),
    lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=12), children, max_size=6),
    max_leaves=20,
)
KEYS = sorted({key for entry in FIXTURE["descriptors"] for key in entry["value"]} | {"name", "poly", "word_size"})


@st.composite
def near_descriptors(draw: st.DrawFn) -> dict[str, object]:
    """A fixture descriptor JSON with one key replaced, dropped or added: close enough to reach deep checks."""
    value: dict[str, object] = dict(draw(st.sampled_from(FIXTURE["descriptors"]))["value"])
    key = draw(st.sampled_from(KEYS))
    action = draw(st.sampled_from(["replace", "drop", "nested"]))
    if action == "drop":
        value.pop(key, None)
    elif action == "nested":
        value["algorithm"] = dict(FIXTURE["descriptors"][0]["value"]["algorithm"]) | {key: draw(json_values)}
    else:
        value[key] = draw(json_values)
    return value


# SPEC-002 R60: the parser raises only `schema` errors, and what parses serializes back to itself.
@given(st.one_of(json_values, near_descriptors()))
def test_parser_raises_only_descriptor_errors(value: object) -> None:
    reason = None
    try:
        descriptor = descriptor_from_json(value)
    except DescriptorError as error:
        reason = error.reason
    else:
        assert descriptor_json(descriptor) == value
    assert reason in {None, "schema"}


# SPEC-002 R79: static validation of random schema-valid descriptor sets raises only DescriptorError.
@given(st.lists(descriptors, max_size=4))
def test_static_validation_raises_only_descriptor_errors(items: list[Descriptor]) -> None:
    regions = [
        ChecksumRegion(d.name, d.memory_id, "recalculable", d, None, None, Reference("interpreter", None, None))
        for d in items
    ]
    reason = None
    try:
        validate_variant(regions, LAYOUT)
    except DescriptorError as error:
        reason = error.reason
    assert reason != "schema"
