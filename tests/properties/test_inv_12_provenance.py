"""SPEC-000 invariant 12 (Provenance hashes): SPEC-001 R60-R65.

The oracle is the third-party `rfc8785` package (the JCS used by generate.py) plus `hashlib`; the
core's own canonicalization is never compared with itself.
"""

import hashlib
from collections.abc import Mapping, Sequence

import rfc8785
from hypothesis import given
from hypothesis import strategies as st

from core.kernel import Dump, MemoryLayout, canonical_json, canonical_order, image_hash, layout_hash, version_hash
from tests.properties.strategies import Scenario, dumps_and_layouts, scenarios

SAFE = 2**53 - 1

type JsonValue = int | str | Sequence[JsonValue] | Mapping[str, JsonValue] | None

json_values: st.SearchStrategy[JsonValue] = st.recursive(
    st.none() | st.integers(-SAFE, SAFE) | st.text(),
    lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=6), children, max_size=4),
    max_leaves=12,
)


def sha(value: JsonValue) -> str:
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


# SPEC-001 R60
@given(json_values)
def test_canonical_json_matches_rfc8785(value: JsonValue) -> None:
    assert canonical_json(value) == rfc8785.dumps(value)


# SPEC-001 R61, R62, R63, R64, R65
@given(scenarios())
def test_hashes_match_an_independent_jcs(s: Scenario) -> None:
    for p in s.version.patches:
        body: dict[str, JsonValue] = {"memory_id": p.memory_id, "offset": p.offset, "length": p.length}
        assert p.patch_hash == sha({**body, "before": p.before.hex(), "after": p.after.hex()})
    order = [p.patch_hash for p in canonical_order(s.version)]
    assert version_hash(s.version) == sha(
        {
            "base_image_hash": s.version.base_image_hash,
            "layout_hash": s.version.layout_hash,
            "patches": order,
            "overlaps": sorted([a, b] for a, b in s.version.overlaps),
        }
    )


# SPEC-001 R62, R63
@given(dumps_and_layouts())
def test_image_and_layout_hashes_match_an_independent_jcs(dl: tuple[Dump, MemoryLayout]) -> None:
    dump, layout = dl
    assert image_hash(dump) == sha(
        {
            "dump_kind": dump.dump_kind,
            "memories": [
                {
                    "memory_id": m.memory_id,
                    "base_address": m.base_address,
                    "size": len(m.data),
                    "sha256": hashlib.sha256(m.data).hexdigest(),
                }
                for m in sorted(dump.memories, key=lambda m: m.memory_id)
            ],
        }
    )
    assert layout_hash(layout) == sha(
        {
            "memories": [
                {
                    "memory_id": m.memory_id,
                    "base_address": m.base_address,
                    "size": m.size,
                    "regions": [{"kind": r.kind, "start": r.start, "end": r.end, "name": r.name} for r in m.regions],
                }
                for m in sorted(layout.memories, key=lambda m: m.memory_id)
            ]
        }
    )
