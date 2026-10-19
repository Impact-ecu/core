"""SPEC-002 R15, R16, R18 as properties: probe order independence and status, rebase preservation."""

from dataclasses import dataclass, replace

from hypothesis import given
from hypothesis import strategies as st

from core.kernel import Dump, Memory
from core.plugins import (
    EcuPlugin,
    Identification,
    PresentMemory,
    check_identification,
    probe,
    rebase,
)
from tests.properties.strategies import dumps_and_layouts
from tests.unit.plugin_fixtures import DUMP, FakePlugin

FAMILIES = ("synthetic.a", "synthetic.b", "synthetic.c", "synthetic.d", "synthetic.e")
BEHAVIORS = ("silent", "claiming", "raising", "lying")


@dataclass
class Behaving(FakePlugin):
    """A plugin that answers `identify` according to `behavior`."""

    behavior: str = "silent"

    def identify(self, dump: Dump) -> Identification | None:
        ident = super().identify(dump)
        if self.behavior == "raising":
            raise RuntimeError("identify raised")
        if self.behavior == "silent" or ident is None:
            return None
        family = self.family if self.behavior == "claiming" else "other.family"
        return replace(ident, family=family)


@st.composite
def plugin_sets(draw: st.DrawFn) -> list[EcuPlugin]:
    families = draw(st.lists(st.sampled_from(FAMILIES), unique=True, max_size=len(FAMILIES)))
    return [Behaving(family=family, behavior=draw(st.sampled_from(BEHAVIORS))) for family in families]


# SPEC-002 R15, R16: the result never depends on the order plugins are given in, and the status follows R16.
@given(plugin_sets(), st.data())
def test_probe_is_order_independent_and_follows_r16(plugins: list[EcuPlugin], data: st.DataObject) -> None:
    result = probe(plugins, DUMP)
    assert probe(data.draw(st.permutations(plugins)), DUMP) == result
    assert [entry.family for entry in result.entries] == sorted(p.family for p in plugins)
    identified = sum(entry.outcome == "identified" for entry in result.entries)
    failed = any(entry.outcome in ("unavailable", "error") for entry in result.entries)
    expected = (
        "ambiguous_family"
        if identified >= 2
        else "plugin_failure"
        if failed
        else "selected"
        if identified == 1
        else "no_family"
    )
    assert result.status == expected
    assert (result.selected is not None) == (expected == "selected")


@st.composite
def unaddressed(draw: st.DrawFn) -> tuple[Dump, Identification]:
    """A dump with some base addresses null, and an identification satisfying R4 for it."""
    dump, _ = draw(dumps_and_layouts())
    memories = tuple(replace(memory, base_address=None) if draw(st.booleans()) else memory for memory in dump.memories)
    nulled = Dump(dump.dump_kind, memories)
    present = tuple(
        PresentMemory(
            memory.memory_id,
            memory.base_address if memory.base_address is not None else draw(st.none() | st.integers(0, 2**53 - 1)),
            len(memory.data),
        )
        for memory in sorted(memories, key=lambda m: m.memory_id)
    )
    ident = Identification("synthetic.a", None, None, None, None, present, (), (), (), 900)
    return nulled, ident


def _by_id(memories: tuple[Memory, ...]) -> dict[str, Memory]:
    return {memory.memory_id: memory for memory in memories}


# SPEC-002 R18, SPEC-001 R2: only null base addresses change, to the identified ones; bytes, ids and order
# are kept; the result still satisfies R4 with the same identification, and rebase is idempotent.
@given(unaddressed())
def test_rebase_fills_only_null_addresses(case: tuple[Dump, Identification]) -> None:
    dump, ident = case
    rebased = rebase(dump, ident)
    present = {p.memory_id: p.base_address for p in ident.memories_present}
    assert rebased.dump_kind == dump.dump_kind
    assert [m.memory_id for m in rebased.memories] == [m.memory_id for m in dump.memories]
    after = _by_id(rebased.memories)
    for memory in dump.memories:
        assert after[memory.memory_id].data == memory.data
        expected = present[memory.memory_id] if memory.base_address is None else memory.base_address
        assert after[memory.memory_id].base_address == expected
    assert check_identification(ident, rebased, ident.family) == ident
    assert rebase(rebased, ident) == rebased
