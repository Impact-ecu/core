"""SPEC-002 R15-R18: choosing a plugin (`probe`) and filling null base addresses (`rebase`)."""

from dataclasses import dataclass, replace
from typing import cast

import pytest

from core.kernel import Dump, Memory, image_hash
from core.plugins import (
    EcuPlugin,
    Identification,
    PluginContractError,
    PresentMemory,
    Probe,
    ProbeEntry,
    identification_json,
    probe,
    probe_json,
    rebase,
)
from tests.unit.plugin_fixtures import DUMP, IDENT, ORIGINAL, FakePlugin, dump_of

BASE = 0x80000000
RAW = dump_of(ORIGINAL)
UNADDRESSED = Dump("bench_full", (Memory("pflash", None, ORIGINAL),))


@dataclass
class Addressing(FakePlugin):
    """Identifies the fixture and reports the address of its single memory, as R4 allows for a null base."""

    address: int | None = BASE

    def identify(self, dump: Dump) -> Identification | None:
        ident = super().identify(dump)
        if ident is None:
            return None
        known = dump.memories[0].base_address
        return replace(ident, memories_present=(PresentMemory("pflash", known or self.address, 512),))


@dataclass
class Silent(FakePlugin):
    def identify(self, dump: Dump) -> Identification | None:
        del dump
        return None


@dataclass
class Raising(FakePlugin):
    def identify(self, dump: Dump) -> Identification | None:
        del dump
        raise RuntimeError("identify must not raise (R12)")


@dataclass
class Lying(FakePlugin):
    """Returns an identification of another family (R2), which the probe checks like the gate."""

    def identify(self, dump: Dump) -> Identification | None:
        del dump
        return replace(IDENT, family="other.family")


class BadAttribute:
    """A plugin object whose `version` attribute raises when read (R10)."""

    family = "synthetic.bad"
    contract_version = 1
    pii_in_flash = True

    def __getattr__(self, name: str) -> object:
        if name == "version":
            raise RuntimeError("reading version failed")
        raise AttributeError(name)


@dataclass
class Claiming(FakePlugin):
    """Identifies the fixture under its own family: a second plugin claiming the same file."""

    def identify(self, dump: Dump) -> Identification | None:
        ident = super().identify(dump)
        return None if ident is None else replace(ident, family=self.family)


def named(plugin: FakePlugin, family: str) -> FakePlugin:
    return replace(plugin, family=family)


def outcomes(result: Probe) -> list[tuple[str, str]]:
    return [(entry.family, entry.outcome) for entry in result.entries]


# SPEC-002 R15, R16: exactly one identified plugin is selected, with the identification the core checked.
def test_one_identified_plugin_is_selected() -> None:
    result = probe([named(Silent(), "synthetic.other"), FakePlugin()], DUMP)
    assert result.status == "selected"
    selected = result.selected
    assert selected is not None
    assert (selected.family, selected.outcome) == ("synthetic.fixture", "identified")
    assert selected.identification == FakePlugin().identify(DUMP)


# SPEC-002 R15: entries are sorted by family whatever the input order, and every plugin is called.
def test_entries_sorted_by_family() -> None:
    plugins = [named(Silent(), "synthetic.zeta"), FakePlugin(), named(Silent(), "synthetic.alpha")]
    result = probe(plugins, DUMP)
    assert outcomes(result) == [
        ("synthetic.alpha", "not_recognized"),
        ("synthetic.fixture", "identified"),
        ("synthetic.zeta", "not_recognized"),
    ]
    assert probe(list(reversed(plugins)), DUMP) == result


# SPEC-002 R16: no identified plugin is `no_family`, including when no plugin is installed.
def test_no_family() -> None:
    assert probe([Silent()], DUMP).status == "no_family"
    assert probe([], DUMP).status == "no_family"
    assert probe([Silent()], DUMP).selected is None


# SPEC-002 R16: two identified plugins are ambiguous, never resolved by order or confidence.
def test_two_identified_plugins_are_ambiguous() -> None:
    weak = named(Claiming(), "synthetic.weak")
    result = probe([FakePlugin(), weak], DUMP)
    assert result.status == "ambiguous_family"
    assert result.selected is None


# SPEC-002 R16: ambiguity is reported before a plugin failure.
def test_ambiguity_precedes_failure() -> None:
    plugins = [FakePlugin(), named(Claiming(), "synthetic.weak"), named(Raising(), "synthetic.broken")]
    assert probe(plugins, DUMP).status == "ambiguous_family"


# SPEC-002 R11, R15, R16: a plugin whose identify raises is `unavailable` and blocks the selection.
def test_raising_plugin_blocks_selection() -> None:
    result = probe([FakePlugin(), named(Raising(), "synthetic.broken")], DUMP)
    assert outcomes(result) == [("synthetic.broken", "unavailable"), ("synthetic.fixture", "identified")]
    assert result.status == "plugin_failure"
    assert result.selected is None


# SPEC-002 R15, R16: a result that breaks §2.1 is `error` and blocks the selection.
def test_contract_error_blocks_selection() -> None:
    result = probe([FakePlugin(), named(Lying(), "synthetic.liar")], DUMP)
    assert outcomes(result) == [("synthetic.fixture", "identified"), ("synthetic.liar", "error")]
    assert result.status == "plugin_failure"


# SPEC-002 R15: two plugins with one family are refused.
def test_duplicate_family_is_refused() -> None:
    with pytest.raises(PluginContractError) as raised:
        probe([FakePlugin(), Silent()], DUMP)
    assert raised.value.reason == "duplicate_family"


# SPEC-002 R15, R135: a plugin that fails the load-time checks is refused with that reason.
@pytest.mark.parametrize(
    ("plugin", "reason"),
    [
        (replace(FakePlugin(), contract_version=2), "contract_version"),
        (replace(FakePlugin(), family="Not A Family"), "r2"),
        (BadAttribute(), "r10"),
    ],
)
def test_refused_plugin(plugin: object, reason: str) -> None:
    with pytest.raises(PluginContractError) as raised:
        probe([cast("EcuPlugin", plugin)], DUMP)
    assert raised.value.reason == reason


# SPEC-002 R17: the output names status and entries, with identifications as SPEC-002 JSON or null.
def test_probe_json() -> None:
    result = probe([FakePlugin(), named(Silent(), "synthetic.other")], DUMP)
    ident = FakePlugin().identify(DUMP)
    assert ident is not None
    assert probe_json(result) == {
        "status": "selected",
        "entries": [
            {
                "family": "synthetic.fixture",
                "version": "1.0.0",
                "outcome": "identified",
                "identification": identification_json(ident),
            },
            {"family": "synthetic.other", "version": "1.0.0", "outcome": "not_recognized", "identification": None},
        ],
    }


# SPEC-002 R16: the status is derived from the entries, so a hand-built probe cannot claim another one.
def test_status_follows_entries() -> None:
    entries = (ProbeEntry("a.b", "1", "identified", IDENT), ProbeEntry("c.d", "1", "error", None))
    assert Probe(entries).status == "plugin_failure"


# SPEC-002 R18, SPEC-001 R2: a null base address is filled from identify; data and order are unchanged.
def test_rebase_fills_null_base_address() -> None:
    ident = Addressing().identify(UNADDRESSED)
    assert ident is not None
    rebased = rebase(UNADDRESSED, ident)
    assert rebased == Dump("bench_full", (Memory("pflash", BASE, ORIGINAL),))
    assert image_hash(rebased) != image_hash(UNADDRESSED)


# SPEC-002 R18: a known base address is never changed, and rebase is idempotent.
def test_rebase_keeps_known_address_and_is_idempotent() -> None:
    ident = Addressing().identify(RAW)
    assert ident is not None
    assert rebase(RAW, ident) == RAW
    once = rebase(UNADDRESSED, Addressing().identify(UNADDRESSED) or IDENT)
    assert rebase(once, Addressing().identify(once) or IDENT) == once


# SPEC-002 R4, R18: an identification that does not know the address leaves it null.
def test_rebase_without_address_keeps_null() -> None:
    ident = Addressing(address=None).identify(UNADDRESSED)
    assert ident is not None
    assert rebase(UNADDRESSED, ident) == UNADDRESSED


# SPEC-002 R18: an identification that is not of this dump is refused with the R4 reason.
@pytest.mark.parametrize(
    "present",
    [
        (PresentMemory("pflash", BASE, 511),),
        (PresentMemory("eeprom", BASE, 512),),
    ],
)
def test_rebase_refuses_foreign_identification(present: tuple[PresentMemory, ...]) -> None:
    with pytest.raises(PluginContractError) as raised:
        rebase(UNADDRESSED, replace(IDENT, memories_present=present))
    assert raised.value.reason == "r4"


# SPEC-002 R4, R18: a known address that the identification contradicts is refused.
def test_rebase_refuses_contradicting_address() -> None:
    with pytest.raises(PluginContractError) as raised:
        rebase(RAW, replace(IDENT, memories_present=(PresentMemory("pflash", BASE + 16, 512),)))
    assert raised.value.reason == "r4"


# SPEC-002 R18: anything but an Identification is refused (`r12`).
def test_rebase_refuses_non_identification() -> None:
    with pytest.raises(PluginContractError) as raised:
        rebase(UNADDRESSED, cast("Identification", None))
    assert raised.value.reason == "r12"
