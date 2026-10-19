"""Choosing a plugin for a dump and filling null base addresses (SPEC-002 R15-R18).

Both are pure: plugin exceptions become data (R11), and nothing here is resolved by order, priority or
confidence (R16).
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from typing import Literal

from core.kernel import Dump
from core.plugins._checks import check_identification, check_plugin
from core.plugins._contract import EcuPlugin, Identification, identification_json
from core.plugins._errors import PluginContractError
from core.plugins._jcs import ContractJson

Outcome = Literal["identified", "not_recognized", "unavailable", "error"]
ProbeStatus = Literal["selected", "no_family", "ambiguous_family", "plugin_failure"]


class _Raised(Exception):
    """A plugin method raised (R11)."""


def _guarded[T](method: Callable[[], T]) -> T:
    try:
        return method()
    except Exception as error:
        raise _Raised(type(error).__name__) from error


@dataclass(frozen=True, slots=True)
class ProbeEntry:
    """R15: one plugin's answer; `identification` is set only for `identified`."""

    family: str
    version: str
    outcome: Outcome
    identification: Identification | None


@dataclass(frozen=True, slots=True)
class Probe:
    """R15, R16. The status is derived from the entries, so it cannot disagree with them."""

    entries: tuple[ProbeEntry, ...]

    @property
    def status(self) -> ProbeStatus:
        """R16, in its order."""
        identified = [entry for entry in self.entries if entry.outcome == "identified"]
        if len(identified) >= 2:
            return "ambiguous_family"
        if any(entry.outcome in ("unavailable", "error") for entry in self.entries):
            return "plugin_failure"
        return "selected" if identified else "no_family"

    @property
    def selected(self) -> ProbeEntry | None:
        """The one identified entry when the status is `selected`, else None."""
        if self.status != "selected":
            return None
        return next(entry for entry in self.entries if entry.outcome == "identified")


def _admitted(plugin: EcuPlugin) -> None:
    """R15: R135, R2 and R10 as at load time; an attribute that raises is `r10`."""
    try:
        check_plugin(plugin)
    except PluginContractError:
        raise
    except Exception as error:
        raise PluginContractError("r10", f"reading the plugin attributes raised {type(error).__name__}") from error


def _family(plugin: EcuPlugin) -> str:
    return plugin.family


def _entry(plugin: EcuPlugin, dump: Dump) -> ProbeEntry:
    family, version = plugin.family, plugin.version
    try:
        raw = _guarded(lambda: plugin.identify(dump))
    except _Raised:
        return ProbeEntry(family, version, "unavailable", None)
    try:
        ident = check_identification(raw, dump, family)
    except PluginContractError:
        return ProbeEntry(family, version, "error", None)
    if ident is None:
        return ProbeEntry(family, version, "not_recognized", None)
    return ProbeEntry(family, version, "identified", ident)


def probe(plugins: Sequence[EcuPlugin], dump: Dump) -> Probe:
    """R15: `identify` of every plugin, each result checked as the gate checks it (SPEC-004 R12)."""
    for plugin in plugins:
        _admitted(plugin)
    families = [plugin.family for plugin in plugins]
    duplicated = sorted({family for family in families if families.count(family) > 1})
    if duplicated:
        raise PluginContractError("duplicate_family", ", ".join(duplicated))
    return Probe(tuple(_entry(plugin, dump) for plugin in sorted(plugins, key=_family)))


def probe_json(result: Probe) -> dict[str, ContractJson]:
    """R17."""
    entries: list[ContractJson] = [
        {
            "family": entry.family,
            "version": entry.version,
            "outcome": entry.outcome,
            "identification": None if entry.identification is None else identification_json(entry.identification),
        }
        for entry in result.entries
    ]
    return {"status": result.status, "entries": entries}


def rebase(dump: Dump, ident: Identification) -> Dump:
    """R18: fill each null `base_address` from `ident.memories_present`; a known address never changes."""
    given: object = ident
    if not isinstance(given, Identification):
        raise PluginContractError("r12", f"rebase takes an Identification, not {type(given).__name__}")
    check_identification(given, dump, given.family)
    present = {memory.memory_id: memory.base_address for memory in ident.memories_present}
    memories = tuple(
        replace(memory, base_address=present[memory.memory_id]) if memory.base_address is None else memory
        for memory in dump.memories
    )
    return Dump(dump.dump_kind, memories)
