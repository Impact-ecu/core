"""Calling an untrusted plugin (SPEC-002 R11): every exception it raises is data, never a crash of the gate."""

from collections.abc import Callable

from core.gate._evidence import EvidenceAdmissionFn, FieldEvidence, Timestamp, admitted_by_evidence
from core.gate._report import PluginRef
from core.plugins import Admission, ContractJson, EcuPlugin, admission, check_plugin


class PluginFault(Exception):
    """A plugin or reference method raised: the plugin (or reference) is unavailable or failed (SPEC-002 R11)."""


def call[T](method: Callable[[], T]) -> T:
    try:
        return method()
    except Exception as error:
        raise PluginFault(type(error).__name__) from error


def plugin_ref(plugin: EcuPlugin | None) -> PluginRef | None:
    """The plugin's `{family, version}`, or None when there is no plugin or it breaks SPEC-002 R2, R10, R135."""
    if plugin is None:
        return None
    try:
        call(lambda: check_plugin(plugin))
    except PluginFault:
        return None
    return PluginRef(plugin.family, plugin.version)


def conformance_admission(report: ContractJson | None, plugin: EcuPlugin) -> Admission | None:
    """SPEC-004 R15 via SPEC-002 R132: None when the report is missing, not JSON, or does not match the plugin."""
    if report is None:
        return None
    try:
        return admission(report, plugin)
    except (TypeError, ValueError):
        return None


def admitted_variants(
    conformance: Admission,
    plugin: PluginRef,
    admit: EvidenceAdmissionFn,
    evidence: FieldEvidence | None,
    as_of: Timestamp,
) -> frozenset[str]:
    """R15 intersected with R16: the conformance report's admitted set and `golden_field` under a current head."""
    return conformance.admitted & admitted_by_evidence(admit(evidence, as_of), plugin.family)
