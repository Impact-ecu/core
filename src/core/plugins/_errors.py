"""Rejections raised by the core while checking a plugin (SPEC-002 R9, §9). None is a `KernelError`."""


class _ReasonError(Exception):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


class PluginContractError(_ReasonError):
    """A plugin output that breaks SPEC-002 (R9, R11). The plugin is unavailable for the job, except R58."""


class DescriptorError(_ReasonError):
    """A descriptor set that fails static validation (R79), or a resolution failure on a dump (R66)."""


class InterpreterDivergence(_ReasonError):
    """The interpreter's two engines disagree (R81): an internal error, never a `fail` status."""

    def __init__(self, detail: str) -> None:
        super().__init__("engine_divergence", detail)
