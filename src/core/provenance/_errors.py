"""Provenance errors (SPEC-005 R91). Chain verification never raises: it returns findings."""


class ProvenanceError(Exception):
    """Base of every provenance rejection. `reason` is a stable machine string (SPEC-005 R91)."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


class ShapeError(ProvenanceError):
    """An object without exactly its listed keys, or a value of the wrong type (SPEC-005 R3)."""


class EventError(ProvenanceError):
    """An event that cannot be built: `unknown_type`, `bad_payload`, `not_genesis`, `test_key` (R32, R36, R56)."""


class RecordError(ProvenanceError):
    """An export or audit record that contradicts its inputs (SPEC-005 R11, R13, R14, R17)."""


class SignatureError(ProvenanceError):
    """A `Signer` that returned something other than one 64-byte signature by the named key (R50, R53)."""


class ReportBindingError(ProvenanceError):
    """A `ReportFile` that fails SPEC-005 R61. `reasons` lists every failed check, sorted."""

    def __init__(self, reasons: tuple[str, ...]) -> None:
        super().__init__(reasons[0], ", ".join(reasons))
        self.reasons = reasons
