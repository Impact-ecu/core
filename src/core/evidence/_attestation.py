"""`FieldAttestation`: shape, hash and verification (SPEC-006 §4, R40-R52), and the canonicalizers of R43 and R45.

The ECU commitment is only shape-checked and compared here: `core` never holds the commitment secret and never
computes a lookup key or a commitment (R46). Signing happens outside `core` with the attester's key (R49).
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from core.evidence._errors import EvidenceError, ensure
from core.evidence._json import (
    DTC,
    FAMILY,
    HEX32,
    SIG,
    TIMESTAMP,
    TOOL_NAME,
    UNIT_ID,
    VARIANT,
    digest,
    exact,
    increasing,
    listing,
    matches,
    text,
    verified,
)
from core.evidence._registry import AttesterRegistry
from core.provenance import Raw, Verifier

ATTESTATION_SCHEMA = "impact.field-attestation.v1"
ATTESTATION_DOMAIN = "impact.field-attestation-signature.v1"
ATTESTATION_KEYS = frozenset(
    {
        "schema",
        "subject_image_hash",
        "identification",
        "write_tool",
        "readback_image_hash",
        "communicates",
        "dtcs_after_clear_and_reread",
        "tool_checksum_status",
        "ecu_commitment",
        "ecu_commitment_epoch",
        "attester_key_id",
        "created_at",
    }
)
IDENTIFICATION_KEYS = frozenset({"family", "hw_id", "sw_id", "checksum_variant_id"})
WRITE_TOOL_KEYS = frozenset({"name", "version"})
SIGNED_KEYS = frozenset({"attestation", "attestation_hash", "signature"})
MAX_TOOL_VERSION = 64

ToolChecksumStatus = Literal["ok", "mismatch", "not_reported"]
_STATUSES: Mapping[str, ToolChecksumStatus] = {"ok": "ok", "mismatch": "mismatch", "not_reported": "not_reported"}

_ASCII_WHITESPACE = " \t\n\r\x0b\x0c"
_UNIT_SEPARATORS = frozenset(" -./:_")


def _ascii_upper(value: str) -> str:
    return "".join(char.upper() if "a" <= char <= "z" else char for char in value)


def canonical_dtcs(raw: Sequence[str]) -> list[str]:
    """R43: strip ASCII whitespace, uppercase ASCII letters, validate (`bad_dtc`), deduplicate and sort."""
    codes: set[str] = set()
    for entry in raw:
        code = _ascii_upper(entry.strip(_ASCII_WHITESPACE)) if isinstance(entry, str) else ""
        if not matches(code, DTC):
            raise EvidenceError("bad_dtc", repr(entry))
        codes.add(code)
    return sorted(codes)


def canonical_unit_id(raw: str) -> str:
    """R45: the canonical `UnitId` of an ECU serial (UDS DID 0xF18C), or `bad_unit_id`."""
    value = raw if isinstance(raw, str) else ""
    unit_id = _ascii_upper("".join(char for char in value if char not in _UNIT_SEPARATORS))
    if not matches(unit_id, UNIT_ID):
        raise EvidenceError("bad_unit_id", repr(raw))
    return unit_id


@dataclass(frozen=True, slots=True)
class FieldAttestation:
    """R40, built only by `parse_attestation`, so every value has the stated form."""

    subject_image_hash: str
    family: str
    hw_id: str | None
    sw_id: str | None
    checksum_variant_id: str
    write_tool_name: str
    write_tool_version: str
    readback_image_hash: str | None
    communicates: bool
    dtcs_after_clear_and_reread: tuple[str, ...]
    tool_checksum_status: ToolChecksumStatus
    ecu_commitment: str | None
    ecu_commitment_epoch: str | None
    attester_key_id: str
    created_at: str

    def to_json(self) -> Mapping[str, Raw]:
        return {
            "schema": ATTESTATION_SCHEMA,
            "subject_image_hash": self.subject_image_hash,
            "identification": {
                "family": self.family,
                "hw_id": self.hw_id,
                "sw_id": self.sw_id,
                "checksum_variant_id": self.checksum_variant_id,
            },
            "write_tool": {"name": self.write_tool_name, "version": self.write_tool_version},
            "readback_image_hash": self.readback_image_hash,
            "communicates": self.communicates,
            "dtcs_after_clear_and_reread": list(self.dtcs_after_clear_and_reread),
            "tool_checksum_status": self.tool_checksum_status,
            "ecu_commitment": self.ecu_commitment,
            "ecu_commitment_epoch": self.ecu_commitment_epoch,
            "attester_key_id": self.attester_key_id,
            "created_at": self.created_at,
        }

    @property
    def attestation_hash(self) -> str:
        """R48: `sha256(JCS(FieldAttestation))`."""
        return digest(self.to_json())


def _nullable_hex(value: Raw) -> bool:
    return value is None or matches(value, HEX32)


def _identification_ok(value: Raw) -> bool:
    return (
        exact(value, IDENTIFICATION_KEYS)
        and matches(value["family"], FAMILY)
        and matches(value["checksum_variant_id"], VARIANT)
        and (value["hw_id"] is None or text(value["hw_id"]))
        and (value["sw_id"] is None or text(value["sw_id"]))
    )


def _write_tool_ok(value: Raw) -> bool:
    version = value.get("version") if isinstance(value, Mapping) else None
    return (
        exact(value, WRITE_TOOL_KEYS)
        and matches(value["name"], TOOL_NAME)
        and text(version)
        and 0 < len(version) <= MAX_TOOL_VERSION
    )


def _dtcs_ok(value: Raw) -> bool:
    # R43: already canonical, so each list has one form.
    return listing(value) and all(matches(code, DTC) for code in value) and increasing([str(code) for code in value])


def _commitment_ok(commitment: Raw, epoch: Raw) -> bool:
    # R40, R46, R47: both null, or both 32-byte hex; never anything derived from a serial in `core`.
    return (commitment is None and epoch is None) or (matches(commitment, HEX32) and matches(epoch, HEX32))


def _shape_ok(value: Raw) -> bool:
    return (
        exact(value, ATTESTATION_KEYS)
        and value["schema"] == ATTESTATION_SCHEMA
        and matches(value["subject_image_hash"], HEX32)
        and _identification_ok(value["identification"])
        and _write_tool_ok(value["write_tool"])
        and _nullable_hex(value["readback_image_hash"])
        and isinstance(value["communicates"], bool)
        and _dtcs_ok(value["dtcs_after_clear_and_reread"])
        and isinstance(value["tool_checksum_status"], str)
        and value["tool_checksum_status"] in _STATUSES
        and _commitment_ok(value["ecu_commitment"], value["ecu_commitment_epoch"])
        and matches(value["attester_key_id"], HEX32)
        and matches(value["created_at"], TIMESTAMP)
    )


def _str(value: Raw) -> str:
    return value if isinstance(value, str) else ""


def _opt(value: Raw) -> str | None:
    return value if isinstance(value, str) else None


def _member(value: Raw, key: str) -> Raw:
    return value.get(key) if isinstance(value, Mapping) else None


def parse_attestation(value: Raw) -> FieldAttestation:
    """R40, R43: a `FieldAttestation` of exactly the stated shape, else `EvidenceError` `bad_shape`."""
    if not _shape_ok(value):
        raise EvidenceError("bad_shape", "not a FieldAttestation (SPEC-006 R40)")
    identification, tool = _member(value, "identification"), _member(value, "write_tool")
    dtcs = _member(value, "dtcs_after_clear_and_reread")
    return FieldAttestation(
        subject_image_hash=_str(_member(value, "subject_image_hash")),
        family=_str(_member(identification, "family")),
        hw_id=_opt(_member(identification, "hw_id")),
        sw_id=_opt(_member(identification, "sw_id")),
        checksum_variant_id=_str(_member(identification, "checksum_variant_id")),
        write_tool_name=_str(_member(tool, "name")),
        write_tool_version=_str(_member(tool, "version")),
        readback_image_hash=_opt(_member(value, "readback_image_hash")),
        communicates=_member(value, "communicates") is True,
        dtcs_after_clear_and_reread=tuple(_str(code) for code in dtcs) if listing(dtcs) else (),
        tool_checksum_status=_STATUSES.get(_str(_member(value, "tool_checksum_status")), "mismatch"),
        ecu_commitment=_opt(_member(value, "ecu_commitment")),
        ecu_commitment_epoch=_opt(_member(value, "ecu_commitment_epoch")),
        attester_key_id=_str(_member(value, "attester_key_id")),
        created_at=_str(_member(value, "created_at")),
    )


def attestation_hash(value: Raw) -> str:
    """R48 of a raw `FieldAttestation`; `bad_shape` if it is not one."""
    return parse_attestation(value).attestation_hash


def _signed(value: Raw) -> tuple[FieldAttestation, str, str] | None:
    if not exact(value, SIGNED_KEYS) or not _shape_ok(value["attestation"]):
        return None
    stored_hash, signature = value["attestation_hash"], value["signature"]
    if matches(stored_hash, HEX32) and matches(signature, SIG):
        return parse_attestation(value["attestation"]), stored_hash, signature
    return None


def verify_attestation(signed: Raw, registry: AttesterRegistry, verifier: Verifier) -> list[str]:
    """R50: `[]` or exactly one reason, in R50 order. The public key comes only from `registry`."""
    parsed = _signed(signed)
    if parsed is None:
        reasons = ["bad_shape"]
    elif parsed[0].attestation_hash != parsed[1]:
        reasons = ["attestation_hash_mismatch"]
    else:
        reasons = _trust_reasons(*parsed, registry, verifier)
    ensure(len(reasons) <= 1, "SPEC-006 R50")
    return reasons


def _trust_reasons(
    attestation: FieldAttestation, stored_hash: str, signature: str, registry: AttesterRegistry, verifier: Verifier
) -> list[str]:
    """R50 from `unknown_attester` on, with R77 for revoked keys."""
    entry = registry.attester(attestation.attester_key_id)
    if entry is None:
        return ["unknown_attester"]
    inclusion = registry.inclusion(stored_hash)
    # R77: only a `retired` key's attestations included before its revocation survive it.
    included_at = (
        inclusion.seq if inclusion is not None and inclusion.attester_key_id == entry.attester_key_id else None
    )
    if entry.revoked is not None and (included_at is None or not entry.counts_at(included_at)):
        return ["revoked_attester"]
    if "attester" not in entry.roles:
        return ["not_attester"]
    if not verified(verifier, entry.public_key, ATTESTATION_DOMAIN, stored_hash, signature):
        return ["bad_signature"]
    return []
