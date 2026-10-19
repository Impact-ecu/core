"""Signing inputs and the injected `Signer`/`Verifier` (SPEC-005 R50-R57). No Ed25519 code lives here (R55)."""

from typing import Protocol

from core.provenance._errors import SignatureError
from core.provenance._json import sha256_hex, signing_input

REPORT_DOMAIN = "impact.report-signature.v1"
ANCHOR_DOMAIN = "impact.anchor-signature.v1"
KEY_EVENT_DOMAIN = "impact.key-event-signature.v1"
GENERIC_AUDIT_DOMAIN = "impact.generic-audit-signature.v1"

# R56: the synthetic keys of SPEC-005 §12 (`key.key_id`) and SPEC-006 §12 (`keys`). A test checks this set
# against both vector files, so it cannot drift from them.
TEST_KEY_IDS = frozenset(
    {
        "83299ff053ca22658116fb63fbcfbadabfd166ac75b2a523cbe5210c7d08ef79",
        "34899563765b0913a82bf6177082564241c9be4eb318548e48ed2dc2f23379d0",
        "4a7448d0a693e4fa927530f7a394c5c6b116c66254be5ea36fd95a27ade23e19",
        "5d4f33ab43ef49471f606c8c7e4cfdc26011980b385d810871f6399881e6338c",
        "7064327d245dfac8651ecc3f0c5ed9d9106d4ed71a09e2c2dfc8882538e0e6da",
        "885d8e2ba7c9389405586e85a6d225be6de9c3c5c6db370474c21d277d5f2033",
        "ae873854ddced454afd7516f18b35cd4295ba0f8371d0cbec4c8892b5071f1a8",
        "bc8f2033ec0e03a9fa482374b0be1e8840b84512c377eebd9b13e5d06887a5dc",
        "bda10450d69d2b78922d1d1dee7e6b7b8d5c1823a727d1012acb51b78610492d",
        "cdfc59703e6cf762dd53227aaf76ced0ad3b3d355bc837c93f6602ebff6ec265",
    }
)


class Signer(Protocol):
    """Holds a private key outside `core` (R53) and signs the message `core` builds."""

    @property
    def key_id(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


class Verifier(Protocol):
    """An RFC 8032 PureEd25519 verifier injected by the consumer (R55)."""

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool: ...


def key_id_of(public_key_hex: str) -> str:
    """R50: `key_id = sha256(public key bytes)`."""
    return sha256_hex(bytes.fromhex(public_key_hex))


def sign(signer: Signer, domain: str, hash_hex: str) -> str:
    """R51: sign the JCS of `{domain, hash}` and return the 64-byte signature in lowercase hex."""
    signature = signer.sign(signing_input(domain, hash_hex))
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise SignatureError("bad_signature", f"the signer of {signer.key_id} did not return 64 bytes")
    return signature.hex()


def verified(verifier: Verifier, public_key_hex: str, domain: str, hash_hex: str, signature_hex: str) -> bool:
    """R51 through the injected verifier. Callers pass validated hex; only a literal `True` is acceptance."""
    message = signing_input(domain, hash_hex)
    return verifier.verify(bytes.fromhex(public_key_hex), message, bytes.fromhex(signature_hex)) is True
