"""SPEC-004 R16, SPEC-006 R83, R84: the gate runs `core.evidence.evidence_admission` itself, fail-closed."""

from dataclasses import replace
from typing import Any

from core.evidence import FieldEvidence
from core.gate._evidence import REGISTRY_TRUST, admission_with, admitted_by_evidence, published_admission
from core.gate._release import run_release
from core.provenance import Raw
from tests.unit.evidence_support import DTC_SET, EPOCH, SIGNER, build, enroll, head_for, registry_chain, sign_head
from tests.unit.gate_support import CONFORMANCE, CORE_VERSION, Overridden, Scenario, check, doc, rule_ids
from tests.unit.plugin_fixtures import IDENT, FakePlugin
from tests.unit.provenance_support import VERIFIER
from tests.unit.test_evidence_admission import APPROVE, NEGATIVE, PX, PX2, QY, QY2, RENEWED, UZ, P, Q, S, T, U

FAMILY, VARIANT = "synthetic.family", "synthetic.variant.1"


def field_evidence() -> tuple[FieldEvidence, Raw]:
    """A signed, current registry head under which the SPEC-006 synthetic variant is `golden_field` (dev keys,
    outside test mode), and the trust anchor of that registry."""
    chain = registry_chain()
    for key in (P, Q, U):
        enroll(chain, key)
    enroll(chain, S, ("reviewer",))
    enroll(chain, T, ("reviewer",), rotates=P)
    APPROVE(chain)
    registry = build(chain)
    head = sign_head(head_for(registry), SIGNER)
    trust = {
        "tenant_id": chain[0].tenant_id,
        "genesis_hash": chain[0].hash,
        "key_id": SIGNER.key_id,
        "public_key": SIGNER.public_key,
    }
    return FieldEvidence(head, registry, [NEGATIVE, RENEWED], [PX, QY, UZ, PX2, QY2], DTC_SET, EPOCH), trust


AS_OF = "2026-10-19T12:00:00Z"


# SPEC-006 R60: no registry trust anchor is published yet, so the published gate admits nothing.
def test_published_gate_admits_nothing() -> None:
    evidence, _ = field_evidence()
    assert REGISTRY_TRUST is None
    admission = published_admission(evidence, AS_OF, VERIFIER)
    assert (admission.status, admission.reasons) == ("unavailable", ("untrusted_head",))


# SPEC-004 R16: missing evidence or verifier, or evidence core.evidence rejects, is `unavailable`.
def test_fail_closed() -> None:
    evidence, trust = field_evidence()
    admit = admission_with(trust)
    assert admit(None, AS_OF, VERIFIER).reasons == ("missing_evidence",)
    assert admit(evidence, AS_OF, None).reasons == ("untrusted_head",)
    assert admit(evidence, "not a timestamp", VERIFIER).reasons == ("bad_shape",)
    assert admit(evidence, "2026-10-21T00:00:00Z", VERIFIER).reasons == ("head_expired",)
    current = admit(evidence, AS_OF, VERIFIER)
    assert current.status == "current"
    assert admitted_by_evidence(current, FAMILY, VARIANT)
    assert not admitted_by_evidence(current, FAMILY, None)
    assert not admitted_by_evidence(current, FAMILY, "other")


def synthetic_plugin() -> Overridden:
    ident = replace(IDENT, family=FAMILY, checksum_variant_id=VARIANT)
    return Overridden(family=FAMILY, replaced={"identify": lambda d: FakePlugin().identify(d) and ident})


# SPEC-004 R15, R16, SPEC-006 R84: with a current head listing the variant `golden_field`, release goes through.
def test_release_with_real_field_evidence() -> None:
    evidence, trust = field_evidence()
    plugin = synthetic_plugin()
    conformance = {
        **CONFORMANCE,
        "plugin": {"family": FAMILY, "version": "1.0.0"},
        "variants": [{"checksum_variant_id": VARIANT, "admitted": True}],
    }
    admit = admission_with(trust)
    s = Scenario(plugin=plugin)
    common: dict[str, Any] = {
        "evidence": evidence,
        "as_of": AS_OF,
        "verifier": VERIFIER,
        "conformance_report": conformance,
    }
    result = check(s.original, admit, plugin=plugin, **common)
    assert doc(result.report)["verdict"] == "no findings"
    released = run_release(s.unverified(), s.args(input=result, **common), admit, CORE_VERSION)
    assert released.verdict == "no findings"
    # Expired evidence at the same release: every variant is unknown again and the run blocks (R16).
    stale = s.blocked(admit=admit, input=result, **{**common, "as_of": "2026-10-21T00:00:00Z"})
    assert "G-VERIFY" in rule_ids(stale)
