"""SPEC-005 §6: `verify_chain` (R40, R41), anchors (R42), segments (R44), cross-chain checks (R45, R46).

Every finding reason of R40, R44 and R46 has a test here (R91). Chains use dev keys, so `test_mode` is off.
"""

import copy
import hashlib
import json
from typing import Any

import rfc8785

from core.provenance import (
    AnchorFile,
    AnchorStatement,
    ChainReport,
    Checkpoint,
    CheckpointKey,
    Event,
    ShapeError,
    commitment,
    make_anchor,
    parse_anchor,
    verify_chain,
    verify_segment,
    verify_tenant,
)
from core.provenance._verify import NO_POSITION
from tests.unit.provenance_support import (
    CLI,
    OTHER,
    SERVER,
    SPEC006,
    TENANT,
    TEST_SIGNER,
    VERIFIER,
    Ed25519Signer,
    add,
    add_signed,
    dev_key,
    expect,
    import_payload,
    raw,
    start,
)


def add_export(chain: list[Event], signer: Ed25519Signer, report_hash: str = "12" * 32) -> Event:
    message = rfc8785.dumps({"domain": "impact.report-signature.v1", "hash": report_hash})
    payload = {
        "provenance_hash": "34" * 32,
        "report_hash": report_hash,
        "key_id": signer.key_id,
        "signature": signer.sign(message).hex(),
    }
    return add(chain, "export", payload)


def anchor(chain: list[Event], seq: int | None = None, signer: Ed25519Signer = SERVER) -> AnchorFile:
    head = chain[-1] if seq is None else chain[seq]
    return make_anchor(tenant_id=TENANT, genesis_hash=chain[0].hash, head=head, day="2026-10-18", signer=signer)


def server_chain() -> list[Event]:
    chain = [start()]
    add(chain, "import", import_payload())
    add_export(chain, SERVER)
    return chain


def reasons(report: ChainReport) -> list[tuple[int, str]]:
    return [(f.seq, f.reason) for f in report.findings]


def rehash_from(events: list[dict[str, Any]], index: int) -> None:
    """Recompute hashes with an independent JCS, as an attacker with store access would (R41)."""
    for i in range(index, len(events)):
        if i > 0:
            events[i]["prev_hash"] = events[i - 1]["hash"]
        body = {k: v for k, v in events[i].items() if k != "hash"}
        events[i]["hash"] = hashlib.sha256(rfc8785.dumps(body)).hexdigest()


# SPEC-005 R40: an intact chain, its report fields and its anchor.
def test_intact_chain() -> None:
    chain = server_chain()
    report = verify_chain(raw(chain), [anchor(chain)], VERIFIER)
    assert report.status == "intact"
    assert report.findings == ()
    assert report.genesis_hash == chain[0].hash
    assert report.signer_key_id == SERVER.key_id
    assert report.head is not None
    assert (report.head.seq, report.head.hash) == (2, chain[2].hash)
    assert report.anchored_through == 2
    assert report.segment_from is None
    assert verify_chain(raw(chain), [], VERIFIER).anchored_through is None


# SPEC-005 R40: input order is not trusted.
def test_input_order_is_not_trusted() -> None:
    chain = server_chain()
    assert verify_chain(raw(chain)[::-1], [], VERIFIER) == verify_chain(raw(chain), [], VERIFIER)


# SPEC-005 R32, R40 step 1
def test_not_genesis() -> None:
    assert reasons(verify_chain([], [], VERIFIER)) == [(0, "not_genesis")]
    chain = server_chain()
    events = raw(chain)
    assert (1, "not_genesis") in reasons(verify_chain(events[1:], [], VERIFIER))
    for field, value in (("actor", {"kind": "user", "id": "u"}), ("project_id", "p"), ("prev_hash", "11" * 32)):
        mutated = copy.deepcopy(events)
        mutated[0][field] = value
        rehash_from(mutated, 0)
        found = reasons(verify_chain(mutated, [], VERIFIER))
        assert (0, "not_genesis") in found
        # A genesis that is `not_genesis` enrolls nothing, so the export's key is unknown.
        assert (2, "unknown_key") in found
    no_keys = copy.deepcopy(events)
    no_keys[0]["payload"]["signing_keys"] = []
    rehash_from(no_keys, 0)
    assert reasons(verify_chain(no_keys, [], VERIFIER)) == [(0, "not_genesis"), (2, "unknown_key")]
    second = [start(), *chain[1:]]
    add(second, "import", import_payload())
    stored = raw(second)
    stored.insert(1, {**raw([start(OTHER)])[0], "seq": 1, "prev_hash": stored[0]["hash"], "event_id": "ff" * 16})
    for later in stored[2:]:
        later["seq"] += 1
    rehash_from(stored, 1)
    assert (1, "not_genesis") in reasons(verify_chain(stored, [], VERIFIER))


# SPEC-005 R3, R40 step 2: a shape defect is a finding, never an exception.
def test_bad_shape() -> None:
    events = raw(server_chain())
    missing = copy.deepcopy(events)
    del missing[1]["ts"]
    found = reasons(verify_chain(missing, [], VERIFIER))
    assert (1, "bad_shape") in found
    assert (2, "prev_mismatch") not in found
    no_seq = copy.deepcopy(events)
    no_seq[1]["seq"] = "1"
    assert (NO_POSITION, "bad_shape") in reasons(verify_chain([*no_seq, 7, None], [], VERIFIER))
    unhashable = copy.deepcopy(events)
    unhashable[1]["hash"] = 5
    found = reasons(verify_chain(unhashable, [], VERIFIER))
    assert (1, "bad_shape") in found
    assert (2, "prev_mismatch") in found
    broken_genesis = copy.deepcopy(events)
    broken_genesis[0]["tenant_id"] = "Tenant"
    found = reasons(verify_chain(broken_genesis, [], VERIFIER))
    assert {(0, "bad_shape"), (0, "not_genesis"), (1, "tenant_mismatch")} <= set(found)


# SPEC-005 R31, R40 step 2
def test_hash_mismatch() -> None:
    events = raw(server_chain())
    events[1]["payload"]["origin"] = "obd_read"
    assert reasons(verify_chain(events, [], VERIFIER)) == [(1, "hash_mismatch")]
    floats = raw(server_chain())
    floats[1]["payload"]["image_hash"] = 1.5
    assert reasons(verify_chain(floats, [], VERIFIER)) == [(1, "bad_payload"), (1, "hash_mismatch")]


# SPEC-005 R33, R41: a removed middle event, a duplicate seq.
def test_seq_gap_duplicate_and_prev_mismatch() -> None:
    chain = server_chain()
    add(chain, "import", import_payload())
    events = raw(chain)
    report = verify_chain([events[0], events[3]], [], VERIFIER)
    assert reasons(report) == [(3, "prev_mismatch"), (3, "seq_gap")]
    gap = report.findings[1]
    assert gap.missing is not None
    assert (gap.missing.first, gap.missing.last) == (1, 2)
    assert report.findings[0].missing is None
    assert gap.to_json() == {"seq": 3, "reason": "seq_gap", "informational": False, "missing": {"first": 1, "last": 2}}
    duplicate = copy.deepcopy(events[1])
    duplicate["event_id"] = "ee" * 16
    rehash_from([events[0], duplicate], 1)
    found = reasons(verify_chain([*events, duplicate], [], VERIFIER))
    assert (1, "seq_duplicate") in found


# SPEC-005 R38: a clock going backwards is informational.
def test_ts_regression() -> None:
    events = raw(server_chain())
    events[1]["ts"] = "2000-01-01T00:00:00Z"
    rehash_from(events, 1)
    report = verify_chain(events, [], VERIFIER)
    assert report.status == "intact"
    assert reasons(report) == [(1, "ts_regression")]
    assert report.findings[0].informational


# SPEC-005 R33, R35
def test_tenant_mismatch_and_duplicate_event_id() -> None:
    events = raw(server_chain())
    events[1]["tenant_id"] = "tenant-b"
    rehash_from(events, 1)
    assert reasons(verify_chain(events, [], VERIFIER)) == [(1, "tenant_mismatch")]
    events = raw(server_chain())
    events[2]["event_id"] = events[1]["event_id"]
    rehash_from(events, 2)
    assert reasons(verify_chain(events, [], VERIFIER)) == [(2, "duplicate_event_id")]


# SPEC-005 R36
def test_unknown_type_and_bad_payload() -> None:
    events = raw(server_chain())
    events[1]["type"] = "note"
    rehash_from(events, 1)
    assert reasons(verify_chain(events, [], VERIFIER)) == [(1, "unknown_type")]
    events = raw(server_chain())
    events[1]["payload"]["vin"] = "WVWZZZ1JZXW000001"
    rehash_from(events, 1)
    assert reasons(verify_chain(events, [], VERIFIER)) == [(1, "bad_payload")]
    genesis_payload = raw(server_chain())
    genesis_payload[0]["payload"]["signing_keys"][0]["key_id"] = OTHER.key_id
    rehash_from(genesis_payload, 0)
    # A genesis whose key_id is not the SHA-256 of its public key enrolls nothing (R50).
    assert reasons(verify_chain(genesis_payload, [], VERIFIER)) == [(0, "bad_payload"), (2, "unknown_key")]


# SPEC-005 R56: the vector keys outside test mode.
def test_test_key() -> None:
    chain = [start(TEST_SIGNER, test_mode=True)]
    assert reasons(verify_chain(raw(chain), [], VERIFIER)) == [(0, "test_key")]
    assert verify_chain(raw(chain), [], VERIFIER, test_mode=True).status == "intact"
    chain = [start()]
    payload = {"key_id": TEST_SIGNER.key_id, "public_key": TEST_SIGNER.public_key}
    add_signed(chain, "key_enrolled", payload, SERVER, test_mode=True)
    events = raw(chain)
    assert reasons(verify_chain(events, [], VERIFIER)) == [(1, "test_key")]
    attester = next(iter(SPEC006["keys"]["keys"].values()))
    chain = [start()]
    attester_payload = {
        "attester_key_id": attester["key_id"],
        "public_key": attester["public_key"],
        "roles": ["attester"],
        "rotates": None,
        "rotation_signature": None,
        "reason_commitment": "56" * 32,
    }
    add_signed(chain, "attester_enrolled", attester_payload, SERVER)
    assert reasons(verify_chain(raw(chain), [], VERIFIER)) == [(1, "test_key")]
    assert verify_chain(raw(chain), [], VERIFIER, test_mode=True).findings == ()
    other = dict(attester_payload, attester_key_id="78" * 32)
    chain = [start()]
    add_signed(chain, "attester_enrolled", other, SERVER)
    assert verify_chain(raw(chain), [], VERIFIER).findings == ()


# SPEC-005 R52, R57: keys enrolled and revoked by signed events.
def test_key_lifecycle() -> None:
    chain = [start()]
    add_signed(chain, "key_enrolled", {"key_id": OTHER.key_id, "public_key": OTHER.public_key}, SERVER)
    add_export(chain, OTHER)
    add_signed(chain, "key_revoked", {"key_id": OTHER.key_id, "reason": "retired"}, SERVER)
    add_export(chain, OTHER)
    add_export(chain, SERVER)
    report = verify_chain(raw(chain), [], VERIFIER)
    # Revocation never invalidates earlier signatures (R52).
    assert reasons(report) == [(4, "revoked_key")]


def test_unknown_key_and_bad_signature() -> None:
    chain = [start()]
    add_export(chain, OTHER)
    add_signed(chain, "key_enrolled", {"key_id": CLI.key_id, "public_key": CLI.public_key}, OTHER)
    add_export(chain, CLI)
    # A key_enrolled with a finding enrolls nothing.
    assert reasons(verify_chain(raw(chain), [], VERIFIER)) == [
        (1, "unknown_key"),
        (2, "unknown_key"),
        (3, "unknown_key"),
    ]
    chain = server_chain()
    events = raw(chain)
    events[2]["payload"]["report_hash"] = "99" * 32
    rehash_from(events, 2)
    assert reasons(verify_chain(events, [], VERIFIER)) == [(2, "bad_signature")]
    chain = [start()]
    add_signed(chain, "key_enrolled", {"key_id": OTHER.key_id, "public_key": OTHER.public_key}, SERVER)
    add_export(chain, OTHER)
    replayed = raw(chain)
    # R57: the same signed key event at another seq no longer verifies, and enrolls nothing.
    replayed.insert(1, raw([add(chain[:1], "import", import_payload())])[0])
    for later in replayed[2:]:
        later["seq"] += 1
    rehash_from(replayed, 1)
    assert reasons(verify_chain(replayed, [], VERIFIER)) == [(2, "bad_signature"), (3, "unknown_key")]


# SPEC-005 R40 step 3: an unauthenticated revocation still takes effect (fail-closed); the earliest one counts.
def test_revocation_takes_effect_even_unsigned() -> None:
    chain = [start()]
    add_signed(chain, "key_revoked", {"key_id": SERVER.key_id, "reason": "compromised"}, OTHER)
    add_export(chain, SERVER)
    assert reasons(verify_chain(raw(chain), [], VERIFIER)) == [(1, "unknown_key"), (2, "revoked_key")]
    chain = [start()]
    add_signed(chain, "key_revoked", {"key_id": OTHER.key_id, "reason": "compromised"}, SERVER)
    add_signed(chain, "key_enrolled", {"key_id": OTHER.key_id, "public_key": OTHER.public_key}, SERVER)
    add_export(chain, OTHER)
    add_signed(chain, "key_revoked", {"key_id": OTHER.key_id, "reason": "retired"}, SERVER)
    assert reasons(verify_chain(raw(chain), [], VERIFIER)) == [(3, "revoked_key")]


# SPEC-005 R41, R42, R40 step 4: every anchor reason.
def test_anchor_reasons() -> None:
    chain = server_chain()
    events = raw(chain)
    good = anchor(chain)
    assert reasons(verify_chain(events[:2], [good], VERIFIER)) == [(2, "truncated")]
    statement = good.statement
    forged = AnchorFile(
        AnchorStatement(statement.tenant_id, statement.genesis_hash, 2, "77" * 32, statement.day),
        good.statement_hash,
        good.key_id,
        good.signature,
    )
    assert reasons(verify_chain(events, [forged], VERIFIER)) == [(2, "anchor_mismatch"), (2, "bad_anchor")]
    other_tenant = make_anchor(
        tenant_id="tenant-b", genesis_hash=chain[0].hash, head=chain[2], day="2026-10-18", signer=SERVER
    )
    assert reasons(verify_chain(events, [other_tenant], VERIFIER)) == [(2, "anchor_mismatch")]
    other_chain = make_anchor(tenant_id=TENANT, genesis_hash="88" * 32, head=chain[2], day="2026-10-18", signer=SERVER)
    assert reasons(verify_chain(events, [other_chain], VERIFIER)) == [(2, "anchor_mismatch")]
    assert reasons(verify_chain(events, [anchor(chain, signer=OTHER)], VERIFIER)) == [(2, "unknown_key")]
    bad_signature = AnchorFile(statement, good.statement_hash, good.key_id, "00" * 64)
    found = verify_chain(events, [bad_signature], VERIFIER)
    assert reasons(found) == [(2, "bad_signature")]
    assert found.anchored_through is None
    # R41: a rewrite with every hash recomputed is caught only by a covering anchor.
    rewritten = copy.deepcopy(events)
    rewritten[1]["payload"]["origin"] = "obd_read"
    rehash_from(rewritten, 1)
    assert verify_chain(rewritten, [], VERIFIER).status == "intact"
    assert reasons(verify_chain(rewritten, [good], VERIFIER)) == [(2, "anchor_mismatch")]
    # Anchors at several seqs: `anchored_through` is the highest without findings.
    assert verify_chain(events, [anchor(chain, 1), good, anchor(chain, 0)], VERIFIER).anchored_through == 2
    assert verify_chain(events, [anchor(chain, 1), forged], VERIFIER).anchored_through == 1


# SPEC-005 R40 step 4: a revocation at exactly the anchored seq counts.
def test_anchor_revoked_at_its_seq() -> None:
    chain = [start()]
    add_signed(chain, "key_enrolled", {"key_id": OTHER.key_id, "public_key": OTHER.public_key}, SERVER)
    add_signed(chain, "key_revoked", {"key_id": OTHER.key_id, "reason": "compromised"}, SERVER)
    assert reasons(verify_chain(raw(chain), [anchor(chain, 2, signer=OTHER)], VERIFIER)) == [(2, "revoked_key")]
    assert verify_chain(raw(chain), [anchor(chain, 1, signer=OTHER)], VERIFIER).findings == ()


def checkpoint_of(chain: list[Event], seq: int, signers: list[Ed25519Signer]) -> Checkpoint:
    keys = tuple(CheckpointKey(s.key_id, s.public_key, 0, None) for s in signers)
    return Checkpoint(seq, chain[seq].hash, keys)


# SPEC-005 R44: a server segment from an anchored checkpoint.
def test_segment_from_anchored_checkpoint() -> None:
    chain = server_chain()
    add_export(chain, SERVER)
    cut = anchor(chain, 1)
    tail = raw(chain)[2:]
    # An anchor before the checkpoint covers nothing in the segment and is not checked against it.
    anchors = [anchor(chain, 0), cut, anchor(chain)]
    report = verify_segment(checkpoint_of(chain, 1, [SERVER]), tail, anchors, VERIFIER, None)
    assert report.status == "intact"
    assert report.findings == ()
    assert report.segment_from == 2
    assert report.genesis_hash == chain[0].hash
    assert report.anchored_through == 3
    assert report.head is not None
    assert report.head.seq == 3
    unanchored = verify_segment(checkpoint_of(chain, 1, [SERVER]), tail, [anchor(chain)], VERIFIER, None)
    assert (1, "unanchored_checkpoint") in reasons(unanchored)
    assert unanchored.genesis_hash is None
    gap = verify_segment(checkpoint_of(chain, 1, [SERVER]), raw(chain)[3:], [cut], VERIFIER, None)
    assert reasons(gap) == [(3, "prev_mismatch"), (3, "seq_gap")]
    revoked = Checkpoint(1, chain[1].hash, (CheckpointKey(SERVER.key_id, SERVER.public_key, 0, 1),))
    assert reasons(verify_segment(revoked, tail, [cut], VERIFIER, None)) == [
        (1, "anchor_mismatch"),
        (1, "revoked_key"),
        (1, "unanchored_checkpoint"),
        (2, "revoked_key"),
        (3, "revoked_key"),
    ]
    empty = verify_segment(checkpoint_of(chain, 1, [SERVER]), [], [cut], VERIFIER, None)
    assert empty.status == "intact"
    assert empty.head is not None
    assert empty.head.seq == 1
    with_genesis = verify_segment(checkpoint_of(chain, 1, [SERVER]), [*tail, "junk"], [cut], VERIFIER, None)
    assert reasons(with_genesis) == [(NO_POSITION, "bad_shape")]
    lost = verify_segment(checkpoint_of(chain, 1, [SERVER]), ["junk"], [], VERIFIER, None)
    assert reasons(lost) == [(NO_POSITION, "bad_shape"), (1, "unanchored_checkpoint")]


def cli_setup() -> tuple[list[Event], list[Event], list[AnchorFile]]:
    """A CLI chain with two exports and a server chain that references its seq-1 head, anchored."""
    cli = [start(CLI, role="cli")]
    add_export(cli, CLI)
    add_export(cli, CLI)
    server = [start()]
    add_signed(
        server,
        "chain_ref",
        {"chain_signer_key_id": CLI.key_id, "genesis_hash": cli[0].hash, "seq": 1, "head_hash": cli[1].hash},
        SERVER,
    )
    return cli, server, [anchor(server)]


# SPEC-005 R44, R45: a CLI segment is accepted through an anchored chain_ref of the server chain.
def test_cli_segment() -> None:
    cli, server, anchors = cli_setup()
    report = verify_segment(checkpoint_of(cli, 1, [CLI]), raw(cli)[2:], anchors, VERIFIER, raw(server))
    assert report.findings == ()
    assert (report.genesis_hash, report.signer_key_id, report.anchored_through) == (cli[0].hash, CLI.key_id, 1)
    later = verify_segment(checkpoint_of(cli, 0, [CLI]), raw(cli)[1:], anchors, VERIFIER, raw(server))
    assert reasons(later) == [(0, "unanchored_checkpoint")]
    assert later.anchored_through is None
    unanchored = verify_segment(checkpoint_of(cli, 1, [CLI]), raw(cli)[2:], [], VERIFIER, raw(server))
    assert reasons(unanchored) == [(1, "unanchored_checkpoint")]
    beyond = [start()]
    add_signed(
        beyond,
        "chain_ref",
        {"chain_signer_key_id": CLI.key_id, "genesis_hash": cli[0].hash, "seq": 9, "head_hash": cli[1].hash},
        SERVER,
    )
    add_signed(
        beyond,
        "chain_ref",
        {"chain_signer_key_id": CLI.key_id, "genesis_hash": cli[0].hash, "seq": 1, "head_hash": cli[1].hash},
        SERVER,
    )
    through = verify_segment(checkpoint_of(cli, 1, [CLI]), raw(cli)[2:], [anchor(beyond)], VERIFIER, raw(beyond))
    assert through.anchored_through is None
    as_cli = [start(SERVER, role="cli")]
    add_signed(
        as_cli,
        "chain_ref",
        {"chain_signer_key_id": CLI.key_id, "genesis_hash": cli[0].hash, "seq": 1, "head_hash": cli[1].hash},
        SERVER,
    )
    not_server = verify_segment(checkpoint_of(cli, 1, [CLI]), raw(cli)[2:], [anchor(as_cli)], VERIFIER, raw(as_cli))
    assert reasons(not_server) == [(1, "unanchored_checkpoint")]


# SPEC-005 R45, R46: tenant verification.
def test_verify_tenant_intact() -> None:
    cli, server, anchors = cli_setup()
    report = verify_tenant([raw(cli), raw(server)], anchors, VERIFIER)
    assert report.status == "intact"
    assert report.findings == ()
    assert [c.genesis_hash for c in report.chains] == sorted([cli[0].hash, server[0].hash])
    server_report = next(c for c in report.chains if c.genesis_hash == server[0].hash)
    assert server_report.anchored_through == 1


def test_chain_ref_mismatch() -> None:
    cli, server, anchors = cli_setup()
    ref = {"chain_signer_key_id": CLI.key_id, "genesis_hash": cli[0].hash, "seq": 2, "head_hash": "66" * 32}
    add_signed(server, "chain_ref", ref, SERVER)
    add_signed(server, "chain_ref", {**ref, "genesis_hash": "67" * 32, "seq": 0}, SERVER)
    add_signed(
        server, "chain_ref", {**ref, "chain_signer_key_id": OTHER.key_id, "seq": 1, "head_hash": cli[1].hash}, SERVER
    )
    report = verify_tenant([raw(server), raw(cli)], anchors, VERIFIER)
    assert report.status == "broken"
    assert [(f.genesis_hash, f.seq, f.reason) for f in report.findings] == sorted(
        [
            (cli[0].hash, 2, "chain_ref_mismatch"),
            ("67" * 32, 0, "chain_ref_mismatch"),
            (cli[0].hash, 1, "chain_ref_mismatch"),
        ]
    )
    assert all(not f.informational for f in report.findings)
    assert all(c.status == "intact" for c in report.chains)


def test_unconfirmed_after_revocation() -> None:
    cli, server, anchors = cli_setup()
    add_signed(server, "key_revoked", {"key_id": CLI.key_id, "reason": "compromised"}, SERVER)
    report = verify_tenant([raw(cli), raw(server)], anchors, VERIFIER)
    assert [(f.seq, f.reason) for f in report.findings] == [(2, "unconfirmed_after_revocation")]
    assert report.findings[0].genesis_hash == cli[0].hash
    assert report.status == "broken"
    never_synced, server2, anchors2 = cli_setup()
    lone = [start(dev_key("lone"), role="cli")]
    add_export(lone, dev_key("lone"))
    add_signed(server2, "key_revoked", {"key_id": dev_key("lone").key_id, "reason": "compromised"}, SERVER)
    found = verify_tenant([raw(lone), raw(server2), raw(never_synced)], anchors2, VERIFIER)
    assert [(f.genesis_hash, f.seq, f.reason) for f in found.findings] == [
        (lone[0].hash, 1, "unconfirmed_after_revocation")
    ]


def test_verify_tenant_broken_chain() -> None:
    cli, server, anchors = cli_setup()
    events = raw(cli)
    events[1]["ts"] = "x"
    report = verify_tenant([events, raw(server)], anchors, VERIFIER)
    assert report.status == "broken"
    # The referenced seq 1 is malformed, so it does not carry the referenced head (R46).
    assert [(f.seq, f.reason) for f in report.findings] == [(1, "chain_ref_mismatch")]
    empty = verify_tenant([[]], [], VERIFIER)
    assert empty.chains[0].genesis_hash is None
    assert empty.status == "broken"


# SPEC-005 R3, R42: anchors have exactly their form.
def test_anchor_shapes() -> None:
    chain = server_chain()
    good = anchor(chain)
    stored = json.loads(json.dumps({**good.to_json(), "statement": dict(good.statement.to_json())}))
    assert parse_anchor(stored) == good
    broken_values: list[Any] = [
        {**stored, "extra": 1},
        {**stored, "statement": {**stored["statement"], "day": "1"}},
        [],
    ]
    for broken in broken_values:
        with expect("bad_shape", ShapeError):
            parse_anchor(broken)
    with expect("bad_shape", ShapeError):
        AnchorStatement(TENANT, chain[0].hash, -1, chain[0].hash, "2026-10-18")
    not_a_statement: Any = good.statement.to_json()
    with expect("bad_shape", ShapeError):
        AnchorFile(not_a_statement, good.statement_hash, good.key_id, good.signature)
    with expect("bad_shape", ShapeError):
        AnchorFile(good.statement, good.statement_hash, good.key_id, "00")


# SPEC-005 R40 step 1: a genesis at seq > 0 enrolls nothing, even with a valid payload.
def test_later_genesis_enrolls_nothing() -> None:
    chain = server_chain()
    events = raw(chain)
    later = raw([start(OTHER)])[0]
    later.update(seq=3, prev_hash=events[-1]["hash"], ts=events[-1]["ts"])
    events.append(later)
    rehash_from(events, 3)
    exported = [*chain]
    add_export(exported, OTHER)
    signed_by_other = raw(exported)[-1]
    signed_by_other.update(seq=4, prev_hash=events[-1]["hash"], ts=events[-1]["ts"])
    events.append(signed_by_other)
    rehash_from(events, 4)
    assert reasons(verify_chain(events, [], VERIFIER)) == [(3, "not_genesis"), (4, "unknown_key")]


# SPEC-005 R82, R83, R84: consent and erasure are events over commitments; after crypto-shredding every hash and
# signature still verifies, because hashed fields hold only hashes and commitments.
def test_consent_and_erasure_keep_the_chain_verifiable() -> None:
    record = commitment("0a" * 32, {"consent": "synthetic consent record"})
    chain = server_chain()
    add(
        chain,
        "consent_granted",
        {"artifact_sha256": "bb" * 32, "purpose": "corpus", "legal_basis": "consent", "record_commitment": record},
    )
    add(chain, "consent_revoked", {"artifact_sha256": "bb" * 32, "purpose": "corpus", "record_commitment": record})
    add(chain, "erasure", {"subject": "artifact", "ref": "bb" * 32, "reason": "consent_revoked"})
    add(chain, "erasure", {"subject": "record", "ref": record, "reason": "data_subject_request"})
    report = verify_chain(raw(chain), [anchor(chain)], VERIFIER)
    assert report.status == "intact"
    assert report.anchored_through == chain[-1].seq
