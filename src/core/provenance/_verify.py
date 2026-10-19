"""Chain verification (SPEC-005 R40-R46): findings, never exceptions, never a boolean.

Events enter as raw JSON (`Raw`) because a stored chain is untrusted: a malformed event is a finding.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal

from core.provenance._anchor import AnchorFile
from core.provenance._events import event_defect, key_event_hash
from core.provenance._json import (
    HEX32_CHECK,
    ZERO_HASH,
    Json,
    Raw,
    as_int,
    as_mapping,
    as_str,
    items,
    member,
    to_json,
    try_hash,
    uint,
)
from core.provenance._payloads import KEY_EVENT_TYPES, REPORT_EVENT_TYPES
from core.provenance._signing import (
    ANCHOR_DOMAIN,
    KEY_EVENT_DOMAIN,
    REPORT_DOMAIN,
    TEST_KEY_IDS,
    Verifier,
    verified,
)

Status = Literal["intact", "broken"]
Previous = tuple[int, str | None, str | None]

# R40 step 5: the only informational reason.
INFORMATIONAL = frozenset({"ts_regression"})
# A stored element whose `seq` is not an integer has no position in the chain; its finding carries this seq.
NO_POSITION = -1


@dataclass(frozen=True, slots=True)
class Missing:
    first: int
    last: int


@dataclass(frozen=True, slots=True)
class Finding:
    seq: int
    reason: str
    missing: Missing | None = None

    @property
    def informational(self) -> bool:
        return self.reason in INFORMATIONAL

    def to_json(self) -> dict[str, Json | bool]:
        missing = None if self.missing is None else {"first": self.missing.first, "last": self.missing.last}
        return {"seq": self.seq, "reason": self.reason, "informational": self.informational, "missing": missing}


@dataclass(frozen=True, slots=True)
class Head:
    seq: int
    hash: str


@dataclass(frozen=True, slots=True)
class ChainReport:
    """R40. `segment_from` is the first `seq` a segment report covers (R44: R35 holds only from there), else None."""

    status: Status
    genesis_hash: str | None
    signer_key_id: str | None
    head: Head | None
    anchored_through: int | None
    findings: tuple[Finding, ...]
    segment_from: int | None = None


@dataclass(frozen=True, slots=True)
class CheckpointKey:
    key_id: str
    public_key: str
    enrolled_seq: int
    revoked_seq: int | None


@dataclass(frozen=True, slots=True)
class Checkpoint:
    """R44: the key state at `seq`, so steps 3 and 4 apply R52 as from genesis."""

    seq: int
    hash: str
    keys: tuple[CheckpointKey, ...]


@dataclass(frozen=True, slots=True)
class ChainRef:
    """A `chain_ref` whose R57 signature verified: it vouches for `(seq, head_hash)` of the chain it names."""

    at: int
    chain_signer_key_id: str
    genesis_hash: str
    seq: int
    head_hash: str


@dataclass(slots=True)
class _State:
    """What verification learns while walking one chain (R52 key state, R45 references, R46 revocations)."""

    tenant_id: str | None
    genesis_hash: str
    verifier: Verifier
    test_mode: bool
    keys: dict[str, tuple[str, int]] = field(default_factory=dict)
    revoked: dict[str, int] = field(default_factory=dict)
    revocations: list[tuple[str, int]] = field(default_factory=list)
    chain_refs: list[ChainRef] = field(default_factory=list)
    report_seqs: list[int] = field(default_factory=list)
    hashes: dict[int, str] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

    def add(self, seq: int, reason: str | None, missing: Missing | None = None) -> None:
        if reason is not None:
            self.findings.append(Finding(seq, reason, missing))

    def key_reason(self, key_id: Raw, seq: int, *, inclusive: bool) -> str | None:
        """R52 (events: strictly lower `seq`) and R40 step 4 (anchors: `seq` at most the anchored one)."""
        entry = self.keys.get(as_str(key_id))
        if entry is None or entry[1] > seq or (entry[1] == seq and not inclusive):
            return "unknown_key"
        revoked = self.revoked.get(as_str(key_id))
        if revoked is not None and (revoked < seq or (revoked == seq and inclusive)):
            return "revoked_key"
        return None

    def signature_reason(self, key_id: Raw, domain: str, hash_hex: Raw, signature: Raw) -> str | None:
        """R51 through the injected verifier, after the key checks of R52."""
        entry = self.keys.get(as_str(key_id), ("", 0))
        if verified(self.verifier, entry[0], domain, as_str(hash_hex), as_str(signature)):
            return None
        return "bad_signature"

    def enroll(self, key_id: str, public_key: str, seq: int) -> None:
        if key_id in TEST_KEY_IDS and not self.test_mode:
            self.add(seq, "test_key")
        self.keys.setdefault(key_id, (public_key, seq))

    def revoke(self, key_id: str, seq: int) -> None:
        # Fail-closed: the earliest revocation wins, and it counts even for a key enrolled later.
        self.revoked[key_id] = min(seq, self.revoked.get(key_id, seq))
        self.revocations.append((key_id, seq))


@dataclass(frozen=True, slots=True)
class _Walked:
    report: ChainReport
    state: _State
    role: str | None


def _place(events: Sequence[Raw]) -> tuple[list[tuple[int, Raw]], int]:
    """R40: input order is not trusted. Sort by `seq`, then stored hash and content for a total order.

    Returns the placed events and the number of elements without an integer `seq`.
    """
    placed: list[tuple[int, str, str, Raw]] = []
    for event in events:
        seq = member(event, "seq")
        if uint(seq):
            placed.append((as_int(seq), as_str(member(event, "hash")), try_hash(event) or "", event))
    placed.sort(key=_placement)
    return [(seq, event) for seq, _, _, event in placed], len(events) - len(placed)


def _placement(entry: tuple[int, str, str, Raw]) -> tuple[int, str, str]:
    return entry[0], entry[1], entry[2]


def _genesis_ok(seq: int, event: Raw) -> bool:
    """R32 for the first event, including `actor.kind = system` and exactly one enrolled key (R40 step 1)."""
    return (
        event_defect(event) in {None, "bad_payload"}
        and seq == 0
        and member(event, "type") == "genesis"
        and member(event, "prev_hash") == ZERO_HASH
        and member(event, "project_id") is None
        and member(member(event, "actor"), "kind") == "system"
        and len(items(member(member(event, "payload"), "signing_keys"))) == 1
    )


def _json(value: Raw) -> Json:
    try:
        return to_json(value)
    except ValueError:
        return None


def _walk(placed: Sequence[tuple[int, Raw]], state: _State, *, previous: Previous | None, from_genesis: bool) -> None:
    """R40 steps 2 and 3 over `placed`, starting after `previous` (seq, hash, ts)."""
    first_ok = from_genesis and _genesis_ok(*placed[0])
    seen_ids: set[str] = set()
    for index, (seq, event) in enumerate(placed):
        stored_hash, ts = member(event, "hash"), member(event, "ts")
        defect = event_defect(event)
        if defect == "bad_shape":
            state.add(seq, "bad_shape")
            previous = (seq, _text(stored_hash), _text(ts))
            continue
        state.hashes.setdefault(seq, as_str(stored_hash))
        _link(state, seq, event, previous)
        if member(event, "tenant_id") != state.tenant_id:
            state.add(seq, "tenant_mismatch")
        event_id = as_str(member(event, "event_id"))
        if event_id in seen_ids:
            state.add(seq, "duplicate_event_id")
        seen_ids.add(event_id)
        previous = (seq, as_str(stored_hash), as_str(ts))
        event_type = as_str(member(event, "type"))
        is_genesis = from_genesis and index == 0
        if event_type == "genesis" and not is_genesis:
            # R40 step 1: a later genesis enrolls nothing.
            state.add(seq, "not_genesis")
        state.add(seq, defect)
        if defect is None and (event_type != "genesis" or (is_genesis and first_ok)):
            _apply(state, seq, event_type, member(event, "payload"))


def _link(state: _State, seq: int, event: Raw, previous: Previous | None) -> None:
    body = {key: value for key, value in as_mapping(_json(event)).items() if key != "hash"}
    if try_hash(body) != member(event, "hash"):
        state.add(seq, "hash_mismatch")
    if previous is None:
        return
    previous_seq, previous_hash, previous_ts = previous
    if seq == previous_seq:
        state.add(seq, "seq_duplicate")
    elif seq != previous_seq + 1:
        state.add(seq, "seq_gap", Missing(previous_seq + 1, seq - 1))
    if previous_hash is None or member(event, "prev_hash") != previous_hash:
        state.add(seq, "prev_mismatch")
    if previous_ts is not None and as_str(member(event, "ts")) < previous_ts:
        # R38: order is `seq`; a clock going backwards is informational only.
        state.add(seq, "ts_regression")


def _apply(state: _State, seq: int, event_type: str, payload: Raw) -> None:
    """R40 step 3 and the key state of R52 for one well-formed event."""
    signed_ok = True
    if event_type in REPORT_EVENT_TYPES:
        key_id = member(payload, "key_id")
        reason = state.key_reason(key_id, seq, inclusive=False) or state.signature_reason(
            key_id, REPORT_DOMAIN, member(payload, "report_hash"), member(payload, "signature")
        )
        state.add(seq, reason)
        state.report_seqs.append(seq)
    elif event_type in KEY_EVENT_TYPES:
        signer = member(payload, "signer_key_id")
        digest = key_event_hash(
            tenant_id=as_str(state.tenant_id),
            genesis_hash=state.genesis_hash,
            seq=seq,
            event_type=event_type,
            payload=as_mapping(_json(payload)),
        )
        reason = state.key_reason(signer, seq, inclusive=False) or state.signature_reason(
            signer, KEY_EVENT_DOMAIN, digest, member(payload, "signature")
        )
        state.add(seq, reason)
        signed_ok = reason is None
    if event_type == "genesis":
        for key in items(member(payload, "signing_keys")):
            state.enroll(as_str(member(key, "key_id")), as_str(member(key, "public_key")), seq)
    elif event_type == "key_enrolled" and signed_ok:
        state.enroll(as_str(member(payload, "key_id")), as_str(member(payload, "public_key")), seq)
    elif event_type == "attester_enrolled" and as_str(member(payload, "attester_key_id")) in TEST_KEY_IDS:
        # R56 names the SPEC-006 attester keys too: enrolling one outside test mode is `test_key`.
        state.add(seq, None if state.test_mode else "test_key")
    elif event_type == "key_revoked":
        # R40 step 3: a revocation takes effect even with a finding.
        state.revoke(as_str(member(payload, "key_id")), seq)
    elif event_type == "chain_ref" and signed_ok:
        ref = ChainRef(
            seq,
            as_str(member(payload, "chain_signer_key_id")),
            as_str(member(payload, "genesis_hash")),
            as_int(member(payload, "seq")),
            as_str(member(payload, "head_hash")),
        )
        state.chain_refs.append(ref)


def _anchors(state: _State, anchors: Sequence[AnchorFile], last: int, *, since: int) -> int | None:
    """R40 step 4 for anchors at `seq >= since`. Returns the highest `seq` of an anchor without any finding."""
    anchored: int | None = None
    for anchor in anchors:
        statement = anchor.statement
        seq = statement.seq
        if seq < since:
            continue
        before = len(state.findings)
        if statement.statement_hash != anchor.statement_hash:
            state.add(seq, "bad_anchor")
        state.add(
            seq,
            state.key_reason(anchor.key_id, seq, inclusive=True)
            or state.signature_reason(anchor.key_id, ANCHOR_DOMAIN, anchor.statement_hash, anchor.signature),
        )
        if statement.tenant_id != state.tenant_id or statement.genesis_hash != state.genesis_hash:
            state.add(seq, "anchor_mismatch")
        elif seq > last:
            state.add(seq, "truncated")
        elif state.hashes.get(seq) != statement.head_hash:
            state.add(seq, "anchor_mismatch")
        if len(state.findings) == before:
            anchored = max(seq, NO_POSITION if anchored is None else anchored)
    return anchored


def _status(findings: Sequence[Finding]) -> Status:
    return "broken" if any(not finding.informational for finding in findings) else "intact"


def _finding_key(finding: Finding) -> tuple[int, str]:
    return finding.seq, finding.reason


def _report(
    state: _State,
    *,
    genesis_hash: str | None,
    signer_key_id: str | None,
    anchored: int | None,
    segment_from: int | None = None,
) -> ChainReport:
    last = max(state.hashes, default=None)
    head = None if last is None else Head(last, state.hashes[last])
    findings = tuple(sorted(state.findings, key=_finding_key))
    return ChainReport(_status(findings), genesis_hash, signer_key_id, head, anchored, findings, segment_from)


def _text(value: Raw) -> str | None:
    return value if isinstance(value, str) else None


def _full(events: Sequence[Raw], anchors: Sequence[AnchorFile], verifier: Verifier, test_mode: bool) -> _Walked:
    placed, unplaced = _place(events)
    first_seq, first = placed[0] if placed else (0, None)
    stored = member(first, "hash")
    state = _State(
        _text(member(first, "tenant_id")), as_str(stored) if HEX32_CHECK(stored) else "", verifier, test_mode
    )
    for _ in range(unplaced):
        state.add(NO_POSITION, "bad_shape")
    first_ok = _genesis_ok(first_seq, first)
    if not first_ok:
        state.add(first_seq, "not_genesis")
    if placed:
        _walk(placed, state, previous=None, from_genesis=True)
    anchored = _anchors(state, anchors, placed[-1][0] if placed else NO_POSITION, since=0)
    payload = member(first, "payload")
    signer = as_str(member(items(member(payload, "signing_keys"))[0], "key_id")) if first_ok else ""
    report = _report(
        state,
        genesis_hash=state.genesis_hash if first_ok else None,
        signer_key_id=signer if signer in state.keys else None,
        anchored=anchored,
    )
    return _Walked(report, state, as_str(member(payload, "role")) if first_ok else None)


def verify_chain(
    events: Sequence[Raw], anchors: Sequence[AnchorFile], verifier: Verifier, *, test_mode: bool = False
) -> ChainReport:
    """R40 from genesis. `test_mode` admits the R56 test keys and is passed only by vector tests."""
    return _full(events, anchors, verifier, test_mode).report


def _own_anchors(chain: Sequence[Raw], anchors: Sequence[AnchorFile]) -> list[AnchorFile]:
    placed, _ = _place(chain)
    genesis_hash = member(placed[0][1], "hash") if placed else None
    return [anchor for anchor in anchors if anchor.statement.genesis_hash == genesis_hash]


def _anchored_refs(server: _Walked) -> list[ChainRef]:
    """R45: the references of an intact server chain at or below its anchored head protect what they name."""
    through = server.report.anchored_through
    if server.report.status != "intact" or server.role != "server" or through is None:
        return []
    return [ref for ref in server.state.chain_refs if ref.at <= through]


@dataclass(frozen=True, slots=True)
class _Identity:
    tenant_id: str | None
    genesis_hash: str
    signer_key_id: str | None
    anchored_through: int | None = None
    anchored_head: str | None = None


_NO_IDENTITY = _Identity(None, "", None)


def _anchor_identity(checkpoint: Checkpoint, anchors: Sequence[AnchorFile], keys: _State) -> _Identity:
    """R44 for a server chain: a valid anchor of the checkpoint's `seq` and `hash`."""
    for anchor in anchors:
        statement = anchor.statement
        covers = (statement.seq, statement.head_hash) == (checkpoint.seq, checkpoint.hash)
        valid = (
            statement.statement_hash == anchor.statement_hash
            and keys.key_reason(anchor.key_id, statement.seq, inclusive=True) is None
            and keys.signature_reason(anchor.key_id, ANCHOR_DOMAIN, anchor.statement_hash, anchor.signature) is None
        )
        if covers and valid:
            return _Identity(statement.tenant_id, statement.genesis_hash, None)
    return _NO_IDENTITY


def _ref_identity(
    checkpoint: Checkpoint, anchors: Sequence[AnchorFile], server_chain: Sequence[Raw], keys: _State
) -> _Identity:
    """R44 for a CLI chain: an anchored `chain_ref` of the server chain names the checkpoint's `seq` and `hash`."""
    server = _full(server_chain, _own_anchors(server_chain, anchors), keys.verifier, keys.test_mode)
    refs = _anchored_refs(server)
    for ref in refs:
        if (ref.seq, ref.head_hash) == (checkpoint.seq, checkpoint.hash):
            latest = max((r for r in refs if r.genesis_hash == ref.genesis_hash), key=_ref_seq)
            tenant = server.state.tenant_id
            return _Identity(tenant, ref.genesis_hash, ref.chain_signer_key_id, latest.seq, latest.head_hash)
    return _NO_IDENTITY


def _ref_seq(ref: ChainRef) -> int:
    return ref.seq


def verify_segment(
    checkpoint: Checkpoint,
    events: Sequence[Raw],
    anchors: Sequence[AnchorFile],
    verifier: Verifier,
    server_chain: Sequence[Raw] | None,
) -> ChainReport:
    """R44: R40 steps 2-5 from `checkpoint`. `server_chain` is required for, and only for, a `role: cli` chain.

    Never in test mode: segments are a retention mechanism for real chains (R56).
    """
    keys = _State(None, "", verifier, test_mode=False)
    for key in checkpoint.keys:
        keys.keys[key.key_id] = (key.public_key, key.enrolled_seq)
        if key.revoked_seq is not None:
            keys.revoke(key.key_id, key.revoked_seq)
    identity = (
        _anchor_identity(checkpoint, anchors, keys)
        if server_chain is None
        else _ref_identity(checkpoint, anchors, server_chain, keys)
    )
    placed, unplaced = _place(events)
    tenant = identity.tenant_id
    if tenant is None and placed:
        tenant = _text(member(placed[0][1], "tenant_id"))
    state = _State(tenant, identity.genesis_hash, verifier, False, keys=keys.keys, revoked=keys.revoked)
    for _ in range(unplaced):
        state.add(NO_POSITION, "bad_shape")
    if identity.tenant_id is None:
        state.add(checkpoint.seq, "unanchored_checkpoint")
    state.hashes[checkpoint.seq] = checkpoint.hash
    if placed:
        _walk(placed, state, previous=(checkpoint.seq, checkpoint.hash, None), from_genesis=False)
    if server_chain is None:
        anchored = _anchors(state, anchors, max(state.hashes), since=checkpoint.seq)
    else:
        # R45: protected up to the highest referenced seq, if this segment carries that head.
        through = identity.anchored_through
        anchored = through if through is not None and state.hashes.get(through) == identity.anchored_head else None
    return _report(
        state,
        genesis_hash=identity.genesis_hash or None,
        signer_key_id=identity.signer_key_id,
        anchored=anchored,
        segment_from=checkpoint.seq + 1,
    )


@dataclass(frozen=True, slots=True)
class TenantFinding:
    genesis_hash: str
    seq: int
    reason: str

    @property
    def informational(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class TenantReport:
    status: Status
    chains: tuple[ChainReport, ...]
    findings: tuple[TenantFinding, ...]


def _ref_findings(walked: Sequence[_Walked]) -> list[TenantFinding]:
    """R46: every verified `chain_ref` names a chain of the tenant whose `seq` carries `head_hash`."""
    by_genesis = {w.state.genesis_hash: w for w in walked if w.report.genesis_hash is not None}
    findings: list[TenantFinding] = []
    for chain in walked:
        for ref in chain.state.chain_refs:
            target = by_genesis.get(ref.genesis_hash)
            if (
                target is None
                or target.report.signer_key_id != ref.chain_signer_key_id
                or target.state.hashes.get(ref.seq) != ref.head_hash
            ):
                findings.append(TenantFinding(ref.genesis_hash, ref.seq, "chain_ref_mismatch"))
    return findings


def _revocation_findings(server: _Walked, cli: _Walked) -> list[TenantFinding]:
    """R46: after a server-chain revocation of a CLI key at server `seq` n, every export or audit of that CLI
    chain beyond the highest `seq` confirmed by a `chain_ref` at a server `seq` below n."""
    findings: list[TenantFinding] = []
    for key_id, revoked_at in server.state.revocations:
        if key_id not in cli.state.keys:
            continue
        confirmed = [
            ref.seq
            for ref in server.state.chain_refs
            if ref.genesis_hash == cli.state.genesis_hash
            and ref.at < revoked_at
            and cli.state.hashes.get(ref.seq) == ref.head_hash
        ]
        through = max(confirmed, default=NO_POSITION)
        findings.extend(
            TenantFinding(cli.state.genesis_hash, seq, "unconfirmed_after_revocation")
            for seq in cli.state.report_seqs
            if seq > through
        )
    return findings


def _tenant_key(finding: TenantFinding) -> tuple[str, int, str]:
    return finding.genesis_hash, finding.seq, finding.reason


def _chain_key(report: ChainReport) -> str:
    return report.genesis_hash or ""


def verify_tenant(
    chains: Sequence[Sequence[Raw]], anchors: Sequence[AnchorFile], verifier: Verifier, *, test_mode: bool = False
) -> TenantReport:
    """R46: every chain of a tenant, the `chain_ref`s between them and CLI keys revoked from the server chain.

    Each chain is verified with the anchors that name its genesis; a CLI chain has none of its own (R42).
    """
    walked = [_full(chain, _own_anchors(chain, anchors), verifier, test_mode) for chain in chains]
    findings = _ref_findings(walked)
    for server in (w for w in walked if w.role == "server"):
        for cli in (w for w in walked if w.role == "cli"):
            findings.extend(_revocation_findings(server, cli))
    unique = tuple(sorted(set(findings), key=_tenant_key))
    reports = tuple(sorted((w.report for w in walked), key=_chain_key))
    broken = bool(unique) or any(report.status == "broken" for report in reports)
    return TenantReport("broken" if broken else "intact", reports, unique)
