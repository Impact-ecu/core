"""Independent reproduction of an Impact export from its reproduction bundle (SPEC-005 §9, R70-R76).

    python -I reproduce.py <bundle.json>

One file, Python standard library only, and no code shared with `core` (R71, R72): the canonical JSON, the
hashes, the Kahn order, apply and the Ed25519 verification are written here from SPEC-001, SPEC-005 and
RFC 8032. It reads only the bundle named on the command line (R71). It prints one JSON object (R74) and exits
0 when the export is reproduced, 1 when it is not, and 2 on a usage error (SPEC-005 R78).

The bundle holds the original's bytes, which can contain personal data (R70): keep it with the tenant.
"""

import hashlib
import heapq
import json
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass

BUNDLE_SCHEMA = "impact.reproduction-bundle.v1"
BUNDLE_KEYS = ("checksum_patches", "gate_report", "layout", "original", "overlaps", "patches", "report_file", "schema")
REPORT_DOMAIN = "impact.report-signature.v1"
DUMP_KINDS = frozenset({"bench_full", "boot_full", "obd_full", "obd_partial", "virtual"})
REGION_KINDS = frozenset({"calibration", "checksum", "protected"})
MAX_INT = 2**53 - 1
HEX32 = re.compile(r"[0-9a-f]{64}")
HEX_BYTES = re.compile(r"(?:[0-9a-f]{2})*")
MEMORY_ID = re.compile(r"[a-z][a-z0-9_]{0,31}")
LIMITS = (
    "Proves only that the released bytes are exactly the original plus the listed patches plus the recorded "
    "checksum patches (SPEC-005 R75).",
    "Does not recompute checksum values and does not re-run gate rules (SPEC-005 R75).",
    "Proves the report's integrity, not its origin: origin needs the tenant's chain export (SPEC-005 R61).",
)
BEST_EFFORT = (
    "best_effort: the export ran in an environment installed from a lockfile, not a released image; this result "
    "is never evidence for a golden file or an oracle: record (SPEC-005 R16, R17)."
)


class Malformed(Exception):
    """The bundle cannot be read as SPEC-005 §9 describes; the run stops here."""

    def __init__(self, field: str, expected: object, got: object) -> None:
        super().__init__(field)
        self.field = field
        self.expected = expected
        self.got = got


@dataclass(frozen=True)
class Mismatch:
    step: int
    field: str
    expected: object
    got: object


class Run:
    """Collects mismatches for the step being run (R74). A `Malformed` ends the run at that step."""

    def __init__(self) -> None:
        self.step = 0
        self.reproducibility: str | None = None
        self.mismatches: list[Mismatch] = []

    def check(self, field: str, expected: object, got: object) -> None:
        if expected != got:
            self.mismatches.append(Mismatch(self.step, field, expected, got))


# Canonical JSON (SPEC-001 R60, SPEC-005 R1, R4, R72): the stdlib encoding equals RFC 8785 for integers within
# 2**53 - 1, ASCII keys and strings without lone surrogates, so anything else is refused, never hashed.


def _jcs_check(value: object, field: str) -> None:
    if value is None or isinstance(value, bool | str):
        if isinstance(value, str) and any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise Malformed(field, "a string without lone surrogates (SPEC-005 R4)", "lone surrogate")
        return
    if isinstance(value, int):
        if -MAX_INT <= value <= MAX_INT:
            return
        raise Malformed(field, "an integer within 2**53 - 1 (SPEC-001 R60)", str(value))
    if isinstance(value, list):
        for index, item in enumerate(value):
            _jcs_check(item, f"{field}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not key.isascii():
                raise Malformed(field, "ASCII object keys (SPEC-005 R4)", key)
            _jcs_check(item, f"{field}.{key}")
        return
    raise Malformed(field, "JSON without floats (SPEC-005 R1)", type(value).__name__)


def canonical(value: object, field: str = "value") -> bytes:
    _jcs_check(value, field)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_jcs(value: object, field: str = "value") -> str:
    return hashlib.sha256(canonical(value, field)).hexdigest()


# Ed25519 verification, RFC 8032 §5.1 (PureEd25519), with the cofactored group equation of §5.1.7.

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, -1, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)
type Point = tuple[int, int, int, int]
_IDENTITY: Point = (0, 1, 1, 0)


def _add(a: Point, b: Point) -> Point:
    """RFC 8032 §5.1.4, extended homogeneous coordinates."""
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    a_ = (y1 - x1) * (y2 - x2) % _P
    b_ = (y1 + x1) * (y2 + x2) % _P
    c_ = 2 * t1 * t2 * _D % _P
    d_ = 2 * z1 * z2 % _P
    e, f, g, h = b_ - a_, d_ - c_, d_ + c_, b_ + a_
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _multiply(scalar: int, point: Point) -> Point:
    result = _IDENTITY
    while scalar:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _same(a: Point, b: Point) -> bool:
    x1, y1, z1, _ = a
    x2, y2, z2, _ = b
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


def _recover_x(y: int, sign: int) -> int | None:
    """RFC 8032 §5.1.3 steps 2-4."""
    u = (y * y - 1) % _P
    v = (_D * y * y + 1) % _P
    x = u * pow(v, 3, _P) * pow(u * pow(v, 7, _P), (_P - 5) // 8, _P) % _P
    vxx = v * x * x % _P
    if vxx != u:
        if vxx != (-u) % _P:
            return None
        x = x * _SQRT_M1 % _P
    if x == 0 and sign:
        return None
    return _P - x if x & 1 != sign else x


def _decode_point(encoded: bytes) -> Point | None:
    """RFC 8032 §5.1.3: a non-canonical y (y >= p) or a point off the curve is rejected."""
    y = int.from_bytes(encoded, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        return None
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


# RFC 8032 §5.1: the base point B, y = 4/5 with x positive (even).
_BASE_X = 15112221349535400772501151409588531511454012693041857206046113283949847762202
_BASE_Y = 46316835694926478169428394003475163141307993866256225615783033603165251855960
_BASE: Point = (_BASE_X, _BASE_Y, 1, _BASE_X * _BASE_Y % _P)


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """RFC 8032 §5.1.7: [8][S]B = [8]R + [8][k]A."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a = _decode_point(public_key)
    r = _decode_point(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if a is None or r is None or s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % _L
    return _same(_multiply(8 * s, _BASE), _multiply(8, _add(r, _multiply(k, a))))


# Readers. Each names the bundle field it reads, so a mismatch says where the bundle is wrong.


def _member(value: object, key: str, field: str) -> object:
    if not isinstance(value, dict) or key not in value:
        raise Malformed(f"{field}.{key}", "present", None)
    return value[key]


def _fields(value: object, field: str, keys: Iterable[str]) -> dict[str, object]:
    expected = sorted(keys)
    if not isinstance(value, dict):
        raise Malformed(field, f"an object with keys {expected}", type(value).__name__)
    if sorted(value) != expected:
        raise Malformed(field, f"an object with keys {expected}", sorted(value))
    return value


def _string(value: object, field: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or (pattern is not None and not pattern.fullmatch(value)):
        raise Malformed(field, "a string" if pattern is None else f"a string matching {pattern.pattern}", value)
    return value


def _integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_INT:
        raise Malformed(field, "an integer in [0, 2**53 - 1] (SPEC-001 §2)", value)
    return value


def _list(value: object, field: str) -> list[object]:
    if not isinstance(value, list):
        raise Malformed(field, "a list", type(value).__name__)
    return value


def _hex(value: object, field: str) -> bytes:
    """Byte strings are lowercase hex (SPEC-001 R60). A bad one is never echoed: it can be dump bytes (R70)."""
    if not isinstance(value, str) or not HEX_BYTES.fullmatch(value):
        raise Malformed(field, "lowercase hex (SPEC-001 R60)", "not lowercase hex")
    return bytes.fromhex(value)


def _hashes(value: object, field: str) -> list[str]:
    return [_string(item, f"{field}[{i}]", HEX32) for i, item in enumerate(_list(value, field))]


def _pairs(value: object, field: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for i, item in enumerate(_list(value, field)):
        pair = _hashes(item, f"{field}[{i}]")
        if len(pair) != 2:
            raise Malformed(f"{field}[{i}]", "a pair of patch hashes", len(pair))
        pairs.append((pair[0], pair[1]))
    return pairs


# SPEC-001 data shapes and hashes (§2, §7).


@dataclass(frozen=True)
class Patch:
    memory_id: str
    offset: int
    length: int
    before: bytes
    after: bytes
    patch_hash: str

    @property
    def end(self) -> int:
        return self.offset + self.length


@dataclass(frozen=True)
class Memory:
    memory_id: str
    base_address: int | None
    data: bytes


@dataclass(frozen=True)
class Region:
    kind: str
    start: int
    end: int


@dataclass(frozen=True)
class Original:
    dump_kind: str
    memories: dict[str, Memory]
    image_hash: str


def patch_hash(memory_id: str, offset: int, before: bytes, after: bytes) -> str:
    """SPEC-001 R61."""
    value = {"memory_id": memory_id, "offset": offset, "length": len(before), "before": before.hex()}
    return sha256_jcs(value | {"after": after.hex()})


def image_hash(dump_kind: str, memories: Iterable[Memory]) -> str:
    """SPEC-001 R62."""
    entries = [
        {
            "memory_id": memory.memory_id,
            "base_address": memory.base_address,
            "size": len(memory.data),
            "sha256": hashlib.sha256(memory.data).hexdigest(),
        }
        for memory in sorted(memories, key=lambda memory: memory.memory_id)
    ]
    return sha256_jcs({"dump_kind": dump_kind, "memories": entries})


def _patch(value: object, field: str) -> Patch:
    """SPEC-001 §2.3 with R10 and R12."""
    raw = _fields(value, field, ("after", "before", "length", "memory_id", "offset"))
    memory_id = _string(raw["memory_id"], f"{field}.memory_id", MEMORY_ID)
    offset = _integer(raw["offset"], f"{field}.offset")
    length = _integer(raw["length"], f"{field}.length")
    before = _hex(raw["before"], f"{field}.before")
    after = _hex(raw["after"], f"{field}.after")
    if length == 0 or len(before) != length or len(after) != length:
        raise Malformed(field, "length > 0 and len(before) == len(after) == length (SPEC-001 R10)", "bad_length")
    if before == after:
        raise Malformed(field, "before != after (SPEC-001 R12)", "noop_patch")
    return Patch(memory_id, offset, length, before, after, patch_hash(memory_id, offset, before, after))


def _patches(value: object, field: str) -> list[Patch]:
    patches = [_patch(item, f"{field}[{i}]") for i, item in enumerate(_list(value, field))]
    seen: set[str] = set()
    for patch in patches:
        if patch.patch_hash in seen:
            raise Malformed(field, "no patch_hash twice (SPEC-001 R14)", patch.patch_hash)
        seen.add(patch.patch_hash)
    return patches


def _overlap(a: Patch, b: Patch) -> bool:
    return a.memory_id == b.memory_id and a.offset < b.end and b.offset < a.end


def canonical_order(patches: list[Patch], overlaps: list[tuple[str, str]]) -> list[Patch]:
    """SPEC-001 R22 checks, then R25: Kahn's algorithm with a min-heap on (memory_id, offset, patch_hash)."""
    by_hash = {patch.patch_hash: patch for patch in patches}
    listed: set[frozenset[str]] = set()
    successors: dict[str, list[str]] = {h: [] for h in by_hash}
    pending = dict.fromkeys(by_hash, 0)
    for index, (first, second) in enumerate(overlaps):
        pair = frozenset((first, second))
        known = first in by_hash and second in by_hash and first != second
        if not known or pair in listed or not _overlap(by_hash[first], by_hash[second]):
            expected = "only overlapping pairs of listed patches, each once (SPEC-001 R22)"
            raise Malformed(f"overlaps[{index}]", expected, "spurious_order")
        listed.add(pair)
        successors[first].append(second)
        pending[second] += 1
    for i, a in enumerate(patches):
        for b in patches[i + 1 :]:
            if _overlap(a, b) and frozenset((a.patch_hash, b.patch_hash)) not in listed:
                raise Malformed("overlaps", "every overlapping pair ordered (SPEC-001 R22)", "missing_order")
    heap = [(p.memory_id, p.offset, p.patch_hash) for p in patches if pending[p.patch_hash] == 0]
    heapq.heapify(heap)
    order: list[Patch] = []
    while heap:
        current = by_hash[heapq.heappop(heap)[2]]
        order.append(current)
        for successor in successors[current.patch_hash]:
            pending[successor] -= 1
            if pending[successor] == 0:
                heapq.heappush(heap, (by_hash[successor].memory_id, by_hash[successor].offset, successor))
    if len(order) != len(patches):
        raise Malformed("overlaps", "an acyclic order (SPEC-001 R22)", "cycle")
    return order


def version_hash(base_image_hash: str, layout: str, order: list[Patch], overlaps: list[tuple[str, str]]) -> str:
    """SPEC-001 R64."""
    pairs = sorted([first, second] for first, second in overlaps)
    hashes = [patch.patch_hash for patch in order]
    return sha256_jcs({"base_image_hash": base_image_hash, "layout_hash": layout, "patches": hashes, "overlaps": pairs})


# The steps of R73.


def _record(run: Run, report_file: object) -> dict[str, object]:
    """Step 1: SPEC-005 R61 integrity of the report file. Returns the export record."""
    raw = _fields(report_file, "report_file", ("event", "report", "report_hash"))
    report, event = raw["report"], raw["event"]
    kind = _member(report, "kind", "report")
    if kind != "export":
        raise Malformed("report.kind", "export (an audit has no release to reproduce)", kind)
    record = _member(report, "record", "report")
    if not isinstance(record, dict):
        raise Malformed("report.record", "an object", type(record).__name__)
    report_hash = _string(raw["report_hash"], "report_file.report_hash", HEX32)
    record_hash = _string(_member(report, "record_hash", "report"), "report.record_hash", HEX32)
    signer = _member(report, "signer", "report")
    public_key = _hex(_member(signer, "public_key", "report.signer"), "report.signer.public_key")
    key_id = _string(_member(signer, "key_id", "report.signer"), "report.signer.key_id", HEX32)
    run.check("report_file.report_hash", report_hash, sha256_jcs(report, "report"))
    run.check("report.record_hash", record_hash, sha256_jcs(record, "report.record"))
    run.check("report.signer.key_id", key_id, hashlib.sha256(public_key).hexdigest())
    if not isinstance(event, dict):
        raise Malformed("event", "an object", type(event).__name__)
    body = {key: value for key, value in event.items() if key != "hash"}
    run.check("event.hash", _member(event, "hash", "event"), sha256_jcs(body, "event"))
    run.check("event.type", "export", _member(event, "type", "event"))
    run.check("event.tenant_id", _member(report, "tenant_id", "report"), _member(event, "tenant_id", "event"))
    payload = _member(event, "payload", "event")
    run.check("event.payload.report_hash", report_hash, _member(payload, "report_hash", "event.payload"))
    run.check("event.payload.provenance_hash", record_hash, _member(payload, "provenance_hash", "event.payload"))
    run.check("event.payload.key_id", key_id, _member(payload, "key_id", "event.payload"))
    signature = _hex(_member(payload, "signature", "event.payload"), "event.payload.signature")
    message = canonical({"domain": REPORT_DOMAIN, "hash": report_hash})
    valid = ed25519_verify(public_key, message, signature)
    run.check("event.payload.signature", "valid", "valid" if valid else "invalid")
    return record


def reproducibility(record: dict[str, object]) -> str:
    """R74: never upgraded. `full` only for a record that says `full` and ran in a released image (R16, R17)."""
    claimed = record.get("reproducibility")
    build = record.get("build")
    kind = build.get("kind") if isinstance(build, dict) else None
    return "full" if claimed == "full" and kind == "image" else "best_effort"


def _hex32(record: dict[str, object], key: str) -> str:
    return _string(record.get(key), f"report.record.{key}", HEX32)


def _original(run: Run, value: object, record: dict[str, object]) -> Original:
    """Step 2: SPEC-001 R62 of the original equals `image_hash_original`."""
    raw = _fields(value, "original", ("dump_kind", "memories"))
    dump_kind = _string(raw["dump_kind"], "original.dump_kind")
    if dump_kind not in DUMP_KINDS:
        raise Malformed("original.dump_kind", sorted(DUMP_KINDS), dump_kind)
    memories: dict[str, Memory] = {}
    for i, item in enumerate(_list(raw["memories"], "original.memories")):
        field = f"original.memories[{i}]"
        entry = _fields(item, field, ("base_address", "data", "memory_id"))
        memory_id = _string(entry["memory_id"], f"{field}.memory_id", MEMORY_ID)
        base = None if entry["base_address"] is None else _integer(entry["base_address"], f"{field}.base_address")
        data = _hex(entry["data"], f"{field}.data")
        if not data or memory_id in memories:
            raise Malformed(field, "non-empty data and a unique memory_id (SPEC-001 R1)", memory_id)
        memories[memory_id] = Memory(memory_id, base, data)
    if not memories:
        raise Malformed("original.memories", "at least one memory (SPEC-001 R1)", 0)
    digest = image_hash(dump_kind, memories.values())
    run.check("image_hash_original", _hex32(record, "image_hash_original"), digest)
    return Original(dump_kind, memories, digest)


def _layout(
    run: Run, value: object, original: Original, record: dict[str, object]
) -> tuple[str, dict[str, list[Region]]]:
    """Step 3: SPEC-001 R4, R5, then R63 of the layout equals `layout_hash`."""
    raw = _fields(value, "layout", ("memories",))
    regions: dict[str, list[Region]] = {}
    entries: list[tuple[str, dict[str, object]]] = []
    for i, item in enumerate(_list(raw["memories"], "layout.memories")):
        field = f"layout.memories[{i}]"
        memory = _fields(item, field, ("base_address", "memory_id", "regions", "size"))
        memory_id = _string(memory["memory_id"], f"{field}.memory_id", MEMORY_ID)
        base = None if memory["base_address"] is None else _integer(memory["base_address"], f"{field}.base_address")
        size = _integer(memory["size"], f"{field}.size")
        dumped = original.memories.get(memory_id)
        if memory_id in regions or dumped is None or dumped.base_address != base or len(dumped.data) != size:
            raise Malformed(field, "the original's memory_id, base_address and size (SPEC-001 R5)", "shape_mismatch")
        cover = 0
        listed: list[Region] = []
        hashed: list[object] = []
        for j, region_value in enumerate(_list(memory["regions"], f"{field}.regions")):
            where = f"{field}.regions[{j}]"
            region = _fields(region_value, where, ("end", "kind", "name", "start"))
            kind = _string(region["kind"], f"{where}.kind")
            start, end = _integer(region["start"], f"{where}.start"), _integer(region["end"], f"{where}.end")
            name = _string(region["name"], f"{where}.name")
            if kind not in REGION_KINDS or start != cover or end <= start:
                raise Malformed(where, "sorted regions that cover [0, size) exactly (SPEC-001 R4)", "bad_cover")
            cover = end
            listed.append(Region(kind, start, end))
            hashed.append({"kind": kind, "start": start, "end": end, "name": name})
        if cover != size:
            raise Malformed(
                f"{field}.regions", "sorted regions that cover [0, size) exactly (SPEC-001 R4)", "bad_cover"
            )
        regions[memory_id] = listed
        entries.append((memory_id, {"memory_id": memory_id, "base_address": base, "size": size, "regions": hashed}))
    if set(regions) != set(original.memories):
        raise Malformed("layout.memories", sorted(original.memories), sorted(regions))
    digest = sha256_jcs({"memories": [entry for _, entry in sorted(entries, key=lambda pair: pair[0])]})
    run.check("layout_hash", _hex32(record, "layout_hash"), digest)
    return digest, regions


def _inside(patch: Patch, regions: dict[str, list[Region]], kind: str) -> bool:
    return any(r.kind == kind and r.start <= patch.offset and patch.end <= r.end for r in regions[patch.memory_id])


def _write(buffers: dict[str, bytearray], patch: Patch, regions: dict[str, list[Region]], kind: str) -> None:
    """SPEC-001 R23 or R40 (containment), then R21 (precondition), then the write."""
    field = f"patch {patch.patch_hash}"
    if patch.memory_id not in buffers:
        raise Malformed(field, "a memory of the original (SPEC-001 R23)", "unknown_memory")
    if not _inside(patch, regions, kind):
        reason = "out_of_region" if kind == "calibration" else "checksum_out_of_region"
        raise Malformed(field, f"inside one {kind} region (SPEC-001 R23, R40)", reason)
    buffer = buffers[patch.memory_id]
    if bytes(buffer[patch.offset : patch.end]) != patch.before:
        raise Malformed(field, "the current bytes equal before (SPEC-001 R21)", "before_mismatch")
    buffer[patch.offset : patch.end] = patch.after


def _image(original: Original, buffers: dict[str, bytearray]) -> str:
    memories = [Memory(m.memory_id, m.base_address, bytes(buffers[m.memory_id])) for m in original.memories.values()]
    return image_hash(original.dump_kind, memories)


def _run(run: Run, bundle: object) -> None:
    """R73 steps 1 to 7, in order."""
    raw = _fields(bundle, "bundle", BUNDLE_KEYS)
    if raw["schema"] != BUNDLE_SCHEMA:
        raise Malformed("bundle.schema", BUNDLE_SCHEMA, raw["schema"])
    run.step = 1
    record = _record(run, raw["report_file"])
    run.reproducibility = reproducibility(record)
    run.step = 2
    original = _original(run, raw["original"], record)
    run.step = 3
    layout_digest, regions = _layout(run, raw["layout"], original, record)
    run.step = 4
    patches = _patches(raw["patches"], "patches")
    overlaps = _pairs(raw["overlaps"], "overlaps")
    listed = _hashes(record.get("patch_hashes"), "report.record.patch_hashes")
    order = canonical_order(patches, overlaps)
    if sorted(listed) != sorted(p.patch_hash for p in patches):
        run.check("patch_hashes", sorted(listed), sorted(p.patch_hash for p in patches))
    else:
        run.check("patch_order", listed, [p.patch_hash for p in order])
    run.check("overlaps", _pairs(record.get("overlaps"), "report.record.overlaps"), sorted(overlaps))
    digest = version_hash(original.image_hash, layout_digest, order, overlaps)
    run.check("version_hash", _hex32(record, "version_hash"), digest)
    run.step = 5
    if any(m.base_address is None for m in original.memories.values()):
        raise Malformed("original.memories", "every base_address known (SPEC-001 R2)", "unknown_base_address")
    buffers = {memory_id: bytearray(memory.data) for memory_id, memory in original.memories.items()}
    for patch in order:
        _write(buffers, patch, regions, "calibration")
    run.check("image_hash_apply", _hex32(record, "image_hash_apply"), _image(original, buffers))
    run.step = 6
    checksum = sorted(_patches(raw["checksum_patches"], "checksum_patches"), key=lambda p: (p.memory_id, p.offset))
    listed = _hashes(record.get("checksum_patch_hashes"), "report.record.checksum_patch_hashes")
    run.check("checksum_patch_hashes", listed, [p.patch_hash for p in checksum])
    for i, patch in enumerate(checksum):
        if i and _overlap(checksum[i - 1], patch):
            raise Malformed("checksum_patches", "disjoint checksum patches (SPEC-001 R40, R22)", patch.patch_hash)
        _write(buffers, patch, regions, "checksum")
    run.check("image_hash_release", _hex32(record, "image_hash_release"), _image(original, buffers))
    run.step = 7
    run.check("gate_report_hash", _hex32(record, "gate_report_hash"), sha256_jcs(raw["gate_report"], "gate_report"))


def _no_float(text: str) -> object:
    raise Malformed("bundle", "JSON without floats or non-finite numbers (SPEC-005 R1)", text)


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise Malformed("bundle", "JSON without duplicate keys (SPEC-005 R3)", key)
        value[key] = item
    return value


def _result(run: Run) -> dict[str, object]:
    """R74, with the R75 limits; a `best_effort` record says so."""
    limits = [*LIMITS, BEST_EFFORT] if run.reproducibility == "best_effort" else list(LIMITS)
    return {
        "status": "not_reproduced" if run.mismatches else "reproduced",
        "reproducibility": run.reproducibility,
        "mismatches": [
            {"step": m.step, "field": m.field, "expected": m.expected, "got": m.got} for m in run.mismatches
        ],
        "limits": limits,
    }


def reproduce(data: bytes) -> dict[str, object]:
    """The R74 result for the bundle bytes."""
    run = Run()
    try:
        try:
            bundle: object = json.loads(
                data.decode("utf-8"), parse_float=_no_float, parse_constant=_no_float, object_pairs_hook=_unique_keys
            )
        except (UnicodeDecodeError, ValueError) as error:
            raise Malformed("bundle", "UTF-8 JSON", type(error).__name__) from error
        _run(run, bundle)
    except Malformed as error:
        run.mismatches.append(Mismatch(run.step, error.field, error.expected, error.got))
    return _result(run)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write("usage: python -I reproduce.py <bundle.json>\n")
        return 2
    try:
        with open(argv[1], "rb") as handle:
            result = reproduce(handle.read())
    except OSError as error:
        run = Run()
        run.mismatches.append(Mismatch(0, "bundle", "a readable file", error.strerror))
        result = _result(run)
    sys.stdout.write(json.dumps(result, sort_keys=True, indent=2) + "\n")
    return 0 if result["status"] == "reproduced" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
