"""SPEC-005 R72: the script's own canonical order and Ed25519 edges, against SPEC-001 vectors and RFC 8032 §5.1.

Expected values come from specs/vectors/spec-001/vectors.json and from the curve equation of RFC 8032 §5.1.
"""

import pytest

import reproduce
from tests.reproduce.bundles import original
from tests.vectors.test_spec_001 import VECTORS as SPEC001

V5 = [case for case in SPEC001["cases"] if case["id"].startswith("V5")]
BASE_IMAGE = SPEC001["original"]["image_hash"]
BASE_LAYOUT = SPEC001["layouts"]["base"]["layout_hash"]
P = 2**255 - 19
D = -121665 * pow(121666, P - 2, P) % P


# SPEC-001 R22, R25, R64 (cases V5, V5b-V5h) through the script's own order and version hash.
@pytest.mark.parametrize("case", V5, ids=[case["id"] for case in V5])
def test_spec001_overlap_cases(case: dict[str, object]) -> None:
    names = case["patches"]
    pairs = case["overlaps"]
    assert isinstance(names, list)
    assert isinstance(pairs, list)
    hashes = {name: SPEC001["patches"][name]["patch_hash"] for name in names}
    raw = [SPEC001["patches"][name]["value"] for name in names]
    expect = case["expect"]
    assert isinstance(expect, dict)
    if expect.get("reason") == "duplicate_patch":
        with pytest.raises(reproduce.Malformed) as dup:
            reproduce._patches(raw, "patches")
        assert dup.value.got == hashes[names[0]]
        return
    patches = reproduce._patches(raw, "patches")
    assert [p.patch_hash for p in patches] == [hashes[n] for n in names]
    overlaps = [(SPEC001["patches"][a]["patch_hash"], SPEC001["patches"][b]["patch_hash"]) for a, b in pairs]
    if "reason" in expect:
        with pytest.raises(reproduce.Malformed) as caught:
            reproduce.canonical_order(patches, overlaps)
        assert caught.value.got == expect["reason"]
        return
    order = reproduce.canonical_order(patches, overlaps)
    if "canonical_order" in expect:
        assert [p.patch_hash for p in order] == [hashes[n] for n in expect["canonical_order"]]
    assert reproduce.version_hash(BASE_IMAGE, BASE_LAYOUT, order, overlaps) == expect["version_hash"]
    memories = {m["memory_id"]: m for m in original()["memories"]}
    buffers = {memory_id: bytearray.fromhex(m["data"]) for memory_id, m in memories.items()}
    regions = {"pflash": [reproduce.Region("calibration", 16, 48)], "dflash": []}
    for patch in order:
        reproduce._write(buffers, patch, regions, "calibration")
    image = reproduce.Original(
        "bench_full",
        {k: reproduce.Memory(k, m["base_address"], bytes.fromhex(m["data"])) for k, m in memories.items()},
        BASE_IMAGE,
    )
    assert reproduce._image(image, buffers) == expect["image_hash"]


# SPEC-001 R61 through the script's own encoding.
def test_patch_hash_is_spec001() -> None:
    for vector in SPEC001["patches"].values():
        value = vector["value"]
        before, after = bytes.fromhex(value["before"]), bytes.fromhex(value["after"])
        assert reproduce.patch_hash(value["memory_id"], value["offset"], before, after) == vector["patch_hash"]


def _encode(y: int, sign: int = 0) -> bytes:
    return (y | sign << 255).to_bytes(32, "little")


def _on_curve(y: int) -> bool:
    """RFC 8032 §5.1.3: x² = (y² - 1) / (d y² + 1) has a root iff the quotient is a square (Euler's criterion)."""
    quotient = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    return quotient == 0 or pow(quotient, (P - 1) // 2, P) == 1


# SPEC-005 R72: point decoding of RFC 8032 §5.1.3.
def test_point_decoding() -> None:
    off = next(y for y in range(2, 100) if not _on_curve(y))
    on = next(y for y in range(2, 100) if _on_curve(y))
    assert reproduce._decode_point(_encode(off)) is None
    point = reproduce._decode_point(_encode(on))
    assert point is not None
    x, y, z, t = point
    assert (z, t) == (1, x * y % P)
    assert (-x * x + y * y) % P == (1 + D * x * x * y * y) % P
    assert x % 2 == 0
    flipped = reproduce._decode_point(_encode(on, 1))
    assert flipped is not None
    assert flipped[0] == P - x
    # y = 1 gives x = 0, which has no negative: the sign bit set is rejected.
    assert reproduce._decode_point(_encode(1)) == (0, 1, 1, 0)
    assert reproduce._decode_point(_encode(1, 1)) is None
    # A non-canonical y (y >= p) is rejected.
    assert reproduce._decode_point(_encode(P + 1)) is None


TEST1_PUBLIC = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
TEST1_SIGNATURE = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)
L = 2**252 + 27742317777372353535851937790883648493


# SPEC-005 R72: RFC 8032 §5.1.7 rejections.
def test_signature_rejections() -> None:
    assert reproduce.ed25519_verify(TEST1_PUBLIC, b"", TEST1_SIGNATURE)
    assert not reproduce.ed25519_verify(TEST1_PUBLIC[:31], b"", TEST1_SIGNATURE)
    assert not reproduce.ed25519_verify(TEST1_PUBLIC, b"", TEST1_SIGNATURE[:63])
    s = int.from_bytes(TEST1_SIGNATURE[32:], "little")
    malleated = TEST1_SIGNATURE[:32] + (s + L).to_bytes(32, "little")
    assert not reproduce.ed25519_verify(TEST1_PUBLIC, b"", malleated)
    off = next(y for y in range(2, 100) if not _on_curve(y))
    assert not reproduce.ed25519_verify(_encode(off), b"", TEST1_SIGNATURE)
    assert not reproduce.ed25519_verify(TEST1_PUBLIC, b"", _encode(off) + TEST1_SIGNATURE[32:])
