"""SPEC-002 R62, R81: engine A, engine B and an independent test-side oracle agree on every value.

Oracles: `zlib.crc32` for the ISO-HDLC parameters, a test-side LSB-first reflected CRC (a different
formulation from both engines) for any fully reflected model, `struct` for words, `hashlib` for digests.
"""

import hashlib
import struct
import zlib

from hypothesis import given
from hypothesis import strategies as st

from core.plugins import Crc32, WordAlgorithm
from core.plugins.descriptor import _engines
from tests.properties.descriptor_strategies import aligned_pieces, crc32s, word_algorithms

ISO_HDLC = Crc32(0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, True, True)


def reverse(value: int, bits: int) -> int:
    return int(f"{value:0{bits}b}"[::-1], 2)


def crc_lsb_first(message: bytes, algorithm: Crc32) -> int:
    """Reflected register with the reversed polynomial: equal to R62 when reflect_in and reflect_out."""
    poly = reverse(algorithm.poly, 32)
    reg = reverse(algorithm.init, 32)
    for byte in message:
        reg ^= byte
        for _ in range(8):
            reg = (reg >> 1) ^ poly if reg & 1 else reg >> 1
    return reg ^ algorithm.xor_out


def words_struct(algorithm: WordAlgorithm, pieces: list[bytes]) -> int:
    code = {1: "B", 2: "H", 4: "I"}[algorithm.word_size]
    order = "<" if algorithm.endianness == "little" else ">"
    acc = algorithm.init
    bits = 16 if algorithm.name == "sum16" else 32 if algorithm.name == "sum32" else 8 * algorithm.word_size
    for piece in pieces:
        for word in struct.unpack(f"{order}{len(piece) // algorithm.word_size}{code}", piece):
            acc = acc ^ word if algorithm.name == "xor" else (acc + word) % (1 << bits)
    return acc


# SPEC-002 R62, R81: CRC-32/ISO-HDLC equals zlib on both engines.
@given(st.binary(max_size=300))
def test_crc_iso_hdlc_matches_zlib(message: bytes) -> None:
    expected = zlib.crc32(message)
    assert _engines.crc32_a(message, ISO_HDLC) == _engines.crc32_b(message, ISO_HDLC) == expected
    assert _engines.value(ISO_HDLC, [message], "iso") == expected


# SPEC-002 R62, R81: any CRC model; both engines agree, and fully reflected models match the oracle.
@given(crc32s, st.lists(st.binary(max_size=60), max_size=4))
def test_crc_engines_agree(algorithm: Crc32, pieces: list[bytes]) -> None:
    message = b"".join(pieces)
    a, b = _engines.crc32_a(message, algorithm), _engines.crc32_b(message, algorithm)
    assert a == b == _engines.value(algorithm, pieces, "crc")
    assert 0 <= a < 2**32
    if algorithm.reflect_in and algorithm.reflect_out:
        assert a == crc_lsb_first(message, algorithm)


# SPEC-002 R62, R67, R81: word-by-word, byte lanes and struct agree for sums and xor.
@given(st.data())
def test_word_engines_agree(data: st.DataObject) -> None:
    algorithm = data.draw(word_algorithms())
    pieces = data.draw(aligned_pieces(algorithm))
    expected = words_struct(algorithm, pieces)
    assert _engines.words_a(algorithm, pieces) == _engines.words_b(algorithm, pieces) == expected
    assert _engines.value(algorithm, pieces, "words") == expected ^ algorithm.xor_out


# SPEC-002 R77, R81: the mirror digest of both engines is SHA-256.
@given(st.binary(max_size=500))
def test_digest_engines_agree(data: bytes) -> None:
    assert _engines.digest_a(data) == _engines.digest_b(data) == hashlib.sha256(data).hexdigest()
    assert _engines.digest(data, "mirror") == hashlib.sha256(data).hexdigest()
