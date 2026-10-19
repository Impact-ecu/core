"""The interpreter's two engines (SPEC-002 R81) and their comparison.

Engine A is the R62 reference: the bitwise MSB-first CRC register and word-by-word accumulation.
Engine B is a 256-entry table CRC for the same register (reflection by bit reversal of input bytes and
of the result) and byte-lane accumulation. Neither calls the other; `agree` is the only place a value
leaves this module, and a difference is `InterpreterDivergence`, never a `fail` status.
"""

import hashlib
from collections.abc import Sequence

from core.plugins._errors import InterpreterDivergence
from core.plugins._schema import Algorithm, Crc32, WordAlgorithm, width

MASK32 = 0xFFFFFFFF


def agree(a: int, b: int, what: str) -> int:
    if a != b:
        raise InterpreterDivergence(f"{what}: engine A {a:#x}, engine B {b:#x}")
    return a


def agree_digest(a: str, b: str, what: str) -> str:
    if a != b:
        raise InterpreterDivergence(f"{what}: engine A {a}, engine B {b}")
    return a


# Engine A.


def _reverse_a(value: int, bits: int) -> int:
    out = 0
    for _ in range(bits):
        out = (out << 1) | (value & 1)
        value >>= 1
    return out


def crc32_a(message: bytes, algorithm: Crc32) -> int:
    reg = algorithm.init
    for byte in message:
        b = _reverse_a(byte, 8) if algorithm.reflect_in else byte
        reg ^= b << 24
        for _ in range(8):
            reg = ((reg << 1) ^ algorithm.poly) & MASK32 if reg & 0x80000000 else (reg << 1) & MASK32
    if algorithm.reflect_out:
        reg = _reverse_a(reg, 32)
    return reg ^ algorithm.xor_out


def words_a(algorithm: WordAlgorithm, pieces: Sequence[bytes]) -> int:
    """Raw accumulator (before `xor_out`), one word at a time."""
    size = algorithm.word_size
    modulus = 1 << width(algorithm)
    acc = algorithm.init
    for piece in pieces:
        for offset in range(0, len(piece), size):
            word = int.from_bytes(piece[offset : offset + size], algorithm.endianness)
            acc = acc ^ word if algorithm.name == "xor" else (acc + word) % modulus
    return acc


def digest_a(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# Engine B.


def _reverse_b(value: int, bits: int) -> int:
    return int(format(value, f"0{bits}b")[::-1], 2)


def _crc_table(poly: int) -> tuple[int, ...]:
    table: list[int] = []
    for index in range(256):
        reg = index << 24
        for _ in range(8):
            reg = (reg << 1) ^ poly if reg & 0x80000000 else reg << 1
        table.append(reg & MASK32)
    return tuple(table)


def crc32_b(message: bytes, algorithm: Crc32) -> int:
    table = _crc_table(algorithm.poly)
    data = bytes(_reverse_b(byte, 8) for byte in message) if algorithm.reflect_in else message
    reg = algorithm.init
    for byte in data:
        reg = ((reg << 8) & MASK32) ^ table[(reg >> 24) ^ byte]
    if algorithm.reflect_out:
        reg = _reverse_b(reg, 32)
    return reg ^ algorithm.xor_out


def words_b(algorithm: WordAlgorithm, pieces: Sequence[bytes]) -> int:
    """Raw accumulator by byte lanes: lane i holds the i-th least significant byte of every word."""
    size = algorithm.word_size
    lanes = [0] * size
    for piece in pieces:
        for lane in range(size):
            # Position of the lane's byte inside each word.
            position = lane if algorithm.endianness == "little" else size - 1 - lane
            column = piece[position::size]
            if algorithm.name == "xor":
                for byte in column:
                    lanes[lane] ^= byte
            else:
                lanes[lane] += sum(column)
    total = sum(lane_value << (8 * lane) for lane, lane_value in enumerate(lanes))
    if algorithm.name == "xor":
        return algorithm.init ^ total
    return (algorithm.init + total) % (1 << width(algorithm))


def digest_b(data: bytes) -> str:
    hasher = hashlib.sha256()
    for offset in range(0, len(data), 64):
        hasher.update(bytes(data[offset : offset + 64]))
    return hasher.hexdigest()


# Both engines, compared.


def raw(algorithm: WordAlgorithm, pieces: Sequence[bytes], what: str) -> int:
    return agree(words_a(algorithm, pieces), words_b(algorithm, pieces), what)


def value(algorithm: Algorithm, pieces: Sequence[bytes], what: str) -> int:
    """R62 `value` over the message pieces, in `[0, 2**W)`."""
    if isinstance(algorithm, Crc32):
        message = b"".join(pieces)
        return agree(crc32_a(message, algorithm), crc32_b(message, algorithm), what)
    return raw(algorithm, pieces, what) ^ algorithm.xor_out


def digest(data: bytes, what: str) -> str:
    return agree_digest(digest_a(data), digest_b(data), what)
