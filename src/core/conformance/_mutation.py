"""Seeded single-byte mutations for R117 (inside) and R118 (outside).

The generator is SHA-256 in counter mode over the run seed and a label, so a run is reproducible from
its recorded seed (R127) and the core needs no `random` module (SPEC-001 R71).
"""

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

Mode = Literal["sample", "full"]
UNIFORM = 1000  # R117, R118
EDGE = 64  # R117


@dataclass(frozen=True, slots=True)
class Mutation:
    """XOR `xor` (non-zero) into the byte at `offset` of `memory_id`."""

    memory_id: str
    offset: int
    xor: int


@dataclass(frozen=True, slots=True)
class Piece:
    """`[start, end)` of one memory: a resolved message piece, a static covered range or an output field."""

    memory_id: str
    start: int
    end: int


class Stream:
    """Deterministic draws from `(seed, label)`."""

    __slots__ = ("_buffer", "_counter", "_prefix")

    def __init__(self, seed: int, label: str) -> None:
        self._prefix = f"{seed}:{label}:".encode()
        self._counter = 0
        self._buffer = b""

    def _bytes(self, count: int) -> bytes:
        while len(self._buffer) < count:
            self._buffer += hashlib.sha256(self._prefix + str(self._counter).encode()).digest()
            self._counter += 1
        out, self._buffer = self._buffer[:count], self._buffer[count:]
        return out

    def below(self, bound: int) -> int:
        """Uniform in `[0, bound)`, by rejection so that no value is favored."""
        span = 1 << 64
        limit = span - span % bound
        while True:
            draw = int.from_bytes(self._bytes(8), "big")
            if draw < limit:
                return draw % bound

    def nonzero_byte(self) -> int:
        return 1 + self.below(255)


def _nth(pieces: Sequence[Piece], index: int) -> tuple[str, int]:
    """The `index`-th byte of the concatenated pieces; `index` is below their total length."""
    for piece in pieces[:-1]:
        length = piece.end - piece.start
        if index < length:
            return (piece.memory_id, piece.start + index)
        index -= length
    return (pieces[-1].memory_id, pieces[-1].start + index)


def _mutations(stream: Stream, positions: set[tuple[str, int]]) -> tuple[Mutation, ...]:
    return tuple(Mutation(memory_id, offset, stream.nonzero_byte()) for memory_id, offset in sorted(positions))


def inside_mutations(
    seed: int, label: str, covered: Sequence[Piece], fields: Sequence[Piece], mode: Mode
) -> tuple[Mutation, ...]:
    """R117: uniform positions over the covered bytes, 64 bytes at each edge and the edges of each piece,
    and every byte of each output field; with `full`, every covered byte instead of the uniform sample."""
    stream = Stream(seed, label)
    positions: set[tuple[str, int]] = set()
    total = sum(piece.end - piece.start for piece in covered)
    if mode == "full":
        positions.update(_nth(covered, index) for index in range(total))
    elif total:
        positions.update(_nth(covered, stream.below(total)) for _ in range(UNIFORM))
    for piece in covered:
        positions.update((piece.memory_id, offset) for offset in range(piece.start, min(piece.end, piece.start + EDGE)))
        positions.update((piece.memory_id, offset) for offset in range(max(piece.start, piece.end - EDGE), piece.end))
    for piece in fields:
        positions.update((piece.memory_id, offset) for offset in range(piece.start, piece.end))
    return _mutations(stream, positions)


def _start(piece: Piece) -> int:
    return piece.start


def _complement(sizes: dict[str, int], excluded: Sequence[Piece]) -> list[Piece]:
    out: list[Piece] = []
    for memory_id in sorted(sizes):
        position = 0
        for piece in sorted((p for p in excluded if p.memory_id == memory_id), key=_start):
            if piece.start > position:
                out.append(Piece(memory_id, position, piece.start))
            position = max(position, piece.end)
        if position < sizes[memory_id]:
            out.append(Piece(memory_id, position, sizes[memory_id]))
    return out


def outside_mutations(seed: int, label: str, sizes: dict[str, int], excluded: Sequence[Piece]) -> tuple[Mutation, ...]:
    """R118: uniform positions over bytes outside every coverage, output field and table of the variant."""
    stream = Stream(seed, label)
    free = _complement(sizes, excluded)
    total = sum(piece.end - piece.start for piece in free)
    positions = {_nth(free, stream.below(total)) for _ in range(UNIFORM)} if total else set()
    return _mutations(stream, positions)
