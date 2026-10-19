"""Test-only importers. Every byte is synthetic; the container format below exists only in these tests.

Synthetic container ("synth"), all integers big-endian:
    b"SYNC" | flags u8 (bit 0: encrypted) | read_mode u8 (0: not recorded, 1-5: DUMP_KINDS[i-1]) | count u8
    count x ( id_len u8 | id | has_base u8 | base u32 | length u32 | data )
    sha256 of everything above (32 bytes)
"""

import hashlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from core.importers import ImportParams, ImportRejected
from core.kernel import Dump, DumpKind, Memory

MAGIC = b"SYNC"
DUMP_KINDS: tuple[DumpKind, ...] = ("bench_full", "boot_full", "obd_full", "obd_partial", "virtual")
MEMORY_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_")


def encode_synth(
    memories: Sequence[tuple[str, int | None, bytes]], *, read_mode: int = 0, encrypted: bool = False
) -> bytes:
    body = bytearray(MAGIC)
    body += bytes([1 if encrypted else 0, read_mode, len(memories)])
    for memory_id, base, data in memories:
        raw_id = memory_id.encode("ascii")
        body += bytes([len(raw_id)]) + raw_id
        body += bytes([0 if base is None else 1]) + (base or 0).to_bytes(4, "big")
        body += len(data).to_bytes(4, "big") + data
    return bytes(body) + hashlib.sha256(body).digest()


def _valid_memory_id(raw: bytes) -> bool:
    text = raw.decode("ascii", "replace")
    return 1 <= len(text) <= 32 and "a" <= text[0] <= "z" and set(text) <= MEMORY_ID_CHARS


class SynthImporter:
    """A careful importer of the synthetic container: never raises, never guesses (SPEC-006 R12, R13)."""

    importer_id = "test.synth"
    version = "1.0.0"
    contract_version = 1
    container_kind = "synth"

    def import_file(self, data: bytes, params: ImportParams) -> Dump | ImportRejected:
        rejection = self._precheck(data, params)
        if rejection is not None:
            return rejection
        memories = self._memories(data[:-32])
        if not memories:
            return ImportRejected("malformed", "synth")
        if data[5] and DUMP_KINDS[data[5] - 1] != params.dump_kind:
            return ImportRejected("dump_kind_conflict", "synth")
        return Dump(params.dump_kind, tuple(memories))

    @staticmethod
    def _precheck(data: bytes, params: ImportParams) -> ImportRejected | None:
        if not data.startswith(MAGIC):
            return ImportRejected("unsupported_container", None)
        if len(data) < 7 + 32:
            return ImportRejected("malformed", "synth")
        if data[4] & 1:
            return ImportRejected("encrypted_container", "synth")
        if dict(params.options) != {}:
            return ImportRejected("bad_params", "synth")
        if hashlib.sha256(data[:-32]).digest() != data[-32:] or data[4] > 1 or data[5] > len(DUMP_KINDS):
            return ImportRejected("malformed", "synth")
        return None

    @staticmethod
    def _memories(body: bytes) -> list[Memory] | None:
        position, memories, seen = 7, [], set()
        for _ in range(body[6]):
            if position >= len(body):
                return None
            id_len = body[position]
            raw_id = body[position + 1 : position + 1 + id_len]
            position += 1 + id_len
            header = body[position : position + 9]
            if len(raw_id) != id_len or len(header) != 9 or header[0] > 1 or not _valid_memory_id(raw_id):
                return None
            length = int.from_bytes(header[5:9], "big")
            payload = body[position + 9 : position + 9 + length]
            position += 9 + length
            memory_id = raw_id.decode("ascii")
            if len(payload) != length or length == 0 or memory_id in seen:
                return None
            seen.add(memory_id)
            base = int.from_bytes(header[1:5], "big") if header[0] else None
            memories.append(Memory(memory_id, base, payload))
        return memories if position == len(body) else None


@dataclass
class ScriptedImporter:
    """An importer whose behavior a test chooses; used to break the contract on purpose."""

    behavior: Callable[[bytes, ImportParams], Dump | ImportRejected]
    importer_id: str = "test.scripted"
    version: str = "1.0.0"
    contract_version: int = 1
    container_kind: str = "scripted"
    calls: list[bytes] = field(default_factory=list)

    def import_file(self, data: bytes, params: ImportParams) -> Dump | ImportRejected:
        self.calls.append(data)
        return self.behavior(data, params)
