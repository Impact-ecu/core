"""The built-in raw importer (SPEC-006 §3.4)."""

from typing import final

import core
from core.importers._contract import (
    CONTRACT_VERSION,
    DUMP_KINDS,
    MEMORY_ID,
    RAW_IMPORTER_ID,
    ImportParams,
    ImportRejected,
)
from core.kernel import Dump, KernelInvariantError, Memory

RAW_CONTAINER_KIND = "raw"


def ensure(holds: bool, rule: str) -> None:
    # Not `assert`: it must stay active under `python -O` (SPEC-006 R112).
    if not holds:
        raise KernelInvariantError(rule)


@final
class RawImporter:
    """One file is one memory, bytes unchanged, `base_address` unknown (SPEC-006 R27-R29).

    Never chosen by `dispatch` (R26): the caller selects it explicitly.
    """

    __slots__ = ()

    importer_id: str = RAW_IMPORTER_ID
    # R27: the raw importer is part of `core` and versioned with it.
    version: str = core.__version__
    contract_version: int = CONTRACT_VERSION
    container_kind: str = RAW_CONTAINER_KIND

    def import_file(self, data: bytes, params: ImportParams) -> Dump | ImportRejected:
        # R28: exactly `{memory_id}`, no defaults. dump_kind is re-checked so a direct call never raises (R12).
        options = params.options
        if (
            params.dump_kind not in DUMP_KINDS
            or set(options) != {"memory_id"}
            or not isinstance(memory_id := options["memory_id"], str)
            or MEMORY_ID.fullmatch(memory_id) is None
        ):
            return ImportRejected("bad_params", RAW_CONTAINER_KIND)
        if not data:
            return ImportRejected("empty_input", RAW_CONTAINER_KIND)
        dump = Dump(params.dump_kind, (Memory(memory_id, None, data),))
        ensure(
            len(dump.memories) == 1 and dump.memories[0].data is data and dump.memories[0].base_address is None,
            "SPEC-006 R29",
        )
        return dump


RAW_IMPORTER = RawImporter()
