"""Importers (SPEC-006 §3): the `Importer` contract, `run_import`, `dispatch` and the raw importer.

Imports `core.kernel` only (SPEC-006 R4). Pure: no I/O, network, clock, randomness, environment,
threads or global state (SPEC-001 R71).
"""

from core.importers._contract import (
    CONTRACT_VERSION,
    MAX_INPUT_BYTES,
    MAX_MEMORIES,
    RAW_IMPORTER_ID,
    Imported,
    Importer,
    ImporterContractError,
    ImportParams,
    ImportRecord,
    ImportRejected,
    RejectReason,
    dispatch,
    import_record_hash,
    import_record_jcs,
    outcome_jcs,
    run_import,
)
from core.importers._json import JsonValue, jcs, jcs_hash
from core.importers._raw import RAW_CONTAINER_KIND, RAW_IMPORTER, RawImporter

__all__ = [
    "CONTRACT_VERSION",
    "MAX_INPUT_BYTES",
    "MAX_MEMORIES",
    "RAW_CONTAINER_KIND",
    "RAW_IMPORTER",
    "RAW_IMPORTER_ID",
    "ImportParams",
    "ImportRecord",
    "ImportRejected",
    "Imported",
    "Importer",
    "ImporterContractError",
    "JsonValue",
    "RawImporter",
    "RejectReason",
    "dispatch",
    "import_record_hash",
    "import_record_jcs",
    "jcs",
    "jcs_hash",
    "outcome_jcs",
    "run_import",
]
