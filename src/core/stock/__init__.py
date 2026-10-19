"""Stock registry (SPEC-008): is this memory image what the factory shipped for this software version?

Pure (R40): no I/O, network, clock, randomness, environment reads or threads. The registry, `as_of`, the
identification and the `Verifier` are inputs. The classification is information, never a gate input (R26).
"""

from core.stock._check import MemoryStock, Status, StockCheck, stock_check, stock_check_json
from core.stock._registry import (
    SignedStockRegistry,
    StockEntry,
    StockError,
    StockRegistry,
    kept_sha256,
    parse_signed_registry,
    registry_hash,
)

__all__ = [
    "MemoryStock",
    "SignedStockRegistry",
    "Status",
    "StockCheck",
    "StockEntry",
    "StockError",
    "StockRegistry",
    "kept_sha256",
    "parse_signed_registry",
    "registry_hash",
    "stock_check",
    "stock_check_json",
]
