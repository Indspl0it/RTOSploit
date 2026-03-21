"""Fuzz input injection via HAL hooks.

Routes fuzz bytes to discovered input channels (UART RX, SPI RX, etc.)
based on HAL database semantic analysis.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from rtosploit.peripherals.hal_database import HALDatabase
from rtosploit.utils.binary import FirmwareImage

logger = logging.getLogger(__name__)


@dataclass
class FuzzableInput:
    """A discovered fuzzable input point."""
    symbol: str
    address: int
    peripheral_type: str  # "uart", "spi", "i2c", etc.
    vendor: str
    buffer_size: int = 256  # Default buffer size
    priority: int = 0  # Higher = more fuzz bytes allocated

# Priority by peripheral type (UART gets most bytes since it's most common attack surface)
_TYPE_PRIORITY: dict[str, int] = {
    "uart": 100,
    "ble": 90,
    "spi": 70,
    "i2c": 60,
    "gpio": 20,
    "adc": 10,
}


class InputInjector:
    """Routes fuzz data to HAL input hooks."""

    def __init__(self, inputs: Optional[list[FuzzableInput]] = None) -> None:
        self._inputs = inputs or []
        self._total_injected: int = 0

    @classmethod
    def discover(cls, firmware: FirmwareImage) -> "InputInjector":
        """Auto-discover fuzzable input points from firmware symbols."""
        if not firmware.symbols:
            return cls([])

        db = HALDatabase()
        input_funcs = db.get_input_functions()

        inputs: list[FuzzableInput] = []
        seen_symbols: set[str] = set()

        for entry in input_funcs:
            if entry.symbol in firmware.symbols and entry.symbol not in seen_symbols:
                seen_symbols.add(entry.symbol)
                inputs.append(FuzzableInput(
                    symbol=entry.symbol,
                    address=firmware.symbols[entry.symbol],
                    peripheral_type=entry.peripheral_type,
                    vendor=entry.vendor,
                    priority=_TYPE_PRIORITY.get(entry.peripheral_type, 0),
                ))

        # Sort by priority (highest first)
        inputs.sort(key=lambda x: -x.priority)

        logger.info(f"Discovered {len(inputs)} fuzzable input points")
        for inp in inputs:
            logger.debug(f"  {inp.symbol} @ 0x{inp.address:08X} ({inp.peripheral_type})")

        return cls(inputs)

    @property
    def inputs(self) -> list[FuzzableInput]:
        return list(self._inputs)

    @property
    def input_count(self) -> int:
        return len(self._inputs)

    @property
    def total_injected(self) -> int:
        return self._total_injected

    def split_data(self, data: bytes) -> list[tuple[FuzzableInput, bytes]]:
        """Split fuzz data across input channels proportional to priority.

        Returns list of (input, data_chunk) pairs.
        """
        if not self._inputs or not data:
            return []

        total_priority = sum(inp.priority or 1 for inp in self._inputs)
        result: list[tuple[FuzzableInput, bytes]] = []
        offset = 0

        for i, inp in enumerate(self._inputs):
            priority = inp.priority or 1
            # Last input gets remaining bytes
            if i == len(self._inputs) - 1:
                chunk = data[offset:]
            else:
                chunk_size = max(1, len(data) * priority // total_priority)
                chunk = data[offset:offset + chunk_size]
                offset += chunk_size

            if chunk:
                result.append((inp, chunk))

        self._total_injected += len(data)
        return result

    def get_breakpoint_addresses(self) -> list[int]:
        """Return addresses where GDB breakpoints should be set for input injection."""
        return [inp.address for inp in self._inputs]

    def to_dict(self) -> dict:
        """Serialize for reporting."""
        return {
            "input_count": len(self._inputs),
            "total_injected": self._total_injected,
            "inputs": [
                {
                    "symbol": inp.symbol,
                    "address": f"0x{inp.address:08X}",
                    "type": inp.peripheral_type,
                    "vendor": inp.vendor,
                    "priority": inp.priority,
                }
                for inp in self._inputs
            ],
        }
