"""SVD-backed peripheral model for automatic register emulation.

Uses SVD register definitions to provide intelligent read/write behavior
without any hand-written peripheral logic. Suitable as a Layer 1 stub
that makes firmware boot by returning plausible register values.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

from rtosploit.peripherals.model import PeripheralModel
from rtosploit.peripherals.svd_model import SVDPeripheral, SVDRegister

logger = logging.getLogger(__name__)

# Patterns that indicate a status/ready register (return all-bits-set)
_STATUS_PATTERNS = re.compile(
    r"(STATUS|EVENTS|READY|READYN?|INTENSET|INTENCLR)",
    re.IGNORECASE,
)

# Patterns that indicate clear-on-read behavior (nRF event registers)
_EVENT_CLEAR_PATTERNS = re.compile(
    r"^EVENTS?_",
    re.IGNORECASE,
)


@dataclass
class AccessStats:
    """Track register access statistics for debugging."""

    reads: int = 0
    writes: int = 0
    unmatched_reads: int = 0
    unmatched_writes: int = 0


class SVDPeripheralModel(PeripheralModel):
    """Peripheral model backed by SVD register definitions.

    Behavior per access type:
    - read-only: return reset_value (immutable)
    - read-write: return current value (tracks writes)
    - write-only: return 0, accept writes

    Smart heuristics:
    - Registers with "STATUS", "EVENTS", "READY" in name -> return all-bits-set
    - Registers with "EVENT" prefix in name -> clear-on-read (nRF pattern)
    """

    def __init__(
        self,
        svd_peripheral: SVDPeripheral,
        name: Optional[str] = None,
    ) -> None:
        periph_name = name or svd_peripheral.name
        super().__init__(
            periph_name,
            svd_peripheral.base_address,
            svd_peripheral.size,
        )
        self._svd = svd_peripheral
        self._register_map: dict[int, SVDRegister] = {
            r.offset: r for r in svd_peripheral.registers
        }
        self.stats = AccessStats()
        self.reset()

    def reset(self) -> None:
        """Reset all registers to their SVD-defined reset values."""
        self._registers.clear()
        for reg in self._svd.registers:
            self._registers[reg.offset] = reg.reset_value

    def read_register(self, offset: int, size: int = 4) -> int:
        """Read a register with access-type-aware behavior."""
        self.stats.reads += 1
        reg = self._register_map.get(offset)

        if reg is None:
            # Unknown register offset — return 0
            self.stats.unmatched_reads += 1
            logger.debug(
                "%s: unmatched read at offset 0x%03x",
                self.name,
                offset,
            )
            return 0

        # Smart heuristic: status/ready registers return all-bits-set
        if _STATUS_PATTERNS.search(reg.name):
            mask = (1 << reg.size) - 1
            value = mask
        else:
            value = self._registers.get(offset, reg.reset_value)

        # Access type behavior
        if reg.access == "write-only":
            return 0
        elif reg.access == "read-only":
            value = reg.reset_value

        # Clear-on-read for nRF event registers
        if _EVENT_CLEAR_PATTERNS.search(reg.name):
            self._registers[offset] = 0

        return value

    def write_register(self, offset: int, value: int, size: int = 4) -> None:
        """Write a register with access-type-aware behavior."""
        self.stats.writes += 1
        reg = self._register_map.get(offset)

        if reg is None:
            self.stats.unmatched_writes += 1
            logger.debug(
                "%s: unmatched write 0x%08x at offset 0x%03x",
                self.name,
                value,
                offset,
            )
            # Still store it — firmware may read it back
            self._registers[offset] = value
            return

        if reg.access == "read-only":
            # Silently ignore writes to read-only registers
            logger.debug(
                "%s: ignored write to read-only register %s",
                self.name,
                reg.name,
            )
            return

        self._registers[offset] = value

    def get_irq(self) -> Optional[int]:
        """Return the first IRQ number if defined in SVD."""
        if self._svd.irq_numbers:
            return self._svd.irq_numbers[0]
        return None

    @property
    def svd_peripheral(self) -> SVDPeripheral:
        """Access the underlying SVD peripheral definition."""
        return self._svd
