"""Smart MMIO fallback handler for unmapped peripheral addresses.

Catches all MMIO accesses not handled by SVD models or HAL hooks.
Returns intelligent defaults based on access patterns.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from rtosploit.peripherals.models.svd_peripheral import SVDPeripheralModel

logger = logging.getLogger(__name__)


@dataclass
class MMIOAccess:
    """Record of a single MMIO access."""

    address: int
    is_write: bool
    value: int
    count: int = 1


# Cortex-M Private Peripheral Bus (PPB) system register defaults
_SYSTEM_REGISTER_DEFAULTS: dict[int, int] = {
    # SysTick
    0xE000E010: 0x00000004,  # SYST_CSR: CLKSOURCE=1, not enabled
    0xE000E014: 0x00FFFFFF,  # SYST_RVR: max reload
    0xE000E018: 0x00000000,  # SYST_CVR: current value
    0xE000E01C: 0x00000000,  # SYST_CALIB
    # NVIC (simplified)
    # NVIC_ISER0-7 (0xE000E100-0xE000E11C): all zeros (no interrupts enabled)
    # NVIC_ICER0-7 (0xE000E180-0xE000E19C): all zeros
    # NVIC_ISPR0-7 (0xE000E200-0xE000E21C): all zeros (no pending)
    # NVIC_ICPR0-7 (0xE000E280-0xE000E29C): all zeros
    # SCB
    0xE000ED00: 0x410FC241,  # CPUID: Cortex-M4 r0p1
    0xE000ED04: 0x00000000,  # ICSR
    0xE000ED08: 0x00000000,  # VTOR
    0xE000ED0C: 0xFA050000,  # AIRCR
    0xE000ED10: 0x00000000,  # SCR
    0xE000ED14: 0x00000200,  # CCR: STKALIGN=1
    0xE000ED24: 0x00000000,  # SHCSR
    # FPU
    0xE000ED88: 0x00F00000,  # CPACR: CP10+CP11 full access
    0xE000EF34: 0x00000000,  # FPCCR
    0xE000EF38: 0x00000000,  # FPCAR
    0xE000EF3C: 0x00000000,  # FPDSCR
}


class MMIOFallbackModel:
    """Catch-all MMIO handler for unmapped peripheral addresses.

    Strategy:
    - First read at new address: return 0x00000001 (generic "ready" bit)
    - Subsequent reads at same address: return last written value, or "ready"
    - Track all accesses for diagnostics
    - Detect poll loops: if same address read >10 times without write,
      alternate between 0x0 and 0x1 to break the loop
    """

    def __init__(self) -> None:
        self._written_values: dict[int, int] = {}
        self._read_counts: dict[int, int] = defaultdict(int)
        self._write_counts: dict[int, int] = defaultdict(int)
        self._access_log: list[MMIOAccess] = []
        self._max_log_size: int = 10000

    def read_register(self, address: int, size: int = 4) -> int:
        """Handle MMIO read at given address."""
        self._read_counts[address] += 1
        count = self._read_counts[address]

        # Log access
        if len(self._access_log) < self._max_log_size:
            self._access_log.append(
                MMIOAccess(address=address, is_write=False, value=0, count=count)
            )

        # If previously written, return that value (echo-back)
        if address in self._written_values:
            value = self._written_values[address]
            logger.debug("MMIO fallback read 0x%08X -> 0x%08X (echo)", address, value)
            return value

        # Poll loop detection: alternate 0/1 after 10 reads
        if count > 10:
            value = 0x1 if (count % 2 == 0) else 0x0
            logger.debug(
                "MMIO fallback read 0x%08X -> 0x%08X (poll loop #%d)",
                address,
                value,
                count,
            )
            return value

        # Default: return "ready" bit
        logger.debug("MMIO fallback read 0x%08X -> 0x00000001 (ready default)", address)
        return 0x00000001

    def write_register(self, address: int, value: int, size: int = 4) -> None:
        """Handle MMIO write at given address."""
        self._written_values[address] = value
        self._write_counts[address] += 1
        self._read_counts[address] = 0  # Reset read count on write

        if len(self._access_log) < self._max_log_size:
            self._access_log.append(
                MMIOAccess(address=address, is_write=True, value=value)
            )

        logger.debug("MMIO fallback write 0x%08X <- 0x%08X", address, value)

    def get_access_log(self) -> list[MMIOAccess]:
        """Return a copy of the access log."""
        return list(self._access_log)

    def get_unhandled_addresses(self) -> list[int]:
        """Return sorted list of all accessed addresses."""
        addrs = set(self._read_counts.keys()) | set(self._write_counts.keys())
        return sorted(addrs)

    def get_access_stats(self) -> dict[int, dict[str, int]]:
        """Return per-address read/write counts."""
        addrs = set(self._read_counts.keys()) | set(self._write_counts.keys())
        return {
            addr: {
                "reads": self._read_counts.get(addr, 0),
                "writes": self._write_counts.get(addr, 0),
            }
            for addr in sorted(addrs)
        }

    @property
    def total_reads(self) -> int:
        """Total number of fallback reads."""
        return sum(self._read_counts.values())

    @property
    def total_writes(self) -> int:
        """Total number of fallback writes."""
        return sum(self._write_counts.values())


class CortexMSystemRegisters:
    """Handle Cortex-M system registers in the PPB region (0xE0000000-0xE00FFFFF).

    Provides sensible defaults for SysTick, NVIC, SCB, and FPU registers
    so firmware that probes system configuration can proceed without hanging.
    """

    def __init__(self) -> None:
        self._values: dict[int, int] = dict(_SYSTEM_REGISTER_DEFAULTS)
        self._systick_counter: int = 0

    def contains(self, address: int) -> bool:
        """Check whether address falls in the PPB region."""
        return 0xE0000000 <= address < 0xE0100000

    def read_register(self, address: int, size: int = 4) -> int:
        """Read a system register, with special handling for SysTick CVR."""
        # SysTick current value: decrement each read to simulate countdown
        if address == 0xE000E018:
            self._systick_counter = (self._systick_counter - 1) & 0x00FFFFFF
            return self._systick_counter
        return self._values.get(address, 0x00000000)

    def write_register(self, address: int, value: int, size: int = 4) -> None:
        """Write a system register, with special handling for NVIC and SCB."""
        self._values[address] = value

        # NVIC_ISPR writes set pending interrupts (just track)
        if 0xE000E200 <= address <= 0xE000E21C:
            logger.debug("NVIC set pending: 0x%08X", value)

        # SCB_AIRCR write with VECTKEY resets
        if address == 0xE000ED0C and (value >> 16) == 0x05FA:
            if value & 0x4:  # SYSRESETREQ
                logger.warning("System reset requested via AIRCR")


class CompositeMMIOHandler:
    """Chains SVD models -> system registers -> MMIO fallback.

    Routes MMIO accesses to the most specific handler available:
    1. Cortex-M system registers (PPB region 0xE0000000-0xE00FFFFF)
    2. SVD-backed peripheral models (known peripheral address ranges)
    3. Generic MMIO fallback (everything else)
    """

    def __init__(
        self,
        svd_models: Optional[dict[str, SVDPeripheralModel]] = None,
        fallback: Optional[MMIOFallbackModel] = None,
        system_regs: Optional[CortexMSystemRegisters] = None,
    ) -> None:
        self._svd_models = svd_models or {}
        self._fallback = fallback or MMIOFallbackModel()
        self._system_regs = system_regs or CortexMSystemRegisters()
        self._svd_handled: int = 0
        self._fallback_handled: int = 0
        self._system_handled: int = 0

    def read(self, address: int, size: int = 4) -> int:
        """Route a read to the appropriate handler."""
        # System registers first (PPB region)
        if self._system_regs.contains(address):
            self._system_handled += 1
            return self._system_regs.read_register(address, size)

        # SVD models (address converted to offset from peripheral base)
        for _name, model in self._svd_models.items():
            periph = model.svd_peripheral
            if periph.base_address <= address < periph.base_address + periph.size:
                self._svd_handled += 1
                offset = address - periph.base_address
                return model.read_register(offset, size)

        # Fallback (uses absolute address)
        self._fallback_handled += 1
        return self._fallback.read_register(address, size)

    def write(self, address: int, value: int, size: int = 4) -> None:
        """Route a write to the appropriate handler."""
        if self._system_regs.contains(address):
            self._system_handled += 1
            self._system_regs.write_register(address, value, size)
            return

        for _name, model in self._svd_models.items():
            periph = model.svd_peripheral
            if periph.base_address <= address < periph.base_address + periph.size:
                self._svd_handled += 1
                offset = address - periph.base_address
                model.write_register(offset, value, size)
                return

        self._fallback_handled += 1
        self._fallback.write_register(address, value, size)

    @property
    def fallback(self) -> MMIOFallbackModel:
        """Access the underlying fallback model for diagnostics."""
        return self._fallback

    @property
    def system_regs(self) -> CortexMSystemRegisters:
        """Access the system register handler."""
        return self._system_regs

    def get_coverage_stats(self) -> dict[str, int | float]:
        """Return handler routing statistics."""
        total = self._svd_handled + self._fallback_handled + self._system_handled
        return {
            "svd_handled": self._svd_handled,
            "system_handled": self._system_handled,
            "fallback_handled": self._fallback_handled,
            "total": total,
            "svd_coverage_pct": round(
                self._svd_handled / max(total, 1) * 100, 1
            ),
        }
