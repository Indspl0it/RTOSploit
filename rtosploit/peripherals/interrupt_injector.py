"""Interrupt injection for rehosted firmware.

Injects interrupts by writing to NVIC Interrupt Set Pending Registers (ISPR).
Uses the firmware's vector table to identify which ISRs are registered.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional, Protocol

from rtosploit.peripherals.svd_model import SVDDevice
from rtosploit.utils.binary import FirmwareImage

logger = logging.getLogger(__name__)


# NVIC register addresses (Cortex-M)
_NVIC_ISPR_BASE = 0xE000_E200  # Interrupt Set Pending Register base
_NVIC_ISPR_COUNT = 8  # 8 registers, 32 bits each = 256 interrupts

# Number of system exception vectors before external IRQs in the Cortex-M
# vector table: initial_sp, reset, nmi, hardfault, memmanage, busfault,
# usagefault, 4x reserved, svc, debugmon, reserved, pendsv, systick = 16.
_SYSTEM_EXCEPTION_COUNT = 16


class GDBInterface(Protocol):
    """Protocol for GDB memory access (satisfied by GDBClient)."""

    def write_memory(self, address: int, data: bytes) -> None: ...
    def read_memory(self, address: int, size: int) -> bytes: ...


@dataclass
class ISREntry:
    """A registered Interrupt Service Routine."""

    irq_number: int
    vector_address: int  # Address in vector table
    handler_address: int  # ISR function address (thumb bit stripped)
    peripheral_name: str = ""
    description: str = ""


class InterruptInjector:
    """Manages interrupt injection for rehosted firmware.

    Parses the Cortex-M vector table to discover registered ISRs and can
    inject interrupts by writing to NVIC_ISPR registers via a GDB connection.
    """

    def __init__(
        self,
        firmware: FirmwareImage,
        svd_device: Optional[SVDDevice] = None,
    ) -> None:
        self._firmware = firmware
        self._svd_device = svd_device
        self._isrs: list[ISREntry] = []
        self._injection_count: dict[int, int] = {}  # irq_number -> count
        self._discover_isrs()

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def _discover_isrs(self) -> None:
        """Discover registered ISRs from the vector table and SVD metadata.

        The Cortex-M vector table starts at the firmware base address.
        Entries 0-15 are system exceptions (SP, Reset, NMI, ..., SysTick).
        Entries 16+ map to external IRQ numbers: IRQ 0 = vector[16], etc.

        ``get_vector_table()`` only returns the first 16 entries, so we
        read external-IRQ entries directly via ``read_word()``.
        """
        # Build IRQ -> peripheral name mapping from SVD
        irq_to_peripheral: dict[int, str] = {}
        if self._svd_device:
            for periph in self._svd_device.peripherals:
                for irq_num in periph.irq_numbers:
                    irq_to_peripheral[irq_num] = periph.name

        # Validate that the vector table is plausible by checking that the
        # system exception region is readable.
        try:
            self._firmware.read_word(self._firmware.base_address)
        except (ValueError, IndexError):
            logger.warning("Could not read vector table base — skipping ISR discovery")
            return

        # Determine the default handler address so we can skip entries that
        # point to it. Many toolchains set unused vectors to the same
        # Default_Handler address.  We use the hardfault handler as a proxy
        # for "not a real ISR" only when it equals the majority of entries.
        default_handler: Optional[int] = None
        try:
            vtable = self._firmware.get_vector_table()
            # If hardfault and reset point to different addresses, hardfault
            # is likely a dedicated handler and not a useful default sentinel.
            hf = vtable.get("hardfault")
            reset = vtable.get("reset")
            if hf is not None and reset is not None and hf != reset:
                default_handler = None  # can't infer a safe default
            elif hf is not None:
                default_handler = hf & ~1
        except (ValueError, Exception):
            pass

        base = self._firmware.base_address
        firmware_end = base + len(self._firmware.data)

        for irq in range(_NVIC_ISPR_COUNT * 32):  # up to 256 external IRQs
            vector_addr = base + (_SYSTEM_EXCEPTION_COUNT + irq) * 4
            try:
                raw_handler = self._firmware.read_word(vector_addr)
            except (ValueError, IndexError):
                # Past end of firmware data — stop scanning.
                break

            # Null or erased entries
            if raw_handler == 0 or raw_handler == 0xFFFF_FFFF:
                continue

            # Strip Thumb bit for address comparison
            handler_addr = raw_handler & ~1

            # Skip if handler points outside firmware
            if handler_addr < base or handler_addr >= firmware_end:
                continue

            # Skip if handler is the default/unused handler
            if default_handler is not None and handler_addr == default_handler:
                continue

            self._isrs.append(
                ISREntry(
                    irq_number=irq,
                    vector_address=vector_addr,
                    handler_address=handler_addr,
                    peripheral_name=irq_to_peripheral.get(irq, ""),
                )
            )

        if self._isrs:
            logger.debug(
                "Discovered %d external ISRs in vector table", len(self._isrs)
            )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def discovered_isrs(self) -> list[ISREntry]:
        """Return a copy of all discovered ISR entries."""
        return list(self._isrs)

    @property
    def injectable_irqs(self) -> list[int]:
        """Return the IRQ numbers that have registered handlers."""
        return [isr.irq_number for isr in self._isrs]

    # ------------------------------------------------------------------
    # Injection
    # ------------------------------------------------------------------

    def inject_interrupt(self, irq_number: int, gdb: GDBInterface) -> bool:
        """Inject an interrupt by writing to NVIC_ISPR.

        Sets the pending bit for *irq_number* so the NVIC will fire the
        corresponding ISR at the next suitable preemption point.

        Args:
            irq_number: External IRQ number (0-255).
            gdb: Object satisfying :class:`GDBInterface` (e.g. ``GDBClient``).

        Returns:
            ``True`` if the write succeeded, ``False`` otherwise.
        """
        if irq_number < 0 or irq_number >= _NVIC_ISPR_COUNT * 32:
            logger.warning("IRQ number %d out of range (0-%d)", irq_number, _NVIC_ISPR_COUNT * 32 - 1)
            return False

        register_index = irq_number // 32
        bit_position = irq_number % 32

        ispr_addr = _NVIC_ISPR_BASE + register_index * 4
        value = 1 << bit_position

        try:
            gdb.write_memory(ispr_addr, value.to_bytes(4, "little"))
            self._injection_count[irq_number] = (
                self._injection_count.get(irq_number, 0) + 1
            )
            logger.debug(
                "Injected IRQ %d via NVIC_ISPR%d (0x%08X = 0x%08X)",
                irq_number,
                register_index,
                ispr_addr,
                value,
            )
            return True
        except Exception as exc:
            logger.warning("Failed to inject IRQ %d: %s", irq_number, exc)
            return False

    def inject_all_discovered(self, gdb: GDBInterface) -> int:
        """Inject all discovered interrupts.

        Returns:
            Number of successful injections.
        """
        count = 0
        for isr in self._isrs:
            if self.inject_interrupt(isr.irq_number, gdb):
                count += 1
        return count

    def inject_for_peripheral(
        self, peripheral_name: str, gdb: GDBInterface
    ) -> int:
        """Inject all interrupts associated with a named peripheral.

        Args:
            peripheral_name: SVD peripheral name (case-insensitive).
            gdb: GDB interface.

        Returns:
            Number of successful injections.
        """
        target = peripheral_name.upper()
        count = 0
        for isr in self._isrs:
            if isr.peripheral_name.upper() == target:
                if self.inject_interrupt(isr.irq_number, gdb):
                    count += 1
        return count

    # ------------------------------------------------------------------
    # Stats / introspection
    # ------------------------------------------------------------------

    def get_injection_stats(self) -> dict[int, int]:
        """Return a mapping of IRQ number to injection count."""
        return dict(self._injection_count)

    def reset_stats(self) -> None:
        """Clear accumulated injection statistics."""
        self._injection_count.clear()
